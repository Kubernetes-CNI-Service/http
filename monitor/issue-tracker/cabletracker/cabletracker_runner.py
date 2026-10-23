#!/usr/bin/env python3
"""Standalone CableTracker runner for Google Sheets.

Collection, source normalization, Case planning and value persistence have
explicit boundaries inside this file. See ARCHITECTURE.md for extension points.
Keeping those boundaries in one file preserves standalone/Docker deployment.

Examples:
  python cabletracker_runner.py \
    --spreadsheet-id "1abc..." \
    --cable-report report.json --operation both --compare-existing

  python cabletracker_runner.py \
    --spreadsheet-id "1abc..." --operation import \
    --json-file inventory.json --json-records-path "data.links" \
    --json-field-map '{"Circuit ID":"id","Status":"state","A Node":"a.node"}'

Before running, share the target Google Sheet with the service account email
listed in your credential JSON (usually ending in iam.gserviceaccount.com).
"""

from __future__ import annotations

import argparse
import copy
import csv
import hashlib
import json
import logging
import os
import re
import signal
import sys
import time
from collections import Counter, defaultdict
from contextlib import contextmanager
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from http.cookiejar import MozillaCookieJar
from http.client import IncompleteRead
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Protocol
from urllib.parse import unquote, urlparse
from zoneinfo import ZoneInfo

import httplib2
import httpx
from google_auth_httplib2 import AuthorizedHttp
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import requests
from requests import RequestException
from openai import OpenAI


SCOPES = ["https://www.googleapis.com/auth/spreadsheets"]
LOGGER = logging.getLogger("cabletracker")
DEFAULT_TIMEZONE = "Asia/Shanghai"
GOOGLE_GET_RETRIES = 3
RETRYABLE_GOOGLE_GET_STATUSES = frozenset({408, 429, 500, 502, 503, 504})


class TimezoneFormatter(logging.Formatter):
    """Format log timestamps in the configured operational timezone."""

    def __init__(self, timezone_name: str) -> None:
        super().__init__("%(asctime)s %(levelname)s %(name)s %(message)s")
        self.timezone = ZoneInfo(timezone_name)

    def formatTime(self, record: logging.LogRecord, datefmt: str | None = None) -> str:
        value = datetime.fromtimestamp(record.created, tz=self.timezone)
        return value.strftime(datefmt or "%Y-%m-%d %H:%M:%S %z")


def configure_logging(level: str = "INFO", timezone_name: str = DEFAULT_TIMEZONE) -> None:
    """Configure process-wide operational logging once."""
    numeric_level = getattr(logging, str(level).upper(), logging.INFO)
    handler = next(
        (item for item in LOGGER.handlers if getattr(item, "_cabletracker", False)),
        None,
    )
    if handler is None:
        handler = logging.StreamHandler()
        handler._cabletracker = True  # type: ignore[attr-defined]
        LOGGER.addHandler(handler)
    handler.setFormatter(TimezoneFormatter(timezone_name))
    LOGGER.setLevel(numeric_level)
    LOGGER.propagate = False


class RetryingAuthorizedHttp(AuthorizedHttp):
    """Retry interrupted Google GET responses without repeating writes."""

    def __init__(
        self, *args: Any, get_retries: int = GOOGLE_GET_RETRIES,
        **kwargs: Any,
    ) -> None:
        super().__init__(*args, **kwargs)
        self.get_retries = max(0, int(get_retries))
        self.io_stats: Counter[str] = Counter()

    def request(
        self, uri: str, method: str = "GET", body: Any = None,
        headers: Any = None, redirections: int = 5,
        connection_type: Any = None, **kwargs: Any,
    ) -> Any:
        retries = self.get_retries if str(method).upper() == "GET" else 0
        for attempt in range(retries + 1):
            started = time.monotonic()
            self.io_stats["get_requests" if str(method).upper() == "GET" else "write_requests"] += 1
            self.io_stats["retries"] += int(attempt > 0)
            self.io_stats["request_body_bytes"] += (
                len(body.encode("utf-8")) if isinstance(body, str)
                else len(body) if isinstance(body, bytes) else 0
            )
            try:
                response = super().request(
                    uri, method=method, body=body, headers=headers,
                    redirections=redirections, connection_type=connection_type,
                    **kwargs,
                )
                content = response[1]
                self.io_stats["response_body_bytes"] += (
                    len(content.encode("utf-8")) if isinstance(content, str)
                    else len(content) if isinstance(content, bytes) else 0
                )
                status = int(getattr(response[0], "status", 0) or 0)
                if (
                    retries
                    and status in RETRYABLE_GOOGLE_GET_STATUSES
                    and attempt < retries
                ):
                    delay = min(2 ** attempt, 8)
                    LOGGER.warning(
                        "Google GET returned retryable status; retrying "
                        "attempt=%s/%s delay_seconds=%s status=%s",
                        attempt + 1,
                        retries,
                        delay,
                        status,
                    )
                    time.sleep(delay)
                    continue
                return response
            except (IncompleteRead, OSError) as error:
                if isinstance(error, IncompleteRead):
                    self.io_stats["response_body_bytes"] += len(error.partial or b"")
                if attempt >= retries:
                    raise
                delay = min(2 ** attempt, 8)
                LOGGER.warning(
                    "Google GET response incomplete; retrying attempt=%s/%s "
                    "delay_seconds=%s error_type=%s bytes_read=%s",
                    attempt + 1,
                    retries,
                    delay,
                    type(error).__name__,
                    len(error.partial or b"")
                    if isinstance(error, IncompleteRead)
                    else 0,
                )
                time.sleep(delay)
            finally:
                self.io_stats["elapsed_ms"] += round((time.monotonic() - started) * 1000)


def log_google_io(service: Any, phase: str) -> None:
    """Application body sizes only: excludes compression, TLS and token traffic."""
    http = getattr(service, "_http", None)
    if isinstance(http, RetryingAuthorizedHttp):
        LOGGER.info("Google IO phase=%s %s", phase,
                    " ".join(f"{key}={value}" for key, value in sorted(http.io_stats.items())))


def operational_timezone(timezone_name: str = DEFAULT_TIMEZONE) -> ZoneInfo:
    """Resolve a configured IANA timezone or raise a user-facing error."""
    try:
        return ZoneInfo(str(timezone_name or DEFAULT_TIMEZONE))
    except (KeyError, ValueError) as error:
        raise ValueError(f"Unknown timezone: {timezone_name!r}") from error


@contextmanager
def timed_step(step: str, **context: Any):
    """Log the start, result, and elapsed duration of one major operation."""
    details = " ".join(
        f"{key}={value}" for key, value in context.items()
        if value not in (None, "")
    )
    suffix = f" {details}" if details else ""
    started = time.monotonic()
    LOGGER.info("Step started step=%s%s", step, suffix)
    try:
        yield
    except Exception:
        LOGGER.error(
            "Step failed step=%s duration_seconds=%.3f%s",
            step, time.monotonic() - started, suffix,
        )
        raise
    else:
        LOGGER.info(
            "Step finished step=%s duration_seconds=%.3f%s",
            step, time.monotonic() - started, suffix,
        )


def operational_now(
    timezone_name: str = DEFAULT_TIMEZONE, now: datetime | None = None,
) -> datetime:
    """Return one timezone-aware operational timestamp."""
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(operational_timezone(timezone_name))

CABLE_REPORT_HEADERS = [
    "Circuit ID", "Status", "Protocol", "A SU Number", "A Node Type", "A Node", "A Rack", "A Port", "A Custom NIC Name", "A RDMA Name", "A RU",
    "A Actual Node", "A Actual Port", "A Port Status", "A Cable Serial", "A Cable PN",
    "A Link Down Counter", "A Module Temperature (C)", "A RX Power Lanes (dBm)",
    "A TX Power Lanes (dBm)", "A RX Power Low Threshold", "A RX Power High Threshold",
    "A TX Power Low Threshold", "A TX Power High Threshold", "A Power Data Stale",
    "A Report", "A Recommended Action", "Z SU Number", "Z Node Type", "Z Node", "Z Rack", "Z Port", "Z Custom NIC Name", "Z RDMA Name", "Z RU", "Z Actual Node",
    "Z Actual Port", "Z Port Status", "Z Cable Serial", "Z Cable PN", "Z Link Down Counter",
    "Z Module Temperature (C)", "Z RX Power Lanes (dBm)", "Z TX Power Lanes (dBm)",
    "Z RX Power Low Threshold", "Z RX Power High Threshold", "Z TX Power Low Threshold",
    "Z TX Power High Threshold", "Z Power Data Stale", "Z Report", "Z Recommended Action",
    "Last Update (UTC)", "Source Line",
    "A Raw BER", "A Effective BER", "A Symbol BER", "A BER Status",
    "Z Raw BER", "Z Effective BER", "Z Symbol BER", "Z BER Status",
]
TRACKING_STATUS_HEADER = "Tracking Status"
STATUS_CYCLES_HEADER = "Status Cycles"
CVT_SOURCE_ROW_HEADER = "__CableTracker CVT Source Row__"
TRACKING_STATUS_NEW = "New"
TRACKING_STATUS_EXISTING = "Existing"
TRACKING_STATUS_MISSING = "Missing"
INSTANCE_HEADER = "Instance"
LEGACY_INSTANCE_HEADER = "CVT Instance"


def normalize_instance_headers(headers: list[Any]) -> list[Any]:
    """Accept the legacy label in-place; never guess between two scope columns."""
    aliases = {INSTANCE_HEADER.casefold(), LEGACY_INSTANCE_HEADER.casefold()}
    indexes = [i for i, header in enumerate(headers)
               if str(header).strip().casefold() in aliases]
    if len(indexes) > 1:
        raise ValueError("Duplicate Instance columns (including legacy aliases); keep only one.")
    result = list(headers)
    if indexes:
        result[indexes[0]] = INSTANCE_HEADER
    return result


def normalize_instance_table(values: list[list[Any]]) -> list[list[Any]]:
    return [normalize_instance_headers(values[0]), *values[1:]] if values else values


def normalize_instance_mapping(mapping: dict[str, str], normalize_targets: bool = False) -> dict[str, str]:
    keys = normalize_instance_headers(list(mapping))
    result = dict(zip(keys, mapping.values()))
    if (normalize_targets and INSTANCE_HEADER in result
            and str(result[INSTANCE_HEADER]).strip().casefold() == LEGACY_INSTANCE_HEADER.casefold()):
        result[INSTANCE_HEADER] = INSTANCE_HEADER
    return result


DEFAULT_FAULT_ID_START = 30001
MAX_FAULT_ID = 99999
DEFAULT_HW_ISSUE_SHEETS = ["GPU Server", "ETH&IB Switch"]
REMEDIATION_HEADERS = [
    "Fault ID", "Source", "Reported by", "Date opened", "Link Type", "Error", "Description", "Local SU Number", "Local Rack", "Local RU", "Local Device", "Local Port",
    "A Discover Node", "A Discover Port", "Z Rack", "Z RU", "Z Node", "Z Port", "Z Discover Node", "Z Discover Port",
    "Status", "Notes", "AI Recommendation", "NV Comments", "Assigned to", "Engineer Assigned", "Action Description", "P-status", "CVT",
    "Date Closed", INSTANCE_HEADER,
]
REMEDIATION_INDEX = {header: index for index, header in enumerate(REMEDIATION_HEADERS)}
REMEDIATION_MANUAL_FIELDS = frozenset({
    "AI Recommendation", "NV Comments", "Assigned to", "Engineer Assigned",
    "Action Description", "P-status",
})
REMEDIATION_CONDITIONAL_FIELDS = frozenset({"Status", "Date Closed"})
CABLING_EVENT_LEGACY_HEADERS = [
    "Event Time", "Event Type", "Fault ID", "Instance", "Cabling Type",
    "A-SU", "Issue Type", "Source", "Open Count",
]
CABLING_EVENT_HEADERS = [
    "Event Time", "Event Type", "Fault ID", "Instance", "Cabling Type",
    "A-SU", "Link Type", "Issue Type", "Source", "Open Count",
]
CABLING_EVENT_INIT = "INIT"
CABLING_EVENT_BASELINE = "BASELINE"
CABLING_EVENT_OPEN = "OPEN"
CABLING_EVENT_CLOSE = "CLOSE"
CABLING_EVENT_SNAPSHOT = "SNAPSHOT"
DEFAULT_CABLING_EVENTS_SHEET = "Cabling_EVENTS"
DEFAULT_CABLING_EVENTS_RETENTION_HOURS = 24 * 7
DEFAULT_CABLING_SUM_PERIOD_HOURS = (1, 4, 8, 24, 48)
DEFAULT_CABLING_SUM_SHEET = "Cabling_SUM"
CABLING_SUM_CHART_HELPER_START_COLUMN = 0
CABLING_SUM_CHART_SCOPE_COLUMNS = 24  # A:X for each Instance/Protocol scope.
CABLING_SUM_CHART_SCOPE_ROWS = 69
CABLING_SUM_CHARTS_PER_SCOPE = 5
CABLING_SUM_CHART_ALT_PREFIX = "CableTracker managed chart: "
CABLING_SUM_DIVIDER_COLOR = {
    "red": 91 / 255, "green": 155 / 255, "blue": 213 / 255,
}
CABLING_SUM_DIMENSION_HEADERS = [
    "Point Time", "Instance", "Type", "A-SU", "Link Type",
]
CABLING_SUM_LEGACY_CVT_HEADERS = [
    "Total", "Pass", "Open", "Link Down", "Mis-wiring", "Others",
]
CABLING_SUM_PASS_RATE_CVT_HEADERS = [
    *CABLING_SUM_LEGACY_CVT_HEADERS, "Pass Rate",
]
CABLING_SUM_PASS_PROGRESS_CVT_HEADERS = [
    *CABLING_SUM_PASS_RATE_CVT_HEADERS, "Pass Progress",
]
CABLING_SUM_CVT_HEADERS = [*CABLING_SUM_LEGACY_CVT_HEADERS, "Rate", "Progress"]
CABLING_SUM_METRIC_HEADERS = [
    "Opened", "Closed", "Delta",
]
IMPORT_TIMESTAMP_PREFIX = "Imported at:"
REMEDIATION_TIMESTAMP_PREFIX = "Updated at:"
CVT_SUM_TIMESTAMP_PREFIX = "Updated at:"
CVT_SUM_LEGACY_HEADERS = [
    "A-SU", "Link Type", "Total", "Pass", "Fail - Link Down",
    "Fail - Mis-wiring", "Fail - Flapping", "Fail - Others", "Warning",
    "No Status", "Pass Rate",
]
CVT_SUM_HEADERS = [
    *CVT_SUM_LEGACY_HEADERS[:2], "Protocol", *CVT_SUM_LEGACY_HEADERS[2:],
]
CVT_SUM_MULTI_HEADERS = [INSTANCE_HEADER, *CVT_SUM_HEADERS]
CVT_SUM_LEGACY_MULTI_HEADERS = [INSTANCE_HEADER, *CVT_SUM_LEGACY_HEADERS]
CVT_SUM_PROTOCOL_ORDER = {"IB": 0, "ETH": 1}
CVT_SUM_LINK_TYPE_ORDER = {"Switch": 0, "Host": 1, "Unknown": 2}
AGENT_STATUS_HEADERS = [
    "Hostname", "IP", "Ping", "Agent Health", "Device Status", "JSON API", "Node Type",
    "Node OS", "DNS Resolved", "DNS Attempts", "DNS Last Attempt", "Last Updated (UTC)",
    "Time Since Update", "DH", "SU", "Rack", "RU", "Comment", INSTANCE_HEADER,
]
BCM_STATUS_HEADERS = [
    "Hostname", "Status", "Health Check Failed", "Health Check Unknown",
    "Provisioning Failed", "Restart Required", INSTANCE_HEADER,
]
DEFAULT_BCM_STATUS_SHEET = "BCM_status"
DEFAULT_BCM_HOST_PATTERNS = (r".*",)
WHITELIST_FILTER_DEVICE = "Device"
WHITELIST_FILTER_ERROR = "Error"
WHITELIST_FILTER_A_SU = "A_SU"
WHITELIST_FILTER_Z_SU = "Z_SU"
WHITELIST_FILTER_VALUE_HEADERS = {
    WHITELIST_FILTER_DEVICE: ("Filter", "Device Name"),
    WHITELIST_FILTER_ERROR: ("Filter",),
    WHITELIST_FILTER_A_SU: ("Filter",),
    WHITELIST_FILTER_Z_SU: ("Filter",),
}


def parse_bool(value: str | bool) -> bool:
    """Accept an explicit true/false command-line value."""
    if isinstance(value, bool):
        return value
    normalized = value.strip().casefold()
    if normalized in {"1", "true", "yes", "on"}:
        return True
    if normalized in {"0", "false", "no", "off"}:
        return False
    raise argparse.ArgumentTypeError("expected true or false")


def parse_fault_id_start(value: str | int) -> int:
    """Accept a Fault ID starting value as either NV30001 or 30001."""
    normalized = str(value).strip().upper()
    if normalized.startswith("NV"):
        normalized = normalized[2:]
    if not normalized.isdigit():
        raise argparse.ArgumentTypeError("expected an NV ID such as NV30001 or a number such as 30001")
    number = int(normalized)
    if not 1 <= number <= MAX_FAULT_ID:
        raise argparse.ArgumentTypeError("Fault ID start must be between NV00001 and NV99999")
    return number


def normalize_cabling_sum_period_hours(
    value: Any, label: str = "cabling_sum_period_hours",
) -> list[int]:
    """Validate an ordered, non-empty list of unique positive hour windows."""
    if isinstance(value, str):
        items: list[Any] = [item.strip() for item in value.split(",") if item.strip()]
        try:
            items = [int(item) for item in items]
        except ValueError as error:
            raise ValueError(f"{label} must contain positive integers.") from error
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise ValueError(f"{label} must be an array of positive integers.")
    if not items:
        raise ValueError(f"{label} must contain at least one period.")
    if any(isinstance(item, bool) or not isinstance(item, int) or item < 1 for item in items):
        raise ValueError(f"{label} must contain positive integers.")
    if len(set(items)) != len(items):
        raise ValueError(f"{label} must not contain duplicate periods.")
    return items


def parse_cabling_sum_period_hours(value: str) -> list[int]:
    """Parse comma-separated Cabling_SUM hour windows for argparse."""
    try:
        return normalize_cabling_sum_period_hours(
            value, "--cabling-sum-period-hours"
        )
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Write a rectangular data range to a Google Sheet."
    )
    parser.add_argument(
        "--credentials",
        default="cre.json",
        help="Path to service-account JSON credentials (default: cre.json).",
    )
    parser.add_argument(
        "--spreadsheet-id",
        help="ID from the Google Sheet URL. Required unless supplied by --instances-config.",
    )
    parser.add_argument(
        "--instances-config", "--instance-config",
        dest="instances_config",
        type=Path,
        help=(
            "JSON file defining multiple CVT instances. Each enabled instance is processed "
            "sequentially; ordinary single-instance arguments remain supported."
        ),
    )
    parser.add_argument(
        "--instance",
        action="append",
        dest="selected_instances",
        help=(
            "Run only the named instance from --instances-config. Repeat the option or use "
            "comma-separated names to select multiple instances."
        ),
    )
    parser.add_argument(
        "--instance-fail-fast",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Stop the current cycle after the first failed instance (default: false).",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
        help="Operational log level (default: INFO).",
    )
    parser.add_argument(
        "--timezone",
        dest="timezone_name",
        default=DEFAULT_TIMEZONE,
        help=f"IANA timezone for dates, timestamps, and logs (default: {DEFAULT_TIMEZONE}).",
    )
    parser.add_argument(
        "--google-proxy",
        help="Optional HTTP proxy for Google authentication and Sheets API, e.g. http://127.0.0.1:7890.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=600,
        help="HTTP timeout in seconds for Google and source APIs (default: 600).",
    )
    parser.add_argument(
        "--interval-seconds",
        type=int,
        default=1800,
        help="Seconds between completed runs (default: 1800).",
    )
    parser.add_argument(
        "--max-runs",
        type=int,
        help="Stop after this many runs; use 0 or omit for continuous runs.",
    )
    parser.add_argument(
        "--range",
        help="Deprecated compatibility option.  When supplied, its sheet name is used as CVT_Import.",
    )
    parser.add_argument(
        "--data-start-row",
        type=int,
        default=3,
        help="Compatibility option; CVT_Import data always starts on row 3.",
    )
    data_source = parser.add_mutually_exclusive_group(required=False)
    data_source.add_argument(
        "--values-json",
        help='Two-dimensional JSON array, e.g. [["Name", "Score"], ["Alice", 95]].',
    )
    data_source.add_argument(
        "--csv",
        type=Path,
        help="Path to a UTF-8 CSV file. Each row is written as one sheet row.",
    )
    data_source.add_argument(
        "--cable-report",
        type=Path,
        help="Path to a cable-validation JSON report, or any JSON document with --json-field-map.",
    )
    data_source.add_argument(
        "--json-file",
        type=Path,
        help="Generic local JSON document. Requires --json-field-map; map keys become CVT_Import column names.",
    )
    data_source.add_argument(
        "--source-file", type=Path,
        help="Local report for --source-type; cannot be combined with legacy file inputs.",
    )
    parser.add_argument(
        "--source-type", default="cvt",
        help="Report adapter: cvt or lldpq. LLDPQ currently supports local JSON files only.",
    )
    parser.add_argument(
        "--source-transport", choices=("api", "file"),
        help="Report transport. When omitted, infer file from a local report, otherwise api.",
    )
    parser.add_argument(
        "--source-api-url",
        help=("API base URL only, e.g. https://127.0.0.1:39443 (no endpoint path). "
              "CVT login, report and Agent paths are appended automatically."),
    )
    parser.add_argument(
        "--cable-api-host",
        default="127.0.0.1",
        help="Cable-validation API host (default: 127.0.0.1).",
    )
    parser.add_argument(
        "--cable-api-port",
        type=int,
        default=19443,
        help="Cable-validation API HTTPS port (default: 19443).",
    )
    parser.add_argument(
        "--cable-api-login-path",
        default="/cablevalidation/login",
        help="Login API path (default: /cablevalidation/login).",
    )
    parser.add_argument(
        "--cable-api-report-path",
        default="/cablevalidation/report/circuits",
        help="Circuits report API path (default: /cablevalidation/report/circuits).",
    )
    parser.add_argument(
        "--cable-api-username",
        default=os.getenv("CABLE_API_USERNAME"),
        help="API username (default: CABLE_API_USERNAME environment variable).",
    )
    parser.add_argument(
        "--cable-api-password-env",
        default="CABLE_API_PASSWORD",
        help="Environment variable containing the API password (default: CABLE_API_PASSWORD).",
    )
    parser.add_argument(
        "--cable-api-insecure-tls",
        action="store_true",
        help="Disable TLS certificate verification for the cable API (equivalent to curl -k).",
    )
    parser.add_argument(
        "--json-field-map",
        help=(
            "JSON object (or path to a JSON file) mapping Sheet column names to JSON paths. "
            "Example: '{\"Circuit ID\": \"id\", \"A Node\": \"endpoints.a.node\"}'."
        ),
    )
    parser.add_argument(
        "--mapping-config",
        help=(
            "Unified JSON mapping file (or inline JSON) with cvt_import and remediation sections. "
            "Cannot be combined with --json-field-map or --remediation-column-map."
        ),
    )
    parser.add_argument(
        "--json-records-path",
        help="Dot-separated path to the records array in a mapped JSON document, e.g. data.circuits.",
    )
    data_source.add_argument(
        "--remediation-from-cvt",
        action="store_true",
        help="Build or refresh the Remediation sheet from Fail records in the cvt sheet.",
    )
    parser.add_argument(
        "--operation",
        choices=("import", "remediation", "both"),
        help=(
            "import: write only the source data; remediation: update the Cabling sheet(s) "
            "from CVT_Import; both: import then update Cabling."
        ),
    )
    parser.add_argument(
        "--cable-api-agent-path",
        default="/cablevalidation/nodes/agents/details?context=dc",
        help="Agent Details API path (default: /cablevalidation/nodes/agents/details?context=dc).",
    )
    parser.add_argument(
        "--agent-cookies",
        type=Path,
        default=Path("cookies.txt"),
        help="curl/Netscape cookie file for the Agent Details API (default: cookies.txt).",
    )
    parser.add_argument(
        "--agent-api-insecure-tls",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Disable TLS certificate verification for the Agent Details API.",
    )
    parser.add_argument(
        "--agent-sheet",
        default="Agent_status",
        help="Agent health target sheet (default: Agent_status).",
    )
    parser.add_argument(
        "--inventory-sheet", default="Inventory",
        help="Inventory lookup for missing node types and LLDPQ Rack/RU (default: Inventory). Empty string disables lookup.",
    )
    parser.add_argument(
        "--server-profile-sheet",
        default="ServerProfile",
        help=(
            "Sheet containing ServerProfile port aliases in the same spreadsheet "
            "(default: ServerProfile)."
        ),
    )
    parser.add_argument(
        "--port-profile-sheet",
        default="PortProfile",
        help=(
            "Sheet containing Port Name -> Custom mappings used for Remediation port fields "
            "(default: PortProfile)."
        ),
    )
    parser.add_argument(
        "--hw-issue-sheet",
        dest="hw_issue_sheets",
        action="append",
        help=(
            "Hardware issue source sheet containing a Host Name column. Repeat for multiple "
            "sheets. Defaults to GPU Server and ETH&IB Switch; use an empty "
            "hw_issue_sheets list in an instances config to disable the feature."
        ),
    )
    parser.add_argument(
        "--whitelist-sheet",
        default="Whitelist",
        help="Device whitelist sheet in the same spreadsheet (default: Whitelist).",
    )
    parser.add_argument(
        "--refresh-agent-status",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Refresh Agent_status; can be used alone or together with --operation import/remediation/both.",
    )
    parser.add_argument(
        "--enable-cabling-events",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "Track lightweight Cabling OPEN/CLOSE events and hourly A-SU snapshots "
            "after successful Cabling updates (default: false)."
        ),
    )
    parser.add_argument(
        "--cabling-events-sheet",
        default=DEFAULT_CABLING_EVENTS_SHEET,
        help=f"Cabling event target sheet (default: {DEFAULT_CABLING_EVENTS_SHEET}).",
    )
    parser.add_argument(
        "--cabling-events-retention-hours",
        type=int,
        default=DEFAULT_CABLING_EVENTS_RETENTION_HOURS,
        help=(
            "Rolling number of hours retained in the Cabling event sheet "
            f"(default: {DEFAULT_CABLING_EVENTS_RETENTION_HOURS}, or 7 days)."
        ),
    )
    parser.add_argument(
        "--refresh-cabling-sum",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "Refresh Cabling_SUM from Cabling event data after a successful cycle "
            "(default: false)."
        ),
    )
    parser.add_argument(
        "--cabling-sum-sheet",
        default=DEFAULT_CABLING_SUM_SHEET,
        help=f"Cabling event summary target sheet (default: {DEFAULT_CABLING_SUM_SHEET}).",
    )
    parser.add_argument(
        "--cabling-sum-period-hours",
        type=parse_cabling_sum_period_hours,
        default=list(DEFAULT_CABLING_SUM_PERIOD_HOURS),
        help=(
            "Comma-separated Cabling_SUM rolling windows in hours, in display order "
            "(default: 1,4,8,24,48)."
        ),
    )
    parser.add_argument(
        "--enable-bcm",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "Fetch BCM device health from REST v1 /rest/v1/status?verbose=1 "
            "and refresh BCM_status (default: false)."
        ),
    )
    parser.add_argument(
        "--bcm-api-url",
        default=os.getenv("CABLETRACKER_BCM_API_URL"),
        help="BCM head-node base URL, e.g. https://bcm.example:8081.",
    )
    parser.add_argument(
        "--bcm-auth",
        choices=("basic", "certificate"),
        default=os.getenv("CABLETRACKER_BCM_AUTH", "basic"),
        help="BCM authentication method: basic or certificate (default: basic).",
    )
    parser.add_argument(
        "--bcm-username",
        default=os.getenv("BCM_API_USERNAME"),
        help="BCM Basic-auth username (default: BCM_API_USERNAME).",
    )
    parser.add_argument(
        "--bcm-password-env",
        default="BCM_API_PASSWORD",
        help="Environment variable containing the BCM Basic-auth password.",
    )
    parser.add_argument(
        "--bcm-cert",
        type=Path,
        help="Client certificate PEM file for --bcm-auth certificate.",
    )
    parser.add_argument(
        "--bcm-key",
        type=Path,
        help="Client private-key PEM file for --bcm-auth certificate.",
    )
    parser.add_argument(
        "--bcm-insecure-tls",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Disable TLS certificate verification only for BCM REST v1.",
    )
    parser.add_argument(
        "--bcm-sheet",
        default=DEFAULT_BCM_STATUS_SHEET,
        help=f"BCM device-health target sheet (default: {DEFAULT_BCM_STATUS_SHEET}).",
    )
    parser.add_argument(
        "--bcm-host-pattern",
        dest="bcm_host_patterns",
        action="append",
        help=(
            "Case-insensitive regex selecting Host nodes that require the BCM UP "
            "gate. Repeat for multiple patterns. Default: .* (all Host nodes)."
        ),
    )
    parser.add_argument(
        "--ai-recommendations",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Generate repair advice in the Remediation AI Recommendation column using an OpenAI-compatible API.",
    )
    parser.add_argument(
        "--ai-after-remediation",
        action="store_true",
        help=(
            "After --operation remediation or both writes all non-AI fields, fill missing "
            "AI Recommendation cells as a separate second phase."
        ),
    )
    parser.add_argument(
        "--refresh-ai-only",
        action="store_true",
        help=(
            "Generate missing AI recommendations for the first eligible rows in existing Remediation "
            "and write only the AI Recommendation cells. No CVT, Remediation metadata, or timestamp changes are made."
        ),
    )
    parser.add_argument(
        "--refresh-ai-recommendations",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Regenerate existing AI Recommendation values; requires --ai-recommendations.",
    )
    parser.add_argument(
        "--ai-base-url",
        default=os.getenv("CABLETRACKER_AI_BASE_URL", "https://inference-api.nvidia.com/v1"),
        help="OpenAI-compatible AI base URL (default: NVIDIA Inference Hub).",
    )
    parser.add_argument(
        "--ai-model",
        default=os.getenv("CABLETRACKER_AI_MODEL", "azure/openai/gpt-5.6-sol"),
        help="Model identifier for --ai-recommendations (default: azure/openai/gpt-5.6-sol).",
    )
    parser.add_argument(
        "--ai-api-key-env",
        default="NVDEV_API_KEY",
        help="Environment variable containing the AI API key (default: NVDEV_API_KEY).",
    )
    parser.add_argument(
        "--ai-proxy",
        default=os.getenv("CABLETRACKER_AI_PROXY"),
        help="Optional HTTP/SOCKS proxy only for the AI API. Omit to connect directly.",
    )
    parser.add_argument(
        "--ai-max-records",
        type=int,
        default=int(os.getenv("CABLETRACKER_AI_MAX_RECORDS", "25")),
        help="Maximum eligible Mis-wiring records sent to AI per run; use 0 for all (default: 25).",
    )
    parser.add_argument(
        "--ai-max-output-tokens",
        type=int,
        default=int(os.getenv("CABLETRACKER_AI_MAX_OUTPUT_TOKENS", "8192")),
        help="Maximum tokens returned by the batch link-correlation request (default: 8192).",
    )
    parser.add_argument(
        "--list-ai-models",
        action="store_true",
        help="List models available to the AI API key, then exit without changing Sheets.",
    )
    parser.add_argument(
        "--ai-error-types",
        default=os.getenv("CABLETRACKER_AI_ERROR_TYPES", "Mis-wiring"),
        help=(
            "Comma-separated Remediation Error types eligible for AI recommendations "
            "(default: Mis-wiring). Use '*' to include every non-closed record."
        ),
    )
    parser.add_argument(
        "--ai-fail-fast",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help="Stop the update if an AI recommendation request fails; by default errors are logged and other updates continue.",
    )
    parser.add_argument(
        "--clear-data",
        action="store_true",
        help="Clear rows 3 onward in CVT_Import and configured Cabling sheets, preserving rows 1-2.",
    )
    parser.add_argument(
        "--fresh-start",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "On the first scheduled cycle after process startup, clear only the CVT import "
            "data rows before writing the validated current report."
        ),
    )
    parser.add_argument(
        "--cvt-sheet",
        default="CVT_Import",
        help="CVT import sheet name (default: CVT_Import).",
    )
    parser.add_argument(
        "--refresh-cvt-sum",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "Refresh the CVT_SUM worksheet after successful CVT processing. "
            "In multi-instance mode all selected instances are written together."
        ),
    )
    parser.add_argument(
        "--cvt-sum-sheet",
        default="CVT_SUM",
        help="CVT summary target sheet (default: CVT_SUM).",
    )
    parser.add_argument(
        "--remediation-sheet",
        help=(
            "Legacy single-sheet target that disables protocol splitting. When omitted, "
            "only explicitly configured IB/ETH Cabling targets are updated."
        ),
    )
    parser.add_argument(
        "--ib-cabling-sheet",
        help=(
            "Target sheet for IB, empty, or unknown Protocol values. "
            "IB Cabling is not updated when this option is omitted."
        ),
    )
    parser.add_argument(
        "--eth-cabling-sheet",
        help=(
            "Target sheet for explicit ETH/Ethernet/RoCE Protocol values. "
            "ETH Cabling is not updated when this option is omitted."
        ),
    )
    parser.add_argument(
        "--refresh-remediation",
        action="store_true",
        help=(
            "After importing a cable report into CVT_Import, upsert the configured "
            "Cabling sheet(s)."
        ),
    )
    parser.add_argument(
        "--include-healthy",
        action="store_true",
        help="Compatibility option; every CVT status is imported by default.",
    )
    parser.add_argument(
        "--failures-only",
        action="store_true",
        help="Import only circuits whose current API/report status is Fail.",
    )
    parser.add_argument(
        "--include-warnings",
        nargs="?",
        const=True,
        type=parse_bool,
        default=False,
        help=(
            "Allow Warning records to create and update Cabling faults in addition "
            "to Fail records (default: false)."
        ),
    )
    parser.add_argument(
        "--columns", "--cvt-columns", dest="cvt_columns",
        help="Comma-separated CVT_Import columns, in the desired order. Defaults to all CVT columns.",
    )
    parser.add_argument(
        "--remediation-columns",
        help="Comma-separated standard Remediation fields to write, in the desired order.",
    )
    parser.add_argument(
        "--min-cycles",
        type=int,
        default=1,
        help=(
            "Create a new Remediation record only after a failing link has held the same "
            "Status for this many cycles (default: 1). Existing records still update immediately."
        ),
    )
    parser.add_argument(
        "--fault-id-start",
        type=parse_fault_id_start,
        default=DEFAULT_FAULT_ID_START,
        help=(
            "First NV Fault ID to allocate when no equal or higher ID exists; accepts "
            "NV30001 or 30001 (default: NV30001)."
        ),
    )
    parser.add_argument(
        "--remediation-column-map",
        help=(
            "JSON object (or path to a JSON file) mapping standard Remediation fields to "
            "custom Sheet header names, e.g. '{\"Fault ID\":\"故障单号\"}'."
        ),
    )
    parser.add_argument(
        "--compare-existing",
        action="store_true",
        help=(
            "With --cable-report, compare Circuit ID values already in the target "
            "sheet and add a Tracking Status column: New, Existing, or Missing."
        ),
    )
    parser.add_argument(
        "--value-input-option",
        choices=("RAW", "USER_ENTERED"),
        default="USER_ENTERED",
        help="How Google Sheets interprets values (default: USER_ENTERED).",
    )
    args = parser.parse_args()
    if args.hw_issue_sheets is None:
        args.hw_issue_sheets = DEFAULT_HW_ISSUE_SHEETS.copy()
    if args.bcm_host_patterns is None:
        args.bcm_host_patterns = list(DEFAULT_BCM_HOST_PATTERNS)
    return args


INSTANCE_CONFIG_OPTIONS: dict[str, dict[str, str]] = {
    "api": {
        "host": "cable_api_host",
        "port": "cable_api_port",
        "login_path": "cable_api_login_path",
        "report_path": "cable_api_report_path",
        "agent_path": "cable_api_agent_path",
        "username": "cable_api_username",
        "password_env": "cable_api_password_env",
        "insecure_tls": "cable_api_insecure_tls",
        "agent_insecure_tls": "agent_api_insecure_tls",
    },
    "sheets": {
        "spreadsheet_id": "spreadsheet_id",
        "cvt_sheet": "cvt_sheet",
        "ib_cabling_sheet": "ib_cabling_sheet",
        "eth_cabling_sheet": "eth_cabling_sheet",
        "remediation_sheet": "remediation_sheet",
        "agent_sheet": "agent_sheet",
        "server_profile_sheet": "server_profile_sheet",
        "inventory_sheet": "inventory_sheet",
        "port_profile_sheet": "port_profile_sheet",
        "hw_issue_sheets": "hw_issue_sheets",
        "whitelist_sheet": "whitelist_sheet",
        "cvt_sum_sheet": "cvt_sum_sheet",
        "bcm_sheet": "bcm_sheet",
        "cabling_events_sheet": "cabling_events_sheet",
        "cabling_sum_sheet": "cabling_sum_sheet",
    },
    "options": {
        "operation": "operation",
        "credentials": "credentials",
        "mapping_config": "mapping_config",
        "google_proxy": "google_proxy",
        "timezone": "timezone_name",
        "timeout": "timeout",
        "include_warnings": "include_warnings",
        "min_cycles": "min_cycles",
        "fault_id_start": "fault_id_start",
        "refresh_agent_status": "refresh_agent_status",
        "refresh_cvt_sum": "refresh_cvt_sum",
        "cabling_events_enabled": "enable_cabling_events",
        "cabling_events_retention_hours": "cabling_events_retention_hours",
        "refresh_cabling_sum": "refresh_cabling_sum",
        "cabling_sum_period_hours": "cabling_sum_period_hours",
        "fresh_start": "fresh_start",
        "failures_only": "failures_only",
        "ai_recommendations": "ai_recommendations",
        "ai_after_remediation": "ai_after_remediation",
        "ai_base_url": "ai_base_url",
        "ai_model": "ai_model",
        "ai_api_key_env": "ai_api_key_env",
        "ai_proxy": "ai_proxy",
        "ai_max_records": "ai_max_records",
        "ai_fail_fast": "ai_fail_fast",
    },
    "source": {
        "source_type": "source_type",
        "source_transport": "source_transport",
        "source_file": "source_file",
        "source_api_url": "source_api_url",
        "cable_report": "cable_report",
        "json_file": "json_file",
        "json_records_path": "json_records_path",
    },
    "bcm": {
        "enabled": "enable_bcm",
        "api_url": "bcm_api_url",
        "auth": "bcm_auth",
        "username": "bcm_username",
        "password_env": "bcm_password_env",
        "cert": "bcm_cert",
        "key": "bcm_key",
        "insecure_tls": "bcm_insecure_tls",
        "host_patterns": "bcm_host_patterns",
    },
}

# BCM is kept as an internal section so common/instance values can still be
# merged with the same machinery as the other groups. It is deliberately not a
# user-facing grouped section: instances JSON uses only flat bcm_* keys.
INSTANCE_INPUT_SECTIONS = tuple(
    section for section in INSTANCE_CONFIG_OPTIONS if section != "bcm"
)

INSTANCE_FLAT_OPTIONS: dict[str, tuple[str, str]] = {
    "host": ("api", "host"),
    "port": ("api", "port"),
    "login_path": ("api", "login_path"),
    "report_path": ("api", "report_path"),
    "agent_path": ("api", "agent_path"),
    "username": ("api", "username"),
    "username_env": ("api", "username_env"),
    "password_env": ("api", "password_env"),
    "insecure_tls": ("api", "insecure_tls"),
    "agent_insecure_tls": ("api", "agent_insecure_tls"),
    "bcm_enabled": ("bcm", "enabled"),
    "bcm_api_url": ("bcm", "api_url"),
    "bcm_auth": ("bcm", "auth"),
    "bcm_username": ("bcm", "username"),
    "bcm_username_env": ("bcm", "username_env"),
    "bcm_password_env": ("bcm", "password_env"),
    "bcm_cert": ("bcm", "cert"),
    "bcm_key": ("bcm", "key"),
    "bcm_insecure_tls": ("bcm", "insecure_tls"),
    "bcm_host_patterns": ("bcm", "host_patterns"),
    **{
        key: ("sheets", key)
        for key in INSTANCE_CONFIG_OPTIONS["sheets"]
    },
    **{
        key: ("options", key)
        for key in INSTANCE_CONFIG_OPTIONS["options"]
    },
    **{
        key: ("source", key)
        for key in INSTANCE_CONFIG_OPTIONS["source"]
    },
    # Backward-compatible singular spelling; normalized to the new list option.
    "hw_issue_sheet": ("sheets", "hw_issue_sheets"),
}

INSTANCE_BOOL_OPTIONS = {
    "cable_api_insecure_tls", "agent_api_insecure_tls", "include_warnings",
    "refresh_agent_status", "refresh_cvt_sum", "enable_cabling_events",
    "refresh_cabling_sum",
    "failures_only", "ai_recommendations",
    "ai_after_remediation", "ai_fail_fast", "fresh_start", "enable_bcm",
    "bcm_insecure_tls",
}
INSTANCE_INT_OPTIONS = {
    "cable_api_port", "timeout", "min_cycles", "ai_max_records",
    "cabling_events_retention_hours",
}
INSTANCE_PATH_OPTIONS = {
    "credentials", "mapping_config", "cable_report", "json_file", "source_file", "bcm_cert", "bcm_key",
}
INSTANCE_STRING_LIST_OPTIONS = {"hw_issue_sheets", "bcm_host_patterns"}
INSTANCE_INT_LIST_OPTIONS = {"cabling_sum_period_hours"}


def safe_instance_suffix(name: str) -> str:
    """Return a Google-Sheets-safe suffix while keeping the instance name recognizable."""
    suffix = re.sub(r"[:\\/?*\[\]]+", "_", name.strip())
    suffix = re.sub(r"\s+", "_", suffix).strip("_'")
    if not suffix:
        raise ValueError("Instance name must contain at least one usable character.")
    return suffix[:80]


def merge_instance_sections(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Merge the supported nested instance sections without sharing mutable dictionaries."""
    result = copy.deepcopy(base)
    for section in INSTANCE_CONFIG_OPTIONS:
        value = override.get(section)
        if value is None:
            continue
        if not isinstance(value, dict):
            raise ValueError(f"Instance config section {section!r} must be an object.")
        result.setdefault(section, {}).update(value)
    return result


def normalize_instance_config(value: dict[str, Any], label: str) -> dict[str, Any]:
    """Accept concise flat options and the supported non-BCM grouped sections."""
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be an object.")
    allowed = {*INSTANCE_INPUT_SECTIONS, *INSTANCE_FLAT_OPTIONS}
    unknown = set(value) - allowed - {"name", "enabled"}
    if unknown:
        raise ValueError(f"Unknown {label} options: {', '.join(sorted(unknown))}")
    result: dict[str, Any] = {}
    for section in INSTANCE_INPUT_SECTIONS:
        section_value = value.get(section)
        if section_value is not None:
            if not isinstance(section_value, dict):
                raise ValueError(f"{label}.{section} must be an object.")
            result[section] = copy.deepcopy(section_value)
    for key, item in value.items():
        if key not in INSTANCE_FLAT_OPTIONS:
            continue
        section, option = INSTANCE_FLAT_OPTIONS[key]
        if option in result.setdefault(section, {}):
            raise ValueError(
                f"{label} defines {key!r} in both flat and grouped form. Use only one."
            )
        result[section][option] = item
    return result


def load_instances_document(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise ValueError(f"Instances config not found: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"--instances-config must be valid readable JSON: {error}") from error
    if not isinstance(document, dict):
        raise ValueError("--instances-config root must be a JSON object.")
    unknown = set(document) - {"common", "defaults", "instances"}
    if unknown:
        raise ValueError(f"Unknown --instances-config root keys: {', '.join(sorted(unknown))}")
    if "common" in document and "defaults" in document:
        raise ValueError("Use either 'common' or legacy 'defaults', not both.")
    defaults = document.get("common", document.get("defaults", {}))
    instances = document.get("instances")
    if not isinstance(defaults, dict):
        raise ValueError("--instances-config common must be an object.")
    if not isinstance(instances, list) or not instances:
        raise ValueError("--instances-config instances must be a non-empty array.")
    return document


def selected_instance_names(values: list[str] | None) -> set[str]:
    return {
        name.strip().casefold()
        for value in (values or [])
        for name in value.split(",")
        if name.strip()
    }


def cli_option_present(option: str) -> bool:
    """Return whether an option was explicitly supplied, including --name=value."""
    return any(
        argument == option or argument.startswith(option + "=")
        for argument in sys.argv[1:]
    )


def apply_instance_sections(
    args: argparse.Namespace, sections: dict[str, Any], config_dir: Path,
) -> None:
    """Apply one merged instance configuration to an argparse Namespace."""
    for section, mapping in INSTANCE_CONFIG_OPTIONS.items():
        raw_options = sections.get(section, {})
        unknown = set(raw_options) - set(mapping) - (
            {"username_env"} if section in {"api", "bcm"} else set()
        )
        if unknown:
            raise ValueError(
                f"Unknown instance {section} options: {', '.join(sorted(unknown))}"
            )
        for key, value in raw_options.items():
            if section == "api" and key == "username_env":
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("api.username_env must be a non-empty environment variable name.")
                args.cable_api_username = os.getenv(value.strip())
                continue
            if section == "bcm" and key == "username_env":
                if not isinstance(value, str) or not value.strip():
                    raise ValueError("bcm.username_env must be a non-empty environment variable name.")
                args.bcm_username = os.getenv(value.strip())
                continue
            attribute = mapping[key]
            if attribute == "fault_id_start":
                value = parse_fault_id_start(value)
            elif attribute in INSTANCE_INT_LIST_OPTIONS:
                value = normalize_cabling_sum_period_hours(
                    value, f"{section}.{key}"
                )
            elif attribute in INSTANCE_STRING_LIST_OPTIONS:
                if isinstance(value, str):
                    value = [value]
                if not isinstance(value, list) or any(
                    not isinstance(item, str) or not item.strip() for item in value
                ):
                    raise ValueError(
                        f"{section}.{key} must be an array of non-empty strings."
                    )
                value = list(dict.fromkeys(item.strip() for item in value))
            elif attribute in INSTANCE_BOOL_OPTIONS:
                if not isinstance(value, bool):
                    raise ValueError(f"{section}.{key} must be true or false.")
            elif attribute in INSTANCE_INT_OPTIONS:
                if isinstance(value, bool) or not isinstance(value, int):
                    raise ValueError(f"{section}.{key} must be an integer.")
            elif value is not None and not isinstance(value, str):
                raise ValueError(f"{section}.{key} must be a string or null.")
            if attribute in INSTANCE_PATH_OPTIONS and value:
                candidate = Path(value)
                value = candidate if candidate.is_absolute() else config_dir / candidate
                if attribute in {"credentials", "mapping_config"}:
                    value = str(value)
            setattr(args, attribute, value)
        if (
            section == "api"
            and "insecure_tls" in raw_options
            and "agent_insecure_tls" not in raw_options
        ):
            args.agent_api_insecure_tls = raw_options["insecure_tls"]


def instance_namespaces(base_args: argparse.Namespace) -> list[argparse.Namespace]:
    """Build isolated single-instance argument sets from --instances-config."""
    if not base_args.instances_config:
        return [base_args]
    document = load_instances_document(base_args.instances_config)
    defaults = normalize_instance_config(
        document.get("common", document.get("defaults", {})), "common"
    )
    requested = selected_instance_names(base_args.selected_instances)
    result: list[argparse.Namespace] = []
    seen_names: set[str] = set()
    configured_names: set[str] = set()
    config_dir = base_args.instances_config.resolve().parent
    fault_id_scopes = configured_fault_id_scopes(base_args, document)

    for entry in document["instances"]:
        if not isinstance(entry, dict):
            raise ValueError("Every instances entry must be an object.")
        name = entry.get("name")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Every instance requires a non-empty name.")
        name = name.strip()
        normalized_name = name.casefold()
        if normalized_name in configured_names:
            raise ValueError(f"Duplicate instance name: {name}")
        configured_names.add(normalized_name)
        enabled = entry.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError(f"Instance {name!r} enabled must be true or false.")
        if not enabled or (requested and normalized_name not in requested):
            continue

        scoped = copy.deepcopy(base_args)
        scoped.instances_config = None
        scoped.selected_instances = None
        scoped.instance_name = name
        instance_options = normalize_instance_config(entry, f"instance {name!r}")
        sections = merge_instance_sections(defaults, instance_options)
        apply_instance_sections(scoped, sections, config_dir)
        # Reservation includes disabled/unselected peers, but never enables their updates.
        scoped._fault_id_scope_sheets = fault_id_scopes.get(scoped.spreadsheet_id, [])
        # These cycle-level summary switches are intentionally overridable from the
        # command line even when common supplies defaults in instances.json.
        if cli_option_present("--refresh-cvt-sum"):
            scoped.refresh_cvt_sum = base_args.refresh_cvt_sum
        if cli_option_present("--cvt-sum-sheet"):
            scoped.cvt_sum_sheet = base_args.cvt_sum_sheet
        if cli_option_present("--enable-cabling-events"):
            scoped.enable_cabling_events = base_args.enable_cabling_events
        if cli_option_present("--cabling-events-sheet"):
            scoped.cabling_events_sheet = base_args.cabling_events_sheet
        if cli_option_present("--cabling-events-retention-hours"):
            scoped.cabling_events_retention_hours = (
                base_args.cabling_events_retention_hours
            )
        if cli_option_present("--refresh-cabling-sum"):
            scoped.refresh_cabling_sum = base_args.refresh_cabling_sum
        if cli_option_present("--cabling-sum-sheet"):
            scoped.cabling_sum_sheet = base_args.cabling_sum_sheet
        if cli_option_present("--cabling-sum-period-hours"):
            scoped.cabling_sum_period_hours = list(
                base_args.cabling_sum_period_hours
            )
        for option, attribute in (
            ("--source-type", "source_type"),
            ("--source-transport", "source_transport"),
            ("--source-file", "source_file"),
            ("--source-api-url", "source_api_url"),
            ("--inventory-sheet", "inventory_sheet"),
            ("--enable-bcm", "enable_bcm"),
            ("--bcm-api-url", "bcm_api_url"),
            ("--bcm-auth", "bcm_auth"),
            ("--bcm-username", "bcm_username"),
            ("--bcm-password-env", "bcm_password_env"),
            ("--bcm-cert", "bcm_cert"),
            ("--bcm-key", "bcm_key"),
            ("--bcm-insecure-tls", "bcm_insecure_tls"),
            ("--bcm-sheet", "bcm_sheet"),
            ("--bcm-host-pattern", "bcm_host_patterns"),
        ):
            if cli_option_present(option):
                setattr(scoped, attribute, copy.deepcopy(getattr(base_args, attribute)))
        suffix = safe_instance_suffix(name)
        sheets = sections.get("sheets", {})
        if "agent_sheet" not in sheets or not sheets.get("agent_sheet"):
            scoped.agent_sheet = f"Agent_status_{suffix}"
        if scoped.agent_cookies == Path("cookies.txt"):
            scoped.agent_cookies = Path(f"cookies_{suffix}.txt")
        if not scoped.spreadsheet_id:
            raise ValueError(
                f"Instance {name!r} requires sheets.spreadsheet_id or --spreadsheet-id."
            )
        for attribute in ("cvt_sheet",):
            if not isinstance(getattr(scoped, attribute), str) or not getattr(scoped, attribute).strip():
                raise ValueError(f"Instance {name!r} requires a non-empty {attribute}.")
        result.append(scoped)
        seen_names.add(normalized_name)

    missing = requested - seen_names
    if missing:
        raise ValueError(f"Requested instances not found or disabled: {', '.join(sorted(missing))}")
    if not result:
        raise ValueError("No enabled instances were selected.")

    cvt_targets: set[tuple[str, str]] = set()
    for scoped in result:
        target = (scoped.spreadsheet_id, scoped.cvt_sheet.casefold())
        if target in cvt_targets:
            raise ValueError(
                "Each instance must use a unique CVT sheet within the same Spreadsheet; "
                f"duplicate: {scoped.cvt_sheet}"
            )
        cvt_targets.add(target)
    return result


def configured_fault_id_scopes(
    base_args: argparse.Namespace, document: dict[str, Any],
) -> dict[str, list[str]]:
    """Collect known Cabling names per Spreadsheet without running inactive instances."""
    sheet_keys = ("ib_cabling_sheet", "eth_cabling_sheet", "remediation_sheet")

    def sheet_options(config: dict[str, Any]) -> dict[str, Any]:
        grouped = config.get("sheets") or {}
        if not isinstance(grouped, dict):
            grouped = {}  # Active instance validation handles invalid sections.
        return {
            key: config.get(key, grouped.get(key))
            for key in ("spreadsheet_id", *sheet_keys)
            if key in config or key in grouped
        }

    common = sheet_options(document.get("common", document.get("defaults", {})))
    scopes: dict[str, set[str]] = defaultdict(set)
    for entry in [common, *document["instances"]]:
        if not isinstance(entry, dict):
            continue  # Normal instance validation reports malformed entries.
        options = {**common, **sheet_options(entry)}
        spreadsheet_id = options.get("spreadsheet_id", base_args.spreadsheet_id)
        if not spreadsheet_id:
            continue
        for key in sheet_keys:
            name = options.get(key, getattr(base_args, key, None))
            if isinstance(name, str) and name.strip():
                scopes[spreadsheet_id].add(name.strip())
    return {key: sorted(names) for key, names in scopes.items()}


def endpoint_value(endpoint: dict[str, Any], field: str) -> Any:
    """Read an endpoint field and normalize JSON null so Sheets clears stale values."""
    if not isinstance(endpoint, dict):
        return ""
    if field in {"cable_sn", "cable_pn"}:
        advanced_stats = endpoint.get("advanced_stats") or {}
        value = advanced_stats.get(field, "") if isinstance(advanced_stats, dict) else ""
    else:
        value = endpoint.get(field, "")
    # Google Sheets skips JSON null values instead of overwriting the target cell.
    # An explicit empty string clears the prior value while preserving formatting.
    return "" if value is None else value


def advanced_value(endpoint: dict[str, Any], *path: str) -> Any:
    """Safely read nested telemetry values from a report endpoint."""
    value: Any = endpoint.get("advanced_stats") if isinstance(endpoint, dict) else None
    for field in path:
        if not isinstance(value, dict):
            return ""
        value = value.get(field)
    if isinstance(value, list):
        return ", ".join(str(item) for item in value)
    return "" if value is None else value


def format_timestamp(timestamp: Any) -> str:
    if not isinstance(timestamp, (int, float)) or timestamp <= 0:
        return ""
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()


def date_only(value: Any) -> Any:
    """Keep the date portion of ISO-like timestamps while leaving other values intact."""
    if isinstance(value, str) and re.fullmatch(r"\d{4}-\d{2}-\d{2}(?:[T ].*)?", value):
        return value[:10]
    return value


def current_date(timezone_name: str = DEFAULT_TIMEZONE) -> str:
    return operational_now(timezone_name).date().isoformat()


def current_datetime(
    timezone_name: str = DEFAULT_TIMEZONE, now: datetime | None = None,
) -> str:
    """Return the operational date and time at minute precision."""
    return operational_now(timezone_name, now).strftime("%Y-%m-%d %H:%M")


def valid_open_date(value: Any) -> str:
    date_value = str(value or "").strip()
    return "" if date_value.startswith("1970-01-01") else date_value


def ber_value(endpoint: dict[str, Any], field: str) -> Any:
    stats = endpoint.get("advanced_stats") or {}
    ber = stats.get("ber_stats") or {} if isinstance(stats, dict) else {}
    value = ber.get(field, "") if isinstance(ber, dict) else ""
    if field in {"raw_ber", "effective_ber", "symbol_ber"} and isinstance(value, (int, float)):
        return format(value, ".15G").replace("e", "E")
    return value.replace("e", "E") if isinstance(value, str) else value


@dataclass(frozen=True)
class EndpointObservation:
    """Source-independent endpoint data; no worksheet labels or client objects."""

    su: Any = ""
    node_type: Any = ""
    node: Any = ""
    rack: Any = ""
    port: Any = ""
    custom_nic: Any = ""
    rdma_name: Any = ""
    ru: Any = ""
    actual_node: Any = ""
    actual_port: Any = ""
    port_status: Any = ""
    cable_serial: Any = ""
    cable_part_number: Any = ""
    linkdown_counter: Any = ""
    temperature: Any = ""
    rx_power: Any = ""
    tx_power: Any = ""
    rx_low: Any = ""
    rx_high: Any = ""
    tx_low: Any = ""
    tx_high: Any = ""
    power_stale: Any = ""
    report: Any = ""
    recommended_action: Any = ""
    raw_ber: Any = ""
    effective_ber: Any = ""
    symbol_ber: Any = ""
    ber_status: Any = ""


@dataclass(frozen=True)
class LinkObservation:
    """Normalized link observation, distinct from a Cabling Case lifecycle."""

    circuit_id: Any
    status: Any
    protocol: Any
    a: EndpointObservation
    z: EndpointObservation
    last_update: Any = ""
    source_line: Any = ""
    instance: Any = ""
    status_cycles: int = 1
    tracking_status: Any = ""
    source_row: Any = ""


# Only this projection knows the positional layout of the default import sheet.
# Custom JSON path mappings retain their separate, existing projection behavior.
ENDPOINT_IMPORT_FIELDS = (
    "su", "node_type", "node", "rack", "port", "custom_nic", "rdma_name", "ru",
    "actual_node", "actual_port", "port_status", "cable_serial", "cable_part_number",
    "linkdown_counter", "temperature", "rx_power", "tx_power", "rx_low", "rx_high",
    "tx_low", "tx_high", "power_stale", "report", "recommended_action",
)
ENDPOINT_BER_FIELDS = ("raw_ber", "effective_ber", "symbol_ber", "ber_status")
ENDPOINT_COLUMN_BINDINGS = {
    "su": "SU Number", "node_type": "Node Type", "node": "Node", "rack": "Rack",
    "port": "Port", "custom_nic": "Custom NIC Name", "rdma_name": "RDMA Name", "ru": "RU",
    "actual_node": "Actual Node", "actual_port": "Actual Port", "port_status": "Port Status",
    "cable_serial": "Cable Serial", "cable_part_number": "Cable PN",
    "linkdown_counter": "Link Down Counter", "temperature": "Module Temperature (C)",
    "rx_power": "RX Power Lanes (dBm)", "tx_power": "TX Power Lanes (dBm)",
    "rx_low": "RX Power Low Threshold", "rx_high": "RX Power High Threshold",
    "tx_low": "TX Power Low Threshold", "tx_high": "TX Power High Threshold",
    "power_stale": "Power Data Stale", "report": "Report", "recommended_action": "Recommended Action",
    "raw_ber": "Raw BER", "effective_ber": "Effective BER", "symbol_ber": "Symbol BER", "ber_status": "BER Status",
}


def observations_from_import_table(values: list[list[Any]]) -> list[LinkObservation]:
    """Decode canonical import headers at the legacy table/domain boundary."""
    if not values:
        raise ValueError("The cvt sheet is empty; no remediation records can be created.")
    values = normalize_instance_table(values)
    positions = {header: index for index, header in enumerate(values[0])}
    if "Circuit ID" not in positions or "Status" not in positions:
        raise ValueError("The cvt sheet must contain Circuit ID and Status columns.")

    def cell(row: list[Any], header: str) -> Any:
        index = positions.get(header)
        return row[index] if index is not None and index < len(row) else ""

    result = []
    for physical_row, row in enumerate(values[1:], start=3):
        try:
            cycles = int(str(cell(row, STATUS_CYCLES_HEADER)).strip())
        except (TypeError, ValueError):
            cycles = 1
        endpoints = [EndpointObservation(**{
            name: cell(row, f"{side} {suffix}")
            for name, suffix in ENDPOINT_COLUMN_BINDINGS.items()
        }) for side in ("A", "Z")]
        result.append(LinkObservation(
            cell(row, "Circuit ID"), cell(row, "Status"), cell(row, "Protocol"), *endpoints,
            last_update=cell(row, "Last Update (UTC)"), source_line=cell(row, "Source Line"),
            instance=cell(row, INSTANCE_HEADER), status_cycles=cycles,
            tracking_status=cell(row, TRACKING_STATUS_HEADER),
            source_row=cell(row, CVT_SOURCE_ROW_HEADER) or physical_row,
        ))
    return result


def project_link_observation(link: LinkObservation) -> list[Any]:
    """Project a normalized observation onto the unchanged default CVT schema."""
    return [
        link.circuit_id, link.status, link.protocol,
        *(getattr(link.a, name) for name in ENDPOINT_IMPORT_FIELDS),
        *(getattr(link.z, name) for name in ENDPOINT_IMPORT_FIELDS),
        link.last_update, link.source_line,
        *(getattr(link.a, name) for name in ENDPOINT_BER_FIELDS),
        *(getattr(link.z, name) for name in ENDPOINT_BER_FIELDS),
    ]


class ReportAdapter(Protocol):
    """Future sources normalize here, without taking responsibility for Sheets."""

    def normalize(self, document: Any, include_healthy: bool) -> list[LinkObservation]:
        ...


class CvtReportAdapter:
    """Translate CVT JSON only; authentication and storage belong elsewhere."""

    @staticmethod
    def endpoint(value: Any) -> EndpointObservation:
        endpoint = value or {}
        if not isinstance(endpoint, dict):
            raise ValueError("Cable report endpoints must be JSON objects or null.")
        return EndpointObservation(
            su=endpoint_value(endpoint, "su_number"),
            node_type=endpoint_value(endpoint, "node_type"),
            node=endpoint_value(endpoint, "node"),
            rack=endpoint_value(endpoint, "rack"),
            port=endpoint_value(endpoint, "display_port"),
            custom_nic=endpoint_value(endpoint, "custom_nic_name"),
            rdma_name=endpoint_value(endpoint, "rdma_name"),
            ru=endpoint_value(endpoint, "unit"),
            actual_node=endpoint_value(endpoint, "actual_node"),
            actual_port=endpoint_value(endpoint, "actual_port"),
            port_status=endpoint_value(endpoint, "port_status"),
            cable_serial=endpoint_value(endpoint, "cable_sn"),
            cable_part_number=endpoint_value(endpoint, "cable_pn"),
            linkdown_counter=advanced_value(endpoint, "linkdown_counter"),
            temperature=advanced_value(endpoint, "temp_stats", "module_temperature"),
            rx_power=advanced_value(endpoint, "power_stats", "rx_power_lane"),
            tx_power=advanced_value(endpoint, "power_stats", "tx_power_lane"),
            rx_low=advanced_value(endpoint, "power_stats", "rx_power_low_th"),
            rx_high=advanced_value(endpoint, "power_stats", "rx_power_high_th"),
            tx_low=advanced_value(endpoint, "power_stats", "tx_power_low_th"),
            tx_high=advanced_value(endpoint, "power_stats", "tx_power_high_th"),
            power_stale=advanced_value(endpoint, "power_stats", "power_data_stale"),
            report=endpoint_value(endpoint, "report"),
            recommended_action=endpoint_value(endpoint, "remediation_action"),
            raw_ber=ber_value(endpoint, "raw_ber"),
            effective_ber=ber_value(endpoint, "effective_ber"),
            symbol_ber=ber_value(endpoint, "symbol_ber"),
            ber_status=ber_value(endpoint, "ber_status"),
        )

    def link(self, circuit: dict[str, Any]) -> LinkObservation:
        a, z = circuit.get("a_endpoint") or {}, circuit.get("z_endpoint") or {}
        normalized_a, normalized_z = self.endpoint(a), self.endpoint(z)
        timestamps = [endpoint.get("last_update") for endpoint in (a, z)
                      if isinstance(endpoint.get("last_update"), (int, float))]
        return LinkObservation(
            circuit_id=circuit.get("circuit_id", ""), status=circuit.get("status", ""),
            protocol=circuit.get("protocol", ""), a=normalized_a, z=normalized_z,
            last_update=format_timestamp(max(timestamps, default=0)),
            source_line=circuit.get("source_line_number", ""),
        )

    def normalize(self, document: Any, include_healthy: bool) -> list[LinkObservation]:
        if not isinstance(document, list):
            raise ValueError("Cable report must be a JSON array of circuit records.")
        return [self.link(circuit) for circuit in document
                if isinstance(circuit, dict)
                and (include_healthy or circuit.get("status") == "Fail")]


def cable_report_row(circuit: dict[str, Any]) -> list[Any]:
    """Compatibility entry point for callers expecting a single table row."""
    return project_link_observation(CvtReportAdapter().link(circuit))


class LldpqReportAdapter:
    """Normalize the LLDPQ schema-v1 lldp_results export, not CVT circuit JSON."""

    STATUS_MAP = {"SUCCESS": "Pass", "FAILED": "Fail", "WARNING": "Warning", "NO INFO": ""}

    def normalize(self, document: Any, include_healthy: bool) -> list[LinkObservation]:
        if not isinstance(document, dict) or not isinstance(document.get("rows"), list):
            raise ValueError("LLDPQ report must be a JSON object with a rows array.")
        if document.get("schema_version", 1) != 1:
            raise ValueError("Unsupported LLDPQ schema_version; expected 1.")
        if document.get("domain", "lldp_results") != "lldp_results":
            raise ValueError("LLDPQ report domain must be lldp_results.")
        collection_status = document.get("collection_status")
        if collection_status is not None and str(collection_status).strip().casefold() not in {
            "", "ok", "success", "complete", "completed",
        }:
            raise ValueError("LLDPQ collection_status does not indicate a complete report.")
        rows = document["rows"]
        if "row_count" in document and document["row_count"] != len(rows):
            raise ValueError("LLDPQ row_count does not match the rows array.")
        links = []
        seen: set[tuple[str, str, str, str]] = set()

        def text(row: dict[str, Any], field: str) -> str:
            value = row.get(field)
            if value is None:
                return ""
            if not isinstance(value, str):
                raise ValueError(f"LLDPQ {field} must be a string or null.")
            return value.strip()

        for number, row in enumerate(rows, start=1):
            if not isinstance(row, dict):
                raise ValueError(f"LLDPQ row {number} must be an object.")
            status = text(row, "status").upper()
            if status not in self.STATUS_MAP:
                raise ValueError(f"LLDPQ row {number} has an unsupported status {status!r}.")
            # Hostnames are case-insensitive; normalize consistently in both IDs
            # and displayed endpoint fields so a casing-only change cannot reopen a Case.
            a_node, z_node = text(row, "local_device").casefold(), text(row, "expected_device").casefold()
            a_port, z_port = text(row, "local_port"), text(row, "expected_port")
            if not a_node or not a_port:
                raise ValueError(f"LLDPQ row {number} requires local_device and local_port.")
            identity = (a_node, a_port, z_node, z_port)
            if identity in seen:
                raise ValueError(f"LLDPQ row {number} duplicates an expected link identity.")
            seen.add(identity)
            # No row number, status or discovered neighbor is part of identity.
            # Keep direction: two separately observed ends are separate source records.
            circuit_id = "lldpq-" + hashlib.sha256(
                json.dumps(identity, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            health = text(row, "connection_health")
            if "wrong device" in health.casefold() or "port mismatch" in health.casefold():
                # Use the shared classifier without changing CVT's keyword rules.
                health = "Mis-wiring: " + health
            link = LinkObservation(
                circuit_id=circuit_id, status=self.STATUS_MAP[status], protocol="ethernet",
                a=EndpointObservation(node=a_node, port=a_port,
                    port_status=text(row, "port_status"), report=health),
                z=EndpointObservation(node=z_node, port=z_port,
                    actual_node=text(row, "actual_device").casefold(),
                    actual_port=text(row, "actual_port")),
                last_update=format_timestamp(document.get("generated_at")), source_line=number,
            )
            if include_healthy or link.status == "Fail":
                links.append(link)
        return links


# Register only implemented adapters. Unsupported types must fail before any
# sheet write; never decode an unfamiliar source using CVT's field assumptions.
SOURCE_ADAPTERS: dict[str, Callable[[], ReportAdapter]] = {
    "cvt": CvtReportAdapter, "lldpq": LldpqReportAdapter,
}


def source_reporter(args: argparse.Namespace) -> str:
    return str(getattr(args, "source_type", None) or "cvt").strip().upper()


def inventory_node_type(value: Any) -> str:
    """Recognize explicit Inventory types, never infer topology from hostnames."""
    normalized = re.sub(r"[\s_-]+", " ", str(value or "").strip().casefold())
    return {
        "switch": "Switch", "ib switch": "Switch", "eth switch": "Switch",
        "ethernet switch": "Switch", "infiniband switch": "Switch",
        "eth&ib switch": "Switch", "ib&eth switch": "Switch",
        "host": "Host", "server": "Host", "gpu server": "Host",
        "cpu server": "Host", "compute": "Host", "compute node": "Host",
        "gpu": "Host", "cpu": "Host",
    }.get(normalized, "")


class InventoryLocations(dict):
    """Location index plus independent type conflicts; legacy location API is retained."""

    def __init__(self) -> None:
        super().__init__()
        self.node_types: dict[tuple[str, str], str | None] = {}


def inventory_locations(values: list[list[Any]]) -> InventoryLocations:
    """Index locations and optional types; ambiguous scoped keys block fallback."""
    result = InventoryLocations()
    if not values or not any(str(v or "").strip() for row in values for v in row):
        return result
    headers = [str(v).strip().casefold() for v in normalize_instance_headers(values[0])]
    for required in ("hostname", "rack", "ru"):
        if headers.count(required) != 1:
            raise ValueError(f"Inventory requires one {required!r} column in its first row.")
    if headers.count("instance") > 1:
        raise ValueError("Inventory has duplicate Instance columns.")
    if headers.count("type") > 1:
        raise ValueError("Inventory has duplicate Type columns.")
    positions = {h: i for i, h in enumerate(headers)}

    def cell(row: list[Any], name: str) -> Any:
        index = positions.get(name)
        value = row[index] if index is not None and index < len(row) else ""
        return "" if value is None else value.strip() if isinstance(value, str) else value

    for row in values[1:]:
        hostname = str(cell(row, "hostname")).casefold()
        if not hostname:
            continue
        instance = str(cell(row, "instance")).casefold()
        key = ("" if instance == "*" else instance, hostname)
        node_type = inventory_node_type(cell(row, "type"))
        if key not in result.node_types:
            result.node_types[key] = node_type
        elif result.node_types[key] is not None and result.node_types[key] != node_type:
            result.node_types[key] = None
            LOGGER.warning("Inventory type conflict instance=%s hostname=%s; type lookup skipped", key[0] or "*", hostname)
        location = (cell(row, "rack"), cell(row, "ru"))
        if key not in result:
            result[key] = location
        elif result[key] is not None and tuple(map(str, result[key])) != tuple(map(str, location)):
            result[key] = None
            LOGGER.warning("Inventory location conflict instance=%s hostname=%s; lookup skipped", key[0] or "*", hostname)
    return result


def enrich_inventory_locations(
    values: list[list[Any]], locations: dict[tuple[str, str], tuple[Any, Any] | None],
    instance_name: str = "", *, fill_locations: bool = True,
) -> list[list[Any]]:
    """Fill missing expected endpoint types and optional Rack/RU, never discoveries."""
    if not values or not locations:
        return values
    values = normalize_instance_table(values)
    positions = {str(h): i for i, h in enumerate(values[0])}
    result = [row.copy() for row in values]
    node_types = getattr(locations, "node_types", {})
    filled = 0
    for row in result[1:]:
        def cell(name: str) -> Any:
            i = positions.get(name)
            return row[i] if i is not None and i < len(row) else ""
        instance = str(cell(INSTANCE_HEADER) or instance_name).strip().casefold()
        for side in ("A", "Z"):
            node = str(cell(f"{side} Node") or "").strip().casefold()
            if not node:
                continue
            key = (instance, node)
            location = locations[key] if key in locations else locations.get(("", node))
            node_type = node_types[key] if key in node_types else node_types.get(("", node))
            fields = list(zip(("Rack", "RU"), location)) if fill_locations and location is not None else []
            fields.append(("Node Type", node_type or ""))
            for field, value in fields:
                name = f"{side} {field}"
                old = cell(name)
                if name not in positions or (old is not None and str(old).strip()) or value == "":
                    continue
                i = positions[name]
                row.extend([""] * max(0, i + 1 - len(row)))
                row[i] = value
                filled += 1
    LOGGER.info("Inventory endpoints enriched instance=%s filled_cells=%s", instance_name or "single", filled)
    return result


def load_inventory_locations(service: Any, args: argparse.Namespace) -> dict:
    """Read an optional Inventory once per instance cycle; never create or write it."""
    sheet_name = str(getattr(args, "inventory_sheet", "Inventory") or "").strip()
    if not sheet_name:
        return {}
    cached = getattr(args, "_inventory_locations", None)
    if cached is not None:
        return cached
    metadata = service.spreadsheets().get(
        spreadsheetId=args.spreadsheet_id,
        fields="sheets.properties(title,gridProperties(rowCount,columnCount))",
    ).execute()
    properties = next((s["properties"] for s in metadata.get("sheets", [])
                       if s["properties"]["title"] == sheet_name), None)
    if properties is None:
        LOGGER.warning("Inventory sheet missing sheet=%s; endpoint lookup skipped", sheet_name)
        args._inventory_locations = {}
        return {}
    grid = properties["gridProperties"]
    quoted = quoted_sheet_name(sheet_name)
    headers = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id,
        range=f"{quoted}!A1:{sheet_column_name(grid['columnCount'] - 1)}1",
    ).execute().get("values", [])
    if not headers or not any(str(h).strip() for h in headers[0]):
        LOGGER.warning("Inventory has no header sheet=%s; endpoint lookup skipped", sheet_name)
        args._inventory_locations = {}
        return {}
    inventory_locations(headers)  # Validate before retrieving any device data.
    selected = [(i, str(h).strip().casefold()) for i, h in enumerate(normalize_instance_headers(headers[0]))
                if str(h).strip().casefold() in {"hostname", "rack", "ru", "type", "instance"}]
    values = [[h for _, h in selected]]
    if grid["rowCount"] > 1:
        ranges = [f"{quoted}!{sheet_column_name(i)}2:{sheet_column_name(i)}{grid['rowCount']}" for i, _ in selected]
        columns = service.spreadsheets().values().batchGet(
            spreadsheetId=args.spreadsheet_id, ranges=ranges,
        ).execute().get("valueRanges", [])
        if len(columns) != len(ranges):
            raise ValueError("Inventory read returned incomplete columns; refusing partial enrichment.")
        data = [c.get("values", []) for c in columns]
        for r in range(max((len(c) for c in data), default=0)):
            values.append([c[r][0] if r < len(c) and c[r] else "" for c in data])
    args._inventory_locations = inventory_locations(values)
    return args._inventory_locations


def enrich_from_inventory(service: Any, args: argparse.Namespace, values: list[list[Any]]) -> list[list[Any]]:
    fill_locations = source_reporter(args) == "LLDPQ"
    # CVT with complete endpoint types needs no Inventory request at all.
    if not fill_locations:
        positions = {h: i for i, h in enumerate(values[0])} if values else {}
        if not any(
            type_col in positions and (positions[type_col] >= len(row)
                                      or not str(row[positions[type_col]] or "").strip())
            and node_col in positions and positions[node_col] < len(row)
            and str(row[positions[node_col]] or "").strip()
            for row in values[1:] for node_col, type_col in
            (("A Node", "A Node Type"), ("Z Node", "Z Node Type"))
        ):
            return values
    return enrich_inventory_locations(
        values, load_inventory_locations(service, args), getattr(args, "instance_name", "") or "",
        fill_locations=fill_locations,
    )


def managed_reporter(value: Any) -> str | None:
    """Recognize automation ownership without treating arbitrary reporters as tools."""
    return {"cvt": "CVT", "lldpq": "LLDPQ"}.get(str(value or "").strip().casefold())


@dataclass(frozen=True)
class SourceSettings:
    source_type: str
    transport: str
    file: Path | None = None
    api_url: str | None = None


def validate_source_api_url(value: str) -> str:
    """Validate an API origin, not an endpoint; allow one optional trailing slash."""
    try:
        parsed = urlparse(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("--source-api-url must be a valid HTTP(S) URL.") from error
    if (
        parsed.scheme not in {"http", "https"} or not parsed.hostname
        or parsed.username is not None or parsed.password is not None
        or parsed.path not in {"", "/"} or parsed.params
        or "?" in value or "#" in value or "\\" in value
        or any(char.isspace() for char in value)
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError(
            "--source-api-url must be an HTTP(S) base URL, e.g. https://127.0.0.1:39443, "
            "without endpoint path, query, userinfo or fragment. Use the separate API path options."
        )
    return value.rstrip("/")


def resolve_source_settings(
    args: argparse.Namespace, *, require_input: bool = True,
) -> SourceSettings:
    """Resolve flat source options without mutating legacy CLI/config attributes."""
    source_type = str(getattr(args, "source_type", None) or "cvt").strip().casefold()
    if source_type not in SOURCE_ADAPTERS:
        raise ValueError(
            f"Unsupported --source-type {source_type!r}; implemented adapters: "
            + ", ".join(sorted(SOURCE_ADAPTERS))
            + ". Implement the adapter before selecting this source type."
        )
    files = [path for path in (
        getattr(args, "source_file", None), getattr(args, "cable_report", None),
        getattr(args, "json_file", None),
    ) if path]
    if len(files) > 1:
        raise ValueError("Use only one of --source-file, --cable-report, or --json-file.")
    file_path = Path(files[0]) if files else None
    api_url = str(getattr(args, "source_api_url", None) or "").strip() or None
    if api_url:
        api_url = validate_source_api_url(api_url)
    transport = str(getattr(args, "source_transport", None) or "").strip().casefold()
    transport = transport or ("file" if file_path else "api")
    if transport not in {"file", "api"}:
        raise ValueError("--source-transport must be api or file; SSH is not implemented.")
    if file_path and api_url:
        raise ValueError("Do not combine a local report with --source-api-url.")
    if transport == "api" and file_path:
        raise ValueError("--source-transport api cannot be combined with a local report.")
    if transport == "file" and api_url:
        raise ValueError("--source-transport file cannot be combined with --source-api-url.")
    if require_input and transport == "file" and not file_path:
        raise ValueError("--source-transport file requires --source-file (or a legacy report file).")
    if source_type == "lldpq":
        if api_url or (require_input and transport != "file"):
            raise ValueError("LLDPQ currently supports source_transport=file only; API authentication is not implemented.")
        if getattr(args, "json_field_map", None) or getattr(args, "json_records_path", None):
            raise ValueError("LLDPQ uses its built-in adapter; do not set --json-field-map or --json-records-path.")
        if getattr(args, "refresh_agent_status", False):
            raise ValueError("Agent refresh is CVT-specific; set refresh_agent_status=false for LLDPQ instances.")
        if getattr(args, "values_json", None) or getattr(args, "csv", None):
            raise ValueError("LLDPQ requires a JSON report file, not --values-json or --csv.")
    if (getattr(args, "values_json", None) or getattr(args, "csv", None)) and (
        file_path or api_url or getattr(args, "source_transport", None)
    ):
        raise ValueError("Raw --values-json/--csv inputs cannot be combined with source transport options.")
    return SourceSettings(source_type, transport, file_path, api_url)


def source_api_requested(args: argparse.Namespace) -> bool:
    """Connection settings do not cause report fetches in remediation-only modes."""
    if args.operation in ("import", "both"):
        return True  # Existing mode flag; local files still take precedence in load_values.
    if args.operation == "remediation" or any(getattr(args, name, False) for name in (
        "remediation_from_cvt", "refresh_ai_only", "clear_data", "list_ai_models",
    )):
        return False
    return bool(getattr(args, "source_api_url", None)) or (
        str(getattr(args, "source_transport", None) or "").strip().casefold() == "api"
    )


def cable_report_values(circuits: Any, include_healthy: bool) -> list[list[Any]]:
    return normalize_report_values(circuits, CvtReportAdapter(), include_healthy)


def normalize_report_values(
    document: Any, adapter: ReportAdapter, include_healthy: bool,
) -> list[list[Any]]:
    """Compatibility table boundary shared by source adapters and current rules."""
    links = adapter.normalize(document, include_healthy)
    return [list(CABLE_REPORT_HEADERS)] + [project_link_observation(link) for link in links]


def parse_columns(value: str | None, available: list[str], option: str) -> list[str]:
    """Parse a header selection while keeping the sheet schema explicit and safe."""
    if not value:
        return available.copy()
    columns = normalize_instance_headers([column.strip() for column in value.split(",") if column.strip()])
    unknown = [column for column in columns if column not in available]
    duplicate = len(columns) != len(set(columns))
    if not columns or unknown or duplicate:
        detail = f" unknown columns: {', '.join(unknown)}." if unknown else ""
        raise ValueError(f"{option} must be a comma-separated list of distinct supported headers.{detail}")
    return columns


def load_json_field_map(source: str | None) -> dict[str, str] | None:
    """Load a Sheet-column -> JSON-path mapping from inline JSON or a JSON file."""
    if not source:
        return None
    candidate = Path(source)
    try:
        raw = json.loads(candidate.read_text(encoding="utf-8")) if candidate.is_file() else json.loads(source)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"--json-field-map must be valid JSON or a readable JSON file: {error}") from error
    if not isinstance(raw, dict) or not raw:
        raise ValueError("--json-field-map must be a non-empty object of Sheet column names to JSON paths.")
    mapping = {str(column).strip(): str(path).strip() for column, path in raw.items()}
    if any(not column or not path for column, path in mapping.items()):
        raise ValueError("Each --json-field-map column name and JSON path must be non-empty.")
    return normalize_instance_mapping(mapping)


def load_unified_mapping_config(source: str | None) -> tuple[dict[str, str], dict[str, str]] | None:
    """Load one mapping config that defines both CVT_Import and Remediation headers."""
    if not source:
        return None
    candidate = Path(source)
    try:
        raw = json.loads(candidate.read_text(encoding="utf-8")) if candidate.is_file() else json.loads(source)
    except (OSError, json.JSONDecodeError) as error:
        raise ValueError(f"--mapping-config must be valid JSON or a readable JSON file: {error}") from error
    if not isinstance(raw, dict) or set(raw) != {"cvt_import", "remediation"}:
        raise ValueError("--mapping-config must contain exactly 'cvt_import' and 'remediation' objects.")

    def mapping(section: str) -> dict[str, str]:
        value = raw[section]
        if not isinstance(value, dict) or not value:
            raise ValueError(f"--mapping-config.{section} must be a non-empty object.")
        result = {str(key).strip(): str(item).strip() for key, item in value.items()}
        if any(not key or not item for key, item in result.items()):
            raise ValueError(f"--mapping-config.{section} contains an empty key or value.")
        return result

    return (normalize_instance_mapping(mapping("cvt_import")),
            normalize_instance_mapping(mapping("remediation"), normalize_targets=True))


def resolve_json_path(source: Any, path: str) -> Any:
    """Resolve a dotted JSON path and return the original JSON value."""
    value = source
    for part in path.split("."):
        if isinstance(value, dict):
            value = value.get(part, "")
        elif isinstance(value, list) and part.isdecimal():
            index = int(part)
            value = value[index] if index < len(value) else ""
        else:
            return ""
    return value


def json_path_value(source: Any, path: str) -> Any:
    """Resolve a dotted JSON path. Missing paths produce an empty cell, not an import failure."""
    value = resolve_json_path(source, path)
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return value


def mapped_json_values(document: Any, mapping: dict[str, str], records_path: str | None) -> list[list[Any]]:
    mapping = normalize_instance_mapping(mapping)
    records: Any = document if records_path is None else resolve_json_path(document, records_path)
    if not isinstance(records, list):
        raise ValueError("Mapped JSON records must be an array; use --json-records-path for a nested array.")
    headers = list(mapping)
    return [headers] + [
        [json_path_value(record, mapping[header]) if isinstance(record, dict) else "" for header in headers]
        for record in records
    ]


def cvt_headers(args: argparse.Namespace) -> list[str]:
    headers = normalize_instance_headers(list(args.json_field_mapping)) if args.json_field_mapping else [*CABLE_REPORT_HEADERS]
    if args.compare_existing:
        if STATUS_CYCLES_HEADER not in headers:
            status_index = headers.index("Status") + 1 if "Status" in headers else len(headers)
            headers.insert(status_index, STATUS_CYCLES_HEADER)
        if TRACKING_STATUS_HEADER not in headers:
            headers.append(TRACKING_STATUS_HEADER)
    if INSTANCE_HEADER not in headers:
        headers.append(INSTANCE_HEADER)
    return headers


def add_instance_column(values: list[list[Any]], instance_name: str | None) -> list[list[Any]]:
    """Append the owning instance to a freshly collected table."""
    if not values:
        return values
    values = normalize_instance_table(values)
    instance_name = instance_name or ""
    headers = [str(header) for header in values[0]]
    if INSTANCE_HEADER in headers:
        instance_index = headers.index(INSTANCE_HEADER)
        result = [values[0].copy()]
        for source_row in values[1:]:
            row = source_row.copy()
            if len(row) <= instance_index:
                row.extend([""] * (instance_index + 1 - len(row)))
            row[instance_index] = instance_name
            result.append(row)
        return result
    return [values[0] + [INSTANCE_HEADER]] + [row + [instance_name] for row in values[1:]]


def should_clear_cvt_on_start(args: argparse.Namespace) -> bool:
    """Return true only for an enabled fresh start in the process's first cycle."""
    return bool(args.fresh_start and getattr(args, "first_cycle", True))


def remediation_header_map(source: str | None, custom: dict[str, str] | None = None) -> dict[str, str]:
    """Return canonical Remediation fields mapped to their target Sheet headers."""
    result = {header: header for header in REMEDIATION_HEADERS}
    result.update({"Description": "Issue Desc", "Error": "Issue Type"})
    custom = custom if custom is not None else load_json_field_map(source)
    if custom is None:
        return result
    custom = normalize_instance_mapping(custom, normalize_targets=True)
    unknown = [header for header in custom if header not in result]
    if unknown:
        raise ValueError(
            "--remediation-column-map keys must be standard Remediation fields; "
            f"unknown: {', '.join(unknown)}"
        )
    result.update(custom)
    if len(set(result.values())) != len(result):
        raise ValueError("--remediation-column-map target header names must be distinct.")
    return result


def selected_remediation_headers(args: argparse.Namespace) -> tuple[list[str], list[str]]:
    """Return canonical fields and their corresponding target Sheet headers."""
    remediation_columns = getattr(args, "remediation_columns", None)
    if remediation_columns:
        canonical = parse_columns(
            remediation_columns, REMEDIATION_HEADERS, "--remediation-columns"
        )
        if INSTANCE_HEADER not in canonical:
            canonical.append(INSTANCE_HEADER)
    else:
        canonical = REMEDIATION_HEADERS.copy()
    return canonical, [args.remediation_header_mapping[header] for header in canonical]


def cabling_targets(args: argparse.Namespace) -> list[tuple[str | None, str]]:
    """Return protocol family and sheet-name pairs for remediation updates."""
    if args.remediation_sheet:
        return [(None, args.remediation_sheet)]
    if args.eth_cabling_sheet and args.ib_cabling_sheet == args.eth_cabling_sheet:
        raise ValueError("--ib-cabling-sheet and --eth-cabling-sheet must use different names.")
    targets = []
    if args.ib_cabling_sheet:
        targets.append(("ib", args.ib_cabling_sheet))
    if args.eth_cabling_sheet:
        targets.append(("eth", args.eth_cabling_sheet))
    return targets


def cabling_args(args: argparse.Namespace, sheet_name: str) -> argparse.Namespace:
    """Create a per-sheet argument view without mutating the caller's arguments."""
    scoped = copy.copy(args)
    scoped.remediation_sheet = sheet_name
    return scoped


def read_once_for_instance(args: argparse.Namespace, key: Any, loader: Callable[[], Any]) -> Any:
    """Share immutable reference/import reads between IB/ETH, never across cycles."""
    cache = getattr(args, "_instance_read_cache", None)
    if cache is None:
        return loader()
    if key not in cache:
        cache[key] = loader()
    return copy.deepcopy(cache[key])


def committed_cabling_key(args: argparse.Namespace, sheet_name: str) -> tuple[str, str, str]:
    return (str(getattr(args, "credentials", "")), args.spreadsheet_id, sheet_name.casefold())


def protocol_family(value: Any) -> str:
    """Route only explicit Ethernet protocols to ETH; every other value defaults to IB."""
    normalized = re.sub(r"[^a-z0-9]+", "", str(value or "").casefold())
    if normalized in {"eth", "ethernet", "roce", "rocev1", "rocev2"}:
        return "eth"
    return "ib"


def filter_cvt_by_protocol(values: list[list[Any]], family: str | None) -> list[list[Any]]:
    """Filter a CVT table for one Cabling target while preserving its header row."""
    if family is None or not values:
        return values
    headers = [str(header) for header in values[0]]
    if "Protocol" not in headers:
        raise ValueError(
            "CVT_Import must contain a Protocol column when using IB Cabling and ETH Cabling."
        )
    protocol_index = headers.index("Protocol")
    return [values[0]] + [
        row for row in values[1:]
        if protocol_family(row[protocol_index] if protocol_index < len(row) else "") == family
    ]


def attach_cvt_source_rows(
    values: list[list[Any]], data_start_row: int = 3,
) -> list[list[Any]]:
    """Attach the physical CVT_Import row before protocol filtering changes row offsets."""
    if not values:
        return values
    headers = [str(header) for header in values[0]]
    if CVT_SOURCE_ROW_HEADER in headers:
        source_index = headers.index(CVT_SOURCE_ROW_HEADER)
        result = [values[0].copy()]
        for sheet_row, source_row in enumerate(values[1:], start=data_start_row):
            row = source_row.copy()
            if len(row) <= source_index:
                row.extend([""] * (source_index + 1 - len(row)))
            row[source_index] = sheet_row
            result.append(row)
        return result
    return [values[0] + [CVT_SOURCE_ROW_HEADER]] + [
        row + [sheet_row]
        for sheet_row, row in enumerate(values[1:], start=data_start_row)
    ]


def canonicalize_remediation_values(
    values: list[list[Any]], header_mapping: dict[str, str]
) -> list[list[Any]]:
    """Map custom Sheet headers back to canonical names before merging remediation rows."""
    if not values:
        return values
    values = normalize_instance_table(values)
    header_mapping = normalize_instance_mapping(header_mapping, normalize_targets=True)
    source_positions = {str(header): index for index, header in enumerate(values[0])}
    canonical_headers = list(header_mapping)

    rows = [
        [
            row[source_positions[header_mapping[canonical]]]
            if header_mapping[canonical] in source_positions
            and source_positions[header_mapping[canonical]] < len(row)
            else ""
            for canonical in canonical_headers
        ]
        for row in values[1:]
    ]
    return [canonical_headers] + rows


def project_columns(values: list[list[Any]], columns: list[str]) -> list[list[Any]]:
    """Return a rectangular table containing only selected named columns."""
    if not values:
        return values
    positions = {header: index for index, header in enumerate(values[0])}
    return [columns] + [[row[positions[column]] if positions[column] < len(row) else "" for column in columns]
                        for row in values[1:]]


def read_cable_report_document(report_path: Path) -> Any:
    """Local transport: read JSON without interpreting link fields."""
    if not report_path.is_file():
        raise ValueError(f"Cable report not found: {report_path}")
    try:
        with report_path.open("r", encoding="utf-8") as report_file:
            circuits = json.load(report_file)
    except json.JSONDecodeError as error:
        raise ValueError(f"Cable report is not valid JSON: {error.msg}") from error

    return circuits


def load_cable_report(report_path: Path, include_healthy: bool) -> list[list[Any]]:
    return cable_report_values(read_cable_report_document(report_path), include_healthy)


def cable_api_url(host: str, port: int, path: str) -> str:
    """Build an HTTPS URL for an endpoint on the Cable-validation API."""
    if not host or "://" in host or "/" in host:
        raise ValueError("--cable-api-host must be a hostname or IP address without a scheme or path.")
    if not 1 <= port <= 65535:
        raise ValueError("--cable-api-port must be between 1 and 65535.")
    if not path.startswith("/"):
        raise ValueError("Cable API paths must start with '/'.")
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return f"https://{netloc}:{port}{path}"


def cvt_endpoint_url(args: argparse.Namespace, path: str) -> str:
    """Build all CVT endpoints from one base; legacy host/port remain supported."""
    if (
        not isinstance(path, str) or not path.startswith("/") or path.startswith("//")
        or "\\" in path or "#" in path or any(char.isspace() for char in path)
    ):
        raise ValueError("CVT API paths must start with a single '/' and stay on the API host.")
    base_url = str(getattr(args, "source_api_url", None) or "").strip()
    if base_url:
        return validate_source_api_url(base_url) + path
    return cable_api_url(args.cable_api_host, args.cable_api_port, path)


def fetch_cable_api_document(args: argparse.Namespace) -> Any:
    """CVT transport: authenticate and collect JSON without interpreting records."""
    settings = resolve_source_settings(args)
    if settings.source_type != "cvt":
        raise ValueError("Only CVT API authentication is implemented; use a local LLDPQ report file.")
    password = os.getenv(args.cable_api_password_env)
    if not args.cable_api_username or not password:
        raise ValueError(
            "Set CABLE_API_USERNAME and CABLE_API_PASSWORD (or pass --cable-api-username "
            "and --cable-api-password-env) before importing from the cable API."
        )
    if settings.transport != "api":
        raise ValueError("API collection requires source_transport=api.")
    login_url = cvt_endpoint_url(args, args.cable_api_login_path)
    report_url = cvt_endpoint_url(args, args.cable_api_report_path)
    try:
        with requests.Session() as session:
            login_response = session.post(
                login_url,
                data={"httpd_username": args.cable_api_username, "httpd_password": password},
                verify=not args.cable_api_insecure_tls,
                timeout=args.timeout,
            )
            login_response.raise_for_status()
            report_response = session.get(
                report_url,
                verify=not args.cable_api_insecure_tls,
                timeout=args.timeout,
            )
            report_response.raise_for_status()
            circuits = report_response.json()
    except RequestException as error:
        raise ValueError(f"Cable API request failed: {error}") from error
    except ValueError as error:
        raise ValueError(f"Cable API returned invalid JSON: {error}") from error
    return circuits


def load_cable_api_report(args: argparse.Namespace) -> list[list[Any]]:
    settings = resolve_source_settings(args)
    return normalize_report_values(
        fetch_cable_api_document(args), SOURCE_ADAPTERS[settings.source_type](), args.include_healthy,
    )


def agent_timestamp(value: Any, timezone_name: str = DEFAULT_TIMEZONE) -> str:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(
            value, tz=operational_timezone(timezone_name)
        ).strftime("%Y-%m-%d %H:%M:%S")
    return "" if value is None else str(value)


def load_agent_status(args: argparse.Namespace) -> list[list[Any]]:
    """Refresh the login cookie and fetch the current Agent Details response."""
    password = os.getenv(args.cable_api_password_env)
    if not args.cable_api_username or not password:
        raise ValueError(
            "Set CABLE_API_USERNAME and CABLE_API_PASSWORD before refreshing Agent_status."
        )
    login_url = cvt_endpoint_url(args, args.cable_api_login_path)
    agent_url = cvt_endpoint_url(args, args.cable_api_agent_path)
    try:
        with requests.Session() as session:
            login_response = session.post(
                login_url,
                data={"httpd_username": args.cable_api_username, "httpd_password": password},
                verify=not args.agent_api_insecure_tls,
                timeout=args.timeout,
            )
            login_response.raise_for_status()
            if not session.cookies:
                raise ValueError("Agent login succeeded but did not return a session cookie.")
            cookie_jar = MozillaCookieJar(str(args.agent_cookies))
            for cookie in session.cookies:
                cookie_jar.set_cookie(cookie)
            args.agent_cookies.parent.mkdir(parents=True, exist_ok=True)
            cookie_jar.save(ignore_discard=True, ignore_expires=True)
            session.cookies.update(cookie_jar)
            response = session.get(
                agent_url, verify=not args.agent_api_insecure_tls, timeout=args.timeout
            )
            response.raise_for_status()
            records = response.json()
    except (RequestException, OSError) as error:
        raise ValueError(f"Agent Details API request failed: {error}") from error
    except ValueError as error:
        raise ValueError(f"Agent Details API returned invalid JSON: {error}") from error
    if not isinstance(records, list):
        raise ValueError("Agent Details API response must be a JSON array.")

    def text(value: Any) -> Any:
        return "" if value is None else value

    rows = []
    for record in records:
        if not isinstance(record, dict):
            continue
        rows.append([
            text(record.get("hostname")), text(record.get("ip")), text(record.get("ping")),
            text(record.get("agent")), text(record.get("device_status")), text(record.get("json_api")),
            text(record.get("node_type")), text(record.get("node_os")), text(record.get("dns_resolved")),
            text(record.get("dns_attempts")), agent_timestamp(
                record.get("dns_last_attempt"), args.timezone_name
            ),
            agent_timestamp(record.get("last_updated"), args.timezone_name),
            text(record.get("time_since_update")),
            text(record.get("dh")), text(record.get("su")), text(record.get("rack")),
            text(record.get("unit")), text(record.get("comment")),
            getattr(args, "instance_name", None) or "",
        ])
    rows.sort(key=lambda row: str(row[0]))
    return [AGENT_STATUS_HEADERS] + rows


def bcm_status_url(base_url: str | None) -> str:
    """Build the one supported BCM REST v1 endpoint from a head-node base URL."""
    value = str(base_url or "").strip().rstrip("/")
    parsed = urlparse(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "--bcm-api-url must be a BCM head-node base URL without credentials, "
            "path, query, or fragment, e.g. https://bcm.example:8081."
        )
    return f"{value}/rest/v1/status"


def load_bcm_status(args: argparse.Namespace) -> list[list[Any]]:
    """Fetch device health using only BCM REST v1 status?verbose=1."""
    endpoint = bcm_status_url(args.bcm_api_url)
    request_options: dict[str, Any] = {
        "params": {"verbose": "1"},
        "verify": not args.bcm_insecure_tls,
        "timeout": args.timeout,
        "headers": {"Accept": "application/json"},
    }
    if args.bcm_auth == "basic":
        password = os.getenv(args.bcm_password_env)
        if not args.bcm_username or not password:
            raise ValueError(
                "BCM Basic authentication requires --bcm-username (or BCM_API_USERNAME) "
                f"and the {args.bcm_password_env} environment variable."
            )
        request_options["auth"] = (args.bcm_username, password)
    elif args.bcm_auth == "certificate":
        if not args.bcm_cert or not args.bcm_key:
            raise ValueError(
                "BCM certificate authentication requires --bcm-cert and --bcm-key."
            )
        if not args.bcm_cert.is_file():
            raise ValueError(f"BCM client certificate not found: {args.bcm_cert}")
        if not args.bcm_key.is_file():
            raise ValueError(f"BCM client key not found: {args.bcm_key}")
        request_options["cert"] = (str(args.bcm_cert), str(args.bcm_key))
    else:
        raise ValueError("--bcm-auth must be basic or certificate.")

    try:
        response = requests.get(endpoint, **request_options)
        response.raise_for_status()
        records = response.json()
    except RequestException as error:
        raise ValueError(f"BCM REST v1 status request failed: {error}") from error
    except ValueError as error:
        raise ValueError(f"BCM REST v1 status returned invalid JSON: {error}") from error
    if not isinstance(records, list):
        raise ValueError("BCM REST v1 status response must be a JSON array.")

    instance_name = getattr(args, "instance_name", None) or ""
    rows = []
    for record in records:
        if not isinstance(record, dict):
            continue
        rows.append([
            "" if record.get("hostname") is None else record.get("hostname"),
            "" if record.get("status") is None else record.get("status"),
            "" if record.get("health_check_failed") is None else record.get("health_check_failed"),
            "" if record.get("health_check_unknown") is None else record.get("health_check_unknown"),
            "" if record.get("provisioning_failed") is None else record.get("provisioning_failed"),
            "" if record.get("restart_required") is None else record.get("restart_required"),
            instance_name,
        ])
    rows.sort(key=lambda row: str(row[0]).casefold())
    return [BCM_STATUS_HEADERS] + rows


def normalize_bcm_hostname(value: Any) -> str:
    """Normalize CVT and BCM hostnames for case-insensitive exact matching."""
    return str(value or "").strip().rstrip(".").casefold()


def compile_bcm_host_patterns(
    patterns: list[str] | tuple[str, ...] | None,
) -> list[re.Pattern[str]]:
    """Compile the Host selectors used to decide whether BCM gating applies."""
    values = list(DEFAULT_BCM_HOST_PATTERNS if patterns is None else patterns)
    compiled: list[re.Pattern[str]] = []
    for pattern in values:
        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("BCM Host patterns must be non-empty strings.")
        try:
            compiled.append(re.compile(pattern, flags=re.IGNORECASE))
        except re.error as error:
            raise ValueError(
                f"Invalid BCM Host regex {pattern!r}: {error}"
            ) from error
    return compiled


def bcm_status_by_hostname(values: list[list[Any]]) -> dict[str, str]:
    """Index BCM status rows; conflicting duplicates fail closed as non-UP."""
    if not values:
        return {}
    positions = {str(header): index for index, header in enumerate(values[0])}
    hostname_index = positions.get("Hostname")
    status_index = positions.get("Status")
    if hostname_index is None or status_index is None:
        raise ValueError("BCM status data must contain Hostname and Status columns.")
    result: dict[str, str] = {}
    for row in values[1:]:
        hostname = normalize_bcm_hostname(
            row[hostname_index] if hostname_index < len(row) else ""
        )
        status = str(row[status_index] if status_index < len(row) else "").strip()
        if not hostname:
            continue
        previous = result.get(hostname)
        if previous is None:
            result[hostname] = status
        elif previous.casefold() != status.casefold():
            result[hostname] = "CONFLICT"
    return result


def summarize_bcm_selected_hosts(
    host_statuses: dict[str, str],
    host_patterns: list[str] | tuple[str, ...] | None,
) -> Counter[str]:
    """Count unique BCM hosts selected by the configured case-insensitive regexes."""
    compiled_patterns = compile_bcm_host_patterns(host_patterns)
    summary: Counter[str] = Counter()
    for hostname, status in host_statuses.items():
        normalized_hostname = normalize_bcm_hostname(hostname)
        if not normalized_hostname or not any(
            pattern.search(normalized_hostname) for pattern in compiled_patterns
        ):
            continue
        summary["matched"] += 1
        normalized_status = str(status or "").strip().casefold()
        if normalized_status == "up":
            summary["up"] += 1
        elif normalized_status == "down":
            summary["down"] += 1
        else:
            summary["non_up"] += 1
    return summary


def bcm_new_case_gate_by_link(
    cvt_values: list[list[Any]],
    host_statuses: dict[str, str] | None,
    port_mapping: dict[str, str] | None = None,
    host_patterns: list[str] | tuple[str, ...] | None = None,
) -> dict[tuple[str, str, str, str, str], str]:
    """Return BCM decisions for Host links selected by configured regexes."""
    if host_statuses is None or not cvt_values:
        return {}
    compiled_patterns = compile_bcm_host_patterns(host_patterns)
    positions = {str(header): index for index, header in enumerate(cvt_values[0])}

    def value(row: list[Any], header: str) -> str:
        index = positions.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    decisions: dict[tuple[str, str, str, str, str], str] = {}
    for row in cvt_values[1:]:
        a_type = value(row, "A Node Type").casefold()
        z_type = value(row, "Z Node Type").casefold()
        if cabling_link_type(a_type, z_type) != "Host":
            continue
        instance = value(row, INSTANCE_HEADER)
        a_node = value(row, "A Node")
        a_port = mapped_port_name(value(row, "A Port"), port_mapping)
        z_node = value(row, "Z Node")
        z_port = mapped_port_name(value(row, "Z Port"), port_mapping)
        if not all((a_node, a_port, z_node, z_port)):
            continue
        key = (instance, a_node, a_port, z_node, z_port)
        hostnames = [
            normalize_bcm_hostname(node)
            for endpoint_type, node in ((a_type, a_node), (z_type, z_node))
            if endpoint_type == "host"
        ]
        selected_hostnames = [
            hostname for hostname in hostnames
            if hostname and any(
                pattern.search(hostname) for pattern in compiled_patterns
            )
        ]
        if not selected_hostnames:
            decisions[key] = "bypassed"
            continue
        statuses = [host_statuses.get(hostname) for hostname in selected_hostnames]
        if len(statuses) != len(selected_hostnames) or any(
            status is None or not str(status).strip() for status in statuses
        ):
            decisions[key] = "not_found"
        elif any(str(status).strip().casefold() == "down" for status in statuses):
            decisions[key] = "down"
        elif any(str(status).strip().casefold() != "up" for status in statuses):
            decisions[key] = "non_up"
        else:
            decisions[key] = "allowed"
    return decisions


def collect_bcm_status_for_cycle(
    args: argparse.Namespace,
) -> tuple[list[list[Any]] | None, dict[str, str] | None]:
    """Collect BCM once; API failure closes only the Host new-case gate."""
    if not args.enable_bcm:
        return None, None
    try:
        values = load_bcm_status(args)
        host_statuses = bcm_status_by_hostname(values)
        summary = summarize_bcm_selected_hosts(
            host_statuses,
            getattr(args, "bcm_host_patterns", list(DEFAULT_BCM_HOST_PATTERNS)),
        )
        LOGGER.info(
            "BCM selected Host summary instance=%s matched=%s up=%s down=%s "
            "non_up=%s patterns=%s",
            getattr(args, "instance_name", None) or "single",
            summary["matched"],
            summary["up"],
            summary["down"],
            summary["non_up"],
            getattr(args, "bcm_host_patterns", list(DEFAULT_BCM_HOST_PATTERNS)),
        )
        return values, host_statuses
    except (ValueError, OSError) as error:
        LOGGER.warning(
            "BCM status unavailable; Host new Case creation disabled for this cycle: %s",
            error,
        )
        # An empty map means BCM is enabled but no Host can prove it is UP.
        # Switch links and existing Cases remain unaffected.
        return None, {}


def compare_report_to_existing(
    report_values: list[list[Any]], existing_values: list[list[Any]]
) -> list[list[Any]]:
    """Merge current and prior reports by Circuit ID, retaining resolved circuits."""
    existing_values = strip_timestamp_row(existing_values)
    report_headers, report_rows = report_values[0], report_values[1:]
    circuit_index = report_headers.index("Circuit ID")

    existing_by_circuit: dict[str, dict[str, Any]] = {}
    if existing_values:
        existing_headers = existing_values[0]
        try:
            existing_circuit_index = existing_headers.index("Circuit ID")
        except ValueError:
            existing_circuit_index = -1
        if existing_circuit_index >= 0:
            for row in existing_values[1:]:
                if existing_circuit_index < len(row) and row[existing_circuit_index]:
                    existing_by_circuit[str(row[existing_circuit_index])] = {
                        header: row[index] if index < len(row) else ""
                        for index, header in enumerate(existing_headers)
                    }

    status_index = report_headers.index("Status") if "Status" in report_headers else -1

    def next_status_cycles(old_row: dict[str, Any] | None, current_status: Any) -> int:
        """Increment only when the latest Pass/Fail value matches the prior run."""
        if old_row is None:
            return 1
        old_status = str(old_row.get("Status", "")).strip().casefold()
        new_status = str(current_status or "").strip().casefold()
        if old_status != new_status:
            return 1
        try:
            previous_cycles = int(str(old_row.get(STATUS_CYCLES_HEADER, "")).strip())
        except (TypeError, ValueError):
            previous_cycles = 0
        return previous_cycles + 1 if previous_cycles > 0 else 1

    output_headers = list(report_headers)
    if STATUS_CYCLES_HEADER not in output_headers:
        insert_index = output_headers.index("Status") + 1 if "Status" in output_headers else len(output_headers)
        output_headers.insert(insert_index, STATUS_CYCLES_HEADER)
    if TRACKING_STATUS_HEADER not in output_headers:
        output_headers.append(TRACKING_STATUS_HEADER)
    report_index_by_header = {header: index for index, header in enumerate(report_headers)}

    def output_row(source: list[Any] | dict[str, Any], tracking_status: str, cycles: Any) -> list[Any]:
        if isinstance(source, dict):
            return [
                cycles if header == STATUS_CYCLES_HEADER
                else tracking_status if header == TRACKING_STATUS_HEADER
                else source.get(header, "")
                for header in output_headers
            ]
        return [
            cycles if header == STATUS_CYCLES_HEADER
            else tracking_status if header == TRACKING_STATUS_HEADER
            else source[report_index_by_header[header]]
            if header in report_index_by_header and report_index_by_header[header] < len(source) else ""
            for header in output_headers
        ]

    result = [output_headers]
    current_circuit_ids = set()
    for row in report_rows:
        circuit_id = str(row[circuit_index])
        current_circuit_ids.add(circuit_id)
        old_row = existing_by_circuit.get(circuit_id)
        tracking_status = TRACKING_STATUS_EXISTING if old_row is not None else TRACKING_STATUS_NEW
        current_status = row[status_index] if status_index >= 0 and status_index < len(row) else ""
        result.append(output_row(row, tracking_status, next_status_cycles(old_row, current_status)))

    for circuit_id, old_row in existing_by_circuit.items():
        if circuit_id not in current_circuit_ids:
            result.append(output_row(old_row, TRACKING_STATUS_MISSING, old_row.get(STATUS_CYCLES_HEADER, "")))
    return result


def sheet_name_from_range(a1_range: str) -> str:
    if "!" not in a1_range:
        raise ValueError("--compare-existing requires a range with a sheet name, e.g. cvt!A1.")
    return a1_range.rsplit("!", 1)[0]


def quoted_sheet_name(sheet_name: str) -> str:
    """Quote a Google Sheets title for safe use in A1 notation."""
    return "'" + sheet_name.replace("'", "''") + "'"


def join_present(*values: Any) -> str:
    unique_values = []
    for value in values:
        text = str(value).strip() if value is not None else ""
        if text and text not in unique_values:
            unique_values.append(text)
    return "; ".join(unique_values)


def issue_type(
    *reports: Any,
    port_statuses: tuple[Any, ...] = (),
    ber_statuses: tuple[Any, ...] = (),
) -> str:
    """Classify raw CVT reports into remediation-friendly issue categories."""
    text = " ".join(str(report or "").casefold() for report in reports)
    categories = []
    if any(marker in text for marker in ("wrong-port", "wrong-neighbor", "mis-wiring", "miswiring", "mismatch")):
        categories.append("Mis-wiring")
    if "flapp" in text:
        categories.append("Flapping")
    if any(marker in text for marker in ("media unplugged", "link down", "port down", "linkdown")):
        categories.append("Link Down")
    if any(marker in text for marker in ("anomalous", "signal", "temperature", "power", " ber", "crc")):
        categories.append("Bad Signal")
    if not categories and any(
        str(status or "").strip().casefold() == "down" for status in port_statuses
    ):
        categories.append("Link Down")
    classification = "; ".join(categories) if categories else "Others"
    has_poor_ber = any(
        str(status or "").strip().casefold() == "poor"
        for status in ber_statuses
    )
    if classification in {"Bad Signal", "Others"} and has_poor_ber:
        return "PoorBER"
    return classification


def cabling_link_type(a_node_type: Any, z_node_type: Any) -> str:
    """Classify only a known switch/switch or switch/host endpoint pair."""
    endpoint_types = {
        str(a_node_type or "").strip().casefold(),
        str(z_node_type or "").strip().casefold(),
    }
    if endpoint_types == {"switch"}:
        return "Switch"
    if "switch" in endpoint_types and "host" in endpoint_types:
        return "Host"
    return "Unknown"


def build_remediation_values(
    cvt_values: list[list[Any]], remediation_min_status_cycles: int = 1,
    include_warnings: bool = False, include_all_current: bool = False,
    timezone_name: str = DEFAULT_TIMEZONE,
) -> list[list[Any]]:
    """Create Cabling-shaped records for eligible faults or every current CVT row."""
    return case_values_from_observations(
        observations_from_import_table(cvt_values), remediation_min_status_cycles,
        include_warnings, include_all_current, timezone_name,
    )


def case_values_from_observations(
    links: list[LinkObservation], min_cycles: int = 1,
    include_warnings: bool = False, include_all_current: bool = False,
    timezone_name: str = DEFAULT_TIMEZONE,
    reported_by: str = "CVT",
) -> list[list[Any]]:
    """Case candidate rules consume normalized links, never a source JSON schema."""

    records = [REMEDIATION_HEADERS]
    eligible_statuses = {"Fail", "Warning"} if include_warnings else {"Fail"}
    for physical_row, link in enumerate(links, start=3):
        if link.tracking_status in {
            TRACKING_STATUS_MISSING,
            "Resolved",  # Backward compatibility for sheets written by an earlier script version.
            "已消失",  # Backward compatibility for sheets written by earlier script versions.
        }:
            continue
        if not include_all_current and (
            link.status not in eligible_statuses
            or link.status_cycles < min_cycles
        ):
            continue
        a_report, z_report = link.a.report, link.z.report
        issue_desc = join_present(a_report, z_report)
        link_type = cabling_link_type(
            link.a.node_type, link.z.node_type
        )
        source_row = link.source_row or physical_row
        record = {
            "Fault ID": link.circuit_id, "Source": str(source_row), "Reported by": reported_by,
            "Date opened": current_datetime(timezone_name), "Link Type": link_type,
            "Description": issue_desc or "Cable validation failure",
            "Error": issue_type(
                a_report, z_report,
                port_statuses=(link.a.port_status, link.z.port_status),
                ber_statuses=(link.a.ber_status, link.z.ber_status),
            ),
            "Local SU Number": link.a.su, "Local Rack": link.a.rack,
            "Local RU": link.a.ru, "Local Device": link.a.node,
            "Local Port": link.a.port, "A Discover Node": link.a.actual_node,
            "A Discover Port": link.a.actual_port,
            "Z Rack": link.z.rack, "Z RU": link.z.ru, "Z Node": link.z.node,
            "Z Port": link.z.port, "Z Discover Node": link.z.actual_node,
            "Z Discover Port": link.z.actual_port, "Status": "New",
            "CVT": link.status,
            INSTANCE_HEADER: link.instance,
        }
        records.append([record.get(header, "") for header in REMEDIATION_HEADERS])
    return records


def remediation_key(row: list[Any]) -> tuple[str, str, str] | None:
    instance = str(row[REMEDIATION_INDEX[INSTANCE_HEADER]]).strip()
    device = str(row[REMEDIATION_INDEX["Local Device"]]).strip()
    port = str(row[REMEDIATION_INDEX["Local Port"]]).strip()
    return (instance, device, port) if device and port else None


def remediation_match_key(row: list[Any]) -> tuple[str, str, str, str, str] | None:
    """Identify one physical link by its instance and expected A/Z endpoints."""
    instance = str(row[REMEDIATION_INDEX[INSTANCE_HEADER]]).strip()
    a_node = str(row[REMEDIATION_INDEX["Local Device"]]).strip()
    a_port = str(row[REMEDIATION_INDEX["Local Port"]]).strip()
    z_node = str(row[REMEDIATION_INDEX["Z Node"]]).strip()
    z_port = str(row[REMEDIATION_INDEX["Z Port"]]).strip()
    return (
        (instance, a_node, a_port, z_node, z_port)
        if a_node and a_port and z_node and z_port else None
    )


def cvt_source_row_by_remediation_key(
    cvt_values: list[list[Any]], port_mapping: dict[str, str] | None = None,
) -> dict[tuple[str, str, str], str]:
    """Map a Remediation local endpoint to its physical CVT_Import row number."""
    if not cvt_values:
        return {}
    index_by_header = {header: index for index, header in enumerate(cvt_values[0])}

    def value(row: list[Any], header: str) -> str:
        index = index_by_header.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    sources: dict[tuple[str, str, str], str] = {}
    # cvt_values has already had the timestamp row removed; data starts at row 3.
    for cvt_sheet_row, row in enumerate(cvt_values[1:], start=3):
        instance = value(row, INSTANCE_HEADER)
        device, port = value(row, "A Node"), mapped_port_name(value(row, "A Port"), port_mapping)
        if device and port:
            sources[(instance, device, port)] = str(
                value(row, CVT_SOURCE_ROW_HEADER) or cvt_sheet_row
            )
    return sources


def remediation_rows_by_key(values: list[list[Any]]) -> dict[tuple[str, str, str], list[Any]]:
    if not values:
        return {}
    index_by_header = {header: index for index, header in enumerate(values[0])}
    result: dict[tuple[str, str, str], list[Any]] = {}
    for source_row in values[1:]:
        row = [
            source_row[index_by_header[header]]
            if header in index_by_header and index_by_header[header] < len(source_row) else ""
            for header in REMEDIATION_HEADERS
        ]
        key = remediation_key(row)
        if key and key not in result:
            result[key] = row
    return result


def next_fault_id_generator(
    existing_rows: list[list[Any]], start: int = DEFAULT_FAULT_ID_START,
):
    """Yield shared NV IDs at or above start, continuing after existing higher IDs."""
    max_number = start - 1
    for row in existing_rows:
        match = re.fullmatch(r"NV(\d+)", str(row[0]).strip())
        if match:
            number = int(match.group(1))
            if number > MAX_FAULT_ID:
                raise ValueError("Fault ID exceeds the supported five-digit range: NV99999.")
            max_number = max(max_number, number)
    while True:
        max_number += 1
        if max_number > MAX_FAULT_ID:
            raise ValueError("Fault ID exceeds the supported five-digit range: NV99999.")
        yield f"NV{max_number:05d}"


def cvt_status_by_remediation_key(
    cvt_values: list[list[Any]], port_mapping: dict[str, str] | None = None,
) -> dict[tuple[str, str, str], str]:
    """Return the latest CVT status keyed by its local endpoint."""
    if not cvt_values:
        return {}
    index_by_header = {header: index for index, header in enumerate(cvt_values[0])}

    def value(row: list[Any], header: str) -> str:
        index = index_by_header.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    result = {}
    for row in cvt_values[1:]:
        instance = value(row, INSTANCE_HEADER)
        device, port = value(row, "A Node"), mapped_port_name(value(row, "A Port"), port_mapping)
        if device and port:
            key, status = (instance, device, port), value(row, "Status")
            # A passing state takes precedence when a report has multiple entries for one key.
            if status.casefold() == "pass" or key not in result:
                result[key] = status
    return result


def cvt_link_type_by_remediation_key(
    cvt_values: list[list[Any]], port_mapping: dict[str, str] | None = None,
) -> dict[tuple[str, str, str], str]:
    """Return the current compact topology label keyed by the Cabling local endpoint."""
    if not cvt_values:
        return {}
    index_by_header = {header: index for index, header in enumerate(cvt_values[0])}

    def value(row: list[Any], header: str) -> str:
        index = index_by_header.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    result: dict[tuple[str, str, str], str] = {}
    for row in cvt_values[1:]:
        instance = value(row, INSTANCE_HEADER)
        device = value(row, "A Node")
        port = mapped_port_name(value(row, "A Port"), port_mapping)
        if device and port:
            result[(instance, device, port)] = cabling_link_type(
                value(row, "A Node Type"), value(row, "Z Node Type")
            )
    return result


def server_profile_custom_nic_map(values: list[list[Any]]) -> dict[str, str]:
    """Build an unambiguous ServerProfile port alias -> CustomNICName map."""
    if not values:
        return {}
    index_by_header = {str(header).strip().casefold(): index for index, header in enumerate(values[0])}
    custom_index = index_by_header.get("customnicname")
    if custom_index is None:
        return {}
    aliases = ("rdmaname", "nicosname", "physicalport")
    candidates: dict[str, set[str]] = {}
    for row in values[1:]:
        custom_name = str(row[custom_index]).strip() if custom_index < len(row) else ""
        if not custom_name:
            continue
        for header in aliases:
            index = index_by_header.get(header)
            alias = str(row[index]).strip() if index is not None and index < len(row) else ""
            if alias:
                candidates.setdefault(alias.casefold(), set()).add(custom_name)
    # Do not guess when the same port alias is assigned to multiple NIC names.
    return {alias: next(iter(names)) for alias, names in candidates.items() if len(names) == 1}


def load_server_profile_custom_nic_map(
    service: Any, args: argparse.Namespace,
) -> dict[str, str]:
    """Read the optional same-spreadsheet ServerProfile alias table."""
    values = (
        service.spreadsheets()
        .values()
        .get(spreadsheetId=args.spreadsheet_id, range=f"{args.server_profile_sheet}!A:Z")
        .execute()
        .get("values", [])
    )
    return server_profile_custom_nic_map(values)


def port_profile_map(values: list[list[Any]]) -> dict[str, str]:
    """Build an unambiguous, case-insensitive Port Name -> Custom lookup."""
    if not values:
        return {}
    header_row_index = next(
        (
            index for index, row in enumerate(values)
            if any(re.sub(r"[\s_-]+", "", str(cell).strip().casefold()) == "portname" for cell in row)
        ),
        None,
    )
    if header_row_index is None:
        return {}
    positions = {
        re.sub(r"[\s_-]+", "", str(header).strip().casefold()): index
        for index, header in enumerate(values[header_row_index])
    }
    port_index = positions.get("portname")
    custom_index = positions.get("custom")
    if custom_index is None:
        custom_index = positions.get("customnicname")
    if port_index is None or custom_index is None:
        return {}
    candidates: dict[str, set[str]] = {}
    for row in values[header_row_index + 1:]:
        port = str(row[port_index]).strip() if port_index < len(row) else ""
        custom = str(row[custom_index]).strip() if custom_index < len(row) else ""
        if port and custom:
            candidates.setdefault(port.casefold(), set()).add(custom)
    # Conflicting mappings are deliberately ignored rather than guessed.
    return {port: next(iter(customs)) for port, customs in candidates.items() if len(customs) == 1}


def load_port_profile_map(service: Any, args: argparse.Namespace) -> dict[str, str]:
    """Read the optional PortProfile table without creating or changing it."""
    metadata = service.spreadsheets().get(
        spreadsheetId=args.spreadsheet_id, fields="sheets.properties.title"
    ).execute()
    available_sheets = {sheet["properties"]["title"] for sheet in metadata.get("sheets", [])}
    if args.port_profile_sheet not in available_sheets:
        return {}
    quoted_name = "'" + args.port_profile_sheet.replace("'", "''") + "'"
    values = (
        service.spreadsheets().values()
        .get(spreadsheetId=args.spreadsheet_id, range=f"{quoted_name}!A:Z")
        .execute().get("values", [])
    )
    return port_profile_map(values)


def mapped_port_name(port: Any, port_mapping: dict[str, str] | None) -> Any:
    """Return Custom when Port Name has an unambiguous mapping; otherwise preserve the source."""
    text = str(port).strip() if port is not None else ""
    return port_mapping.get(text.casefold(), port) if text and port_mapping else port


def map_remediation_ports(
    values: list[list[Any]], port_mapping: dict[str, str] | None,
    freeze_closed: bool = False, respect_reporter: bool = False,
) -> list[list[Any]]:
    """Map local and discovered A/Z port fields using the PortProfile mapping."""
    if not values or not port_mapping:
        return values
    positions = {header: index for index, header in enumerate(values[0])}
    port_positions = [
        positions[header]
        for header in ("Local Port", "A Discover Port", "Z Port", "Z Discover Port")
        if header in positions
    ]
    discover_port_positions = [
        positions[header]
        for header in ("A Discover Port", "Z Discover Port")
        if header in positions
    ]
    status_position = positions.get("Status")
    reporter_position = positions.get("Reported by")
    source_position = positions.get("Source")
    mapped_values = [values[0].copy()]
    for source_row in values[1:]:
        row = source_row.copy()
        if (
            freeze_closed
            and status_position is not None
            and status_position < len(row)
            and str(row[status_position]).strip().casefold() == "closed"
        ):
            mapped_values.append(row)
            continue
        reporter = (
            str(row[reporter_position]).strip().casefold()
            if reporter_position is not None and reporter_position < len(row) else ""
        )
        source = (
            str(row[source_position]).strip().casefold()
            if source_position is not None and source_position < len(row) else ""
        )
        is_cvt_reported = managed_reporter(reporter) is not None or (not reporter and source == "nvis")
        selected_positions = (
            discover_port_positions
            if respect_reporter and not is_cvt_reported
            else port_positions
        )
        for index in selected_positions:
            if index < len(row):
                row[index] = mapped_port_name(row[index], port_mapping)
        mapped_values.append(row)
    return mapped_values


def normalize_hw_hostname(value: Any) -> str:
    """Normalize a hardware-issue hostname for exact, case-insensitive matching."""
    return str(value or "").strip().rstrip(".").casefold()


def hw_issue_hosts_from_sheet(
    values: list[list[Any]], sheet_name: str,
) -> tuple[set[str], dict[str, tuple[str, ...]]]:
    """Return Host Name values and their optional FaultID values from one source."""
    # Vendor sheets may reserve title or timestamp rows before the actual header.
    header_row_index = next(
        (
            index for index, row in enumerate(values)
            if any(str(cell).strip().casefold() == "host name" for cell in row)
        ),
        None,
    )
    if header_row_index is None:
        raise ValueError(
            f"Configured HW Issue sheet {sheet_name!r} must contain a 'Host Name' column."
        )
    positions = {
        str(header).strip().casefold(): index
        for index, header in enumerate(values[header_row_index])
    }
    host_index = positions["host name"]
    status_index = positions.get("status")
    fault_id_index = next(
        (
            index for index, header in enumerate(values[header_row_index])
            if re.sub(r"[\s_-]+", "", str(header).strip().casefold()) == "faultid"
        ),
        None,
    )
    devices = set()
    fault_ids_by_host: dict[str, list[str]] = defaultdict(list)
    for row in values[header_row_index + 1:]:
        device = normalize_hw_hostname(row[host_index]) if host_index < len(row) else ""
        status = (
            str(row[status_index]).strip().casefold()
            if status_index is not None and status_index < len(row) else ""
        )
        if device and status not in {"closed", "resolved"}:
            devices.add(device)
            fault_id = (
                str(row[fault_id_index]).strip()
                if fault_id_index is not None and fault_id_index < len(row) else ""
            )
            if fault_id and fault_id not in fault_ids_by_host[device]:
                fault_ids_by_host[device].append(fault_id)
    return devices, {
        host: tuple(fault_ids) for host, fault_ids in fault_ids_by_host.items()
    }


def hw_issue_host_names_from_sheet(
    values: list[list[Any]], sheet_name: str,
) -> set[str]:
    """Compatibility helper returning only hostnames from one HW source."""
    return hw_issue_hosts_from_sheet(values, sheet_name)[0]


def validate_whitelist_rules(rules: set[str]) -> None:
    """Reject malformed re: rules before Cabling data processing begins."""
    for rule in rules:
        if rule.casefold().startswith("re:"):
            try:
                re.compile(rule[3:], re.IGNORECASE)
            except re.error as error:
                raise ValueError(f"Invalid Whitelist regex {rule!r}: {error}") from error


def normalize_whitelist_filter_type(value: Any) -> str:
    """Return a canonical Filter Type, retaining blank as legacy Device behavior."""
    normalized = str(value or "").strip().casefold()
    if normalized in {"", WHITELIST_FILTER_DEVICE.casefold()}:
        return WHITELIST_FILTER_DEVICE
    if normalized in {WHITELIST_FILTER_ERROR.casefold(), "error type"}:
        return WHITELIST_FILTER_ERROR
    if normalized in {WHITELIST_FILTER_A_SU.casefold(), "asu", "a su", "a-su"}:
        return WHITELIST_FILTER_A_SU
    if normalized in {WHITELIST_FILTER_Z_SU.casefold(), "zsu", "z su", "z-su"}:
        return WHITELIST_FILTER_Z_SU
    supported = ", ".join(WHITELIST_FILTER_VALUE_HEADERS)
    raise ValueError(
        f"Unsupported Whitelist Filter Type {str(value).strip()!r}; supported: {supported}."
    )


def whitelist_filters_from_sheet(
    values: list[list[Any]], instance_name: str = "",
) -> dict[str, set[str]]:
    """Load instance-scoped rules grouped by their extensible Filter Type."""
    if not values:
        return {}
    header_row_index = next(
        (
            index for index, row in enumerate(values)
            if any(
                str(cell).strip().casefold() in {"filter", "device name"}
                for cell in row
            )
        ),
        None,
    )
    if header_row_index is None:
        return {}
    positions = {
        str(header).strip().casefold(): index
        for index, header in enumerate(normalize_instance_headers(values[header_row_index]))
    }
    filter_type_index = positions.get("filter type")
    instance_index = positions.get(INSTANCE_HEADER.casefold())

    current_instance = instance_name.strip().casefold()
    filters: dict[str, set[str]] = {}
    for row_number, row in enumerate(values[header_row_index + 1:], start=header_row_index + 2):
        instance_rule = (
            str(row[instance_index]).strip()
            if instance_index is not None and instance_index < len(row)
            else ""
        )
        applies = (
            not instance_rule
            or instance_rule == "*"
            or (current_instance and instance_rule.casefold() == current_instance)
        )
        if not applies:
            continue
        raw_filter_type = (
            row[filter_type_index]
            if filter_type_index is not None and filter_type_index < len(row)
            else ""
        )
        try:
            filter_type = normalize_whitelist_filter_type(raw_filter_type)
        except ValueError as error:
            raise ValueError(f"Whitelist row {row_number}: {error}") from error
        value_headers = WHITELIST_FILTER_VALUE_HEADERS[filter_type]
        value_indexes = [
            positions[header.casefold()]
            for header in value_headers
            if header.casefold() in positions
        ]
        if not value_indexes:
            raise ValueError(
                f"Whitelist Filter Type {filter_type!r} requires one of these columns: "
                f"{', '.join(value_headers)}."
            )
        rule = next(
            (
                str(row[index]).strip()
                for index in value_indexes
                if index < len(row) and str(row[index]).strip()
            ),
            "",
        )
        if rule:
            filters.setdefault(filter_type, set()).add(rule)
    return filters


def whitelist_rules_from_sheet(
    values: list[list[Any]], instance_name: str = "",
) -> set[str]:
    """Compatibility helper returning the applicable Device filter rules."""
    return whitelist_filters_from_sheet(values, instance_name).get(
        WHITELIST_FILTER_DEVICE, set()
    )


def ensure_whitelist_instance_header(
    service: Any, spreadsheet_id: str, sheet_name: str, sheet_id: int,
    values: list[list[Any]],
) -> None:
    """Migrate the Whitelist schema and append Instance when needed."""
    header_row_index = next(
        (
            index for index, row in enumerate(values)
            if any(
                str(cell).strip().casefold() in {"filter", "device name"}
                for cell in row
            )
        ),
        None,
    )
    if header_row_index is None:
        return
    headers = values[header_row_index]
    normalized_headers = normalize_instance_headers(headers)
    for index, (old, new) in enumerate(zip(headers, normalized_headers)):
        if old != new:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted_sheet_name(sheet_name)}!{sheet_column_name(index)}{header_row_index + 1}",
                valueInputOption="RAW", body={"values": [[new]]},
            ).execute()
            headers[index] = new

    device_name_index = next(
        (
            index for index, header in enumerate(headers)
            if str(header).strip().casefold() == "device name"
        ),
        None,
    )
    has_filter_header = any(
        str(header).strip().casefold() == "filter" for header in headers
    )
    if device_name_index is not None and not has_filter_header:
        filter_cell = f"{sheet_column_name(device_name_index)}{header_row_index + 1}"
        try:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted_sheet_name(sheet_name)}!{filter_cell}",
                valueInputOption="RAW",
                body={"values": [["Filter"]]},
            ).execute()
        except HttpError as error:
            raise ValueError(
                f"Unable to rename the protected {sheet_name} {filter_cell} header "
                "from 'Device Name' to 'Filter'."
            ) from error
        headers[device_name_index] = "Filter"

    rack_index = next(
        (index for index, header in enumerate(headers) if str(header).strip().casefold() == "rack"),
        None,
    )
    if rack_index is not None:
        try:
            service.spreadsheets().batchUpdate(
                spreadsheetId=spreadsheet_id,
                body={"requests": [{"deleteDimension": {"range": {
                    "sheetId": sheet_id,
                    "dimension": "COLUMNS",
                    "startIndex": rack_index,
                    "endIndex": rack_index + 1,
                }}}]},
            ).execute()
        except HttpError as error:
            raise ValueError(
                f"Unable to remove the protected Rack column from {sheet_name}."
            ) from error
        for row in values:
            if rack_index < len(row):
                row.pop(rack_index)
        headers = values[header_row_index]

    comments_index = next(
        (
            index for index, header in enumerate(headers)
            if str(header).strip().casefold() == "comments"
        ),
        None,
    )
    has_filter_type = any(
        str(header).strip().casefold() == "filter type" for header in headers
    )
    if comments_index is not None and not has_filter_type:
        comments_cell = f"{sheet_column_name(comments_index)}{header_row_index + 1}"
        try:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted_sheet_name(sheet_name)}!{comments_cell}",
                valueInputOption="RAW",
                body={"values": [["Filter Type"]]},
            ).execute()
        except HttpError as error:
            raise ValueError(
                f"Unable to rename the protected {sheet_name} {comments_cell} header "
                "from 'Comments' to 'Filter Type'."
            ) from error
        headers[comments_index] = "Filter Type"

    def ensure_header(header_name: str, preferred_index: int | None = None) -> None:
        if any(str(header).strip().casefold() == header_name.casefold() for header in headers):
            return
        target_column_index = (
            len(headers) if preferred_index is None
            else max(0, min(preferred_index, len(headers)))
        )
        inserted = target_column_index < len(headers)
        if inserted:
            try:
                service.spreadsheets().batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body={"requests": [{"insertDimension": {"range": {
                        "sheetId": sheet_id,
                        "dimension": "COLUMNS",
                        "startIndex": target_column_index,
                        "endIndex": target_column_index + 1,
                    }}}]},
                ).execute()
            except HttpError as error:
                raise ValueError(
                    f"Unable to insert the {header_name!r} column in {sheet_name}."
                ) from error
            for row in values:
                row.insert(target_column_index, "")
        if target_column_index:
            try:
                service.spreadsheets().batchUpdate(
                    spreadsheetId=spreadsheet_id,
                    body={"requests": [{"copyPaste": {
                        "source": {
                            "sheetId": sheet_id,
                            "startRowIndex": header_row_index,
                            "endRowIndex": header_row_index + 1,
                            "startColumnIndex": target_column_index - 1,
                            "endColumnIndex": target_column_index,
                        },
                        "destination": {
                            "sheetId": sheet_id,
                            "startRowIndex": header_row_index,
                            "endRowIndex": header_row_index + 1,
                            "startColumnIndex": target_column_index,
                            "endColumnIndex": target_column_index + 1,
                        },
                        "pasteType": "PASTE_FORMAT",
                        "pasteOrientation": "NORMAL",
                    }}]},
                ).execute()
            except HttpError:
                # Formatting may be protected even when the service account can
                # edit values. A visual-style failure must not block filtering.
                pass
        target_cell = f"{sheet_column_name(target_column_index)}{header_row_index + 1}"
        try:
            service.spreadsheets().values().update(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted_sheet_name(sheet_name)}!{target_cell}",
                valueInputOption="RAW",
                body={"values": [[header_name]]},
            ).execute()
        except HttpError as error:
            raise ValueError(
                f"{sheet_name} is missing the {header_name!r} header, and "
                f"{target_cell} is protected. Add the header manually or allow the "
                "service account to edit that cell."
            ) from error
        if inserted:
            headers[target_column_index] = header_name
        else:
            headers.append(header_name)

    datahall_index = next(
        (
            index for index, header in enumerate(headers)
            if str(header).strip().casefold() in {"datahall", "datahalll"}
        ),
        None,
    )
    ensure_header(
        INSTANCE_HEADER,
        datahall_index + 1 if datahall_index is not None else None,
    )


def load_remediation_device_sets(
    service: Any, args: argparse.Namespace,
) -> tuple[set[str], dict[str, tuple[str, ...]], dict[str, set[str]]]:
    """Load configured HW hosts and devices excluded by the Whitelist."""
    metadata = service.spreadsheets().get(
        spreadsheetId=args.spreadsheet_id,
        fields="sheets.properties(sheetId,title)",
    ).execute()
    available_sheets = {
        sheet["properties"]["title"]: sheet["properties"].get("sheetId")
        for sheet in metadata.get("sheets", [])
    }

    def values_for_sheet(sheet_name: str) -> list[list[Any]]:
        # Whitelist remains optional. An absent sheet means no exclusion rules.
        if sheet_name not in available_sheets:
            return []
        quoted_name = "'" + sheet_name.replace("'", "''") + "'"
        return (
            service.spreadsheets().values()
            .get(spreadsheetId=args.spreadsheet_id, range=f"{quoted_name}!A:Z")
            .execute().get("values", [])
        )

    configured_hw_sheets = getattr(
        args, "hw_issue_sheets", DEFAULT_HW_ISSUE_SHEETS.copy()
    )
    if isinstance(configured_hw_sheets, str):
        configured_hw_sheets = [configured_hw_sheets]
    hw_sheet_names = list(dict.fromkeys(
        str(name).strip() for name in configured_hw_sheets if str(name).strip()
    ))
    missing_hw_sheets = [name for name in hw_sheet_names if name not in available_sheets]
    if missing_hw_sheets:
        raise ValueError(
            "Configured HW Issue sheet(s) not found: " + ", ".join(missing_hw_sheets)
        )

    hw_issue_devices: set[str] = set()
    hw_fault_ids_by_host: dict[str, list[str]] = defaultdict(list)
    if hw_sheet_names:
        ranges = [bounded_sheet_range(name, 26) for name in hw_sheet_names]
        response = (
            service.spreadsheets().values()
            .batchGet(spreadsheetId=args.spreadsheet_id, ranges=ranges)
            .execute()
        )
        value_ranges = response.get("valueRanges", [])
        if len(value_ranges) != len(hw_sheet_names):
            raise ValueError(
                "Google Sheets did not return every configured HW Issue sheet. "
                "Cabling was not changed."
            )
        for sheet_name, value_range in zip(hw_sheet_names, value_ranges):
            sheet_devices, sheet_fault_ids = hw_issue_hosts_from_sheet(
                value_range.get("values", []), sheet_name
            )
            hw_issue_devices.update(sheet_devices)
            for host, fault_ids in sheet_fault_ids.items():
                for fault_id in fault_ids:
                    if fault_id not in hw_fault_ids_by_host[host]:
                        hw_fault_ids_by_host[host].append(fault_id)
    whitelist_values = values_for_sheet(args.whitelist_sheet)
    if args.whitelist_sheet in available_sheets:
        ensure_whitelist_instance_header(
            service, args.spreadsheet_id, args.whitelist_sheet,
            available_sheets[args.whitelist_sheet], whitelist_values,
        )
    whitelist_filters = whitelist_filters_from_sheet(
        whitelist_values,
        getattr(args, "instance_name", ""),
    )
    for rules in whitelist_filters.values():
        validate_whitelist_rules(rules)
    return (
        hw_issue_devices,
        {host: tuple(ids) for host, ids in hw_fault_ids_by_host.items()},
        whitelist_filters,
    )


def remediation_nodes(row: list[Any]) -> tuple[str, str]:
    """Return the A and Z node values represented by a canonical remediation row."""
    return (
        str(row[REMEDIATION_INDEX["Local Device"]]).strip(),
        str(row[REMEDIATION_INDEX["Z Node"]]).strip(),
    )


def has_listed_node(row: list[Any], devices: set[str]) -> bool:
    return any(
        normalize_hw_hostname(node) in devices
        for node in remediation_nodes(row) if node
    )


def hw_fault_ids_for_row(
    row: list[Any], fault_ids_by_host: dict[str, tuple[str, ...]],
) -> tuple[str, ...]:
    """Return ordered, de-duplicated HW FaultIDs associated with either endpoint."""
    result: list[str] = []
    for node in remediation_nodes(row):
        for fault_id in fault_ids_by_host.get(normalize_hw_hostname(node), ()):
            if fault_id not in result:
                result.append(fault_id)
    return tuple(result)


def merge_hw_fault_id_notes(existing_note: Any, fault_ids: tuple[str, ...]) -> str:
    """Replace CableTracker-managed FaultID lines while preserving other Notes text."""
    remaining_lines = [
        line for line in str(existing_note or "").splitlines()
        if not re.match(r"^\s*FaultID\s*:", line, flags=re.IGNORECASE)
    ]
    base_note = "\n".join(remaining_lines).strip()
    fault_note = "\n".join(f"FaultID: {fault_id}" for fault_id in fault_ids)
    return "\n\n".join(part for part in (base_note, fault_note) if part)


def whitelist_rule_matches(node: str, rule: str) -> bool:
    """Match one Whitelist rule using exact, glob, or explicit re: syntax."""
    if rule.casefold().startswith("re:"):
        return re.search(rule[3:], node, re.IGNORECASE) is not None
    if any(character in rule for character in "*?["):
        return fnmatchcase(node.casefold(), rule.casefold())
    return node.casefold() == rule.casefold()


def has_whitelisted_node(row: list[Any], rules: set[str]) -> bool:
    return any(
        whitelist_rule_matches(node, rule)
        for node in remediation_nodes(row)
        if node
        for rule in rules
    )


def has_whitelist_match(row: list[Any], filters: dict[str, set[str]]) -> bool:
    """Dispatch a canonical Cabling row through its configured Whitelist filters."""
    for filter_type, rules in filters.items():
        if filter_type == WHITELIST_FILTER_DEVICE and has_whitelisted_node(row, rules):
            return True
        if filter_type == WHITELIST_FILTER_ERROR:
            error_value = str(row[REMEDIATION_INDEX["Error"]]).strip()
            if error_value and any(
                whitelist_rule_matches(error_value, rule) for rule in rules
            ):
                return True
        if filter_type == WHITELIST_FILTER_A_SU:
            a_su = str(row[REMEDIATION_INDEX["Local SU Number"]]).strip()
            if a_su and any(whitelist_rule_matches(a_su, rule) for rule in rules):
                return True
    return False


def cvt_su_whitelist_keys(
    cvt_values: list[list[Any]], filters: dict[str, set[str]],
    port_mapping: dict[str, str] | None = None,
) -> set[tuple[str, str, str]]:
    """Return Cabling keys whose CVT A-SU or Z-SU matches a scoped filter."""
    if not cvt_values:
        return set()
    headers = cvt_values[0]
    positions = {str(header).strip(): index for index, header in enumerate(headers)}
    filter_headers = {
        WHITELIST_FILTER_A_SU: "A SU Number",
        WHITELIST_FILTER_Z_SU: "Z SU Number",
    }
    active_filters = {
        filter_type: rules
        for filter_type, rules in filters.items()
        if filter_type in filter_headers and rules
    }
    for filter_type in active_filters:
        required_header = filter_headers[filter_type]
        if required_header not in positions:
            raise ValueError(
                f"Whitelist Filter Type {filter_type!r} requires the CVT column "
                f"{required_header!r}."
            )
    if not active_filters:
        return set()

    def value(row: list[Any], header: str) -> str:
        index = positions.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    keys: set[tuple[str, str, str]] = set()
    for row in cvt_values[1:]:
        if not any(
            whitelist_rule_matches(value(row, filter_headers[filter_type]), rule)
            for filter_type, rules in active_filters.items()
            for rule in rules
            if value(row, filter_headers[filter_type])
        ):
            continue
        instance = value(row, INSTANCE_HEADER)
        device = value(row, "A Node")
        port = mapped_port_name(value(row, "A Port"), port_mapping)
        if device and port:
            keys.add((instance, device, str(port).strip()))
    return keys


def signal_stats_note(value_for_header: Any, row: list[Any]) -> str:
    """Render the useful A/Z optical and BER telemetry for a Link Down record."""
    fields = (
        ("RX Power", "RX Power Lanes (dBm)", "dBm"),
        ("TX Power", "TX Power Lanes (dBm)", "dBm"),
        ("Raw BER", "Raw BER", ""),
        ("Effective BER", "Effective BER", ""),
        ("Symbol BER", "Symbol BER", ""),
    )
    endpoints = []
    for side in ("A", "Z"):
        stats: dict[str, str] = {}
        for label, suffix, unit in fields:
            value = str(value_for_header(row, f"{side} {suffix}") or "").strip()
            if value:
                stats[label] = f"{label}: {value}{unit if unit else ''}"
        if stats:
            lines = [f"{side} side:"]
            for label in ("RX Power", "TX Power"):
                if label in stats:
                    lines.append(f"  {stats[label]}")
            ber_line = ", ".join(
                stats[label]
                for label in ("Raw BER", "Effective BER", "Symbol BER")
                if label in stats
            )
            if ber_line:
                lines.append(f"  {ber_line}")
            endpoints.append("\n".join(lines))
    # Missing telemetry is not a new diagnosis and must not overwrite the last
    # useful Notes content with an availability placeholder.
    return "\n".join(endpoints)


def cvt_mismatch_note_updates_by_remediation_key(
    cvt_values: list[list[Any]],
    custom_nic_by_actual_port: dict[str, str] | None = None,
    port_mapping: dict[str, str] | None = None,
) -> dict[tuple[str, str, str], str | None]:
    """Return automatic operational Notes; discovered Z endpoints are separate columns."""
    if not cvt_values:
        return {}
    index_by_header = {header: index for index, header in enumerate(cvt_values[0])}

    def value(row: list[Any], header: str) -> str:
        index = index_by_header.get(header)
        return str(row[index]).strip() if index is not None and index < len(row) else ""

    note_updates: dict[tuple[str, str, str], str | None] = {}
    for row in cvt_values[1:]:
        instance = value(row, INSTANCE_HEADER)
        local_node = value(row, "A Node")
        local_port = mapped_port_name(value(row, "A Port"), port_mapping)
        if not local_node or not local_port:
            continue
        reports = f"{value(row, 'A Report')} {value(row, 'Z Report')}".casefold()
        link_down = any(marker in reports for marker in (
            "media unplugged", "link down", "port down", "linkdown",
        ))
        bad_signal = any(marker in reports for marker in (
            "anomalous", "signal", "temperature", "power", " ber", "crc",
        ))
        note = ""
        if link_down or bad_signal:
            note = signal_stats_note(value, row)
        recommended_action = join_present(
            value(row, "A Recommended Action"), value(row, "Z Recommended Action")
        )
        if recommended_action:
            note = "\n\n".join(part for part in (note, f"Recommended action:\n{recommended_action}") if part)
        # No new diagnostic/action means retain the previous useful Notes.
        note_updates[(instance, local_node, local_port)] = note or None
    return note_updates


def issue_change_note_lines(note: Any) -> list[str]:
    """Return de-duplicated CableTracker-managed Issue Type history lines."""
    lines: list[str] = []
    for raw_line in str(note or "").splitlines():
        line = raw_line.strip()
        if re.fullmatch(
            r"Issue changed:\s*.+\s+->\s+.+\s+"
            r"\(\d{4}-\d{2}-\d{2}(?: \d{2}:\d{2})?\)",
            line,
            flags=re.IGNORECASE,
        ) and line not in lines:
            lines.append(line)
    return lines


def merge_mismatch_note(existing_note: Any, mismatch_note: str | None) -> str:
    """Replace nonempty diagnostics; keep prior Notes when no new content exists."""
    diagnostics = str(mismatch_note or "").strip()
    if not diagnostics:
        return str(existing_note or "")
    history = "\n".join(issue_change_note_lines(existing_note))
    return "\n\n".join(part for part in (diagnostics, history) if part)


def append_issue_change_note(
    existing_note: Any,
    previous_issue: Any,
    current_issue: Any,
    changed_date: str,
) -> str:
    """Append one managed Issue Type transition without duplicating it."""
    previous = str(previous_issue or "").strip()
    current = str(current_issue or "").strip()
    note = str(existing_note or "").strip()
    if not previous or not current or previous.casefold() == current.casefold():
        return note
    change = f"Issue changed: {previous} -> {current} ({changed_date})"
    if change in issue_change_note_lines(note):
        return note
    return "\n\n".join(part for part in (note, change) if part)


def prepare_existing_remediation_rows(
    existing_values: list[list[Any]], port_mapping: dict[str, str] | None,
) -> list[list[Any]]:
    """Canonicalize existing rows and apply current port labels without touching Closed rows."""
    index_by_header = (
        {header: index for index, header in enumerate(existing_values[0])}
        if existing_values else {}
    )
    rows = [
        [
            source_row[index_by_header[header]]
            if header in index_by_header and index_by_header[header] < len(source_row) else ""
            for header in REMEDIATION_HEADERS
        ]
        for source_row in existing_values[1:]
        if any(str(value).strip() for value in source_row)
    ]
    return map_remediation_ports(
        [REMEDIATION_HEADERS] + rows,
        port_mapping,
        freeze_closed=True,
        respect_reporter=True,
    )[1:]


def migrate_legacy_fault_ids(
    rows: list[list[Any]], eligible: Callable[[list[Any]], bool], identifier: Any,
    reported_by: str = "CVT",
) -> None:
    """Normalize active CVT-owned Fault IDs in place."""
    idx = REMEDIATION_INDEX
    for row in rows:
        if not eligible(row):
            continue
        if str(row[idx["Reported by"]]).strip().casefold() != reported_by.casefold():
            continue
        old_id = str(row[idx["Fault ID"]]).strip()
        match = re.fullmatch(r"NV(\d+)", old_id)
        if match:
            number = int(match.group(1))
            if number > MAX_FAULT_ID:
                raise ValueError("Fault ID exceeds the supported five-digit range: NV99999.")
            row[idx["Fault ID"]] = f"NV{number:05d}"
        else:
            row[idx["Fault ID"]] = next(identifier)


def refresh_hardware_fault_notes(
    rows: list[list[Any]],
    eligible: Callable[[list[Any]], bool],
    hw_issue_devices: set[str],
    hw_issue_fault_ids: dict[str, tuple[str, ...]],
    reported_by: str = "CVT",
) -> None:
    """Refresh tool-managed HW FaultID lines for active CVT-owned rows."""
    idx = REMEDIATION_INDEX
    for row in rows:
        if not eligible(row):
            continue
        if str(row[idx["Reported by"]]).strip().casefold() != reported_by.casefold():
            continue
        fault_ids = (
            hw_fault_ids_for_row(row, hw_issue_fault_ids)
            if has_listed_node(row, hw_issue_devices) else ()
        )
        row[idx["Notes"]] = merge_hw_fault_id_notes(row[idx["Notes"]], fault_ids)


def normalize_existing_remediation_metadata(
    rows: list[list[Any]], eligible: Callable[[list[Any]], bool],
    reported_by: str = "CVT",
) -> None:
    """Migrate legacy Source/Reported-by/date metadata in active rows."""
    idx = REMEDIATION_INDEX
    for row in rows:
        if not eligible(row):
            continue
        reporter = str(row[idx["Reported by"]]).strip().casefold()
        if row[idx["Source"]] == "Cable Validation" and reporter in {"", "cvt"}:
            row[idx["Source"]] = "NVIS"
        if row[idx["Source"]] == "NVIS" and not row[idx["Reported by"]]:
            row[idx["Reported by"]] = "CVT"
        if str(row[idx["Reported by"]]).strip().casefold() == reported_by.casefold():
            # Preserve minute precision in current rows while still removing the
            # invalid Unix-epoch date written by older CableTracker versions.
            row[idx["Date opened"]] = valid_open_date(row[idx["Date opened"]])


def refresh_existing_remediation_rows(
    rows: list[list[Any]],
    eligible: Callable[[list[Any]], bool],
    latest_rows_by_key: dict[tuple[str, str, str], list[Any]],
    latest_statuses: dict[tuple[str, str, str], str],
    latest_link_types: dict[tuple[str, str, str], str],
    source_rows: dict[tuple[str, str, str], Any],
    note_updates: dict[tuple[str, str, str], str | None],
    hw_issue_devices: set[str],
    timezone_name: str,
    reported_by: str = "CVT",
) -> None:
    """Refresh active rows from the latest CVT snapshot before matching new faults."""
    idx = REMEDIATION_INDEX
    pass_refresh_fields = (
        "Source", "Link Type", "Error", "Description", "Local SU Number",
        "Local Rack", "Local RU", "Local Device", "Local Port",
        "A Discover Node", "A Discover Port", "Z Rack", "Z RU", "Z Node",
        "Z Port", "Z Discover Node", "Z Discover Port", "CVT", INSTANCE_HEADER,
    )
    limited_refresh_fields = (
        "A Discover Node", "A Discover Port", "Z Discover Node", "Z Discover Port", "CVT",
    )
    for row in rows:
        if not eligible(row):
            continue
        key = remediation_key(row)
        if key is None:
            continue
        latest_status = latest_statuses.get(key, "")
        if str(row[idx["Reported by"]]).strip().casefold() != reported_by.casefold():
            if key in latest_rows_by_key:
                latest_row = latest_rows_by_key[key]
                for field in limited_refresh_fields:
                    row[idx[field]] = latest_row[idx[field]]
            else:
                row[idx["CVT"]] = latest_status
            continue
        if key in source_rows:
            row[idx["Source"]] = source_rows[key]
        if key in latest_link_types:
            row[idx["Link Type"]] = latest_link_types[key]
        if latest_status.casefold() == "pass" and key in latest_rows_by_key:
            latest_row = latest_rows_by_key[key]
            for field in pass_refresh_fields:
                row[idx[field]] = latest_row[idx[field]]
        row[idx["CVT"]] = latest_status
        if has_listed_node(row, hw_issue_devices):
            row[idx["Status"]] = "HW Issue"
        elif str(row[idx["Status"]]).strip().casefold() == "hw issue":
            row[idx["Status"]] = "New"
        if (
            latest_status.casefold() == "pass"
            and str(row[idx["Status"]]).strip().casefold() == "new"
        ):
            row[idx["Status"]] = "Closed"
            row[idx["Date Closed"]] = current_datetime(timezone_name)
        # The closing cycle retains the last diagnosis even if the Pass report
        # still carries telemetry/recommendations. Later Closed rows are frozen.
        if str(row[idx["Status"]]).strip().casefold() != "closed" and key in note_updates:
            row[idx["Notes"]] = merge_mismatch_note(row[idx["Notes"]], note_updates[key])


def merge_active_cabling_case(
    previous: list[Any], current: list[Any], latest_status: Any,
    note_update: str | None, hw_issue_devices: set[str], timezone_name: str,
    reported_by: str = "CVT",
) -> list[Any]:
    """Merge one active Case; never perform I/O or allocate a new Fault ID."""
    idx = REMEDIATION_INDEX
    if str(previous[idx["Reported by"]]).strip().casefold() != reported_by.casefold():
        merged = previous.copy()
        for name in ("A Discover Node", "A Discover Port", "Z Discover Node", "Z Discover Port", "CVT"):
            merged[idx[name]] = current[idx[name]]
        merged[idx["CVT"]] = latest_status
        return merged

    merged = current.copy()
    merged[idx["Fault ID"]] = previous[idx["Fault ID"]]
    for name in (
        "Notes", "AI Recommendation", "NV Comments", "Assigned to",
        "Engineer Assigned", "Action Description", "P-status",
    ):
        merged[idx[name]] = previous[idx[name]]
    merged[idx["Reported by"]] = previous[idx["Reported by"]] or current[idx["Reported by"]]
    merged[idx["Date opened"]] = valid_open_date(previous[idx["Date opened"]]) or current[idx["Date opened"]]
    merged[idx["Status"]] = previous[idx["Status"]] or "New"
    if has_listed_node(merged, hw_issue_devices):
        merged[idx["Status"]] = "HW Issue"
    elif str(merged[idx["Status"]]).strip().casefold() == "hw issue":
        merged[idx["Status"]] = "New"
    if (
        str(merged[idx["CVT"]]).casefold() == "pass"
        and str(merged[idx["Reported by"]]).strip().casefold() == reported_by.casefold()
        and str(merged[idx["Status"]]).strip().casefold() == "new"
    ):
        merged[idx["Status"]] = "Closed"
        merged[idx["Date Closed"]] = current_datetime(timezone_name)
    merged[idx["CVT"]] = latest_status
    if str(merged[idx["Status"]]).strip().casefold() != "closed":
        merged[idx["Notes"]] = merge_mismatch_note(merged[idx["Notes"]], note_update)
        merged[idx["Notes"]] = append_issue_change_note(
            merged[idx["Notes"]], previous[idx["Error"]], current[idx["Error"]],
            current_datetime(timezone_name),
        )
    return merged


def upsert_remediation_values(
    cvt_values: list[list[Any]],
    existing_values: list[list[Any]],
    custom_nic_by_actual_port: dict[str, str] | None = None,
    hw_issue_devices: set[str] | None = None,
    hw_issue_fault_ids: dict[str, tuple[str, ...]] | None = None,
    whitelist_filters: dict[str, set[str]] | None = None,
    port_mapping: dict[str, str] | None = None,
    min_cycles: int = 1,
    include_warnings: bool = False,
    instance_name: str = "",
    identifier: Any = None,
    fault_id_start: int = DEFAULT_FAULT_ID_START,
    timezone_name: str = DEFAULT_TIMEZONE,
    bcm_host_statuses: dict[str, str] | None = None,
    bcm_host_patterns: list[str] | tuple[str, ...] | None = None,
    bcm_gate_stats: Counter[str] | None = None,
    reported_by: str = "CVT",
) -> list[list[Any]]:
    """Upsert Fail records by local device/port and preserve operator-maintained fields."""
    idx = REMEDIATION_INDEX
    hw_issue_devices = hw_issue_devices or set()
    hw_issue_fault_ids = hw_issue_fault_ids or {}
    whitelist_filters = whitelist_filters or {}
    observations = observations_from_import_table(cvt_values)
    current_rows = map_remediation_ports(
        case_values_from_observations(
            observations, min_cycles, include_warnings, timezone_name=timezone_name,
            reported_by=reported_by,
        ),
        port_mapping,
    )[1:]
    latest_rows = map_remediation_ports(
        case_values_from_observations(
            observations, min_cycles, include_warnings, include_all_current=True,
            timezone_name=timezone_name,
            reported_by=reported_by,
        ),
        port_mapping,
    )[1:]
    output_rows = prepare_existing_remediation_rows(existing_values, port_mapping)
    identifier = identifier or next_fault_id_generator(output_rows, fault_id_start)
    su_whitelist_keys = cvt_su_whitelist_keys(
        cvt_values, whitelist_filters, port_mapping
    )
    bcm_new_case_gate = bcm_new_case_gate_by_link(
        cvt_values, bcm_host_statuses, port_mapping, bcm_host_patterns
    )

    def belongs_to_current_instance(row: list[Any]) -> bool:
        return not instance_name or str(row[idx[INSTANCE_HEADER]]).strip() == instance_name

    def is_whitelisted(row: list[Any]) -> bool:
        key = remediation_key(row)
        return (
            has_whitelist_match(row, whitelist_filters)
            or (key is not None and key in su_whitelist_keys)
        )

    def eligible_existing_row(
        row: list[Any], *, include_closed: bool = False,
    ) -> bool:
        """Apply the shared ownership, lifecycle, and whitelist update gate."""
        if not belongs_to_current_instance(row) or is_whitelisted(row):
            return False
        return include_closed or str(row[idx["Status"]]).strip().casefold() != "closed"

    normalize_existing_remediation_metadata(output_rows, eligible_existing_row, reported_by)
    migrate_legacy_fault_ids(output_rows, eligible_existing_row, identifier, reported_by)
    # Refresh HW markers before a Pass can close/freeze the row. In particular,
    # resolved HW links lose only their FaultID lines, not diagnostic history.
    refresh_hardware_fault_notes(
        output_rows, eligible_existing_row, hw_issue_devices, hw_issue_fault_ids, reported_by,
    )

    # CVT always reflects the latest CVT status for this local endpoint.
    latest_statuses = cvt_status_by_remediation_key(cvt_values, port_mapping)
    latest_link_types = cvt_link_type_by_remediation_key(cvt_values, port_mapping)
    source_rows = cvt_source_row_by_remediation_key(cvt_values, port_mapping)
    mismatch_note_updates = cvt_mismatch_note_updates_by_remediation_key(
        cvt_values, custom_nic_by_actual_port, port_mapping
    )
    latest_rows_by_key = {
        key: row for row in latest_rows
        if (key := remediation_key(row)) is not None
    }
    refresh_existing_remediation_rows(
        output_rows,
        eligible_existing_row,
        latest_rows_by_key,
        latest_statuses,
        latest_link_types,
        source_rows,
        mismatch_note_updates,
        hw_issue_devices,
        timezone_name,
        reported_by,
    )

    # One active Case represents one physical link lifecycle. Issue Type changes
    # update that Case in place; only a fully Closed history causes a new Case.
    active_indices_by_key: dict[tuple[str, str, str, str, str], list[int]] = defaultdict(list)
    for index, row in enumerate(output_rows):
        if not eligible_existing_row(row):
            continue
        key = remediation_match_key(row)
        if key:
            active_indices_by_key[key].append(index)

    for current_row in current_rows:
        match_key = remediation_match_key(current_row)
        local_key = remediation_key(current_row)
        if match_key is None or local_key is None:
            continue
        if is_whitelisted(current_row):
            continue
        merged = current_row.copy()
        active_indices = active_indices_by_key.get(match_key, [])
        if not active_indices:
            bcm_decision = bcm_new_case_gate.get(match_key)
            if bcm_decision:
                if bcm_gate_stats is not None:
                    bcm_gate_stats[bcm_decision] += 1
                if bcm_decision not in {"allowed", "bypassed"}:
                    continue
            # No active Case represents this full A/Z link. Closed history is
            # retained and a new fault lifecycle receives a new NV ID.
            merged[idx["Fault ID"]] = next(identifier)
            merged[idx["CVT"]] = latest_statuses.get(local_key, "")
            if has_listed_node(merged, hw_issue_devices):
                merged[idx["Status"]] = "HW Issue"
            if local_key in mismatch_note_updates:
                merged[idx["Notes"]] = merge_mismatch_note(
                    merged[idx["Notes"]], mismatch_note_updates[local_key]
                )
            output_rows.append(merged)
            active_indices_by_key[match_key] = [len(output_rows) - 1]
            continue

        for active_index in active_indices:
            output_rows[active_index] = merge_active_cabling_case(
                output_rows[active_index], current_row,
                latest_statuses.get(local_key, ""), mismatch_note_updates.get(local_key),
                hw_issue_devices, timezone_name,
                reported_by,
            )

    # Apply tool-managed HW FaultID lines after ordinary CVT Notes are final.
    refresh_hardware_fault_notes(
        output_rows, eligible_existing_row, hw_issue_devices, hw_issue_fault_ids, reported_by,
    )

    # Existing records are retained in place; new records are appended.
    return [REMEDIATION_HEADERS] + output_rows


def ensure_sheet(service: Any, spreadsheet_id: str, sheet_name: str) -> None:
    """Create a worksheet once, tolerating another writer winning the race."""
    metadata = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id, fields="sheets.properties.title"
    ).execute()
    requested_title = str(sheet_name).casefold()
    existing_titles = {
        str(sheet["properties"]["title"]).casefold()
        for sheet in metadata.get("sheets", [])
    }
    if requested_title in existing_titles:
        return
    try:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": [{"addSheet": {"properties": {"title": sheet_name}}}]},
        ).execute()
    except HttpError:
        # Two CableTracker processes can both observe a missing optional sheet.
        # Only suppress the loser-of-the-race error after the API confirms that
        # the exact requested title now exists; every unrelated API error remains
        # visible to the caller.
        refreshed = service.spreadsheets().get(
            spreadsheetId=spreadsheet_id, fields="sheets.properties.title"
        ).execute()
        refreshed_titles = {
            str(sheet["properties"]["title"]).casefold()
            for sheet in refreshed.get("sheets", [])
        }
        if requested_title not in refreshed_titles:
            raise
        LOGGER.info("Worksheet already created by another writer sheet=%s", sheet_name)


def has_nonempty_header(values: list[list[Any]]) -> bool:
    return bool(values and values[0] and any(str(value).strip() for value in values[0]))


def is_timestamp_row(row: list[Any], prefix: str) -> bool:
    return bool(row and str(row[0]).strip().startswith(prefix))


def strip_timestamp_row(values: list[list[Any]]) -> list[list[Any]]:
    if values and (is_timestamp_row(values[0], IMPORT_TIMESTAMP_PREFIX) or is_timestamp_row(values[0], REMEDIATION_TIMESTAMP_PREFIX)):
        values = values[1:]
    return normalize_instance_table(values)


def insert_sheet_row(service: Any, spreadsheet_id: str, sheet_name: str, index: int) -> None:
    sheets = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id, fields="sheets.properties(sheetId,title)"
    ).execute().get("sheets", [])
    sheet_id = next(sheet["properties"]["sheetId"] for sheet in sheets if sheet["properties"]["title"] == sheet_name)
    service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": [{"insertDimension": {
        "range": {"sheetId": sheet_id, "dimension": "ROWS", "startIndex": index, "endIndex": index + 1}
    }}]}).execute()


def insert_sheet_columns(service: Any, spreadsheet_id: str, sheet_name: str, index: int, count: int = 1) -> None:
    """Insert physical columns so a header migration never shifts existing row values."""
    sheets = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id, fields="sheets.properties(sheetId,title)"
    ).execute().get("sheets", [])
    sheet_id = next(sheet["properties"]["sheetId"] for sheet in sheets if sheet["properties"]["title"] == sheet_name)
    service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": [{"insertDimension": {
        "range": {"sheetId": sheet_id, "dimension": "COLUMNS", "startIndex": index, "endIndex": index + count},
        "inheritFromBefore": index > 0,
    }}]}).execute()


def delete_sheet_columns(service: Any, spreadsheet_id: str, sheet_name: str, index: int, count: int = 1) -> None:
    """Delete physical columns during an explicit schema-removal migration."""
    sheets = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id, fields="sheets.properties(sheetId,title)"
    ).execute().get("sheets", [])
    sheet_id = next(sheet["properties"]["sheetId"] for sheet in sheets if sheet["properties"]["title"] == sheet_name)
    service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={"requests": [{"deleteDimension": {
        "range": {"sheetId": sheet_id, "dimension": "COLUMNS", "startIndex": index, "endIndex": index + count}
    }}]}).execute()


def ensure_remediation_discover_columns(service: Any, args: argparse.Namespace) -> None:
    """Insert newly introduced Cabling columns without corrupting existing row data."""
    current_values = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id,
        range=f"{quoted_sheet_name(args.remediation_sheet)}!2:2",
    ).execute().get("values", [])
    if not current_values or not has_nonempty_header([current_values[0]]):
        return
    current_headers = normalize_instance_headers([str(header) for header in current_values[0]])
    _canonical_headers, target_headers = selected_remediation_headers(args)
    for removed_header in ("Protocol", "Ticket#"):
        if removed_header in current_headers and removed_header not in target_headers:
            remove_index = current_headers.index(removed_header)
            delete_sheet_columns(
                service, args.spreadsheet_id, args.remediation_sheet, remove_index
            )
            current_headers.pop(remove_index)
    legacy_headers = {
        "A Discover Node": ("A Discover Device", "A Discover Node"),
        "A Discover Port": ("A Discover Port", "A-D Port"),
        "Z Discover Node": ("Z Discover Node",),
        "Z Discover Port": ("Z Discover Port", "Z-D Port"),
        "Date Closed": ("Date Closed",),
    }
    for canonical_header in (
        "Link Type", "A Discover Node", "A Discover Port",
        "Z Discover Node", "Z Discover Port", "Date Closed", INSTANCE_HEADER,
    ):
        target_header = args.remediation_header_mapping[canonical_header]
        if target_header not in target_headers:
            continue
        if target_header in current_headers:
            continue
        legacy_header = next(
            (
                header for header in legacy_headers.get(canonical_header, ())
                if header in current_headers
            ),
            None,
        )
        if legacy_header:
            # The existing physical column already contains the mapped data.
            # Rename its header later; never insert a duplicate column for an alias.
            current_headers[current_headers.index(legacy_header)] = target_header
            continue
        insert_index = target_headers.index(target_header)
        insert_sheet_columns(service, args.spreadsheet_id, args.remediation_sheet, insert_index)
        current_headers.insert(insert_index, target_header)


def ensure_cvt_node_type_columns(
    service: Any, args: argparse.Namespace, target_headers: list[str],
) -> None:
    """Insert A/Z Node Type columns without shifting existing CVT data under new headers."""
    current_values = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id, range=f"{quoted_sheet_name(args.cvt_sheet)}!2:2"
    ).execute().get("values", [])
    if not current_values or not has_nonempty_header([current_values[0]]):
        return
    current_headers = [str(header) for header in current_values[0]]
    for header in ("A Node Type", "Z Node Type"):
        if header not in target_headers or header in current_headers:
            continue
        insert_index = target_headers.index(header)
        insert_sheet_columns(service, args.spreadsheet_id, args.cvt_sheet, insert_index)
        current_headers.insert(insert_index, header)


def prepare_timestamp_row(
    service: Any, spreadsheet_id: str, sheet_name: str, prefix: str,
    preserve_first_row: bool = True, timezone_name: str = DEFAULT_TIMEZONE,
) -> bool:
    """Write metadata in row 1 and report whether row 2 already has a header."""
    preview = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range=f"{quoted_sheet_name(sheet_name)}!A1:W2"
    ).execute().get("values", [])
    if preserve_first_row and preview and preview[0] and not is_timestamp_row(preview[0], prefix):
        insert_sheet_row(service, spreadsheet_id, sheet_name, 0)
        preview = service.spreadsheets().values().get(
            spreadsheetId=spreadsheet_id, range=f"{quoted_sheet_name(sheet_name)}!A1:W2"
        ).execute().get("values", [])
    service.spreadsheets().values().update(
        spreadsheetId=spreadsheet_id, range=f"{quoted_sheet_name(sheet_name)}!A1", valueInputOption="RAW",
        body={"values": [[f"{prefix} {operational_now(timezone_name).strftime('%Y-%m-%d %H:%M:%S')}"]]}
    ).execute()
    return len(preview) > 1 and has_nonempty_header([preview[1]])


def ensure_table_headers(service: Any, spreadsheet_id: str, sheet_name: str, headers: list[str]) -> None:
    """Write row-2 headers and clear stale trailing header cells from older schemas."""
    current = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range=f"{quoted_sheet_name(sheet_name)}!2:2"
    ).execute().get("values", [])
    current_headers = current[0] if current else []
    normalize_instance_headers(current_headers)  # Reject ambiguous ownership before writing.
    if current_headers != headers:
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id, range=f"{quoted_sheet_name(sheet_name)}!A2", valueInputOption="RAW",
            body={"values": [headers]},
        ).execute()
        if len(current_headers) > len(headers):
            first_stale = sheet_column_name(len(headers))
            last_stale = sheet_column_name(len(current_headers) - 1)
            service.spreadsheets().values().clear(
                spreadsheetId=spreadsheet_id,
                range=f"{quoted_sheet_name(sheet_name)}!{first_stale}2:{last_stale}2",
                body={},
            ).execute()


def build_sheets_service(credentials: Any, proxy_url: str | None, timeout: int) -> Any:
    if not proxy_url:
        return build(
            "sheets", "v4",
            http=RetryingAuthorizedHttp(
                credentials,
                http=httplib2.Http(timeout=timeout),
                get_retries=GOOGLE_GET_RETRIES,
            ),
            cache_discovery=False,
        )
    proxy = urlparse(proxy_url)
    if proxy.scheme != "http" or not proxy.hostname:
        raise ValueError("--google-proxy must be an HTTP URL, e.g. http://127.0.0.1:7890.")
    proxy_info = httplib2.ProxyInfo(
        proxy_type=httplib2.socks.PROXY_TYPE_HTTP,
        proxy_host=proxy.hostname,
        proxy_port=proxy.port or 80,
        proxy_user=unquote(proxy.username) if proxy.username else None,
        proxy_pass=unquote(proxy.password) if proxy.password else None,
    )
    http = RetryingAuthorizedHttp(
        credentials,
        http=httplib2.Http(proxy_info=proxy_info, timeout=timeout),
        get_retries=GOOGLE_GET_RETRIES,
    )
    return build("sheets", "v4", http=http, cache_discovery=False)


def merge_instance_status_rows(
    current_values: list[list[Any]],
    existing_rows: list[list[Any]],
    instance_name: str | None,
    headers: list[str],
    identity_header: str,
) -> list[list[Any]]:
    """Replace one instance partition while retaining other instances' status rows."""
    current_rows = current_values[1:]
    if not instance_name:
        return current_rows
    instance_index = headers.index(INSTANCE_HEADER)
    normalized_instance = instance_name.strip().casefold()
    retained_rows = []
    for row in existing_rows:
        if not any(str(value).strip() for value in row):
            continue
        row_instance = (
            str(row[instance_index]).strip() if instance_index < len(row) else ""
        )
        # Rows from the old single-instance schema have no ownership marker. Drop
        # them during the first multi-instance refresh instead of duplicating data.
        if row_instance and row_instance.casefold() != normalized_instance:
            retained_rows.append(row)
    merged = retained_rows + current_rows
    identity_index = headers.index(identity_header)
    merged.sort(key=lambda row: (
        str(row[instance_index]).casefold() if instance_index < len(row) else "",
        str(row[identity_index]).casefold() if identity_index < len(row) else "",
    ))
    return merged


def merge_agent_status_rows(
    current_values: list[list[Any]], existing_rows: list[list[Any]], instance_name: str | None,
) -> list[list[Any]]:
    """Replace one instance partition in the shared Agent status table."""
    return merge_instance_status_rows(
        current_values, existing_rows, instance_name, AGENT_STATUS_HEADERS, "Hostname"
    )


def merge_bcm_status_rows(
    current_values: list[list[Any]], existing_rows: list[list[Any]], instance_name: str | None,
) -> list[list[Any]]:
    """Replace one instance partition in the shared BCM status table."""
    return merge_instance_status_rows(
        current_values, existing_rows, instance_name, BCM_STATUS_HEADERS, "Hostname"
    )


def refresh_agent_status(service: Any, args: argparse.Namespace) -> dict[str, Any]:
    """Refresh one instance in a shared Agent sheet without replacing other instances."""
    # Fetch first: a failed/expired login must not update the sheet timestamp and imply success.
    values = load_agent_status(args)
    ensure_sheet(service, args.spreadsheet_id, args.agent_sheet)
    prepare_timestamp_row(
        service, args.spreadsheet_id, args.agent_sheet, REMEDIATION_TIMESTAMP_PREFIX,
        timezone_name=args.timezone_name,
    )
    ensure_table_headers(service, args.spreadsheet_id, args.agent_sheet, AGENT_STATUS_HEADERS)
    data_range = bounded_sheet_range(args.agent_sheet, len(AGENT_STATUS_HEADERS), 3)
    existing_rows = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id, range=data_range,
    ).execute().get("values", [])
    rows = merge_agent_status_rows(
        values, existing_rows, getattr(args, "instance_name", None)
    )
    service.spreadsheets().values().clear(
        spreadsheetId=args.spreadsheet_id, range=data_range, body={}
    ).execute()
    if rows:
        result = service.spreadsheets().values().update(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted_sheet_name(args.agent_sheet)}!A3",
            valueInputOption=args.value_input_option, body={"values": rows},
        ).execute()
    else:
        result = {"updatedCells": 0, "updatedRange": f"{args.agent_sheet}!A3"}
    prepare_timestamp_row(
        service, args.spreadsheet_id, args.agent_sheet, REMEDIATION_TIMESTAMP_PREFIX,
        timezone_name=args.timezone_name,
    )
    return result


def refresh_bcm_status(
    service: Any,
    args: argparse.Namespace,
    values: list[list[Any]] | None = None,
) -> dict[str, Any]:
    """Refresh one instance's BCM REST v1 health rows in a shared Sheet."""
    # Fetch before touching Sheets so an authentication or BCM outage cannot
    # leave a misleading success timestamp.
    values = values if values is not None else load_bcm_status(args)
    ensure_sheet(service, args.spreadsheet_id, args.bcm_sheet)
    prepare_timestamp_row(
        service, args.spreadsheet_id, args.bcm_sheet, REMEDIATION_TIMESTAMP_PREFIX,
        timezone_name=args.timezone_name,
    )
    ensure_table_headers(service, args.spreadsheet_id, args.bcm_sheet, BCM_STATUS_HEADERS)
    data_range = bounded_sheet_range(args.bcm_sheet, len(BCM_STATUS_HEADERS), 3)
    existing_rows = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id, range=data_range,
    ).execute().get("values", [])
    rows = merge_bcm_status_rows(
        values, existing_rows, getattr(args, "instance_name", None)
    )
    service.spreadsheets().values().clear(
        spreadsheetId=args.spreadsheet_id, range=data_range, body={}
    ).execute()
    if rows:
        result = service.spreadsheets().values().update(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted_sheet_name(args.bcm_sheet)}!A3",
            valueInputOption=args.value_input_option,
            body={"values": rows},
        ).execute()
    else:
        result = {"updatedCells": 0, "updatedRange": f"{args.bcm_sheet}!A3"}
    prepare_timestamp_row(
        service, args.spreadsheet_id, args.bcm_sheet, REMEDIATION_TIMESTAMP_PREFIX,
        timezone_name=args.timezone_name,
    )
    return result


def ai_link_context(row: list[Any], positions: dict[str, int]) -> dict[str, str]:
    """Return the physical endpoint fields needed for cabling correlation."""
    context_headers = (
        "Fault ID", "Local SU Number", "Local Device", "Local Port", "Local Rack", "Local RU",
        "A Discover Node", "A Discover Port",
        "Z Node", "Z Port", "Z Rack", "Z RU", "Z Discover Node", "Z Discover Port", "CVT",
    )
    context = {
        header: str(row[positions[header]]).strip() if positions[header] < len(row) else ""
        for header in context_headers
    }
    if INSTANCE_HEADER in positions:
        context[INSTANCE_HEADER] = (
            str(row[positions[INSTANCE_HEADER]]).strip()
            if positions[INSTANCE_HEADER] < len(row) else ""
        )
    return context


def ai_swap_pairs_for_links(
    client: OpenAI,
    rows: list[list[Any]],
    positions: dict[str, int],
    args: argparse.Namespace,
) -> dict[str, str]:
    """Batch-upload the inventory and return compact reciprocal-link correlations."""
    links = [ai_link_context(row, positions) for row in rows]
    response = client.chat.completions.create(
        model=args.ai_model,
        temperature=0.2,
        max_tokens=args.ai_max_output_tokens,
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a data-center cabling technician. The input is the complete current "
                    "Mis-wiring inventory. Correlate records to find reciprocal mispatches and cable "
                    "swaps. Return ONLY a compact JSON object mapping each Fault ID to its reciprocal "
                    "partner Fault ID, or an empty string if no confident reciprocal partner exists. "
                    "Example: {\"NV001\":\"NV002\",\"NV002\":\"NV001\",\"NV003\":\"\"}. "
                    "Treat all Local Device/Local Port (A ends) as correct; identify Z-side swaps only."
                ),
            },
            {"role": "user", "content": json.dumps({"mis_wiring_links": links}, ensure_ascii=False)},
        ],
    )
    content = str(response.choices[0].message.content or "").strip()
    # Models sometimes add a short preface or Markdown fence despite the JSON-only request.
    # Retain just the outer JSON object instead of rejecting an otherwise valid mapping.
    object_start, object_end = content.find("{"), content.rfind("}")
    if object_start >= 0 and object_end > object_start:
        content = content[object_start:object_end + 1]
    try:
        result = json.loads(content)
    except json.JSONDecodeError as error:
        raise ValueError("AI API did not return the required JSON object.") from error
    if not isinstance(result, dict):
        raise ValueError("AI API did not return a Fault ID to recommendation mapping.")
    return {
        str(fault_id): str(partner).strip()
        for fault_id, partner in result.items()
        if isinstance(partner, str) and partner.strip()
    }


def ai_recommendation_for_link(
    client: OpenAI,
    row: list[Any],
    partner: list[Any] | None,
    positions: dict[str, int],
    args: argparse.Namespace,
) -> str:
    """Generate a fresh, focused repair instruction after inventory correlation."""
    payload: dict[str, Any] = {"link": ai_link_context(row, positions)}
    if partner is not None:
        payload["reciprocal_link"] = ai_link_context(partner, positions)
    response = client.chat.completions.create(
        model=args.ai_model,
        temperature=0.2,
        max_tokens=min(args.ai_max_output_tokens, 256),
        messages=[
            {
                "role": "system",
                "content": (
                    "You are a data-center cabling technician. Give exactly one concise repair "
                    "sentence, maximum 45 words. A/Local endpoints are correct and must not move. "
                    "Only correct Z-side terminations. If reciprocal_link is present, describe the "
                    "Z-side cable swap using both links' Local Device and Local Port labels plus the "
                    "Z ports. Otherwise, state the current discovered Z port and expected Z port for "
                    "the cable from the named A Device/A Port. Do not use only Fault IDs and do not "
                    "claim a change was performed."
                ),
            },
            {"role": "user", "content": json.dumps(payload, ensure_ascii=False)},
        ],
    )
    recommendation = str(response.choices[0].message.content or "").strip()
    if not recommendation:
        raise ValueError("AI API returned an empty recommendation.")
    return recommendation


def add_ai_recommendations(values: list[list[Any]], args: argparse.Namespace) -> None:
    """Fill only empty open-record recommendations unless an explicit refresh is requested."""
    if not args.ai_recommendations or len(values) < 2:
        return
    if args.ai_max_records < 0:
        raise ValueError("--ai-max-records must be zero or greater.")
    if args.ai_max_output_tokens < 1:
        raise ValueError("--ai-max-output-tokens must be at least 1.")
    api_key = os.getenv(args.ai_api_key_env)
    if not api_key:
        raise ValueError(f"Set {args.ai_api_key_env} before using --ai-recommendations.")

    positions = {header: index for index, header in enumerate(values[0])}
    required = {"AI Recommendation", "Status", "Error"}
    if not required.issubset(positions):
        raise ValueError("Remediation must include AI Recommendation, Status, and Error columns.")
    ai_index = positions["AI Recommendation"]
    status_index = positions["Status"]
    error_index = positions["Error"]
    instance_index = positions.get(INSTANCE_HEADER)
    instance_name = getattr(args, "instance_name", None)
    allowed_error_types = {
        value.strip().casefold() for value in args.ai_error_types.split(",") if value.strip()
    }
    if not allowed_error_types:
        raise ValueError("--ai-error-types must contain at least one error type.")
    http_client = httpx.Client(timeout=args.timeout, proxy=args.ai_proxy, trust_env=False)
    client = OpenAI(base_url=args.ai_base_url, api_key=api_key, http_client=http_client)
    eligible_rows: list[list[Any]] = []
    try:
        for row in values[1:]:
            if instance_name and (
                instance_index is None
                or instance_index >= len(row)
                or str(row[instance_index]).strip() != instance_name
            ):
                continue
            status = str(row[status_index]).strip().casefold() if status_index < len(row) else ""
            existing = str(row[ai_index]).strip() if ai_index < len(row) else ""
            error_type = str(row[error_index]).strip().casefold() if error_index < len(row) else ""
            error_matches = "*" in allowed_error_types or any(
                allowed_type in error_type for allowed_type in allowed_error_types
            )
            if (
                status == "closed"
                or not error_matches
                or (existing and not args.refresh_ai_recommendations)
            ):
                continue
            if args.ai_max_records and len(eligible_rows) >= args.ai_max_records:
                break
            while len(row) <= ai_index:
                row.append("")
            eligible_rows.append(row)
        if not eligible_rows:
            return
        try:
            partner_by_fault_id = ai_swap_pairs_for_links(client, eligible_rows, positions, args)
        except Exception as error:
            if args.ai_fail_fast:
                raise ValueError(f"AI recommendation request failed: {error}") from error
            LOGGER.warning("AI link-correlation batch skipped error=%s", error)
            return
        rows_by_fault_id = {str(row[0]).strip(): row for row in eligible_rows if str(row[0]).strip()}
        for row in eligible_rows:
            fault_id = str(row[0]).strip()
            partner = rows_by_fault_id.get(partner_by_fault_id.get(fault_id, ""))
            try:
                row[ai_index] = ai_recommendation_for_link(client, row, partner, positions, args)
            except Exception as error:
                if args.ai_fail_fast:
                    raise ValueError(f"AI recommendation request failed for {fault_id}: {error}") from error
                LOGGER.warning(
                    "AI recommendation skipped fault_id=%s error=%s",
                    fault_id or "<new>", error,
                )
    finally:
        client.close()


def sheet_column_name(index: int) -> str:
    """Convert a zero-based column index to an A1 column name."""
    name = ""
    index += 1
    while index:
        index, remainder = divmod(index - 1, 26)
        name = chr(ord("A") + remainder) + name
    return name


def bounded_sheet_range(
    sheet_name: str, column_count: int, start_row: int | None = None,
) -> str:
    """Return an A1 range capped at the table's actual maximum column."""
    if column_count < 1:
        raise ValueError("A bounded Sheet range requires at least one column.")
    start = f"A{start_row}" if start_row is not None else "A"
    return (
        f"{quoted_sheet_name(sheet_name)}!"
        f"{start}:{sheet_column_name(column_count - 1)}"
    )


def cvt_table_range(args: argparse.Namespace, start_row: int | None = None) -> str:
    """Return the configured CVT table range without requesting unused ZZ columns."""
    headers = parse_columns(args.cvt_columns, cvt_headers(args), "--columns")
    return bounded_sheet_range(args.cvt_sheet, len(headers), start_row)


def remediation_table_range(
    args: argparse.Namespace, sheet_name: str | None = None,
    start_row: int | None = None,
) -> str:
    """Return the configured Cabling range at its selected schema width."""
    headers = selected_remediation_headers(args)[1]
    return bounded_sheet_range(
        sheet_name or args.remediation_sheet, len(headers), start_row
    )


def list_ai_models(args: argparse.Namespace) -> list[str]:
    """Return model IDs exposed by the configured OpenAI-compatible endpoint."""
    api_key = os.getenv(args.ai_api_key_env)
    if not api_key:
        raise ValueError(f"Set {args.ai_api_key_env} before using --list-ai-models.")
    http_client = httpx.Client(timeout=args.timeout, proxy=args.ai_proxy, trust_env=False)
    client = OpenAI(base_url=args.ai_base_url, api_key=api_key, http_client=http_client)
    try:
        return sorted(model.id for model in client.models.list().data)
    finally:
        client.close()


def refresh_ai_recommendations_only(service: Any, args: argparse.Namespace) -> dict[str, Any] | None:
    """Fill just missing AI Recommendation cells, preserving every other sheet value."""
    raw_values = (
        service.spreadsheets()
        .values()
        .get(
            spreadsheetId=args.spreadsheet_id,
            range=remediation_table_range(args),
        )
        .execute()
        .get("values", [])
    )
    values = strip_timestamp_row(raw_values)
    if len(values) < 2 or not has_nonempty_header(values):
        return None
    target_header = args.remediation_header_mapping["AI Recommendation"]
    try:
        target_column_index = [str(header) for header in values[0]].index(target_header)
    except ValueError as error:
        raise ValueError(f"Remediation is missing the {target_header!r} column.") from error

    canonical_values = canonicalize_remediation_values(values, args.remediation_header_mapping)
    canonical_ai_index = canonical_values[0].index("AI Recommendation")
    before = [str(row[canonical_ai_index]).strip() if canonical_ai_index < len(row) else ""
              for row in canonical_values[1:]]
    add_ai_recommendations(canonical_values, args)
    updates = []
    column_name = sheet_column_name(target_column_index)
    for data_index, row in enumerate(canonical_values[1:]):
        recommendation = str(row[canonical_ai_index]).strip() if canonical_ai_index < len(row) else ""
        if recommendation != before[data_index]:
            # Row 1 is the import timestamp and row 2 is the header.
            updates.append({
                "range": (
                    f"{quoted_sheet_name(args.remediation_sheet)}!"
                    f"{column_name}{data_index + 3}"
                ),
                "values": [[recommendation]],
            })
    if not updates:
        return None
    response = (
        service.spreadsheets()
        .values()
        .batchUpdate(
            spreadsheetId=args.spreadsheet_id,
            body={"valueInputOption": args.value_input_option, "data": updates},
        )
        .execute()
    )
    # Record count is a CableTracker quota concept; totalUpdatedCells is a
    # Sheets transport metric and may diverge if the write shape changes.
    response["updatedRecords"] = len(updates)
    return response


def refresh_ai_for_targets(
    service: Any, args: argparse.Namespace, targets: list[tuple[str | None, str]],
) -> list[tuple[str, dict[str, Any] | None]]:
    """Run the AI phase across Cabling sheets with one shared per-run record limit."""
    results: list[tuple[str, dict[str, Any] | None]] = []
    remaining = args.ai_max_records
    for _family, sheet_name in targets:
        if args.ai_max_records > 0 and remaining <= 0:
            results.append((sheet_name, None))
            continue
        scoped = cabling_args(args, sheet_name)
        if args.ai_max_records > 0:
            scoped.ai_max_records = remaining
        result = refresh_ai_recommendations_only(service, scoped)
        results.append((sheet_name, result))
        if args.ai_max_records > 0 and result:
            remaining -= int(result.get("updatedRecords", 0))
    return results


def shared_fault_id_generator(
    service: Any, args: argparse.Namespace, targets: list[tuple[str | None, str]],
):
    """Reserve IDs from known Cabling sheets independently of write targets.

    This is a read-before-allocate sequence, not a distributed writer lock.
    Only headers and ID columns are fetched; no inactive sheet is created or changed.
    """
    if not targets:
        return next_fault_id_generator([], args.fault_id_start)
    names = {"IB Cabling", "ETH Cabling", "Cabling", "Remediation"}
    names.update(name for _family, name in targets)
    names.update(getattr(args, "_fault_id_scope_sheets", ()))
    for attribute in ("ib_cabling_sheet", "eth_cabling_sheet", "remediation_sheet"):
        name = getattr(args, attribute, None)
        if name:
            names.add(name)
    metadata = service.spreadsheets().get(
        spreadsheetId=args.spreadsheet_id,
        fields="sheets.properties(title,gridProperties(rowCount,columnCount))",
    ).execute()
    wanted = {name.casefold() for name in names}
    sheets = [sheet["properties"] for sheet in metadata.get("sheets", [])
              if sheet["properties"]["title"].casefold() in wanted]
    available = {sheet["title"].casefold() for sheet in sheets}
    if any(name.casefold() not in available for _family, name in targets):
        raise ValueError("Fault ID allocation: a Cabling update target is missing; refusing to allocate IDs.")
    header_ranges = [
        f"{quoted_sheet_name(sheet['title'])}!A1:"
        f"{sheet_column_name(sheet['gridProperties']['columnCount'] - 1)}"
        f"{min(2, sheet['gridProperties']['rowCount'])}"
        for sheet in sheets
    ]
    headers = service.spreadsheets().values().batchGet(
        spreadsheetId=args.spreadsheet_id, ranges=header_ranges,
    ).execute().get("valueRanges", [])
    if len(headers) != len(sheets):
        raise ValueError("Fault ID allocation: incomplete Cabling header response.")
    aliases = {"fault id", "nv id", args.remediation_header_mapping["Fault ID"].strip().casefold()}
    id_ranges = []
    for sheet, result in zip(sheets, headers):
        rows = result.get("values", [])
        matches = [(r, c) for r, row in enumerate(rows) for c, value in enumerate(row)
                   if str(value).strip().casefold() in aliases]
        if len(matches) != 1:
            # Blank header rows do not prove there are no historical IDs below.
            # Verify an apparently empty tab before excluding it from reservation.
            if not any(str(value).strip() for row in rows for value in row):
                contents = service.spreadsheets().values().get(
                    spreadsheetId=args.spreadsheet_id,
                    range=f"{quoted_sheet_name(sheet['title'])}!A1:"
                          f"{sheet_column_name(sheet['gridProperties']['columnCount'] - 1)}"
                          f"{sheet['gridProperties']['rowCount']}",
                ).execute().get("values", [])
                if not any(str(value).strip() for row in contents for value in row):
                    continue
            raise ValueError(f"Fault ID allocation: cannot identify a unique Fault ID column in {sheet['title']!r}.")
        row_index, column_index = matches[0]
        first_data_row = row_index + 2
        last_row = sheet["gridProperties"]["rowCount"]
        if first_data_row <= last_row:
            column = sheet_column_name(column_index)
            id_ranges.append(f"{quoted_sheet_name(sheet['title'])}!{column}{first_data_row}:{column}{last_row}")
    existing_rows: list[list[Any]] = []
    if id_ranges:
        results = service.spreadsheets().values().batchGet(
            spreadsheetId=args.spreadsheet_id, ranges=id_ranges,
        ).execute().get("valueRanges", [])
        if len(results) != len(id_ranges):
            raise ValueError("Fault ID allocation: incomplete Cabling ID response.")
        existing_rows = [row for result in results for row in result.get("values", []) if row]
    return next_fault_id_generator(existing_rows, args.fault_id_start)


def remediation_rows_with_sheet_numbers(
    raw_values: list[list[Any]], header_mapping: dict[str, str],
) -> list[tuple[int, list[Any]]]:
    """Return non-empty canonical Cabling rows paired with their physical Sheet rows."""
    if not raw_values:
        return []
    data_start_row = (
        3 if is_timestamp_row(raw_values[0], REMEDIATION_TIMESTAMP_PREFIX) else 2
    )
    canonical = canonicalize_remediation_values(
        strip_timestamp_row(raw_values), header_mapping
    )
    if not canonical:
        return []
    return [
        (data_start_row + offset, row)
        for offset, row in enumerate(canonical[1:])
        if any(str(value).strip() for value in row)
    ]


def build_sparse_remediation_plan(
    sheet_name: str,
    initial_raw: list[list[Any]],
    live_raw: list[list[Any]],
    desired_values: list[list[Any]],
    selected_canonical: list[str],
    selected_headers: list[str],
    header_mapping: dict[str, str],
) -> tuple[list[dict[str, Any]], int, int, int]:
    """Build a concurrency-safe Sheets payload without performing any I/O."""
    quoted = quoted_sheet_name(sheet_name)
    live_table = strip_timestamp_row(live_raw)
    live_headers = [str(header) for header in live_table[0]]
    displayed_by_canonical = dict(zip(selected_canonical, selected_headers))
    missing_headers = [
        displayed_by_canonical[field]
        for field in selected_canonical
        if displayed_by_canonical[field] not in live_headers
    ]
    if missing_headers:
        raise ValueError(
            f"{sheet_name} headers changed during the update; missing: "
            + ", ".join(missing_headers)
        )
    column_by_canonical = {
        field: live_headers.index(displayed_by_canonical[field])
        for field in selected_canonical
    }
    initial_entries = remediation_rows_with_sheet_numbers(initial_raw, header_mapping)
    live_entries = remediation_rows_with_sheet_numbers(live_raw, header_mapping)
    desired_rows = desired_values[1:]

    def row_value(row: list[Any], field: str) -> Any:
        index = REMEDIATION_INDEX[field]
        return row[index] if index < len(row) else ""

    live_by_sheet_row = {sheet_row: row for sheet_row, row in live_entries}
    live_by_fault_id: dict[str, tuple[int, list[Any]]] = {}
    for sheet_row, row in live_entries:
        fault_id = str(row_value(row, "Fault ID") or "").strip()
        if fault_id and fault_id not in live_by_fault_id:
            live_by_fault_id[fault_id] = (sheet_row, row)

    changes_by_column: dict[int, dict[int, Any]] = defaultdict(dict)
    concurrent_status_skips = 0
    missing_row_skips = 0
    for index in range(min(len(initial_entries), len(desired_rows))):
        original_sheet_row, initial_row = initial_entries[index]
        desired_row = desired_rows[index]
        original_fault_id = str(row_value(initial_row, "Fault ID") or "").strip()
        if original_fault_id:
            live_entry = live_by_fault_id.get(original_fault_id)
        else:
            live_row = live_by_sheet_row.get(original_sheet_row)
            live_entry = (original_sheet_row, live_row) if live_row is not None else None
        if live_entry is None:
            missing_row_skips += 1
            continue
        live_sheet_row, live_row = live_entry
        old_status = row_value(initial_row, "Status")
        new_status = row_value(desired_row, "Status")
        status_conflict = (
            new_status != old_status and row_value(live_row, "Status") != old_status
        )
        if status_conflict:
            concurrent_status_skips += 1

        for field in selected_canonical:
            if field in REMEDIATION_MANUAL_FIELDS:
                continue
            old_value = row_value(initial_row, field)
            desired_value = row_value(desired_row, field)
            if desired_value == old_value:
                continue
            live_value = row_value(live_row, field)
            if field in REMEDIATION_CONDITIONAL_FIELDS and (
                status_conflict or live_value != old_value
            ):
                continue
            changes_by_column[column_by_canonical[field]][live_sheet_row] = desired_value

    live_fault_ids = set(live_by_fault_id)
    new_rows: list[list[Any]] = []
    for desired_row in desired_rows[len(initial_entries):]:
        fault_id = str(row_value(desired_row, "Fault ID") or "").strip()
        if fault_id and fault_id in live_fault_ids:
            continue
        new_rows.append([row_value(desired_row, field) for field in selected_canonical])
        if fault_id:
            live_fault_ids.add(fault_id)

    data: list[dict[str, Any]] = []
    for column_index, row_changes in sorted(changes_by_column.items()):
        first_row, last_row = min(row_changes), max(row_changes)
        column = sheet_column_name(column_index)
        data.append({
            "range": f"{quoted}!{column}{first_row}:{column}{last_row}",
            # JSON null skips unchanged cells; an empty string clears a changed
            # system field while preserving all other cells and formatting.
            "values": [
                [row_changes.get(sheet_row)]
                for sheet_row in range(first_row, last_row + 1)
            ],
        })

    if new_rows:
        last_live_row = max((sheet_row for sheet_row, _row in live_entries), default=2)
        append_row = max(3, last_live_row + 1)
        last_column = sheet_column_name(len(selected_headers) - 1)
        data.append({
            "range": f"{quoted}!A{append_row}:{last_column}{append_row + len(new_rows) - 1}",
            "values": new_rows,
        })
    return data, concurrent_status_skips, missing_row_skips, len(new_rows)


class TableRepository(Protocol):
    """Value I/O boundary. Formatting, charts and schema migrations stay separate."""

    def read(self, table_range: str) -> list[list[Any]]:
        ...

    def update(self, table_range: str, values: list[list[Any]], input_option: str) -> dict[str, Any]:
        ...

    def batch_update(self, data: list[dict[str, Any]], input_option: str) -> dict[str, Any]:
        ...

    def clear(self, table_range: str) -> dict[str, Any]:
        ...


@dataclass
class GoogleSheetsRepository:
    """One Spreadsheet's values API. Never retries non-idempotent writes."""

    service: Any
    spreadsheet_id: str

    def read(self, table_range: str) -> list[list[Any]]:
        return self.service.spreadsheets().values().get(
            spreadsheetId=self.spreadsheet_id, range=table_range,
        ).execute().get("values", [])

    def update(self, table_range: str, values: list[list[Any]], input_option: str) -> dict[str, Any]:
        return self.service.spreadsheets().values().update(
            spreadsheetId=self.spreadsheet_id, range=table_range,
            valueInputOption=input_option, body={"values": values},
        ).execute()

    def batch_update(self, data: list[dict[str, Any]], input_option: str) -> dict[str, Any]:
        return self.service.spreadsheets().values().batchUpdate(
            spreadsheetId=self.spreadsheet_id,
            body={"valueInputOption": input_option, "data": data},
        ).execute()

    def clear(self, table_range: str) -> dict[str, Any]:
        return self.service.spreadsheets().values().clear(
            spreadsheetId=self.spreadsheet_id, range=table_range, body={},
        ).execute()


def table_value_delta(
    sheet_name: str, previous: list[list[Any]], desired: list[list[Any]],
    width: int, start_row: int = 3,
) -> list[dict[str, Any]]:
    """Diff physical cells, merging vertical runs and adjacent equal-height runs.

    Only the desired rectangle is owned by this operation: historical trailing
    rows and columns outside it are untouched. Empty/missing values explicitly
    become empty strings, never null (which Sheets skips rather than clears).
    """
    def cell(row: list[Any], col: int) -> Any:
        return row[col] if col < len(row) and row[col] is not None else ""

    rectangles: dict[tuple[int, int], list[tuple[int, int]]] = defaultdict(list)
    for col in range(width):
        run = None
        for row_index in range(len(desired) + 1):
            changed = False
            if row_index < len(desired):
                old = cell(previous[row_index], col) if row_index < len(previous) else ""
                new = cell(desired[row_index], col)
                changed = type(old) is not type(new) or old != new
            if changed and run is None:
                run = row_index
            elif not changed and run is not None:
                spans = rectangles[(run, row_index)]
                if spans and spans[-1][1] == col:
                    spans[-1] = (spans[-1][0], col + 1)
                else:
                    spans.append((col, col + 1))
                run = None

    quoted = quoted_sheet_name(sheet_name)
    return [
        {"range": (
            f"{quoted}!{sheet_column_name(left)}{start_row + first}:"
            f"{sheet_column_name(right - 1)}{start_row + end - 1}"
        ), "values": [
            [cell(desired[r], c) for c in range(left, right)]
            for r in range(first, end)
        ]}
        for (first, end), spans in sorted(rectangles.items())
        for left, right in spans
    ]


def value_batch_payloads(
    data: list[dict[str, Any]], input_option: str, max_bytes: int = 1_500_000,
) -> list[list[dict[str, Any]]]:
    """Bound JSON request size; split tall rectangles, never retry writes.

    Preflight every chunk before sending any writes. The byte count describes
    serialized JSON, not compressed wire traffic or HTTP/TLS overhead.
    """
    def size(value: Any) -> int:
        return len(json.dumps(value).encode("utf-8"))

    overhead = size({"valueInputOption": input_option, "data": []})
    items: list[dict[str, Any]] = []

    def split(item: dict[str, Any]) -> None:
        if size(item) + overhead <= max_bytes:
            items.append(item)
            return
        rows = item["values"]
        if len(rows) < 2:
            raise ValueError("One Sheets row exceeds the configured batch payload budget.")
        match = re.fullmatch(r"(.+!)([A-Z]+)([0-9]+)(?::[A-Z]+[0-9]+)?", item["range"])
        if match is None:
            raise ValueError("Cannot split a non-rectangular Sheets values range.")
        prefix, column, row = match.groups()
        mid = len(rows) // 2
        split({"range": f"{prefix}{column}{row}", "values": rows[:mid]})
        split({"range": f"{prefix}{column}{int(row) + mid}", "values": rows[mid:]})

    for item in data:
        split(item)
    batches: list[list[dict[str, Any]]] = []
    batch: list[dict[str, Any]] = []
    used = overhead
    for item in items:
        cost = size(item) + (2 if batch else 0)
        if batch and used + cost > max_bytes:
            batches.append(batch)
            batch, used = [], overhead
            cost = size(item)
        batch.append(item)
        used += cost
    if batch:
        batches.append(batch)
    return batches


def persist_value_delta(
    repository: TableRepository, data: list[dict[str, Any]], input_option: str,
) -> dict[str, Any]:
    batches = value_batch_payloads(data, input_option)
    updated_cells = 0
    for batch in batches:
        result = repository.batch_update(batch, input_option)
        updated_cells += result.get("totalUpdatedCells", 0)
    return {
        "updatedCells": updated_cells,
        "writeRequests": len(batches),
        "payloadBytes": sum(len(json.dumps({
            "valueInputOption": input_option, "data": batch,
        }).encode("utf-8")) for batch in batches),
    }


def sparse_remediation_update(
    service: Any,
    args: argparse.Namespace,
    initial_raw: list[list[Any]],
    desired_values: list[list[Any]],
    selected_canonical: list[str],
    selected_headers: list[str],
) -> dict[str, Any]:
    """Write only changed script-owned cells and append complete new records."""
    return persist_cabling_values(
        GoogleSheetsRepository(service, args.spreadsheet_id), args, initial_raw,
        desired_values, selected_canonical, selected_headers,
    )


def persist_cabling_values(
    repository: TableRepository, args: argparse.Namespace,
    initial_raw: list[list[Any]], desired_values: list[list[Any]],
    selected_canonical: list[str], selected_headers: list[str],
) -> dict[str, Any]:
    """Re-read live rows before applying a plan, preserving concurrent human edits."""
    quoted = quoted_sheet_name(args.remediation_sheet)
    live_raw = repository.read(remediation_table_range(args))
    live_table = strip_timestamp_row(live_raw)
    if not live_table or not has_nonempty_header(live_table):
        result = repository.update(
            f"{quoted}!A2", [selected_headers] + project_columns(
                desired_values, selected_canonical
            )[1:], args.value_input_option,
        )
        result.setdefault("concurrentStatusSkips", 0)
        result.setdefault("newRows", max(0, len(desired_values) - 1))
        return result

    data, concurrent_status_skips, missing_row_skips, new_row_count = (
        build_sparse_remediation_plan(
            args.remediation_sheet,
            initial_raw,
            live_raw,
            desired_values,
            selected_canonical,
            selected_headers,
            args.remediation_header_mapping,
        )
    )

    if data:
        response = repository.batch_update(data, args.value_input_option)
    else:
        response = {"totalUpdatedCells": 0}
    response["updatedCells"] = response.get("totalUpdatedCells", 0)
    response["updatedRange"] = f"{args.remediation_sheet} sparse update"
    response["concurrentStatusSkips"] = concurrent_status_skips
    response["missingRowSkips"] = missing_row_skips
    response["newRows"] = new_row_count
    return response


def normalized_event_su(value: Any) -> str:
    """Keep empty SU values visible in grouped event statistics."""
    return str(value or "").strip() or "Unknown"


def normalized_event_link_type(value: Any) -> str:
    """Normalize the Cabling Link Type used by event grouping."""
    text = str(value or "").strip()
    if text.casefold() == "switch":
        return "Switch"
    if text.casefold() == "host":
        return "Host"
    return text or "Unknown"


def cabling_rows_by_fault(
    values: list[list[Any]], instance_name: str,
) -> dict[str, dict[str, Any]]:
    """Index canonical Cabling rows for one instance by Fault ID."""
    if not values:
        return {}
    positions = {str(header): index for index, header in enumerate(values[0])}

    def cell(row: list[Any], header: str) -> Any:
        index = positions.get(header)
        return row[index] if index is not None and index < len(row) else ""

    result: dict[str, dict[str, Any]] = {}
    for row in values[1:]:
        row_instance = str(cell(row, INSTANCE_HEADER) or "").strip()
        if row_instance != instance_name:
            continue
        fault_id = str(cell(row, "Fault ID") or "").strip()
        if not fault_id:
            continue
        result[fault_id] = {
            "status": str(cell(row, "Status") or "").strip(),
            "a_su": normalized_event_su(cell(row, "Local SU Number")),
            "link_type": normalized_event_link_type(cell(row, "Link Type")),
            "issue_type": str(cell(row, "Error") or "").strip(),
            "reported_by": str(cell(row, "Reported by") or "").strip(),
            "cvt": str(cell(row, "CVT") or "").strip(),
            "date_closed": str(cell(row, "Date Closed") or "").strip(),
        }
    return result


def build_cabling_event_plan(
    existing_event_rows: list[list[Any]],
    previous_cabling: list[list[Any]],
    current_cabling: list[list[Any]],
    instance_name: str,
    cabling_type: str,
    timezone_name: str = DEFAULT_TIMEZONE,
    now: datetime | None = None,
) -> tuple[list[list[Any]], dict[int, list[Any]], Counter[str]]:
    """Plan idempotent Case events and hourly A-SU/Link-Type snapshots."""
    current_time = operational_now(timezone_name, now)
    event_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    hour_time = current_time.replace(minute=0, second=0, microsecond=0).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    cabling_type = str(cabling_type or "ALL").strip().upper() or "ALL"
    instance_name = str(instance_name or "").strip()
    event_index = {header: index for index, header in enumerate(CABLING_EVENT_HEADERS)}

    def event_cell(row: list[Any], header: str) -> str:
        index = event_index[header]
        return str(row[index] if index < len(row) else "").strip()

    scoped_events = [
        (index, row)
        for index, row in enumerate(existing_event_rows)
        if event_cell(row, "Instance") == instance_name
        and event_cell(row, "Cabling Type").upper() == cabling_type
    ]
    initialized = any(
        event_cell(row, "Event Type").upper() == CABLING_EVENT_INIT
        for _index, row in scoped_events
    )
    tracked: dict[str, list[Any]] = {}
    closed: set[str] = set()
    known_groups: set[tuple[str, str]] = set()
    snapshots: dict[tuple[str, str, str], int] = {}
    for index, row in scoped_events:
        event_type = event_cell(row, "Event Type").upper()
        fault_id = event_cell(row, "Fault ID")
        a_su = event_cell(row, "A-SU")
        link_type = event_cell(row, "Link Type")
        if a_su or link_type:
            known_groups.add((
                normalized_event_su(a_su),
                normalized_event_link_type(link_type),
            ))
        if fault_id and event_type in {CABLING_EVENT_BASELINE, CABLING_EVENT_OPEN}:
            tracked.setdefault(fault_id, row)
        elif fault_id and event_type == CABLING_EVENT_CLOSE:
            closed.add(fault_id)
        if event_type == CABLING_EVENT_SNAPSHOT:
            snapshots[(
                event_cell(row, "Event Time"),
                normalized_event_su(a_su),
                normalized_event_link_type(link_type),
            )] = index

    # The final re-read is authoritative. Keep the previous table in the API so
    # reconciliation can evolve without changing its caller.
    del previous_cabling
    current = cabling_rows_by_fault(current_cabling, instance_name)
    append_rows: list[list[Any]] = []
    snapshot_updates: dict[int, list[Any]] = {}
    stats: Counter[str] = Counter()

    def event_row(
        event_type: str,
        fault_id: str = "",
        a_su: str = "",
        link_type: str = "",
        issue_type: str = "",
        source: str = "System",
        open_count: Any = "",
        timestamp: str = event_time,
    ) -> list[Any]:
        return [
            timestamp, event_type, fault_id, instance_name, cabling_type,
            a_su, link_type, issue_type, source, open_count,
        ]

    if not initialized:
        append_rows.append(event_row(CABLING_EVENT_INIT))
        stats["initialized"] += 1
        for fault_id, record in sorted(current.items()):
            if record["status"].casefold() == "closed" or fault_id in tracked:
                continue
            append_rows.append(event_row(
                CABLING_EVENT_BASELINE,
                fault_id,
                record["a_su"],
                record["link_type"],
                record["issue_type"],
            ))
            tracked[fault_id] = append_rows[-1]
            known_groups.add((record["a_su"], record["link_type"]))
            stats["baseline"] += 1
    else:
        for fault_id, record in sorted(current.items()):
            is_closed = record["status"].casefold() == "closed"
            if not is_closed and fault_id not in tracked:
                source = (
                    managed_reporter(record["reported_by"]) or "Manual"
                )
                append_rows.append(event_row(
                    CABLING_EVENT_OPEN,
                    fault_id,
                    record["a_su"],
                    record["link_type"],
                    record["issue_type"],
                    source,
                ))
                tracked[fault_id] = append_rows[-1]
                known_groups.add((record["a_su"], record["link_type"]))
                stats["opened"] += 1
                continue
            if is_closed and fault_id in tracked and fault_id not in closed:
                original = tracked[fault_id]
                original_su = normalized_event_su(event_cell(original, "A-SU"))
                original_link_type = normalized_event_link_type(
                    event_cell(original, "Link Type")
                )
                original_issue = event_cell(original, "Issue Type") or record["issue_type"]
                cvt_closed = (
                    managed_reporter(record["reported_by"]) is not None
                    and record["cvt"].casefold() == "pass"
                    and bool(record["date_closed"])
                )
                append_rows.append(event_row(
                    CABLING_EVENT_CLOSE,
                    fault_id,
                    original_su,
                    original_link_type,
                    original_issue,
                    managed_reporter(record["reported_by"]) if cvt_closed else "Manual",
                ))
                closed.add(fault_id)
                known_groups.add((original_su, original_link_type))
                stats["closed"] += 1

    open_faults_by_group: dict[tuple[str, str], set[str]] = defaultdict(set)
    for fault_id, record in current.items():
        if record["status"].casefold() != "closed":
            group = (record["a_su"], record["link_type"])
            open_faults_by_group[group].add(fault_id)
            known_groups.add(group)

    for a_su, link_type in sorted(
        known_groups, key=lambda item: (item[0].casefold(), item[1].casefold())
    ):
        snapshot = event_row(
            CABLING_EVENT_SNAPSHOT,
            a_su=a_su,
            link_type=link_type,
            open_count=len(open_faults_by_group.get((a_su, link_type), set())),
            timestamp=hour_time,
        )
        existing_index = snapshots.get((hour_time, a_su, link_type))
        if existing_index is None:
            append_rows.append(snapshot)
            stats["snapshots_added"] += 1
        elif list(existing_event_rows[existing_index]) != snapshot:
            snapshot_updates[existing_index] = snapshot
            stats["snapshots_updated"] += 1

    return append_rows, snapshot_updates, stats


def expired_cabling_event_indexes(
    rows: list[list[Any]],
    retention_hours: int,
    timezone_name: str = DEFAULT_TIMEZONE,
    now: datetime | None = None,
) -> list[int]:
    """Return zero-based data-row indexes older than a rolling retention window."""
    current_time = operational_now(timezone_name, now)
    cutoff = current_time - timedelta(hours=retention_hours)
    expired: list[int] = []
    for index, row in enumerate(rows):
        raw_timestamp = str(row[0] if row else "").strip()
        try:
            timestamp = datetime.strptime(raw_timestamp, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            # Preserve malformed or manually added rows rather than deleting data
            # whose age cannot be established safely.
            continue
        timestamp = timestamp.replace(tzinfo=current_time.tzinfo)
        if timestamp < cutoff:
            expired.append(index)
    return expired


def delete_cabling_event_rows(
    service: Any,
    spreadsheet_id: str,
    sheet_name: str,
    data_row_indexes: list[int],
) -> None:
    """Delete expired event rows in descending contiguous blocks."""
    indexes = sorted(set(data_row_indexes))
    if not indexes:
        return
    metadata = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id,
        fields="sheets.properties(sheetId,title)",
    ).execute()
    requested_title = str(sheet_name).casefold()
    sheet_id = next(
        (
            sheet["properties"]["sheetId"]
            for sheet in metadata.get("sheets", [])
            if str(sheet["properties"]["title"]).casefold() == requested_title
        ),
        None,
    )
    if sheet_id is None:
        raise ValueError(f"Cabling event sheet not found: {sheet_name}")

    blocks: list[tuple[int, int]] = []
    start = previous = indexes[0]
    for index in indexes[1:]:
        if index == previous + 1:
            previous = index
            continue
        blocks.append((start, previous))
        start = previous = index
    blocks.append((start, previous))

    requests = [
        {
            "deleteDimension": {
                "range": {
                    "sheetId": sheet_id,
                    "dimension": "ROWS",
                    # Event data starts on physical row 3, zero-based index 2.
                    "startIndex": start + 2,
                    "endIndex": end + 3,
                }
            }
        }
        for start, end in reversed(blocks)
    ]
    service.spreadsheets().batchUpdate(
        spreadsheetId=spreadsheet_id,
        body={"requests": requests},
    ).execute()


def ensure_cabling_events_headers(service: Any, args: argparse.Namespace) -> None:
    """Create the event sheet header without replacing a non-empty foreign schema."""
    ensure_sheet(service, args.spreadsheet_id, args.cabling_events_sheet)
    current = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id,
        range=f"{quoted_sheet_name(args.cabling_events_sheet)}!2:2",
    ).execute().get("values", [])
    current_headers = [str(value) for value in current[0]] if current else []
    normalized_headers = normalize_instance_headers(current_headers)
    if normalized_headers == CABLING_EVENT_HEADERS and current_headers != normalized_headers:
        # A label-only migration must preserve all event history and row positions.
        service.spreadsheets().values().update(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted_sheet_name(args.cabling_events_sheet)}!"
                  f"{sheet_column_name(CABLING_EVENT_HEADERS.index(INSTANCE_HEADER))}2",
            valueInputOption="RAW", body={"values": [[INSTANCE_HEADER]]},
        ).execute()
        return
    current_headers = normalized_headers
    if current_headers == CABLING_EVENT_LEGACY_HEADERS:
        LOGGER.warning(
            "Migrating Cabling event schema with Link Type; clearing legacy "
            "event rows sheet=%s",
            args.cabling_events_sheet,
        )
        service.spreadsheets().values().clear(
            spreadsheetId=args.spreadsheet_id,
            range=bounded_sheet_range(
                args.cabling_events_sheet, len(CABLING_EVENT_HEADERS), 3
            ),
            body={},
        ).execute()
        service.spreadsheets().values().update(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted_sheet_name(args.cabling_events_sheet)}!A2",
            valueInputOption="RAW",
            body={"values": [CABLING_EVENT_HEADERS]},
        ).execute()
        return
    if current_headers and current_headers != CABLING_EVENT_HEADERS:
        raise ValueError(
            f"{args.cabling_events_sheet} header mismatch; no event data was changed. "
            f"Expected {CABLING_EVENT_HEADERS}, got {current_headers}"
        )
    if not current_headers:
        service.spreadsheets().values().update(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted_sheet_name(args.cabling_events_sheet)}!A2",
            valueInputOption="RAW",
            body={"values": [CABLING_EVENT_HEADERS]},
        ).execute()


def refresh_cabling_events(
    service: Any,
    args: argparse.Namespace,
    previous_cabling: list[list[Any]],
    cabling_type: str,
) -> dict[str, Any]:
    """Reconcile lightweight events from the final committed Cabling state."""
    ensure_cabling_events_headers(service, args)
    event_range = f"{quoted_sheet_name(args.cabling_events_sheet)}!A3:J"
    existing_event_rows = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id, range=event_range,
    ).execute().get("values", [])
    final_raw = service.spreadsheets().values().get(
        spreadsheetId=args.spreadsheet_id,
        range=remediation_table_range(args),
    ).execute().get("values", [])
    current_cabling = canonicalize_remediation_values(
        strip_timestamp_row(final_raw), args.remediation_header_mapping
    )
    expired_indexes = expired_cabling_event_indexes(
        existing_event_rows,
        args.cabling_events_retention_hours,
        args.timezone_name,
    )
    if expired_indexes:
        delete_cabling_event_rows(
            service,
            args.spreadsheet_id,
            args.cabling_events_sheet,
            expired_indexes,
        )
        expired_set = set(expired_indexes)
        existing_event_rows = [
            row for index, row in enumerate(existing_event_rows)
            if index not in expired_set
        ]
    append_rows, snapshot_updates, stats = build_cabling_event_plan(
        existing_event_rows,
        previous_cabling,
        current_cabling,
        str(getattr(args, "instance_name", "") or ""),
        cabling_type,
        args.timezone_name,
    )
    quoted = quoted_sheet_name(args.cabling_events_sheet)
    if snapshot_updates:
        data = [
            {"range": f"{quoted}!A{index + 3}:J{index + 3}", "values": [row]}
            for index, row in sorted(snapshot_updates.items())
        ]
        service.spreadsheets().values().batchUpdate(
            spreadsheetId=args.spreadsheet_id,
            body={"valueInputOption": "RAW", "data": data},
        ).execute()
    if append_rows:
        service.spreadsheets().values().append(
            spreadsheetId=args.spreadsheet_id,
            range=f"{quoted}!A3",
            valueInputOption="RAW",
            insertDataOption="INSERT_ROWS",
            body={"values": append_rows},
        ).execute()
    prepare_timestamp_row(
        service,
        args.spreadsheet_id,
        args.cabling_events_sheet,
        REMEDIATION_TIMESTAMP_PREFIX,
        preserve_first_row=False,
        timezone_name=args.timezone_name,
    )
    # This is an actual post-write read, not the planned output. Reuse it only
    # for the cycle's summary; never for subsequent Case writes/live checks.
    committed = getattr(args, "_committed_cabling", None)
    if committed is not None:
        committed[committed_cabling_key(args, args.remediation_sheet)] = final_raw
    return {
        "appendedRows": len(append_rows),
        "snapshotUpdates": len(snapshot_updates),
        "expiredRows": len(expired_indexes),
        **dict(stats),
    }


def parse_cabling_event_time(value: Any, timezone_name: str) -> datetime | None:
    """Parse one Events timestamp in the configured operational timezone."""
    try:
        parsed = datetime.strptime(str(value or "").strip(), "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return None
    return parsed.replace(tzinfo=operational_timezone(timezone_name))


def build_cabling_sum_cvt_metrics(
    reports: list[tuple[str, list[list[Any]]]],
) -> dict[tuple[str, str, str, str], Counter[str]]:
    """Aggregate current CVT reports for Cabling_SUM without using CVT_SUM data."""
    grouped: dict[tuple[str, str, str, str], Counter[str]] = defaultdict(Counter)
    for instance_name, values in reports:
        values = strip_timestamp_row(values)
        if not values or len(values) < 2:
            raise ValueError(
                f"Cabling summary CVT source for {instance_name or 'single instance'} "
                "is empty."
            )
        headers = [str(header) for header in values[0]]
        positions = {header: index for index, header in enumerate(headers)}
        if "Status" not in positions:
            raise ValueError("Cabling summary CVT source must contain a Status column.")

        for row in values[1:]:
            def cell(header: str) -> Any:
                index = positions.get(header, -1)
                return row[index] if 0 <= index < len(row) else ""

            protocol_name = cvt_sum_protocol(cell("Protocol"))
            su = str(cell("A SU Number") or cell("Z SU Number") or "Unknown").strip()
            link_type = cvt_sum_link_type(row, positions)
            counts = grouped[(instance_name, protocol_name, su, link_type)]
            counts["Total"] += 1
            status = cvt_sum_status(cell("Status"))
            if status == "Pass":
                counts["Pass"] += 1
            elif status == "Fail":
                bucket = cvt_sum_fail_bucket(row, positions)
                if bucket in {"Link Down", "Mis-wiring"}:
                    counts[bucket] += 1
                else:
                    counts["Others"] += 1
            else:
                # Warning and empty/unknown statuses remain part of Total and
                # are grouped into Others so the displayed categories reconcile.
                counts["Others"] += 1
    return grouped


def build_cabling_sum_rows(
    event_rows: list[list[Any]],
    timezone_name: str = DEFAULT_TIMEZONE,
    now: datetime | None = None,
    cvt_reports: list[tuple[str, list[list[Any]]]] | None = None,
    period_hours: list[int] | tuple[int, ...] = DEFAULT_CABLING_SUM_PERIOD_HOURS,
) -> tuple[list[list[Any]], str]:
    """Aggregate Events by Instance, Cabling type, A-SU, and Link Type."""
    current_time = operational_now(timezone_name, now)
    point_time = current_time.strftime("%Y-%m-%d %H:%M:%S")
    positions = {header: index for index, header in enumerate(CABLING_EVENT_HEADERS)}

    def cell(row: list[Any], header: str) -> str:
        index = positions[header]
        return str(row[index] if index < len(row) else "").strip()

    parsed_events: list[tuple[datetime, str, str, str, str, str]] = []
    latest_snapshots: dict[tuple[str, str, str, str], tuple[datetime, int]] = {}
    for row in event_rows:
        timestamp = parse_cabling_event_time(cell(row, "Event Time"), timezone_name)
        if timestamp is None or timestamp > current_time:
            continue
        event_type = cell(row, "Event Type").upper()
        instance = cell(row, "Instance")
        cabling_type = cell(row, "Cabling Type").upper() or "ALL"
        a_su = normalized_event_su(cell(row, "A-SU"))
        link_type = normalized_event_link_type(cell(row, "Link Type"))
        if event_type == CABLING_EVENT_SNAPSHOT:
            try:
                open_count = int(float(cell(row, "Open Count") or 0))
            except ValueError:
                continue
            detail_key = (instance, cabling_type, a_su, link_type)
            previous = latest_snapshots.get(detail_key)
            if previous is None or timestamp >= previous[0]:
                latest_snapshots[detail_key] = (timestamp, open_count)
        elif event_type in {CABLING_EVENT_OPEN, CABLING_EVENT_CLOSE}:
            parsed_events.append(
                (timestamp, event_type, instance, cabling_type, a_su, link_type)
            )

    cvt_metrics = build_cabling_sum_cvt_metrics(cvt_reports or [])
    groups: set[tuple[str, str, str, str]] = set(latest_snapshots)
    groups.update((event[2], event[3], event[4], event[5]) for event in parsed_events)
    groups.update(cvt_metrics)
    link_type_order = {"Host": 0, "Switch": 1, "Unknown": 2}
    rows: list[list[Any]] = []
    for instance, cabling_type, a_su, link_type in sorted(
        groups,
        key=lambda item: (
            item[0].casefold(),
            {"IB": 0, "ETH": 1, "ALL": 2}.get(item[1], 3),
            item[2].casefold(),
            link_type_order.get(item[3], 3),
            item[3].casefold(),
        ),
    ):
        detail_key = (instance, cabling_type, a_su, link_type)
        end_open = latest_snapshots.get(detail_key, (current_time, 0))[1]
        current_cvt = cvt_metrics.get(detail_key, Counter())
        total_links = current_cvt["Total"]
        passed_links = current_cvt["Pass"]
        pass_rate: Any = passed_links / total_links if total_links else ""
        row: list[Any] = [
            point_time, instance, cabling_type, a_su, link_type,
            total_links,
            passed_links,
            end_open,
            current_cvt["Link Down"],
            current_cvt["Mis-wiring"],
            current_cvt["Others"],
            pass_rate,
            "",
        ]
        for hours in period_hours:
            cutoff = current_time - timedelta(hours=hours)
            opened = sum(
                1 for event in parsed_events
                if cutoff < event[0] <= current_time
                and event[2:] == (instance, cabling_type, a_su, link_type)
                and event[1] == CABLING_EVENT_OPEN
            )
            closed = sum(
                1 for event in parsed_events
                if cutoff < event[0] <= current_time
                and event[2:] == (instance, cabling_type, a_su, link_type)
                and event[1] == CABLING_EVENT_CLOSE
            )
            net_change = opened - closed
            # If retained history is shorter than the requested window, use all
            # events still available rather than leaving the period blank.
            row.extend([opened, closed, net_change])
        rows.append(row)
    return rows, point_time


def cabling_sum_header_rows(
    period_hours: list[int] | tuple[int, ...] = DEFAULT_CABLING_SUM_PERIOD_HOURS,
) -> list[list[Any]]:
    """Return the two logical header rows for the Cabling_SUM table."""
    group_row: list[Any] = [
        "Cabling progress by A-SU and Link Type",
        *([""] * (len(CABLING_SUM_DIMENSION_HEADERS) - 1)),
    ]
    detail_row: list[Any] = list(CABLING_SUM_DIMENSION_HEADERS)
    group_row.extend([
        "CVT Information", *([""] * (len(CABLING_SUM_CVT_HEADERS) - 1)),
    ])
    detail_row.extend(CABLING_SUM_CVT_HEADERS)
    for hours in period_hours:
        group_row.extend([
            f"Last {hours} Hour{'s' if hours != 1 else ''}",
            *([""] * (len(CABLING_SUM_METRIC_HEADERS) - 1)),
        ])
        detail_row.extend(CABLING_SUM_METRIC_HEADERS)
    return [group_row, detail_row]


def cabling_sum_conditional_format_requests(
    sheet_id: int,
    period_start_column: int,
    period_hours: list[int] | tuple[int, ...],
    end_row_index: int,
) -> list[dict[str, Any]]:
    """Return the complete Cabling_SUM conditional-format rule set."""
    requests: list[dict[str, Any]] = []
    red = {"red": 0.78, "green": 0.08, "blue": 0.08}
    blue = {"red": 0.08, "green": 0.28, "blue": 0.70}
    green = {"red": 0.08, "green": 0.48, "blue": 0.20}
    orange = {"red": 0.88, "green": 0.34, "blue": 0.04}
    amber = {"red": 0.68, "green": 0.43, "blue": 0.02}
    gray = {"red": 0.45, "green": 0.45, "blue": 0.45}
    light_red = {"red": 0.98, "green": 0.88, "blue": 0.88}
    light_orange = {"red": 0.99, "green": 0.92, "blue": 0.82}
    light_amber = {"red": 0.99, "green": 0.96, "blue": 0.80}
    light_gray = {"red": 0.94, "green": 0.94, "blue": 0.94}

    def add_rule(
        start_column: int,
        end_column: int,
        condition_type: str,
        color: dict[str, float],
        *,
        value: str = "0",
        bold: bool = True,
        background: dict[str, float] | None = None,
    ) -> None:
        cell_format: dict[str, Any] = {
            "textFormat": {"bold": bold, "foregroundColor": color},
        }
        if background is not None:
            cell_format["backgroundColor"] = background
        requests.append({"addConditionalFormatRule": {
            "rule": {
                "ranges": [{
                    "sheetId": sheet_id,
                    "startRowIndex": 3,
                    "endRowIndex": end_row_index,
                    "startColumnIndex": start_column,
                    "endColumnIndex": end_column,
                }],
                "booleanRule": {
                    "condition": {
                        "type": condition_type,
                        "values": [{"userEnteredValue": value}],
                    },
                    "format": cell_format,
                },
            },
            "index": 0,
        }})

    cvt_start_column = len(CABLING_SUM_DIMENSION_HEADERS)
    cvt_columns = {
        header: cvt_start_column + CABLING_SUM_CVT_HEADERS.index(header)
        for header in CABLING_SUM_CVT_HEADERS
    }
    total_letter = sheet_column_name(cvt_columns["Total"])
    pass_letter = sheet_column_name(cvt_columns["Pass"])
    add_rule(
        cvt_start_column,
        period_start_column,
        "CUSTOM_FORMULA",
        gray,
        value=f'=AND(${total_letter}4<>"",${total_letter}4=0)',
        bold=False,
        background=light_gray,
    )
    add_rule(
        cvt_columns["Pass"],
        cvt_columns["Pass"] + 1,
        "CUSTOM_FORMULA",
        green,
        value=f"=AND(${total_letter}4>0,${pass_letter}4=${total_letter}4)",
    )
    add_rule(
        cvt_columns["Open"], cvt_columns["Open"] + 1,
        "NUMBER_GREATER", red, background=light_red,
    )
    add_rule(
        cvt_columns["Open"], cvt_columns["Open"] + 1,
        "NUMBER_EQ", green,
    )
    for header, color, background in (
        ("Link Down", red, light_red),
        ("Mis-wiring", orange, light_orange),
        ("Others", amber, light_amber),
    ):
        column = cvt_columns[header]
        add_rule(
            column, column + 1, "NUMBER_GREATER", color,
            background=background,
        )
    pass_rate_column = cvt_columns["Rate"]
    requests.append({"addConditionalFormatRule": {
        "rule": {
            "ranges": [{
                "sheetId": sheet_id,
                "startRowIndex": 3,
                "endRowIndex": end_row_index,
                "startColumnIndex": pass_rate_column,
                "endColumnIndex": pass_rate_column + 1,
            }],
            "gradientRule": {
                "minpoint": {
                    "type": "NUMBER", "value": "0",
                    "color": {"red": 0.90, "green": 0.22, "blue": 0.18},
                },
                "midpoint": {
                    "type": "NUMBER", "value": "0.5",
                    "color": {"red": 1.00, "green": 0.82, "blue": 0.20},
                },
                "maxpoint": {
                    "type": "NUMBER", "value": "1",
                    "color": {"red": 0.46, "green": 0.73, "blue": 0.00},
                },
            },
        },
        "index": 0,
    }})

    for period_index, _hours in enumerate(period_hours):
        period_column = (
            period_start_column
            + period_index * len(CABLING_SUM_METRIC_HEADERS)
        )
        opened_column = period_column + CABLING_SUM_METRIC_HEADERS.index("Opened")
        closed_column = period_column + CABLING_SUM_METRIC_HEADERS.index("Closed")
        delta_column = period_column + CABLING_SUM_METRIC_HEADERS.index("Delta")
        add_rule(opened_column, opened_column + 1, "NUMBER_GREATER", red)
        add_rule(closed_column, closed_column + 1, "NUMBER_GREATER", green)
        add_rule(delta_column, delta_column + 1, "NUMBER_GREATER", red)
        add_rule(delta_column, delta_column + 1, "NUMBER_LESS", blue)
    return requests


def cabling_sum_protocol_divider_requests(
    sheet_id: int,
    rows: list[list[Any]],
    column_count: int,
    end_row_index: int,
) -> list[dict[str, Any]]:
    """Return dynamic green row dividers between IB and ETH groups."""
    if end_row_index <= 3 or column_count <= 0:
        return []
    no_border = {"style": "NONE"}
    requests: list[dict[str, Any]] = [{"updateBorders": {
        "range": {
            "sheetId": sheet_id,
            "startRowIndex": 3,
            "endRowIndex": end_row_index,
            "startColumnIndex": 0,
            "endColumnIndex": column_count,
        },
        "top": no_border,
        "bottom": no_border,
        "innerHorizontal": no_border,
    }}]
    divider = {
        "style": "SOLID_MEDIUM",
        "color": CABLING_SUM_DIVIDER_COLOR,
    }
    for row_offset in range(1, len(rows)):
        previous = rows[row_offset - 1]
        current = rows[row_offset]
        previous_instance = str(previous[1] if len(previous) > 1 else "")
        current_instance = str(current[1] if len(current) > 1 else "")
        previous_type = str(previous[2] if len(previous) > 2 else "").upper()
        current_type = str(current[2] if len(current) > 2 else "").upper()
        if (
            previous_instance == current_instance
            and previous_type == "IB"
            and current_type == "ETH"
        ):
            row_index = 3 + row_offset
            requests.append({"updateBorders": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": row_index,
                    "endRowIndex": row_index + 1,
                    "startColumnIndex": 0,
                    "endColumnIndex": column_count,
                },
                "top": divider,
            }})
    return requests


def _cabling_sum_number(value: Any) -> int:
    """Return one Cabling_SUM metric as an integer for chart aggregation."""
    try:
        return int(float(str(value or 0).replace(",", "")))
    except (TypeError, ValueError):
        return 0


def cabling_sum_issue_bucket(value: Any) -> str:
    """Collapse one Cabling Issue Type into the chart's three categories."""
    categories = {
        item.strip().casefold()
        for item in str(value or "").split(";")
        if item.strip()
    }
    # Match the CVT classification priority used elsewhere: Flapping remains
    # an Other category even if a composite description also mentions link down.
    if "flapping" in categories:
        return "Others"
    if "mis-wiring" in categories or "miswiring" in categories:
        return "Mis-wiring"
    if "link down" in categories or "linkdown" in categories:
        return "Link Down"
    return "Others"


def build_cabling_sum_case_issue_metrics(
    reports: list[tuple[str, str, list[list[Any]]]],
) -> dict[tuple[str, str, str], Counter[str]]:
    """Aggregate current non-Closed Cabling Cases by Instance, type, and A-SU."""
    grouped: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
    required_headers = {"Status", "Error", "Local SU Number", INSTANCE_HEADER}
    for instance_name, cabling_type, values in reports:
        if not values:
            continue
        positions = {
            str(header): index for index, header in enumerate(values[0])
        }
        missing = sorted(required_headers - positions.keys())
        if missing:
            raise ValueError(
                "Cabling summary Case source is missing required columns: "
                + ", ".join(missing)
            )

        def cell(row: list[Any], header: str) -> str:
            index = positions[header]
            return str(row[index] if index < len(row) else "").strip()

        expected_instance = str(instance_name or "").strip().casefold()
        scope_instance = str(instance_name or "Unknown").strip() or "Unknown"
        scope_type = str(cabling_type or "ALL").strip().upper() or "ALL"
        for row in values[1:]:
            row_instance = cell(row, INSTANCE_HEADER).casefold()
            if row_instance != expected_instance:
                continue
            if cell(row, "Status").casefold() == "closed":
                continue
            a_su = cell(row, "Local SU Number") or "Unknown"
            bucket = cabling_sum_issue_bucket(cell(row, "Error"))
            grouped[(scope_instance, scope_type, a_su)][bucket] += 1
    return grouped


def build_cabling_sum_chart_tables(
    rows: list[list[Any]],
    period_hours: list[int] | tuple[int, ...] = DEFAULT_CABLING_SUM_PERIOD_HOURS,
    event_rows: list[list[Any]] | None = None,
    timezone_name: str = DEFAULT_TIMEZONE,
    now: datetime | None = None,
    cabling_reports: list[tuple[str, str, list[list[Any]]]] | None = None,
) -> list[dict[str, Any]]:
    """Build one five-chart helper set for each populated Instance/Protocol."""
    period_hours = normalize_cabling_sum_period_hours(
        period_hours, "cabling_sum_period_hours"
    )
    scoped_rows: dict[tuple[str, str], list[list[Any]]] = defaultdict(list)
    for row in rows:
        expected_width = (
            len(CABLING_SUM_DIMENSION_HEADERS)
            + len(CABLING_SUM_CVT_HEADERS)
            + len(period_hours) * len(CABLING_SUM_METRIC_HEADERS)
        )
        padded = [*row, *([""] * max(0, expected_width - len(row)))]
        instance = str(padded[1] or "Unknown").strip() or "Unknown"
        cabling_type = str(padded[2] or "").strip().upper()
        if cabling_type in {"ETH", "IB"}:
            scoped_rows[(instance, cabling_type)].append(padded)

    type_order = {"ETH": 0, "IB": 1}
    scopes = sorted(
        scoped_rows,
        key=lambda item: (item[0].casefold(), type_order[item[1]]),
    )
    case_issue_metrics = build_cabling_sum_case_issue_metrics(
        cabling_reports or []
    )
    tables: list[dict[str, Any]] = []
    for scope_index, (instance, cabling_type) in enumerate(scopes):
        open_by_su: dict[str, Counter[str]] = defaultdict(Counter)
        health_by_su_link: dict[tuple[str, str], Counter[str]] = defaultdict(
            Counter
        )
        for padded in scoped_rows[(instance, cabling_type)]:
            a_su = str(padded[3] or "Unknown")
            link_type = str(padded[4] or "Unknown").title()
            open_by_su[a_su][link_type] += max(
                0, _cabling_sum_number(padded[7])
            )
            for index, metric in (
                (6, "Pass"), (8, "Link Down"),
                (9, "Mis-wiring"), (10, "Others"),
            ):
                health_by_su_link[(a_su, link_type)][metric] += _cabling_sum_number(
                    padded[index]
                )

        open_rows = [
            [a_su, counts["Host"], counts["Switch"]]
            for a_su, counts in sorted(
                open_by_su.items(), key=lambda item: item[0].casefold()
            )
        ]
        issue_by_su = {
            a_su: counts
            for (metric_instance, metric_type, a_su), counts
            in case_issue_metrics.items()
            if metric_instance == instance and metric_type == cabling_type
        }
        issue_rows = [
            [a_su, counts["Link Down"], counts["Mis-wiring"], counts["Others"]]
            for a_su, counts in sorted(
                issue_by_su.items(), key=lambda item: item[0].casefold()
            )
        ]
        health_rows = [
            [f"{a_su} / {link_type}", counts["Pass"], counts["Link Down"],
             counts["Mis-wiring"], counts["Others"]]
            for (a_su, link_type), counts in sorted(
                health_by_su_link.items(),
                key=lambda item: (
                    item[0][0].casefold(),
                    {"Host": 0, "Switch": 1}.get(item[0][1], 2),
                    item[0][1].casefold(),
                ),
            )
        ]
        burn_down_rows, net_flow_rows = build_hourly_cabling_event_chart_rows(
            event_rows or [], timezone_name, max(period_hours), now,
            instance_name=instance, cabling_type=cabling_type,
        )
        title_prefix = f"{instance} / {cabling_type}"
        alt_prefix = f"{instance}|{cabling_type}|"
        start_column = scope_index * CABLING_SUM_CHART_SCOPE_COLUMNS
        tables.extend([
            {
                "title": f"{title_prefix} - Open Issues by A-SU and Link Type",
                "alt": f"{alt_prefix}open-by-su",
                "startColumn": start_column,
                "headers": ["A-SU", "Host", "Switch"],
                "rows": open_rows,
                "chartType": "BAR",
                "stackedType": "STACKED",
                "series": [("Host", "#76B900", "BAR", "BOTTOM_AXIS"),
                           ("Switch", "#4285F4", "BAR", "BOTTOM_AXIS")],
            },
            {
                "title": f"{title_prefix} - Issue Breakdown by A-SU",
                "alt": f"{alt_prefix}issue-breakdown",
                "startColumn": start_column + 4,
                "headers": ["A-SU", "Link Down", "Mis-wiring", "Others"],
                "rows": issue_rows,
                "chartType": "COLUMN",
                "stackedType": "STACKED",
                "series": [("Link Down", "#E53935", "COLUMN", "LEFT_AXIS"),
                           ("Mis-wiring", "#FB8C00", "COLUMN", "LEFT_AXIS"),
                           ("Others", "#7E57C2", "COLUMN", "LEFT_AXIS")],
            },
            {
                "title": f"{title_prefix} - Link Health by A-SU and Link Type",
                "alt": f"{alt_prefix}link-health",
                "startColumn": start_column + 9,
                "headers": ["A-SU / Link Type", "Pass", "Link Down",
                            "Mis-wiring", "Others"],
                "rows": health_rows,
                "chartType": "BAR",
                "stackedType": "PERCENT_STACKED",
                "series": [("Pass", "#76B900", "BAR", "BOTTOM_AXIS"),
                           ("Link Down", "#E53935", "BAR", "BOTTOM_AXIS"),
                           ("Mis-wiring", "#FB8C00", "BAR", "BOTTOM_AXIS"),
                           ("Others", "#7E57C2", "BAR", "BOTTOM_AXIS")],
            },
            {
                "title": f"{title_prefix} - Fault Backlog Burn-down",
                "alt": f"{alt_prefix}backlog-burn-down",
                "startColumn": start_column + 15,
                "headers": ["Hour", "Cumulative Opened", "Cumulative Closed",
                            "Open Backlog"],
                "rows": burn_down_rows,
                "chartType": "COMBO",
                "stackedType": "NOT_STACKED",
                "series": [
                    ("Cumulative Opened", "#4285F4", "LINE", "LEFT_AXIS"),
                    ("Cumulative Closed", "#22A06B", "LINE", "LEFT_AXIS"),
                    ("Open Backlog", "#F4CCCC", "AREA", "LEFT_AXIS"),
                ],
            },
            {
                "title": f"{title_prefix} - Hourly Case Flow",
                "alt": f"{alt_prefix}hourly-net-flow",
                "startColumn": start_column + 20,
                "headers": ["Hour", "OPEN", "CLOSE", "Net"],
                "rows": net_flow_rows,
                "chartType": "COMBO",
                "stackedType": "NOT_STACKED",
                "series": [
                    ("OPEN", "#CC0000", "COLUMN", "LEFT_AXIS"),
                    ("CLOSE", "#70AD47", "COLUMN", "LEFT_AXIS"),
                    ("Net", "#4285F4", "LINE", "RIGHT_AXIS"),
                ],
            },
        ])
    return tables


def build_hourly_cabling_event_chart_rows(
    event_rows: list[list[Any]],
    timezone_name: str = DEFAULT_TIMEZONE,
    hours: int = 24,
    now: datetime | None = None,
    instance_name: str | None = None,
    cabling_type: str | None = None,
) -> tuple[list[list[Any]], list[list[Any]]]:
    """Build scoped hourly backlog burn-down and net-flow combo series."""
    current_time = operational_now(timezone_name, now)
    current_hour = current_time.replace(minute=0, second=0, microsecond=0)
    bucket_count = max(1, int(hours))
    first_hour = current_hour - timedelta(hours=bucket_count - 1)
    opened_counts: Counter[datetime] = Counter()
    closed_counts: Counter[datetime] = Counter()
    snapshot_history: dict[tuple[str, str, str, str], dict[datetime, int]] = (
        defaultdict(dict)
    )
    positions = {header: index for index, header in enumerate(CABLING_EVENT_HEADERS)}
    time_index = positions["Event Time"]
    type_index = positions["Event Type"]

    def event_cell(row: list[Any], header: str) -> str:
        index = positions[header]
        return str(row[index] if index < len(row) else "").strip()

    for row in event_rows:
        if (
            instance_name is not None
            and event_cell(row, "Instance").casefold()
            != instance_name.casefold()
        ):
            continue
        if (
            cabling_type is not None
            and event_cell(row, "Cabling Type").upper()
            != cabling_type.upper()
        ):
            continue
        event_type = str(row[type_index] if type_index < len(row) else "").upper()
        if event_type not in {
            CABLING_EVENT_BASELINE,
            CABLING_EVENT_OPEN,
            CABLING_EVENT_CLOSE,
            CABLING_EVENT_SNAPSHOT,
        }:
            continue
        timestamp = parse_cabling_event_time(
            row[time_index] if time_index < len(row) else "", timezone_name
        )
        if timestamp is None or timestamp > current_time:
            continue
        bucket = timestamp.replace(minute=0, second=0, microsecond=0)
        if event_type in {CABLING_EVENT_BASELINE, CABLING_EVENT_OPEN}:
            if bucket >= first_hour:
                opened_counts[bucket] += 1
            continue
        if event_type == CABLING_EVENT_CLOSE:
            if bucket >= first_hour:
                closed_counts[bucket] += 1
            continue
        try:
            open_count_index = positions["Open Count"]
            open_count = max(0, int(float(
                row[open_count_index] if open_count_index < len(row) else 0
            )))
        except (TypeError, ValueError):
            continue
        group = (
            event_cell(row, "Instance"),
            event_cell(row, "Cabling Type").upper() or "ALL",
            normalized_event_su(event_cell(row, "A-SU")),
            normalized_event_link_type(event_cell(row, "Link Type")),
        )
        snapshot_history[group][bucket] = open_count

    sorted_snapshots = {
        group: sorted(history.items())
        for group, history in snapshot_history.items()
    }

    def open_total_at(hour: datetime) -> Any:
        total = 0
        found = False
        for history in sorted_snapshots.values():
            latest = next(
                (count for timestamp, count in reversed(history) if timestamp <= hour),
                None,
            )
            if latest is not None:
                found = True
                total += latest
        return total if found else ""

    buckets = [
        first_hour + timedelta(hours=offset) for offset in range(bucket_count)
    ]
    observed_backlogs = [open_total_at(bucket) for bucket in buckets]
    first_observed_index = next(
        (
            index for index, backlog in enumerate(observed_backlogs)
            if backlog != ""
        ),
        None,
    )
    initial_backlog = 0
    if first_observed_index is not None:
        observed = int(observed_backlogs[first_observed_index])
        opened_through_observation = sum(
            opened_counts[bucket]
            for bucket in buckets[:first_observed_index + 1]
        )
        closed_through_observation = sum(
            closed_counts[bucket]
            for bucket in buckets[:first_observed_index + 1]
        )
        initial_backlog = max(
            0,
            observed - opened_through_observation + closed_through_observation,
        )

    cumulative_opened = initial_backlog
    cumulative_closed = 0
    burn_down_rows: list[list[Any]] = []
    net_flow_rows: list[list[Any]] = []
    for bucket in buckets:
        opened = opened_counts[bucket]
        closed = closed_counts[bucket]
        cumulative_opened += opened
        cumulative_closed += closed
        open_backlog = max(0, cumulative_opened - cumulative_closed)
        label = bucket.strftime("%m-%d %H:00")
        burn_down_rows.append([
            label, cumulative_opened, cumulative_closed, open_backlog,
        ])
        net_flow_rows.append([label, opened, closed, opened - closed])
    return burn_down_rows, net_flow_rows


def _chart_grid_range(
    sheet_id: int, start_column: int, end_column: int, row_count: int,
) -> dict[str, int]:
    return {
        "sheetId": sheet_id,
        "startRowIndex": 0,
        "endRowIndex": row_count,
        "startColumnIndex": start_column,
        "endColumnIndex": end_column,
    }


def _chart_rgb_color(value: str) -> dict[str, float]:
    """Convert a six-digit CSS hex color to a Sheets API RGB color."""
    normalized = value.strip().lstrip("#")
    return {
        "red": int(normalized[0:2], 16) / 255,
        "green": int(normalized[2:4], 16) / 255,
        "blue": int(normalized[4:6], 16) / 255,
    }


def _cabling_sum_chart_spec(
    table: dict[str, Any], sheet_id: int,
) -> dict[str, Any]:
    start_column = int(table["startColumn"])
    row_count = 1 + len(table["rows"])
    domain = _chart_grid_range(sheet_id, start_column, start_column + 1, row_count)
    series: list[dict[str, Any]] = []
    for offset, (_name, color, series_type, axis) in enumerate(table["series"], 1):
        series_range = _chart_grid_range(
            sheet_id, start_column + offset, start_column + offset + 1, row_count
        )
        item: dict[str, Any] = {
            "series": {"sourceRange": {"sources": [series_range]}},
            "targetAxis": axis,
            "colorStyle": {"rgbColor": _chart_rgb_color(color)},
        }
        if table["chartType"] == "COMBO":
            item["type"] = series_type
        series.append(item)
    axes = [
        {"position": "BOTTOM_AXIS", "title": "Category"},
        {"position": "LEFT_AXIS", "title": "Links"},
    ]
    if any(item[3] == "RIGHT_AXIS" for item in table["series"]):
        axes.append({"position": "RIGHT_AXIS", "title": "Delta"})
    basic_chart = {
        "chartType": table["chartType"],
        "legendPosition": "BOTTOM_LEGEND",
        "axis": axes,
        "domains": [{"domain": {"sourceRange": {"sources": [domain]}}}],
        "series": series,
        "headerCount": 1,
    }
    if table["chartType"] in {"BAR", "COLUMN", "AREA", "STEPPED_AREA"}:
        basic_chart["stackedType"] = table["stackedType"]
    return {
        "title": table["title"],
        "altText": f"{CABLING_SUM_CHART_ALT_PREFIX}{table['alt']}",
        "fontName": "Arial",
        "titleTextFormat": {"bold": True, "fontSize": 14},
        "backgroundColorStyle": {
            "rgbColor": {"red": 1.0, "green": 1.0, "blue": 1.0}
        },
        "hiddenDimensionStrategy": "SHOW_ALL",
        "basicChart": basic_chart,
    }


def cabling_sum_chart_data_sheet_name(sheet_name: str) -> str:
    """Return the hidden helper-sheet name for one Cabling_SUM worksheet."""
    base = str(sheet_name or DEFAULT_CABLING_SUM_SHEET).strip()
    return f"_{base[:80]}_ChartData"


def chart_config_matches(current: Any, desired: Any) -> bool:
    """Compare managed chart fields, tolerating API defaults/float round trips."""
    if isinstance(desired, dict):
        return isinstance(current, dict) and all(
            chart_config_matches(current.get(key, 0 if value == 0 else None), value)
            for key, value in desired.items()
        )
    if isinstance(desired, list):
        return (isinstance(current, list) and len(current) == len(desired)
                and all(chart_config_matches(a, b) for a, b in zip(current, desired)))
    if isinstance(desired, (int, float)) and isinstance(current, (int, float)):
        return abs(current - desired) < 1e-6
    return current == desired


def refresh_cabling_sum_charts(
    service: Any,
    spreadsheet_id: str,
    sheet_name: str,
    rows: list[list[Any]],
    period_hours: list[int] | tuple[int, ...] = DEFAULT_CABLING_SUM_PERIOD_HOURS,
    event_rows: list[list[Any]] | None = None,
    timezone_name: str = DEFAULT_TIMEZONE,
    cabling_reports: list[tuple[str, str, list[list[Any]]]] | None = None,
) -> int:
    """Refresh per-Instance/Protocol chart blocks without touching user charts."""
    tables = build_cabling_sum_chart_tables(
        rows, period_hours, event_rows, timezone_name,
        cabling_reports=cabling_reports,
    )
    helper_sheet_name = cabling_sum_chart_data_sheet_name(sheet_name)
    ensure_sheet(service, spreadsheet_id, helper_sheet_name)
    metadata = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id,
        fields=(
            "sheets(properties(sheetId,title,gridProperties,hidden),"
            "charts(chartId,spec,position))"
        ),
    ).execute()
    requested = str(sheet_name).casefold()
    sheet = next(
        item for item in metadata.get("sheets", [])
        if str(item["properties"]["title"]).casefold() == requested
    )
    helper_requested = helper_sheet_name.casefold()
    helper_sheet = next(
        item for item in metadata.get("sheets", [])
        if str(item["properties"]["title"]).casefold() == helper_requested
    )
    properties = sheet["properties"]
    sheet_id = int(properties["sheetId"])
    helper_properties = helper_sheet["properties"]
    helper_sheet_id = int(helper_properties["sheetId"])
    grid = properties.get("gridProperties", {})
    grid_columns = int(grid.get("columnCount", 0))
    grid_rows = int(grid.get("rowCount", 0))
    helper_grid = helper_properties.get("gridProperties", {})
    helper_grid_columns = int(helper_grid.get("columnCount", 0))
    helper_grid_rows = int(helper_grid.get("rowCount", 0))
    chart_start_row = max(12, 4 + len(rows))
    scope_count = (
        len(tables) + CABLING_SUM_CHARTS_PER_SCOPE - 1
    ) // CABLING_SUM_CHARTS_PER_SCOPE
    required_rows = chart_start_row + scope_count * CABLING_SUM_CHART_SCOPE_ROWS
    helper_required_rows = max(
        (1 + len(table["rows"]) for table in tables), default=1
    )
    helper_required_columns = max(
        (
            int(table["startColumn"]) + len(table["headers"])
            for table in tables
        ),
        default=1,
    )
    resize_requests: list[dict[str, Any]] = []
    if helper_grid_columns < helper_required_columns:
        resize_requests.append({"appendDimension": {
            "sheetId": helper_sheet_id,
            "dimension": "COLUMNS",
            "length": helper_required_columns - helper_grid_columns,
        }})
    if helper_grid_rows < helper_required_rows:
        resize_requests.append({"appendDimension": {
            "sheetId": helper_sheet_id,
            "dimension": "ROWS",
            "length": helper_required_rows - helper_grid_rows,
        }})
    if grid_rows < required_rows:
        resize_requests.append({"appendDimension": {
            "sheetId": sheet_id,
            "dimension": "ROWS",
            "length": required_rows - grid_rows,
        }})
    if resize_requests:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id, body={"requests": resize_requests}
        ).execute()

    quoted = quoted_sheet_name(helper_sheet_name)
    helper_clear_end = sheet_column_name(
        max(helper_grid_columns, helper_required_columns, 1) - 1
    )
    old_helper = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id,
        range=f"{quoted}!A1:{helper_clear_end}",
        valueRenderOption="UNFORMATTED_VALUE",
    ).execute().get("values", [])
    helper_width = max(helper_grid_columns, helper_required_columns, 1)
    # Pad the old occupied footprint too: disappearing groups/shorter timelines
    # must not leave old values behind in the hidden, tool-owned helper sheet.
    helper_values = [[""] * helper_width
                     for _ in range(max(len(old_helper), helper_required_rows))]
    for table in tables:
        left = int(table["startColumn"])
        for r, row in enumerate([table["headers"], *table["rows"]]):
            helper_values[r][left:left + len(row)] = row
    helper_data = table_value_delta(helper_sheet_name, old_helper, helper_values, helper_width, start_row=1)
    persist_value_delta(GoogleSheetsRepository(service, spreadsheet_id), helper_data, "RAW")

    managed = {
        str(chart.get("spec", {}).get("altText", "")): chart
        for chart in sheet.get("charts", [])
        if str(chart.get("spec", {}).get("altText", "")).startswith(
            CABLING_SUM_CHART_ALT_PREFIX
        )
    }
    requests: list[dict[str, Any]] = [] if helper_properties.get("hidden") else [{"updateSheetProperties": {
        "properties": {"sheetId": helper_sheet_id, "hidden": True},
        "fields": "hidden",
    }}]
    desired_alt_texts: set[str] = set()
    for table_index, table in enumerate(tables):
        scope_index, chart_index = divmod(
            table_index, CABLING_SUM_CHARTS_PER_SCOPE
        )
        row_index = (
            chart_start_row
            + scope_index * CABLING_SUM_CHART_SCOPE_ROWS
            + (46 if chart_index == 4 else 23 if chart_index >= 2 else 0)
        )
        is_right_chart = chart_index in {1, 3}
        width_pixels = 1540 if chart_index == 4 else 760
        spec = _cabling_sum_chart_spec(table, helper_sheet_id)
        desired_alt_texts.add(spec["altText"])
        position = {"overlayPosition": {
            "anchorCell": {
                "sheetId": sheet_id,
                "rowIndex": row_index,
                "columnIndex": 0,
            },
            "offsetXPixels": 780 if is_right_chart else 0,
            "offsetYPixels": 8,
            "widthPixels": width_pixels,
            "heightPixels": 420,
        }}
        existing = managed.get(spec["altText"])
        if existing:
            chart_id = int(existing["chartId"])
            if not chart_config_matches(existing.get("spec"), spec):
                requests.append({"updateChartSpec": {"chartId": chart_id, "spec": spec}})
            if not chart_config_matches(existing.get("position"), position):
                requests.append({"updateEmbeddedObjectPosition": {
                    "objectId": chart_id,
                    "newPosition": position,
                    "fields": (
                        "anchorCell,offsetXPixels,offsetYPixels,"
                        "widthPixels,heightPixels"
                    ),
                }})
        else:
            requests.append({"addChart": {
                "chart": {"spec": spec, "position": position}
            }})
    for alt_text, chart in managed.items():
        if alt_text not in desired_alt_texts:
            requests.append({"deleteEmbeddedObject": {
                "objectId": int(chart["chartId"]),
            }})
    main_column_count = (
        len(CABLING_SUM_DIMENSION_HEADERS)
        + len(CABLING_SUM_CVT_HEADERS)
        + len(period_hours) * len(CABLING_SUM_METRIC_HEADERS)
    )
    if grid_columns > main_column_count:
        # Remove legacy in-sheet chart helper columns after every managed chart
        # has been repointed to the hidden helper worksheet.
        requests.append({"deleteDimension": {"range": {
            "sheetId": sheet_id,
            "dimension": "COLUMNS",
            "startIndex": main_column_count,
            "endIndex": grid_columns,
        }}})
    if requests:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id, body={"requests": requests}
        ).execute()
    return len(tables)


def refresh_cabling_sum_sheet(
    service: Any,
    spreadsheet_id: str,
    sheet_name: str,
    event_rows: list[list[Any]],
    timezone_name: str = DEFAULT_TIMEZONE,
    cvt_reports: list[tuple[str, list[list[Any]]]] | None = None,
    period_hours: list[int] | tuple[int, ...] = DEFAULT_CABLING_SUM_PERIOD_HOURS,
    cabling_reports: list[tuple[str, str, list[list[Any]]]] | None = None,
) -> dict[str, Any]:
    """Replace Cabling_SUM with one formatted A-SU and Link-Type table."""
    period_hours = normalize_cabling_sum_period_hours(
        period_hours, "cabling_sum_period_hours"
    )
    rows, point_time = build_cabling_sum_rows(
        event_rows, timezone_name, cvt_reports=cvt_reports,
        period_hours=period_hours,
    )
    ensure_sheet(service, spreadsheet_id, sheet_name)
    metadata = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id,
        fields=(
            "sheets(properties(sheetId,title,gridProperties),merges,"
            "conditionalFormats)"
        ),
    ).execute()
    requested = str(sheet_name).casefold()
    sheet = next(
        item for item in metadata.get("sheets", [])
        if str(item["properties"]["title"]).casefold() == requested
    )
    properties = sheet["properties"]
    sheet_id = properties["sheetId"]
    existing_merges = sheet.get("merges", [])
    dimension_count = len(CABLING_SUM_DIMENSION_HEADERS)
    cvt_info_count = len(CABLING_SUM_CVT_HEADERS)
    period_start_column = dimension_count + cvt_info_count
    column_count = (
        period_start_column
        + len(period_hours) * len(CABLING_SUM_METRIC_HEADERS)
    )
    required_rows = 3 + len(rows)
    grid = properties.get("gridProperties", {})
    formatted_row_count = max(int(grid.get("rowCount", 0)), required_rows)
    grid_column_count = int(grid.get("columnCount", 0))
    quoted = quoted_sheet_name(sheet_name)
    last_column = sheet_column_name(column_count - 1)
    header_read_column_count = max(1, min(grid_column_count, column_count))
    header_read_last_column = sheet_column_name(header_read_column_count - 1)
    existing_header_rows = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id,
        range=f"{quoted}!A2:{header_read_last_column}3",
    ).execute().get("values", [])
    header_present = any(
        str(cell or "").strip()
        for row in existing_header_rows
        for cell in row
    )
    existing_detail_headers = (
        normalize_instance_headers([str(value or "").strip() for value in existing_header_rows[1]])
        if len(existing_header_rows) > 1 else []
    )
    current_prefix = [*CABLING_SUM_DIMENSION_HEADERS, *CABLING_SUM_CVT_HEADERS]
    legacy_prefixes = [
        [*CABLING_SUM_DIMENSION_HEADERS, *CABLING_SUM_LEGACY_CVT_HEADERS],
        [*CABLING_SUM_DIMENSION_HEADERS, *CABLING_SUM_PASS_RATE_CVT_HEADERS],
        [
            *CABLING_SUM_DIMENSION_HEADERS,
            *CABLING_SUM_PASS_PROGRESS_CVT_HEADERS,
        ],
    ]
    schema_migration = (
        header_present
        and existing_detail_headers[:len(current_prefix)] != current_prefix
        and any(
            existing_detail_headers[:len(prefix)] == prefix
            for prefix in legacy_prefixes
        )
    )
    rebuild_layout = not header_present or schema_migration
    cleanup_requests: list[dict[str, Any]] = []
    if rebuild_layout and existing_merges:
        # Rebuild tool-managed group merges when creating the table or adding
        # a managed column, so rolling-window headers cannot remain shifted.
        cleanup_requests.extend(
            {"unmergeCells": {"range": merge}} for merge in existing_merges
        )
    if schema_migration:
        cleanup_requests.extend(
            {"deleteConditionalFormatRule": {
                "sheetId": sheet_id, "index": index,
            }}
            for index in reversed(range(len(sheet.get("conditionalFormats", []))))
        )
    if cleanup_requests:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": cleanup_requests},
        ).execute()
    resize_requests: list[dict[str, Any]] = []
    if grid_column_count < column_count:
        resize_requests.append({"appendDimension": {
            "sheetId": sheet_id,
            "dimension": "COLUMNS",
            "length": column_count - grid_column_count,
        }})
    elif grid_column_count > column_count:
        # Cabling_SUM is fully managed by CableTracker. Shrink obsolete columns
        # so values and formatting from older, wider layouts cannot remain.
        resize_requests.append({"deleteDimension": {"range": {
            "sheetId": sheet_id,
            "dimension": "COLUMNS",
            "startIndex": column_count,
            "endIndex": grid_column_count,
        }}})
    if int(grid.get("rowCount", 0)) < required_rows:
        resize_requests.append({"appendDimension": {
            "sheetId": sheet_id,
            "dimension": "ROWS",
            "length": required_rows - int(grid.get("rowCount", 0)),
        }})
    resize_requests.extend(cabling_sum_protocol_divider_requests(
        sheet_id, rows, column_count, formatted_row_count,
    ))
    if resize_requests:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id, body={"requests": resize_requests}
        ).execute()

    preserve_existing_layout = header_present and not schema_migration
    data_start_row = 3 if preserve_existing_layout else 2
    service.spreadsheets().values().clear(
        spreadsheetId=spreadsheet_id,
        range=f"{quoted}!A{data_start_row}:{last_column}",
        body={},
    ).execute()
    headers = cabling_sum_header_rows(period_hours)
    table_values = (
        [headers[1], *rows] if preserve_existing_layout else [*headers, *rows]
    )
    data = [
        {
            "range": f"{quoted}!A1",
            "values": [[f"Updated at: {point_time}"]],
        },
        {
            "range": f"{quoted}!A{data_start_row}",
            "values": table_values,
        },
    ]
    if preserve_existing_layout:
        group_labels = [
            (0, "Cabling progress by A-SU and Link Type"),
            (dimension_count, "CVT Information"),
            *[
                (
                    period_start_column
                    + period_index * len(CABLING_SUM_METRIC_HEADERS),
                    f"Last {hours} Hour{'s' if hours != 1 else ''}",
                )
                for period_index, hours in enumerate(period_hours)
            ],
        ]
        data.extend({
            "range": (
                f"{quoted}!{sheet_column_name(column_index)}2"
            ),
            "values": [[label]],
        } for column_index, label in group_labels)
    service.spreadsheets().values().batchUpdate(
        spreadsheetId=spreadsheet_id,
        body={"valueInputOption": "RAW", "data": data},
    ).execute()
    if rows:
        pass_rate_column = (
            dimension_count + CABLING_SUM_CVT_HEADERS.index("Rate")
        )
        progress_column = (
            dimension_count + CABLING_SUM_CVT_HEADERS.index("Progress")
        )
        pass_rate_letter = sheet_column_name(pass_rate_column)
        progress_letter = sheet_column_name(progress_column)
        first_data_row = 4
        last_data_row = first_data_row + len(rows) - 1
        formulas = [
            [
                f'=IF({pass_rate_letter}{row_number}="","",'
                f'SPARKLINE({pass_rate_letter}{row_number},'
                '{"charttype","bar";"max",1;"color1","#76B900"}))'
            ]
            for row_number in range(first_data_row, last_data_row + 1)
        ]
        service.spreadsheets().values().update(
            spreadsheetId=spreadsheet_id,
            range=(
                f"{quoted}!{progress_letter}{first_data_row}:"
                f"{progress_letter}{last_data_row}"
            ),
            valueInputOption="USER_ENTERED",
            body={"values": formulas},
        ).execute()
    chart_count = refresh_cabling_sum_charts(
        service, spreadsheet_id, sheet_name, rows, period_hours,
        event_rows, timezone_name, cabling_reports,
    )

    if preserve_existing_layout:
        return {
            "summaryRows": len(rows),
            "updatedAt": point_time,
            "formatApplied": False,
            "chartCount": chart_count,
        }

    def gradient_color(
        start: dict[str, float], end: dict[str, float], index: int, count: int,
    ) -> dict[str, float]:
        ratio = index / max(count - 1, 1)
        return {
            channel: start[channel] + (end[channel] - start[channel]) * ratio
            for channel in ("red", "green", "blue")
        }

    section_count = 2 + len(period_hours)
    group_palette = [
        gradient_color(
            {"red": 0.46, "green": 0.73, "blue": 0.00},
            {"red": 0.40, "green": 0.40, "blue": 0.40},
            index,
            section_count,
        )
        for index in range(section_count)
    ]
    detail_palette = [
        gradient_color(
            {"red": 0.87, "green": 0.94, "blue": 0.76},
            {"red": 0.91, "green": 0.91, "blue": 0.91},
            index,
            section_count,
        )
        for index in range(section_count)
    ]
    body_palette = [
        gradient_color(
            {"red": 0.97, "green": 0.98, "blue": 0.94},
            {"red": 0.99, "green": 0.99, "blue": 0.99},
            index,
            section_count,
        )
        for index in range(section_count)
    ]
    dimension_group_fill, cvt_group_fill = group_palette[:2]
    dimension_detail_fill, cvt_detail_fill = detail_palette[:2]
    cvt_body_fill = body_palette[1]
    format_requests: list[dict[str, Any]] = [{"mergeCells": {
        "range": {
            "sheetId": sheet_id,
            "startRowIndex": 0,
            "endRowIndex": 1,
            "startColumnIndex": 0,
            "endColumnIndex": 2,
        },
        "mergeType": "MERGE_ALL",
    }}]
    table_sections = ((1, 3, 3 + len(rows)),)
    for header_row, data_start_row, data_end_row in table_sections:
        format_requests.append({"mergeCells": {
            "range": {
                "sheetId": sheet_id,
                "startRowIndex": header_row,
                "endRowIndex": header_row + 1,
                "startColumnIndex": 0,
                "endColumnIndex": dimension_count,
            },
            "mergeType": "MERGE_ALL",
        }})
        format_requests.extend([
            {"mergeCells": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": header_row + 1,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": period_start_column,
                },
                "mergeType": "MERGE_ALL",
            }},
            {"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": header_row + 1,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": period_start_column,
                },
                "cell": {"userEnteredFormat": {
                    "backgroundColor": cvt_group_fill,
                    "textFormat": {
                        "bold": True,
                        "fontFamily": "Arial",
                        "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                    },
                    "horizontalAlignment": "CENTER",
                }},
                "fields": (
                    "userEnteredFormat(backgroundColor,textFormat,"
                    "horizontalAlignment)"
                ),
            }},
            {"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row + 1,
                    "endRowIndex": header_row + 2,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": period_start_column,
                },
                "cell": {"userEnteredFormat": {
                    "backgroundColor": cvt_detail_fill,
                    "textFormat": {
                        "bold": True,
                        "fontFamily": "Arial",
                        "foregroundColor": {"red": 0.12, "green": 0.12, "blue": 0.12},
                    },
                    "horizontalAlignment": "CENTER",
                }},
                "fields": (
                    "userEnteredFormat(backgroundColor,textFormat,"
                    "horizontalAlignment)"
                ),
            }},
            {"updateBorders": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": data_end_row,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": period_start_column,
                },
                "left": {
                    "style": "SOLID_MEDIUM",
                    "color": cvt_group_fill,
                },
                "right": {
                    "style": "SOLID_MEDIUM",
                    "color": cvt_group_fill,
                },
            }},
        ])
        if data_end_row > data_start_row:
            format_requests.append({"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": data_start_row,
                    "endRowIndex": data_end_row,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": period_start_column,
                },
                "cell": {"userEnteredFormat": {
                    "backgroundColor": cvt_body_fill,
                }},
                "fields": "userEnteredFormat.backgroundColor",
            }})
        for period_index, _hours in enumerate(period_hours):
            palette_index = period_index + 2
            group_fill = group_palette[palette_index]
            detail_fill = detail_palette[palette_index]
            body_fill = body_palette[palette_index]
            start_column = (
                period_start_column
                + period_index * len(CABLING_SUM_METRIC_HEADERS)
            )
            format_requests.append({"mergeCells": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": header_row + 1,
                    "startColumnIndex": start_column,
                    "endColumnIndex": start_column + len(CABLING_SUM_METRIC_HEADERS),
                },
                "mergeType": "MERGE_ALL",
            }})
            format_requests.extend([
                {"repeatCell": {
                    "range": {
                        "sheetId": sheet_id,
                        "startRowIndex": header_row,
                        "endRowIndex": header_row + 1,
                        "startColumnIndex": start_column,
                        "endColumnIndex": start_column + len(CABLING_SUM_METRIC_HEADERS),
                    },
                    "cell": {"userEnteredFormat": {
                        "backgroundColor": group_fill,
                        "textFormat": {
                            "bold": True,
                            "fontFamily": "Arial",
                            "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                        },
                        "horizontalAlignment": "CENTER",
                    }},
                    "fields": (
                        "userEnteredFormat(backgroundColor,textFormat,"
                        "horizontalAlignment)"
                    ),
                }},
                {"repeatCell": {
                    "range": {
                        "sheetId": sheet_id,
                        "startRowIndex": header_row + 1,
                        "endRowIndex": header_row + 2,
                        "startColumnIndex": start_column,
                        "endColumnIndex": start_column + len(CABLING_SUM_METRIC_HEADERS),
                    },
                    "cell": {"userEnteredFormat": {
                        "backgroundColor": detail_fill,
                        "textFormat": {
                            "bold": True,
                            "fontFamily": "Arial",
                            "foregroundColor": {
                                "red": 0.12, "green": 0.12, "blue": 0.12,
                            },
                        },
                        "horizontalAlignment": "CENTER",
                    }},
                    "fields": (
                        "userEnteredFormat(backgroundColor,textFormat,"
                        "horizontalAlignment)"
                    ),
                }},
                {"updateBorders": {
                    "range": {
                        "sheetId": sheet_id,
                        "startRowIndex": header_row,
                        "endRowIndex": data_end_row,
                        "startColumnIndex": start_column,
                        "endColumnIndex": start_column + len(CABLING_SUM_METRIC_HEADERS),
                    },
                    "left": {
                        "style": "SOLID_MEDIUM",
                        "color": group_fill,
                    },
                    "right": {
                        "style": "SOLID_MEDIUM",
                        "color": group_fill,
                    },
                }},
            ])
            if data_end_row > data_start_row:
                format_requests.append({"repeatCell": {
                    "range": {
                        "sheetId": sheet_id,
                        "startRowIndex": data_start_row,
                        "endRowIndex": data_end_row,
                        "startColumnIndex": start_column,
                        "endColumnIndex": start_column + len(CABLING_SUM_METRIC_HEADERS),
                    },
                    "cell": {"userEnteredFormat": {
                        "backgroundColor": body_fill,
                    }},
                    "fields": "userEnteredFormat.backgroundColor",
                }})
        if data_end_row > data_start_row:
            format_requests.append({"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": data_start_row,
                    "endRowIndex": data_end_row,
                    "startColumnIndex": dimension_count,
                    "endColumnIndex": column_count,
                },
                "cell": {"userEnteredFormat": {
                    "numberFormat": {"type": "NUMBER", "pattern": "#,##0"},
                    "horizontalAlignment": "CENTER",
                }},
                "fields": "userEnteredFormat(numberFormat,horizontalAlignment)",
            }})
            pass_rate_column = (
                dimension_count + CABLING_SUM_CVT_HEADERS.index("Rate")
            )
            format_requests.append({"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": data_start_row,
                    "endRowIndex": data_end_row,
                    "startColumnIndex": pass_rate_column,
                    "endColumnIndex": pass_rate_column + 1,
                },
                "cell": {"userEnteredFormat": {
                    "numberFormat": {"type": "PERCENT", "pattern": "0.0%"},
                    "horizontalAlignment": "CENTER",
                }},
                "fields": "userEnteredFormat(numberFormat,horizontalAlignment)",
            }})
        format_requests.extend([
            {"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": header_row + 1,
                    "startColumnIndex": 0,
                    "endColumnIndex": dimension_count,
                },
                "cell": {"userEnteredFormat": {
                    "backgroundColor": dimension_group_fill,
                    "textFormat": {
                        "bold": True,
                        "fontFamily": "Arial",
                        "foregroundColor": {"red": 1, "green": 1, "blue": 1},
                    },
                    "horizontalAlignment": "CENTER",
                }},
                "fields": "userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)",
            }},
            {"repeatCell": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row + 1,
                    "endRowIndex": header_row + 2,
                    "startColumnIndex": 0,
                    "endColumnIndex": dimension_count,
                },
                "cell": {"userEnteredFormat": {
                    "backgroundColor": dimension_detail_fill,
                    "textFormat": {
                        "bold": True,
                        "fontFamily": "Arial",
                        "foregroundColor": {"red": 0.12, "green": 0.12, "blue": 0.12},
                    },
                    "horizontalAlignment": "CENTER",
                }},
                "fields": "userEnteredFormat(backgroundColor,textFormat,horizontalAlignment)",
            }},
            {"updateBorders": {
                "range": {
                    "sheetId": sheet_id,
                    "startRowIndex": header_row,
                    "endRowIndex": data_end_row,
                    "startColumnIndex": 0,
                    "endColumnIndex": dimension_count,
                },
                "left": {
                    "style": "SOLID_MEDIUM", "color": dimension_group_fill,
                },
                "right": {
                    "style": "SOLID_MEDIUM", "color": dimension_group_fill,
                },
            }},
        ])
    format_requests.extend([
        {"repeatCell": {
            "range": {
                "sheetId": sheet_id,
                "startRowIndex": 0,
                "endRowIndex": 1,
                "startColumnIndex": 0,
                "endColumnIndex": column_count,
            },
            "cell": {"userEnteredFormat": {
                "backgroundColor": {"red": 1, "green": 1, "blue": 1},
                "textFormat": {
                    "bold": True,
                    "fontFamily": "Arial",
                    "foregroundColor": {"red": 0.15, "green": 0.15, "blue": 0.15},
                },
                "verticalAlignment": "MIDDLE",
            }},
            "fields": (
                "userEnteredFormat(backgroundColor,textFormat,verticalAlignment)"
            ),
        }},
        {"updateBorders": {
            "range": {
                "sheetId": sheet_id,
                "startRowIndex": 0,
                "endRowIndex": 1,
                "startColumnIndex": 0,
                "endColumnIndex": column_count,
            },
            "bottom": {
                "style": "SOLID_MEDIUM",
                "color": {"red": 0.46, "green": 0.73, "blue": 0.00},
            },
        }},
        {"repeatCell": {
            "range": {
                "sheetId": sheet_id,
                "startRowIndex": 0,
                "endRowIndex": formatted_row_count,
                "startColumnIndex": 0,
                "endColumnIndex": column_count,
            },
            "cell": {"userEnteredFormat": {
                "textFormat": {"fontFamily": "Arial"},
                "verticalAlignment": "MIDDLE",
                "horizontalAlignment": "CENTER",
            }},
            "fields": (
                "userEnteredFormat(textFormat.fontFamily,verticalAlignment,"
                "horizontalAlignment)"
            ),
        }},
        {"updateSheetProperties": {
            "properties": {
                "sheetId": sheet_id,
                "gridProperties": {
                    "frozenRowCount": 0,
                    "frozenColumnCount": 0,
                    "hideGridlines": True,
                },
                "tabColor": {"red": 0.46, "green": 0.73, "blue": 0.00},
            },
            "fields": (
                "gridProperties(frozenRowCount,frozenColumnCount,hideGridlines),"
                "tabColor"
            ),
        }},
        {"updateDimensionProperties": {
            "range": {
                "sheetId": sheet_id, "dimension": "ROWS",
                "startIndex": 0, "endIndex": 1,
            },
            "properties": {"pixelSize": 30},
            "fields": "pixelSize",
        }},
        {"autoResizeDimensions": {
            "dimensions": {
                "sheetId": sheet_id,
                "dimension": "COLUMNS",
                "startIndex": 0,
                "endIndex": column_count,
            },
        }},
        {"updateDimensionProperties": {
            "range": {
                "sheetId": sheet_id,
                "dimension": "COLUMNS",
                "startIndex": (
                    dimension_count
                    + CABLING_SUM_CVT_HEADERS.index("Progress")
                ),
                "endIndex": (
                    dimension_count
                    + CABLING_SUM_CVT_HEADERS.index("Progress") + 1
                ),
            },
            "properties": {"pixelSize": 110},
            "fields": "pixelSize",
        }},
    ])
    format_requests.extend(cabling_sum_conditional_format_requests(
        sheet_id,
        period_start_column,
        period_hours,
        formatted_row_count,
    ))
    service.spreadsheets().batchUpdate(
        spreadsheetId=spreadsheet_id, body={"requests": format_requests}
    ).execute()
    return {
        "summaryRows": len(rows),
        "updatedAt": point_time,
        "formatApplied": True,
        "chartCount": chart_count,
    }


@dataclass(frozen=True)
class CablingSnapshot:
    """Tables read at the start of a Case update; keep original physical rows."""

    observations: list[list[Any]]
    existing_raw: list[list[Any]]
    existing_cases: list[list[Any]]


@dataclass(frozen=True)
class CablingPolicy:
    """Explicit business settings, independent of CLI parsing and Sheets clients."""

    min_cycles: int = 1
    include_warnings: bool = False
    instance_name: str = ""
    fault_id_start: int = DEFAULT_FAULT_ID_START
    timezone_name: str = DEFAULT_TIMEZONE
    bcm_host_patterns: tuple[str, ...] = DEFAULT_BCM_HOST_PATTERNS
    reported_by: str = "CVT"

    @classmethod
    def from_args(cls, args: argparse.Namespace) -> CablingPolicy:
        patterns = getattr(args, "bcm_host_patterns", None)
        return cls(
            min_cycles=args.min_cycles, include_warnings=args.include_warnings,
            instance_name=getattr(args, "instance_name", ""),
            fault_id_start=args.fault_id_start, timezone_name=args.timezone_name,
            bcm_host_patterns=tuple(DEFAULT_BCM_HOST_PATTERNS if patterns is None else patterns),
            reported_by=source_reporter(args),
        )


@dataclass
class CablingReferences:
    """Already collected lookup data; None BCM statuses mean gating is disabled."""

    custom_nics: dict[str, str] = field(default_factory=dict)
    port_mapping: dict[str, str] = field(default_factory=dict)
    hw_devices: set[str] = field(default_factory=set)
    hw_fault_ids: dict[str, tuple[str, ...]] = field(default_factory=dict)
    whitelist_filters: dict[str, set[str]] = field(default_factory=dict)
    bcm_statuses: dict[str, str] | None = None


@dataclass
class CablingUpdatePlan:
    """Desired Case values and diagnostics; no network side effects."""

    values: list[list[Any]]
    bcm_gate_stats: Counter[str]


def read_cabling_snapshot(
    repository: TableRepository, args: argparse.Namespace, family: str | None,
) -> CablingSnapshot:
    cvt_raw = read_once_for_instance(
        args, ("import", cvt_table_range(args)),
        lambda: repository.read(cvt_table_range(args)),
    )
    cvt_data_start_row = (
        3 if cvt_raw and is_timestamp_row(cvt_raw[0], IMPORT_TIMESTAMP_PREFIX) else 2
    )
    cvt_values = attach_cvt_source_rows(
        strip_timestamp_row(cvt_raw), data_start_row=cvt_data_start_row
    )
    cvt_values = filter_cvt_by_protocol(cvt_values, family)
    existing_raw = repository.read(remediation_table_range(args))
    existing_values = strip_timestamp_row(existing_raw)
    canonical_existing_values = canonicalize_remediation_values(
        existing_values, args.remediation_header_mapping
    )
    return CablingSnapshot(cvt_values, existing_raw, canonical_existing_values)


def plan_cabling_update(
    snapshot: CablingSnapshot, policy: CablingPolicy, references: CablingReferences,
    identifier: Any = None,
) -> CablingUpdatePlan:
    """Compute desired Cases offline. Only the supplied ID iterator is consumed."""
    bcm_gate_stats: Counter[str] = Counter()
    values = upsert_remediation_values(
        snapshot.observations, snapshot.existing_cases, references.custom_nics,
        hw_issue_devices=references.hw_devices,
        hw_issue_fault_ids=references.hw_fault_ids,
        whitelist_filters=references.whitelist_filters,
        port_mapping=references.port_mapping,
        min_cycles=policy.min_cycles, include_warnings=policy.include_warnings,
        instance_name=policy.instance_name,
        identifier=identifier, fault_id_start=policy.fault_id_start,
        timezone_name=policy.timezone_name,
        bcm_host_statuses=references.bcm_statuses,
        bcm_host_patterns=policy.bcm_host_patterns,
        bcm_gate_stats=bcm_gate_stats,
        reported_by=policy.reported_by,
    )
    return CablingUpdatePlan(values, bcm_gate_stats)


def refresh_remediation(
    service: Any, args: argparse.Namespace, include_ai: bool = False,
    family: str | None = None, identifier: Any = None,
    remediation_device_sets: tuple[
        set[str], dict[str, tuple[str, ...]], dict[str, set[str]]
    ] | None = None,
    bcm_host_statuses: dict[str, str] | None = None,
) -> dict[str, Any] | None:
    """Read -> plan -> persist Cases -> record events after a successful write."""
    committed = getattr(args, "_committed_cabling", None)
    if committed is not None:
        committed.pop(committed_cabling_key(args, args.remediation_sheet), None)
    snapshot = read_cabling_snapshot(
        GoogleSheetsRepository(service, args.spreadsheet_id), args, family,
    )
    snapshot = CablingSnapshot(
        enrich_from_inventory(service, args, snapshot.observations),
        snapshot.existing_raw, snapshot.existing_cases,
    )
    custom_nics = read_once_for_instance(
        args, ("server_profile", args.server_profile_sheet),
        lambda: load_server_profile_custom_nic_map(service, args),
    )
    port_mapping = read_once_for_instance(
        args, ("port_profile", args.port_profile_sheet),
        lambda: load_port_profile_map(service, args),
    )
    hw_devices, hw_fault_ids, whitelist_filters = (
        remediation_device_sets if remediation_device_sets is not None
        else load_remediation_device_sets(service, args)
    )
    references = CablingReferences(
        custom_nics, port_mapping, hw_devices, hw_fault_ids, whitelist_filters,
        bcm_host_statuses,
    )
    plan = plan_cabling_update(snapshot, CablingPolicy.from_args(args), references, identifier)
    values, bcm_gate_stats = plan.values, plan.bcm_gate_stats
    if bcm_host_statuses is not None:
        LOGGER.info(
            "BCM host new-case gate sheet=%s allowed=%s bypassed=%s "
            "skipped_down=%s skipped_not_found=%s skipped_non_up=%s",
            args.remediation_sheet,
            bcm_gate_stats["allowed"],
            bcm_gate_stats["bypassed"],
            bcm_gate_stats["down"],
            bcm_gate_stats["not_found"],
            bcm_gate_stats["non_up"],
        )
    if include_ai:
        add_ai_recommendations(values, args)
    selected_canonical, selected_headers = selected_remediation_headers(args)
    # An empty current fault report must never overwrite historical records.
    if len(values) == 1 and len(snapshot.existing_cases) > 1:
        return None
    result = sparse_remediation_update(
        service,
        args,
        snapshot.existing_raw,
        values,
        selected_canonical,
        selected_headers,
    )
    if getattr(args, "enable_cabling_events", False):
        with timed_step(
            "cabling_events",
            instance=getattr(args, "instance_name", "") or "single",
            sheet=args.cabling_events_sheet,
            protocol=family.upper() if family else "ALL",
        ):
            event_result = refresh_cabling_events(
                service,
                args,
                snapshot.existing_cases,
                family.upper() if family else "ALL",
            )
        result["cablingEvents"] = event_result
    return result


def load_values(args: argparse.Namespace) -> list[list[Any]]:
    settings = resolve_source_settings(args)
    if args.values_json:
        try:
            values = json.loads(args.values_json)
        except json.JSONDecodeError as error:
            raise ValueError(f"--values-json is not valid JSON: {error.msg}") from error
    elif args.csv:
        if not args.csv.is_file():
            raise ValueError(f"CSV file not found: {args.csv}")
        with args.csv.open("r", encoding="utf-8-sig", newline="") as csv_file:
            values = list(csv.reader(csv_file))
    elif settings.transport == "file":
        if settings.source_type == "lldpq":
            values = normalize_report_values(
                read_cable_report_document(settings.file), LldpqReportAdapter(), args.include_healthy,
            )
        elif args.json_field_mapping:
            json_file = settings.file
            if not json_file.is_file():
                raise ValueError(f"JSON file not found: {json_file}")
            try:
                document = json.loads(json_file.read_text(encoding="utf-8"))
            except json.JSONDecodeError as error:
                raise ValueError(f"JSON file is not valid JSON: {error.msg}") from error
            values = mapped_json_values(document, args.json_field_mapping, args.json_records_path)
        elif args.json_file:
            raise ValueError("--json-file requires --json-field-map.")
        else:
            values = normalize_report_values(
                read_cable_report_document(settings.file),
                SOURCE_ADAPTERS[settings.source_type](), args.include_healthy,
            )
    else:
        values = load_cable_api_report(args)

    if not isinstance(values, list) or not values or not all(isinstance(row, list) for row in values):
        raise ValueError("Values must be a non-empty two-dimensional array.")
    return values


def cvt_sum_status(value: Any) -> str:
    """Normalize current CVT states into the fixed summary categories."""
    return {
        "pass": "Pass", "fail": "Fail", "warning": "Warning",
    }.get(str(value or "").strip().casefold(), "")


def cvt_sum_protocol(value: Any) -> str:
    """Use ETH only for explicit Ethernet/RoCE values; unknown values remain IB."""
    return "ETH" if protocol_family(value) == "eth" else "IB"


def cvt_sum_node_type(value: Any) -> str:
    normalized = str(value or "").strip().casefold()
    if "switch" in normalized:
        return "Switch"
    if any(term in normalized for term in ("host", "server", "compute")):
        return "Host"
    return ""


def cvt_sum_link_type(row: list[Any], positions: dict[str, int]) -> str:
    def cell(header: str) -> Any:
        index = positions.get(header, -1)
        return row[index] if 0 <= index < len(row) else ""

    a_type = cvt_sum_node_type(cell("A Node Type"))
    z_type = cvt_sum_node_type(cell("Z Node Type"))
    if a_type == z_type == "Switch":
        return "Switch"
    if {a_type, z_type} == {"Switch", "Host"}:
        return "Host"
    return "Unknown"


def cvt_sum_fail_bucket(row: list[Any], positions: dict[str, int]) -> str:
    """Map the Cabling Issue Type for a Fail row to one summary bucket."""
    def cell(header: str) -> Any:
        index = positions.get(header, -1)
        return row[index] if 0 <= index < len(row) else ""

    classification = issue_type(
        cell("A Report"),
        cell("Z Report"),
        port_statuses=(cell("A Port Status"), cell("Z Port Status")),
        ber_statuses=(cell("A BER Status"), cell("Z BER Status")),
    )
    categories = {
        value.strip().casefold()
        for value in classification.split(";")
        if value.strip()
    }
    # Keep the existing mutually-exclusive CVT_SUM priority while sourcing all
    # classification decisions from the Cabling Issue Type implementation.
    if "flapping" in categories:
        return "Flapping"
    if "mis-wiring" in categories:
        return "Mis-wiring"
    if "link down" in categories:
        return "Link Down"
    return "Others"


def build_cvt_sum_rows(
    reports: list[tuple[str, list[list[Any]]]], multi_instance: bool,
) -> tuple[list[list[Any]], Counter[str], Counter[str], int]:
    """Aggregate current report tables without reading historical CVT_Import rows."""
    rows: list[list[Any]] = []
    statuses: Counter[str] = Counter()
    failures: Counter[str] = Counter()
    circuit_count = 0

    for instance_name, values in reports:
        values = strip_timestamp_row(values)
        if not values or len(values) < 2:
            raise ValueError(f"CVT summary source for {instance_name or 'single instance'} is empty.")
        headers = [str(header) for header in values[0]]
        positions = {header: index for index, header in enumerate(headers)}
        if "Status" not in positions:
            raise ValueError("CVT summary source must contain a Status column.")
        grouped: dict[tuple[str, str, str], Counter[str]] = defaultdict(Counter)
        for row in values[1:]:
            circuit_count += 1

            def cell(header: str) -> Any:
                index = positions.get(header, -1)
                return row[index] if 0 <= index < len(row) else ""

            status = cvt_sum_status(cell("Status"))
            status_key = status or "No Status"
            statuses[status_key] += 1
            protocol_name = cvt_sum_protocol(cell("Protocol"))
            su = str(cell("A SU Number") or cell("Z SU Number") or "Unknown").strip()
            kind = cvt_sum_link_type(row, positions)
            counts = grouped[(protocol_name, su, kind)]
            counts["Total"] += 1
            counts[status_key] += 1
            if status == "Fail":
                bucket = cvt_sum_fail_bucket(row, positions)
                counts[bucket] += 1
                failures[bucket] += 1

        instance_rows: list[list[Any]] = []
        for (protocol_name, su, kind), counts in grouped.items():
            total = counts["Total"]
            row = [
                su, kind, protocol_name, total, counts["Pass"], counts["Link Down"],
                counts["Mis-wiring"], counts["Flapping"], counts["Others"],
                counts["Warning"], counts["No Status"],
                counts["Pass"] / total if total else 0,
            ]
            instance_rows.append(([instance_name, *row] if multi_instance else row))
        rows.extend(instance_rows)

    if multi_instance:
        rows.sort(key=lambda row: (
            str(row[0]).casefold(),
            CVT_SUM_PROTOCOL_ORDER.get(str(row[3]), len(CVT_SUM_PROTOCOL_ORDER)),
            CVT_SUM_LINK_TYPE_ORDER.get(str(row[2]), len(CVT_SUM_LINK_TYPE_ORDER)),
            str(row[1]).casefold(),
        ))
    else:
        rows.sort(key=lambda row: (
            CVT_SUM_PROTOCOL_ORDER.get(str(row[2]), len(CVT_SUM_PROTOCOL_ORDER)),
            CVT_SUM_LINK_TYPE_ORDER.get(str(row[1]), len(CVT_SUM_LINK_TYPE_ORDER)),
            str(row[0]).casefold(),
        ))
    if sum(statuses.values()) != circuit_count:
        raise RuntimeError("CVT_SUM status totals do not reconcile.")
    if sum(failures.values()) != statuses["Fail"]:
        raise RuntimeError("CVT_SUM failure totals do not reconcile.")
    return rows, statuses, failures, circuit_count


def refresh_cvt_sum_sheet(
    service: Any, spreadsheet_id: str, sheet_name: str, rows: list[list[Any]],
    multi_instance: bool, timezone_name: str = DEFAULT_TIMEZONE,
) -> str:
    """Replace CVT_SUM atomically after validating or initializing its row-2 schema."""
    headers = CVT_SUM_MULTI_HEADERS if multi_instance else CVT_SUM_HEADERS
    legacy_headers = (
        (CVT_SUM_LEGACY_MULTI_HEADERS, CVT_SUM_HEADERS, CVT_SUM_LEGACY_HEADERS)
        if multi_instance else (CVT_SUM_LEGACY_HEADERS,)
    )
    ensure_sheet(service, spreadsheet_id, sheet_name)
    quoted = quoted_sheet_name(sheet_name)
    current = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id, range=f"{quoted}!2:2",
    ).execute().get("values", [])
    actual_headers = [str(value) for value in current[0]] if current else []
    normalized_headers = normalize_instance_headers(actual_headers)
    if (not any(header.strip() for header in actual_headers)
            or normalized_headers in legacy_headers
            or (normalized_headers == headers and actual_headers != headers)):
        ensure_table_headers(service, spreadsheet_id, sheet_name, headers)
    elif actual_headers != headers:
        raise ValueError(
            "CVT_SUM header mismatch; no summary data was changed. "
            f"Expected {headers!r}, got {actual_headers!r}"
        )

    last_column = sheet_column_name(len(headers) - 1)
    timestamp = operational_now(timezone_name).strftime(
        f"{CVT_SUM_TIMESTAMP_PREFIX} %Y-%m-%d %H:%M:%S"
    )
    service.spreadsheets().values().clear(
        spreadsheetId=spreadsheet_id, range=f"{quoted}!A3:{last_column}", body={},
    ).execute()
    data = [{"range": f"{quoted}!A1", "values": [[timestamp]]}]
    if rows:
        data.append({"range": f"{quoted}!A3", "values": rows})
    service.spreadsheets().values().batchUpdate(
        spreadsheetId=spreadsheet_id,
        body={"valueInputOption": "RAW", "data": data},
    ).execute()

    metadata = service.spreadsheets().get(
        spreadsheetId=spreadsheet_id,
        fields="sheets(properties(sheetId,title))",
    ).execute()
    sheet_id = next(
        sheet["properties"]["sheetId"] for sheet in metadata.get("sheets", [])
        if sheet["properties"]["title"] == sheet_name
    )
    if rows:
        service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": [{"repeatCell": {
                "range": {
                    "sheetId": sheet_id, "startRowIndex": 2,
                    "endRowIndex": 2 + len(rows),
                    "startColumnIndex": len(headers) - 1,
                    "endColumnIndex": len(headers),
                },
                "cell": {"userEnteredFormat": {
                    "numberFormat": {"type": "PERCENT", "pattern": "0.00%"}
                }},
                "fields": "userEnteredFormat.numberFormat",
            }}]},
        ).execute()
    verify = service.spreadsheets().values().get(
        spreadsheetId=spreadsheet_id,
        range=f"{quoted}!A1:{last_column}{2 + len(rows)}",
    ).execute().get("values", [])
    if (
        not verify or verify[0][:1] != [timestamp]
        or len(verify) < 2 + len(rows)
    ):
        raise RuntimeError("CVT_SUM verification failed after update.")
    return timestamp


def load_cvt_sum_source(args: argparse.Namespace) -> list[list[Any]]:
    """Collect a complete current report when the regular import did not already do so."""
    cached = getattr(args, "_cvt_sum_source_values", None)
    if cached is not None and not args.failures_only:
        return cached
    settings = resolve_source_settings(args)
    if settings.transport == "file" and (not args.json_file or settings.source_type == "lldpq"):
        # Summary-only runs must honor the selected local source, not fall back
        # to an API because a mapping file happens to be configured.
        return normalize_report_values(
            read_cable_report_document(settings.file),
            SOURCE_ADAPTERS[settings.source_type](), include_healthy=True,
        )
    if args.json_file or args.values_json or args.csv:
        raise ValueError(
            "CVT_SUM requires a standard --cable-report or CVT API source when no import "
            "data was collected in this run."
        )
    scoped = copy.copy(args)
    scoped.include_healthy = True
    return load_cable_api_report(scoped)


def has_non_summary_work(args: argparse.Namespace) -> bool:
    """Return whether a cycle has work other than the optional CVT_SUM phase."""
    return bool(any((
        args.operation, args.values_json, args.csv, args.cable_report, args.json_file,
        getattr(args, "source_file", None),
        args.remediation_from_cvt, args.refresh_remediation, args.refresh_agent_status,
        args.enable_bcm, args.refresh_ai_only, args.clear_data, args.list_ai_models,
    )))


def normalize_and_validate_instance_args(
    args: argparse.Namespace,
) -> list[tuple[str | None, str]]:
    """Resolve mappings and modes, then validate one private cycle namespace."""
    # Source connection settings are allowed in remediation-only/shared configs,
    # but must not turn those modes into a report fetch.
    source_input = bool(
        getattr(args, "source_file", None) or args.cable_report or args.json_file
        or source_api_requested(args)
    )
    resolve_source_settings(args, require_input=(source_input or args.operation in ("import", "both")))
    operational_timezone(args.timezone_name)
    args.cabling_sum_period_hours = normalize_cabling_sum_period_hours(
        args.cabling_sum_period_hours, "cabling_sum_period_hours"
    )
    if args.mapping_config and (args.json_field_map or args.remediation_column_map):
        raise ValueError(
            "--mapping-config cannot be combined with --json-field-map or "
            "--remediation-column-map."
        )
    unified_mapping = load_unified_mapping_config(args.mapping_config)
    if unified_mapping:
        args.json_field_mapping, remediation_custom_mapping = unified_mapping
        args.remediation_header_mapping = remediation_header_map(
            None, remediation_custom_mapping
        )
    else:
        args.json_field_mapping = load_json_field_map(args.json_field_map)
        args.remediation_header_mapping = remediation_header_map(
            args.remediation_column_map
        )
    if source_reporter(args) == "LLDPQ":
        # A shared mapping_v4.json may still supply the Cabling display headers.
        # Its CVT raw JSON paths must never be applied to LLDPQ's rows envelope.
        args.json_field_mapping = None
    remediation_targets = cabling_targets(args)
    if args.json_records_path and not args.json_field_mapping:
        raise ValueError("--json-records-path requires --json-field-map.")
    if args.json_field_map and not (args.cable_report or args.json_file or getattr(args, "source_file", None)):
        raise ValueError(
            "--json-field-map requires a local --source-file, --json-file or --cable-report JSON file."
        )
    if args.failures_only and args.include_healthy:
        raise ValueError("Use either --failures-only or --include-healthy, not both.")
    if args.timeout < 1:
        raise ValueError("--timeout must be at least 1 second.")
    if args.enable_bcm:
        bcm_status_url(args.bcm_api_url)
        compile_bcm_host_patterns(args.bcm_host_patterns)
        if not str(args.bcm_sheet or "").strip():
            raise ValueError("--bcm-sheet must not be empty when --enable-bcm is set.")
        if args.bcm_auth not in {"basic", "certificate"}:
            raise ValueError("--bcm-auth must be basic or certificate.")
    if args.refresh_ai_only:
        if args.operation or args.remediation_from_cvt or args.refresh_remediation:
            raise ValueError(
                "--refresh-ai-only cannot be combined with --operation or remediation "
                "refresh flags."
            )
        if any((
            args.values_json, args.csv, args.cable_report, args.json_file,
            getattr(args, "source_file", None),
            args.cable_api_source,
        )):
            raise ValueError(
                "--refresh-ai-only reads Remediation directly and does not accept "
                "an input data source."
            )
        args.ai_recommendations = True
    if args.refresh_ai_recommendations and not args.ai_recommendations:
        raise ValueError("--refresh-ai-recommendations requires --ai-recommendations.")

    args.include_healthy = not args.failures_only
    if args.range:
        args.cvt_sheet = sheet_name_from_range(args.range)
    if args.clear_data:
        if args.fresh_start:
            raise ValueError("Use either --clear-data or --fresh-start, not both.")
        if args.operation or any((
            args.values_json, args.csv, args.cable_report, args.json_file,
            getattr(args, "source_file", None),
            args.cable_api_source,
        )):
            raise ValueError(
                "--clear-data cannot be combined with --operation or an input data source."
            )
        return remediation_targets

    if args.operation:
        if args.remediation_from_cvt or args.refresh_remediation:
            raise ValueError("--operation cannot be combined with legacy remediation flags.")
        if args.operation == "remediation" and any((
            args.values_json, args.csv, args.cable_report, args.json_file,
            getattr(args, "source_file", None),
        )):
            raise ValueError("--operation remediation does not accept an input data source.")
        args.remediation_from_cvt = args.operation == "remediation"
        args.refresh_remediation = args.operation == "both"
    elif not any((
        args.values_json, args.csv, args.cable_report, args.json_file,
        getattr(args, "source_file", None),
        args.cable_api_source, args.remediation_from_cvt,
        args.refresh_agent_status, args.enable_bcm, args.refresh_ai_only,
    )):
        raise ValueError("Provide an input data source or set --operation.")
    imported_source = has_import_report(args)
    if args.compare_existing and not imported_source:
        raise ValueError("--compare-existing requires an imported JSON report or cable API source.")
    if args.refresh_remediation and not imported_source:
        raise ValueError("--refresh-remediation requires an imported JSON report or cable API source.")
    if args.refresh_remediation and args.remediation_from_cvt:
        raise ValueError("Use either --refresh-remediation or --remediation-from-cvt, not both.")
    if args.fresh_start and not imported_source:
        raise ValueError("--fresh-start requires --operation import/both or an imported source.")
    if args.ai_after_remediation:
        args.ai_recommendations = True
    if args.ai_recommendations and not args.refresh_ai_only and not (
        args.remediation_from_cvt or args.refresh_remediation
    ):
        raise ValueError(
            "--ai-recommendations requires --operation remediation or both, "
            "or use --refresh-ai-only."
        )
    if imported_source:
        args.compare_existing = True
    if args.data_start_row < 1:
        raise ValueError("--data-start-row must be at least 1.")
    if args.min_cycles < 1:
        raise ValueError("--min-cycles must be at least 1.")
    if args.enable_cabling_events and not str(args.cabling_events_sheet or "").strip():
        raise ValueError(
            "--cabling-events-sheet must not be empty when --enable-cabling-events is set."
        )
    if args.cabling_events_retention_hours < 1:
        raise ValueError("--cabling-events-retention-hours must be at least 1.")
    if args.refresh_cabling_sum and not str(args.cabling_sum_sheet or "").strip():
        raise ValueError(
            "--cabling-sum-sheet must not be empty when --refresh-cabling-sum is set."
        )
    if args.enable_cabling_events:
        event_sheet = str(args.cabling_events_sheet).strip().casefold()
        conflicting_sheets = {
            str(name or "").strip().casefold()
            for name in (
                args.cvt_sheet,
                args.agent_sheet,
                args.bcm_sheet,
                args.cvt_sum_sheet,
                *(sheet_name for _family, sheet_name in remediation_targets),
            )
            if str(name or "").strip()
        }
        if event_sheet in conflicting_sheets:
            raise ValueError(
                "--cabling-events-sheet must be different from every managed data sheet."
            )
    if args.refresh_cabling_sum:
        summary_sheet = str(args.cabling_sum_sheet).strip().casefold()
        conflicting_sheets = {
            str(name or "").strip().casefold()
            for name in (
                args.cvt_sheet,
                args.agent_sheet,
                args.bcm_sheet,
                args.cvt_sum_sheet,
                args.cabling_events_sheet,
                *(sheet_name for _family, sheet_name in remediation_targets),
            )
            if str(name or "").strip()
        }
        if summary_sheet in conflicting_sheets:
            raise ValueError(
                "--cabling-sum-sheet must be different from every managed data sheet."
            )
    return remediation_targets


def clear_instance_data(
    service: Any, args: argparse.Namespace,
    remediation_targets: list[tuple[str | None, str]],
) -> None:
    """Clear managed data rows while preserving timestamp and header rows."""
    ensure_sheet(service, args.spreadsheet_id, args.cvt_sheet)
    prepare_timestamp_row(
        service, args.spreadsheet_id, args.cvt_sheet, IMPORT_TIMESTAMP_PREFIX,
        timezone_name=args.timezone_name,
    )
    cabling_sheet_names: list[str] = []
    for _family, sheet_name in remediation_targets:
        scoped = cabling_args(args, sheet_name)
        ensure_sheet(service, args.spreadsheet_id, sheet_name)
        prepare_timestamp_row(
            service, args.spreadsheet_id, sheet_name, REMEDIATION_TIMESTAMP_PREFIX,
            preserve_first_row=False, timezone_name=args.timezone_name,
        )
        ensure_remediation_discover_columns(service, scoped)
        ensure_table_headers(
            service, args.spreadsheet_id, sheet_name,
            selected_remediation_headers(scoped)[1],
        )
        cabling_sheet_names.append(sheet_name)
    sheet_names = [args.cvt_sheet, *cabling_sheet_names]
    for sheet_name in sheet_names:
        service.spreadsheets().values().clear(
            spreadsheetId=args.spreadsheet_id,
            range=(
                cvt_table_range(args, 3)
                if sheet_name == args.cvt_sheet
                else remediation_table_range(args, sheet_name, 3)
            ),
            body={},
        ).execute()
    LOGGER.info(
        "Cleared data rows sheets=%s preserved_rows=1-2", ", ".join(sheet_names)
    )


def prepare_remediation_targets(
    service: Any,
    args: argparse.Namespace,
    remediation_targets: list[tuple[str | None, str]],
) -> tuple[set[str], dict[str, tuple[str, ...]], dict[str, set[str]]] | None:
    """Validate shared control data and prepare every configured Cabling sheet."""
    if not (args.remediation_from_cvt or args.refresh_remediation):
        return None
    device_sets = (
        load_remediation_device_sets(service, args) if remediation_targets else None
    )
    for _family, sheet_name in remediation_targets:
        scoped = cabling_args(args, sheet_name)
        ensure_sheet(service, args.spreadsheet_id, sheet_name)
        prepare_timestamp_row(
            service, args.spreadsheet_id, sheet_name, REMEDIATION_TIMESTAMP_PREFIX,
            preserve_first_row=False, timezone_name=args.timezone_name,
        )
        ensure_remediation_discover_columns(service, scoped)
        ensure_table_headers(
            service, args.spreadsheet_id, sheet_name,
            selected_remediation_headers(scoped)[1],
        )
    return device_sets


def refresh_remediation_targets(
    service: Any,
    args: argparse.Namespace,
    remediation_targets: list[tuple[str | None, str]],
    remediation_device_sets: tuple[
        set[str], dict[str, tuple[str, ...]], dict[str, set[str]]
    ] | None,
    bcm_host_statuses: dict[str, str] | None = None,
) -> list[tuple[str, dict[str, Any] | None]]:
    """Refresh all configured protocol Cabling sheets with one shared Fault ID sequence."""
    identifier = shared_fault_id_generator(service, args, remediation_targets)
    results: list[tuple[str, dict[str, Any] | None]] = []
    for family, sheet_name in remediation_targets:
        scoped = cabling_args(args, sheet_name)
        with timed_step(
            "cabling_update",
            instance=getattr(args, "instance_name", "") or "single",
            sheet=sheet_name,
            protocol=family or "all",
        ):
            result = refresh_remediation(
                service, scoped, include_ai=False, family=family,
                identifier=identifier,
                remediation_device_sets=remediation_device_sets,
                bcm_host_statuses=bcm_host_statuses,
            )
        results.append((sheet_name, result))
    return results


def log_instance_results(
    args: argparse.Namespace,
    result: dict[str, Any] | None,
    target_range: str,
    remediation_results: list[tuple[str, dict[str, Any] | None]],
    agent_result: dict[str, Any] | None,
    bcm_result: dict[str, Any] | None,
    ai_results: list[tuple[str, dict[str, Any] | None]],
) -> None:
    """Emit one consistent operational summary for a completed instance run."""
    if result is not None:
        LOGGER.info(
            "CVT data updated cells=%s range=%s",
            result.get("updatedCells", 0), result.get("updatedRange", target_range),
        )
    for sheet_name, remediation_result in remediation_results:
        if not remediation_result:
            LOGGER.info("No active faults; existing records preserved sheet=%s", sheet_name)
            continue
        LOGGER.info(
            "Cabling updated sheet=%s cells=%s range=%s",
            sheet_name,
            remediation_result.get("updatedCells", 0),
            remediation_result.get("updatedRange", sheet_name + "!A1"),
        )
        for key, level, message in (
            ("clearedRows", LOGGER.info, "Cabling trailing rows cleared"),
            ("newRows", LOGGER.info, "Cabling rows appended"),
            ("concurrentStatusSkips", LOGGER.warning, "Concurrent Status edits preserved"),
            ("missingRowSkips", LOGGER.warning, "Moved or removed rows skipped"),
        ):
            if remediation_result.get(key):
                level("%s sheet=%s rows=%s", message, sheet_name, remediation_result[key])
        event_result = remediation_result.get("cablingEvents")
        if event_result:
            LOGGER.info(
                "Cabling events reconciled sheet=%s appended=%s snapshot_updates=%s "
                "opened=%s closed=%s baseline=%s expired=%s",
                sheet_name,
                event_result.get("appendedRows", 0),
                event_result.get("snapshotUpdates", 0),
                event_result.get("opened", 0),
                event_result.get("closed", 0),
                event_result.get("baseline", 0),
                event_result.get("expiredRows", 0),
            )
    if agent_result:
        LOGGER.info(
            "Agent status updated cells=%s range=%s",
            agent_result.get("updatedCells", 0),
            agent_result.get("updatedRange", args.agent_sheet + "!A3"),
        )
    if bcm_result:
        LOGGER.info(
            "BCM status updated cells=%s range=%s",
            bcm_result.get("updatedCells", 0),
            bcm_result.get("updatedRange", args.bcm_sheet + "!A3"),
        )
    for sheet_name, ai_result in ai_results:
        if ai_result is None:
            LOGGER.info("No eligible AI recommendations sheet=%s", sheet_name)
        else:
            LOGGER.info(
                "AI recommendations updated sheet=%s records=%s cells=%s",
                sheet_name,
                ai_result.get("updatedRecords", 0),
                ai_result.get("totalUpdatedCells", 0),
            )


def has_import_report(args: argparse.Namespace) -> bool:
    """Distinguish report imports from raw table writes and remediation-only runs."""
    return bool(args.cable_report or args.json_file or getattr(args, "source_file", None)
                or getattr(args, "cable_api_source", False))


def prepare_cvt_import_sheet(service: Any, args: argparse.Namespace) -> str:
    """Prepare an import target only after the source was collected successfully."""
    if not has_import_report(args):
        return ""
    with timed_step(
        "cvt_sheet_prepare", instance=getattr(args, "instance_name", "") or "single",
        sheet=args.cvt_sheet,
    ):
        ensure_sheet(service, args.spreadsheet_id, args.cvt_sheet)
        header_exists = prepare_timestamp_row(
            service, args.spreadsheet_id, args.cvt_sheet, IMPORT_TIMESTAMP_PREFIX,
            timezone_name=args.timezone_name,
        )
        headers = parse_columns(args.cvt_columns, cvt_headers(args), "--columns")
        ensure_cvt_node_type_columns(service, args, headers)
        ensure_table_headers(service, args.spreadsheet_id, args.cvt_sheet, headers)
        args.data_start_row = 3 if header_exists else 2
        if should_clear_cvt_on_start(args):
            GoogleSheetsRepository(service, args.spreadsheet_id).clear(cvt_table_range(args, 3))
            LOGGER.info("Fresh start cleared CVT data sheet=%s", args.cvt_sheet)
    return args.cvt_sheet


@dataclass(frozen=True)
class ImportUpdatePlan:
    target_range: str
    values: list[list[Any]]


def plan_cvt_import(
    args: argparse.Namespace, values: list[list[Any]], existing_values: list[list[Any]],
) -> ImportUpdatePlan:
    """Compute tracking/cycles and projection without reading or writing Sheets."""
    if args.compare_existing:
        values = compare_report_to_existing(values, existing_values)
        values = add_instance_column(values, getattr(args, "instance_name", None))
    if has_import_report(args):
        values = project_columns(
            values, parse_columns(args.cvt_columns, cvt_headers(args), "--columns")
        )[1:]
    return ImportUpdatePlan(f"{args.cvt_sheet}!A3", values)


def write_cvt_import(
    service: Any, args: argparse.Namespace, source_values: list[list[Any]] | None,
) -> tuple[dict[str, Any], str]:
    """Read historical import values, compute a plan, then persist its body."""
    values = source_values if source_values is not None else load_values(args)
    repository = GoogleSheetsRepository(service, args.spreadsheet_id)
    instance = getattr(args, "instance_name", "") or "single"
    existing_values: list[list[Any]] = []
    if args.compare_existing:
        with timed_step("cvt_compare_existing", instance=instance):
            existing_values = repository.read(cvt_table_range(args))
            plan = plan_cvt_import(args, values, existing_values)
    else:
        plan = plan_cvt_import(args, values, existing_values)
    with timed_step("cvt_sheet_write", instance=instance, sheet=args.cvt_sheet, rows=len(plan.values)):
        if args.compare_existing and has_import_report(args):
            width = len(parse_columns(args.cvt_columns, cvt_headers(args), "--columns"))
            previous = strip_timestamp_row(existing_values)
            delta = table_value_delta(args.cvt_sheet, previous[1:], plan.values, width)
            # A heavily changed/reordered table may be cheaper as one rectangle.
            dense = [{"range": plan.target_range, "values": [
                [(row[c] if c < len(row) and row[c] is not None else "")
                 for c in range(width)] for row in plan.values
            ]}] if plan.values else []
            if len(json.dumps(delta)) > len(json.dumps(dense)):
                delta = dense
            result = persist_value_delta(repository, delta, args.value_input_option)
            result["updatedRange"] = f"{args.cvt_sheet} sparse update"
            LOGGER.info(
                "Import write plan sheet=%s full_cells=%s sent_cells=%s "
                "ranges=%s requests=%s json_payload_bytes=%s full_values_json_bytes=%s",
                args.cvt_sheet, len(plan.values) * width,
                sum(len(row) for item in delta for row in item["values"]),
                len(delta), result["writeRequests"], result["payloadBytes"],
                len(json.dumps({"values": plan.values}).encode("utf-8")),
            )
        else:
            result = repository.update(plan.target_range, plan.values, args.value_input_option)
    return result, plan.target_range


def refresh_auxiliary_status(
    service: Any, args: argparse.Namespace, bcm_values: list[list[Any]] | None,
) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
    """Independent optional status outputs; neither participates in Case writes."""
    instance = getattr(args, "instance_name", "") or "single"
    agent_result = bcm_result = None
    if args.refresh_agent_status:
        with timed_step("agent_status", instance=instance):
            agent_result = refresh_agent_status(service, args)
    if bcm_values is not None:
        with timed_step("bcm_sheet_update", instance=instance):
            bcm_result = refresh_bcm_status(service, args, bcm_values)
    return agent_result, bcm_result


def run_single_instance(args: argparse.Namespace) -> int:
    args._cvt_sum_source_values = None
    args._inventory_locations = None
    args._instance_read_cache = {}
    # Compose passes an empty string for an unset optional proxy; the AI client
    # expects None rather than an empty URL.
    args.ai_proxy = args.ai_proxy or None
    # Host and path options describe the API, but only import modes consume its report endpoint.
    args.cable_api_source = source_api_requested(args)
    if args.list_ai_models:
        try:
            for model_id in list_ai_models(args):
                print(model_id)
            return 0
        except (ValueError, OSError) as error:
            LOGGER.error("Input error: %s", error)
            return 2
    if not args.spreadsheet_id:
        LOGGER.error(
            "Input error: --spreadsheet-id is required unless each instance supplies spreadsheet_id."
        )
        return 2
    credential_path = Path(args.credentials)
    if not credential_path.is_file():
        LOGGER.error("Credential JSON not found: %s", credential_path)
        return 2

    try:
        instance_name = getattr(args, "instance_name", "") or "single"
        with timed_step("google_sheets_connect", instance=instance_name):
            remediation_targets = normalize_and_validate_instance_args(args)
            credentials = service_account.Credentials.from_service_account_file(
                credential_path, scopes=SCOPES
            )
            service = build_sheets_service(credentials, args.google_proxy, args.timeout)
        if args.clear_data:
            with timed_step("clear_data", instance=instance_name):
                clear_instance_data(service, args, remediation_targets)
            return 0
        if args.refresh_ai_only:
            with timed_step("ai_recommendations", instance=instance_name):
                ai_results = refresh_ai_for_targets(service, args, remediation_targets)
            for sheet_name, ai_result in ai_results:
                if ai_result is None:
                    LOGGER.info("No eligible AI recommendations sheet=%s", sheet_name)
                    continue
                LOGGER.info(
                    "AI recommendations updated sheet=%s records=%s cells=%s",
                    sheet_name,
                    ai_result.get("updatedRecords", 0),
                    ai_result.get("totalUpdatedCells", 0),
                )
            return 0
        has_primary_source = any((args.values_json, args.csv, has_import_report(args),
                                  args.remediation_from_cvt))
        with timed_step("bcm_collect", instance=instance_name, enabled=args.enable_bcm):
            bcm_values, bcm_host_statuses = collect_bcm_status_for_cycle(args)
        if (args.refresh_agent_status or args.enable_bcm) and not has_primary_source:
            agent_result, bcm_result = refresh_auxiliary_status(service, args, bcm_values)
            log_instance_results(
                args, None, "", [], agent_result, bcm_result, []
            )
            return 0
        # Fetch and validate the complete source before changing CVT headers or timestamps.
        # A source outage must never leave a partially migrated sheet schema behind.
        source_values = None
        if has_import_report(args):
            with timed_step("cvt_source_load", instance=instance_name):
                source_values = add_instance_column(
                    load_values(args), getattr(args, "instance_name", None)
                )
            with timed_step("inventory_enrich", instance=instance_name):
                source_values = enrich_from_inventory(service, args, source_values)
        elif args.remediation_from_cvt:
            # Validate reference data before any Cabling schema/timestamp changes.
            with timed_step("inventory_load", instance=instance_name):
                load_inventory_locations(service, args)
        if source_values is not None:
            # Preserve the complete current report before Tracking Status merges historical
            # Missing rows. The cycle-level orchestrator uses this for CVT_SUM.
            args._cvt_sum_source_values = source_values
        remediation_needs_update = bool(args.remediation_from_cvt or args.refresh_remediation)
        if remediation_needs_update and not remediation_targets:
            LOGGER.warning(
                "Cabling update skipped reason=no_sheet_configured; "
                "set --ib-cabling-sheet and/or --eth-cabling-sheet"
            )
        remediation_results: list[tuple[str, dict[str, Any] | None]] = []
        ai_results: list[tuple[str, dict[str, Any] | None]] = []
        result: dict[str, Any] | None = None
        target_range = f"{args.cvt_sheet}!A3"
        import_sheet_name = prepare_cvt_import_sheet(service, args)
        with timed_step("cabling_sheet_prepare", instance=instance_name):
            remediation_device_sets = prepare_remediation_targets(
                service, args, remediation_targets
            )
        if args.remediation_from_cvt:
            remediation_results.extend(refresh_remediation_targets(
                service, args, remediation_targets, remediation_device_sets,
                bcm_host_statuses,
            ))
        else:
            result, target_range = write_cvt_import(service, args, source_values)
        if args.refresh_remediation:
            remediation_results.extend(refresh_remediation_targets(
                service, args, remediation_targets, remediation_device_sets,
                bcm_host_statuses,
            ))
        agent_result, bcm_result = refresh_auxiliary_status(service, args, bcm_values)
        if args.ai_recommendations:
            LOGGER.info("Cabling non-AI fields updated; starting AI recommendation phase")
            with timed_step("ai_recommendations", instance=instance_name):
                ai_results = refresh_ai_for_targets(service, args, remediation_targets)
        completed_timestamps = []
        completed_at = operational_now(args.timezone_name).strftime('%Y-%m-%d %H:%M:%S')
        if import_sheet_name:
            completed_timestamps.append({
                "range": f"{quoted_sheet_name(import_sheet_name)}!A1",
                "values": [[f"{IMPORT_TIMESTAMP_PREFIX} {completed_at}"]],
            })
        if remediation_needs_update:
            for _family, sheet_name in remediation_targets:
                completed_timestamps.append({
                    "range": f"{quoted_sheet_name(sheet_name)}!A1",
                    "values": [[f"{REMEDIATION_TIMESTAMP_PREFIX} {completed_at}"]],
                })
        if completed_timestamps:
            # These sheets have already been prepared; no second header read or
            # row migration is needed merely to publish the completion time.
            service.spreadsheets().values().batchUpdate(
                spreadsheetId=args.spreadsheet_id,
                body={"valueInputOption": "RAW", "data": completed_timestamps},
            ).execute()
    except IncompleteRead as error:
        LOGGER.error(
            "Google Sheets GET failed after retries; current cycle aborted safely "
            "instance=%s bytes_read=%s",
            getattr(args, "instance_name", "") or "single",
            len(error.partial or b""),
        )
        return 1
    except (ValueError, OSError) as error:
        LOGGER.error("Input error: %s", error)
        return 2
    except HttpError as error:
        LOGGER.error(
            "Google Sheets API error: %s; check API enablement and service-account sharing",
            error,
        )
        return 1
    except Exception:
        LOGGER.exception(
            "Unexpected instance failure instance=%s",
            getattr(args, "instance_name", "") or "single",
        )
        return 1
    finally:
        if "service" in locals():
            log_google_io(service, "instance")

    log_instance_results(
        args, result, target_range, remediation_results, agent_result, bcm_result, ai_results
    )
    return 0


def refresh_cvt_sum_targets(
    reports: list[tuple[argparse.Namespace, list[list[Any]]]], multi_instance: bool,
) -> int:
    """Write one summary per configured Spreadsheet/sheet target."""
    grouped: dict[tuple[str, str], list[tuple[argparse.Namespace, list[list[Any]]]]] = defaultdict(list)
    for scoped, values in reports:
        sheet_name = str(scoped.cvt_sum_sheet or "").strip()
        if not sheet_name:
            LOGGER.error("Input error: --cvt-sum-sheet must not be empty")
            return 2
        grouped[(scoped.spreadsheet_id, sheet_name)].append((scoped, values))

    try:
        for (spreadsheet_id, sheet_name), target_reports in grouped.items():
            first_args = target_reports[0][0]
            credential_path = Path(first_args.credentials)
            if not credential_path.is_file():
                raise ValueError(f"Credential JSON not found: {credential_path}")
            credentials = service_account.Credentials.from_service_account_file(
                credential_path, scopes=SCOPES
            )
            service = build_sheets_service(
                credentials, first_args.google_proxy, first_args.timeout
            )
            named_values = [
                (str(getattr(scoped, "instance_name", "")),
                 enrich_from_inventory(service, scoped, values))
                for scoped, values in target_reports
            ]
            rows, statuses, failures, circuit_count = build_cvt_sum_rows(
                named_values, multi_instance=multi_instance,
            )
            with timed_step(
                "cvt_sum_update", sheet=sheet_name,
                instances=len(target_reports), circuits=circuit_count,
            ):
                timestamp = refresh_cvt_sum_sheet(
                    service, spreadsheet_id, sheet_name, rows, multi_instance,
                    first_args.timezone_name,
                )
            log_google_io(service, "cvt_sum")
            print(json.dumps({
                "spreadsheet_id": spreadsheet_id,
                "sheet": sheet_name,
                "instances": [name for name, _values in named_values if name],
                "circuits": circuit_count,
                "summary_rows": len(rows),
                "statuses": dict(statuses),
                "failures": dict(failures),
                "updated_at": timestamp,
            }, ensure_ascii=False))
    except (ValueError, OSError, RuntimeError) as error:
        LOGGER.error("Input error: %s", error)
        return 2
    except HttpError as error:
        LOGGER.error("Google Sheets API error while updating CVT_SUM: %s", error)
        return 1
    except Exception:
        LOGGER.exception("Unexpected CVT_SUM update failure")
        return 1
    return 0


def load_cabling_sum_case_reports(
    service: Any,
    spreadsheet_id: str,
    target_args: list[argparse.Namespace],
) -> list[tuple[str, str, list[list[Any]]]]:
    """Read configured Cabling sheets and return canonical per-instance sources."""
    raw_by_sheet: dict[str, list[list[Any]]] = {}
    reports: list[tuple[str, str, list[list[Any]]]] = []
    required = ("Status", "Error", "Local SU Number", INSTANCE_HEADER)
    for scoped in target_args:
        instance_name = str(getattr(scoped, "instance_name", ""))
        for cabling_type, attribute in (
            ("IB", "ib_cabling_sheet"),
            ("ETH", "eth_cabling_sheet"),
        ):
            sheet_name = str(getattr(scoped, attribute, "") or "").strip()
            if not sheet_name:
                continue
            cache_key = sheet_name.casefold()
            if cache_key not in raw_by_sheet:
                committed = getattr(scoped, "_committed_cabling", {})
                snapshot = (committed.get(committed_cabling_key(scoped, sheet_name))
                            if committed else None)
                raw_by_sheet[cache_key] = snapshot if snapshot is not None else (
                    service.spreadsheets().values().get(
                        spreadsheetId=spreadsheet_id,
                        range=remediation_table_range(scoped, sheet_name),
                    ).execute().get("values", [])
                )
            source = strip_timestamp_row(raw_by_sheet[cache_key])
            if not source:
                raise ValueError(
                    f"Cabling summary source sheet {sheet_name!r} is empty."
                )
            actual_headers = {str(header) for header in source[0]}
            missing = [
                scoped.remediation_header_mapping[header]
                for header in required
                if scoped.remediation_header_mapping[header] not in actual_headers
            ]
            if missing:
                raise ValueError(
                    f"Cabling summary source sheet {sheet_name!r} is missing "
                    f"required columns: {', '.join(missing)}"
                )
            reports.append((
                instance_name,
                cabling_type,
                canonicalize_remediation_values(
                    source, scoped.remediation_header_mapping
                ),
            ))
    return reports


def refresh_cabling_sum_targets(targets: list[argparse.Namespace]) -> int:
    """Refresh each Cabling_SUM target from CVT, Cabling, and Events sources."""
    grouped: dict[tuple[str, str], list[argparse.Namespace]] = defaultdict(list)
    for scoped in targets:
        sheet_name = str(scoped.cabling_sum_sheet or "").strip()
        if not sheet_name:
            LOGGER.error("Input error: --cabling-sum-sheet must not be empty")
            return 2
        if sheet_name.casefold() == str(scoped.cabling_events_sheet or "").strip().casefold():
            LOGGER.error(
                "Input error: --cabling-sum-sheet must differ from --cabling-events-sheet"
            )
            return 2
        grouped[(scoped.spreadsheet_id, sheet_name)].append(scoped)

    try:
        for (spreadsheet_id, sheet_name), target_args in grouped.items():
            first_args = target_args[0]
            period_configurations = {
                tuple(normalize_cabling_sum_period_hours(
                    scoped.cabling_sum_period_hours,
                    "cabling_sum_period_hours",
                ))
                for scoped in target_args
            }
            if len(period_configurations) != 1:
                raise ValueError(
                    f"Instances sharing Cabling_SUM sheet {sheet_name!r} must use "
                    "the same cabling_sum_period_hours."
                )
            period_hours = list(next(iter(period_configurations)))
            credential_path = Path(first_args.credentials)
            if not credential_path.is_file():
                raise ValueError(f"Credential JSON not found: {credential_path}")
            credentials = service_account.Credentials.from_service_account_file(
                credential_path, scopes=SCOPES
            )
            service = build_sheets_service(
                credentials, first_args.google_proxy, first_args.timeout
            )
            cvt_reports: list[tuple[str, list[list[Any]]]] = []
            with timed_step(
                "cabling_sum_collect_cvt", sheet=sheet_name,
                instances=len(target_args),
            ):
                for scoped in target_args:
                    cvt_reports.append((
                        str(getattr(scoped, "instance_name", "")),
                        enrich_from_inventory(service, scoped, load_cvt_sum_source(scoped)),
                    ))
            with timed_step(
                "cabling_sum_collect_cabling", sheet=sheet_name,
                instances=len(target_args),
            ):
                cabling_reports = load_cabling_sum_case_reports(
                    service, spreadsheet_id, target_args
                )
            event_rows: list[list[Any]] = []
            seen_sources: set[str] = set()
            with timed_step("cabling_sum_collect_events", sheet=sheet_name):
                for scoped in target_args:
                    event_sheet = str(scoped.cabling_events_sheet or "").strip()
                    normalized_source = event_sheet.casefold()
                    if not event_sheet:
                        raise ValueError(
                            "--cabling-events-sheet must not be empty when refreshing Cabling_SUM."
                        )
                    if normalized_source in seen_sources:
                        continue
                    seen_sources.add(normalized_source)
                    quoted = quoted_sheet_name(event_sheet)
                    header_values = service.spreadsheets().values().get(
                        spreadsheetId=spreadsheet_id, range=f"{quoted}!A2:J2",
                    ).execute().get("values", [])
                    headers = (
                        [str(value) for value in header_values[0]]
                        if header_values else []
                    )
                    if normalize_instance_headers(headers) != CABLING_EVENT_HEADERS:
                        raise ValueError(
                            f"{event_sheet} header mismatch; no Cabling_SUM data was changed. "
                            f"Expected {CABLING_EVENT_HEADERS}, got {headers}"
                        )
                    event_rows.extend(
                        service.spreadsheets().values().get(
                            spreadsheetId=spreadsheet_id, range=f"{quoted}!A3:J",
                        ).execute().get("values", [])
                    )
            with timed_step(
                "cabling_sum_update", sheet=sheet_name,
                instances=len(target_args), event_rows=len(event_rows),
            ):
                result = refresh_cabling_sum_sheet(
                    service,
                    spreadsheet_id,
                    sheet_name,
                    event_rows,
                    first_args.timezone_name,
                    cvt_reports,
                    period_hours,
                    cabling_reports,
                )
            log_google_io(service, "cabling_sum")
            LOGGER.info(
                "Cabling summary updated sheet=%s summary_rows=%s "
                "event_rows=%s cvt_instances=%s cabling_sources=%s "
                "periods=%s updated_at=%s",
                sheet_name,
                result["summaryRows"],
                len(event_rows),
                len(cvt_reports),
                len(cabling_reports),
                period_hours,
                result["updatedAt"],
            )
    except (ValueError, OSError, RuntimeError) as error:
        LOGGER.error("Input error: %s", error)
        return 2
    except HttpError as error:
        LOGGER.error("Google Sheets API error while updating Cabling_SUM: %s", error)
        return 1
    except Exception:
        LOGGER.exception("Unexpected Cabling_SUM update failure")
        return 1
    return 0


def run_once(args: argparse.Namespace) -> int:
    """Run one scheduled cycle, dispatching configured instances sequentially."""
    # All downstream normalization is allowed to mutate this private cycle copy;
    # the parsed process configuration remains immutable across scheduled runs.
    args = copy.deepcopy(args)
    if args.instances_config or has_non_summary_work(args):
        args._committed_cabling = {}
    if not args.instances_config:
        if has_non_summary_work(args):
            exit_code = run_single_instance(args)
            if exit_code:
                return exit_code
        elif not (args.refresh_cvt_sum or args.refresh_cabling_sum):
            return run_single_instance(args)
        if args.refresh_cvt_sum:
            try:
                with timed_step("cvt_sum_collect", instance="single"):
                    source_values = load_cvt_sum_source(args)
            except (ValueError, OSError) as error:
                LOGGER.error("Input error: %s", error)
                return 2
            # Runner-managed Sheets always retain the Instance column so a worksheet
            # can alternate safely between single- and multi-instance execution.
            exit_code = refresh_cvt_sum_targets(
                [(args, source_values)], multi_instance=True
            )
            if exit_code:
                return exit_code
        if args.refresh_cabling_sum:
            return refresh_cabling_sum_targets([args])
        return 0
    try:
        instances = instance_namespaces(args)
    except (ValueError, OSError) as error:
        LOGGER.error("Input error: %s", error)
        return 2
    except Exception:
        LOGGER.exception("Unexpected instance configuration failure")
        return 2

    last_error = 0
    summary_reports: list[tuple[argparse.Namespace, list[list[Any]]]] = []
    cabling_summary_targets: list[argparse.Namespace] = []
    for scoped in instances:
        # The most recent successful instance's post-write read wins when
        # several instances share a Cabling sheet. Reset on every run_once.
        scoped._committed_cabling = args._committed_cabling
        name = scoped.instance_name
        instance_started = time.monotonic()
        LOGGER.info("CVT instance started instance=%s", name)
        try:
            exit_code = (
                run_single_instance(scoped)
                if has_non_summary_work(scoped)
                or not (scoped.refresh_cvt_sum or scoped.refresh_cabling_sum)
                else 0
            )
        except Exception:
            LOGGER.exception("Unexpected CVT instance failure instance=%s", name)
            exit_code = 1
        LOGGER.info(
            "CVT instance finished instance=%s exit_code=%s duration_seconds=%.3f",
            name, exit_code, time.monotonic() - instance_started,
        )
        if exit_code:
            last_error = exit_code
            if args.instance_fail_fast:
                break
            continue
        if scoped.refresh_cvt_sum:
            try:
                with timed_step("cvt_sum_collect", instance=name):
                    summary_reports.append((scoped, load_cvt_sum_source(scoped)))
            except (ValueError, OSError) as error:
                LOGGER.error("Input error collecting CVT_SUM instance=%s error=%s", name, error)
                last_error = 2
                if args.instance_fail_fast:
                    break
            except Exception:
                LOGGER.exception("Unexpected CVT_SUM collection failure instance=%s", name)
                last_error = 1
                if args.instance_fail_fast:
                    break
        if scoped.refresh_cabling_sum:
            cabling_summary_targets.append(scoped)
    # Never replace a shared summary with a partial cycle after any selected instance failed.
    if last_error:
        if summary_reports:
            LOGGER.warning("CVT_SUM update skipped reason=incomplete_multi_instance_cycle")
        if cabling_summary_targets:
            LOGGER.warning("Cabling_SUM update skipped reason=incomplete_multi_instance_cycle")
        return last_error
    if summary_reports:
        exit_code = refresh_cvt_sum_targets(summary_reports, multi_instance=True)
        if exit_code:
            return exit_code
    if cabling_summary_targets:
        return refresh_cabling_sum_targets(cabling_summary_targets)
    return 0


STOP_REQUESTED = False


def request_stop(_signal_number: int, _frame: object) -> None:
    """Finish the current update and prevent another scheduled run."""
    global STOP_REQUESTED
    STOP_REQUESTED = True


def main() -> int:
    args = parse_args()
    try:
        operational_timezone(args.timezone_name)
    except ValueError as error:
        configure_logging(args.log_level, DEFAULT_TIMEZONE)
        LOGGER.error("Input error: %s", error)
        return 2
    configure_logging(args.log_level, args.timezone_name)
    if args.interval_seconds < 1:
        LOGGER.error("Input error: --interval-seconds must be at least 1")
        return 2
    if args.max_runs is not None and args.max_runs < 0:
        LOGGER.error("Input error: --max-runs must be 0 or greater")
        return 2
    if args.max_runs == 0:
        args.max_runs = None

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)
    run_count = 0
    last_exit_code = 0
    while not STOP_REQUESTED:
        run_count += 1
        current_args = copy.deepcopy(args)
        current_args.first_cycle = run_count == 1
        run_started = time.monotonic()
        LOGGER.info("CableTracker run started run=%s", run_count)
        try:
            last_exit_code = run_once(current_args)
        except IncompleteRead as error:
            LOGGER.error(
                "Google Sheets GET failed after retries; current cycle failed "
                "run=%s bytes_read=%s",
                run_count,
                len(error.partial or b""),
            )
            last_exit_code = 1
        except Exception:
            LOGGER.exception("Unexpected CableTracker cycle failure run=%s", run_count)
            last_exit_code = 1
        LOGGER.info(
            "CableTracker run finished run=%s exit_code=%s duration_seconds=%.3f",
            run_count, last_exit_code, time.monotonic() - run_started,
        )
        if args.max_runs is not None and run_count >= args.max_runs:
            break
        if STOP_REQUESTED:
            break
        deadline = time.monotonic() + args.interval_seconds
        while not STOP_REQUESTED and time.monotonic() < deadline:
            time.sleep(min(1, max(0, deadline - time.monotonic())))
    LOGGER.info("CableTracker stopped runs=%s", run_count)
    return last_exit_code


if __name__ == "__main__":
    raise SystemExit(main())
