#!/usr/bin/env python3
"""
generate-monitor-html.py — 以太网监控仪表板
放置位置: /var/www/html/monitor/generate-monitor-html.py
生成文件: /var/www/html/monitor/monitor.html

数据来源:
  Switch Status: Ethernet / InfiniBand / NVLink 最新 tar.gz
  Link Monitor:  SPX / InfiniBand / NVLink 近3天 CSV
  Topology:      99-output-p2p/ 中 Ethernet / InfiniBand 最新验证 XLSX
  Diagrams:      99-output-p2p/ 中最新 *-lldpq.dot / *-air.dot（自动生成或更新 HTML）

建议 cron（在 ethernet/monitor/cron.sh 完成后 5 分钟运行）：
  5 * * * * python3 /var/www/html/monitor/generate-monitor-html.py \
            >> /var/www/html/monitor/generate-monitor.log 2>&1
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import csv
import fcntl
import json
import os
import re
import stat
import sys
import tarfile
import tempfile
import zipfile
from datetime import datetime, timedelta, timezone
from html import escape
from pathlib import Path
from typing import Optional
from urllib.parse import quote
from xml.etree import ElementTree as ET
from zoneinfo import ZoneInfo

from dot_to_html import convert as convert_dot_to_html

# ``generate-monitor-html.py`` is executed from both /var/www/html and the
# Ethernet collector directory.  Add the HTTP root explicitly so the shared
# runtime AIR inventory resolver is importable in either case.
HTTP_ROOT = Path(__file__).resolve().parent.parent
if str(HTTP_ROOT) not in sys.path:
    sys.path.insert(0, str(HTTP_ROOT))
from ztp.dynamic_air_inventory import dynamic_air_devices

# ── 路径配置 ──────────────────────────────────────────────────────────────────
BASE_DIR     = Path(os.path.dirname(os.path.abspath(__file__)))
GLOBAL_FILE  = BASE_DIR / "01-global.yaml"
ETH_MON_DIR  = BASE_DIR / "ethernet"
IB_MON_DIR   = BASE_DIR / "infiniband"
NV_MON_DIR   = BASE_DIR / "nvlink"
ETH_INFO_DIR = ETH_MON_DIR / "eth-info"
SPX_LINK_DIR = ETH_MON_DIR / "spx-link"
IB_INFO_DIR  = IB_MON_DIR  / "ib-info"
IBL_LINK_DIR = IB_MON_DIR  / "ib-link"
NV_INFO_DIR  = NV_MON_DIR  / "nvsw-info"
NVL_LINK_DIR = NV_MON_DIR  / "nvsw-link"
OUTPUT       = BASE_DIR / "monitor.html"
LOG_FILE     = BASE_DIR / "generate-monitor.log"
GENERATION_LOCK = BASE_DIR / ".generate-monitor-html.lock"
DEVICES_CSV  = BASE_DIR / "02-devices_config.csv"
P2P_OUTPUT_DIR = BASE_DIR / "99-output-p2p"
ZTP_STATUS_DIR = BASE_DIR / "ztp-status"
ACTIVE_AIR_JSON = BASE_DIR.parent / "ztp/config/isc-dhcp-server/p2p-air.json"
P2P_INPUT_LINK = (
    BASE_DIR.parent / "ztp/config/cumulus/template/P2P/p2p.xlsx"
)
ETH_LOG      = DEVICES_CSV
IB_LOG       = DEVICES_CSV
NV_LOG       = DEVICES_CSV

def load_display_timezone(path: Path = GLOBAL_FILE):
    """Read the active project's display timezone with a safe local fallback."""
    timezone_name = os.environ.get("MONITOR_TIMEZONE", "").strip()
    if not timezone_name and path.is_file():
        try:
            import yaml

            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            system = data.get("common", {}).get("switch", {}).get("system", {})
            timezone_name = str(
                system.get("date-time", {}).get("timezone", "")
                or data.get("common", {}).get("mgmt", {}).get("timezone", "")
            ).strip()
        except (OSError, UnicodeError, AttributeError, TypeError, ValueError):
            timezone_name = ""
        except ImportError:
            # Monitor should still start on a reduced Python installation.  A
            # project global file normally contains a single timezone field.
            try:
                match = re.search(
                    r"(?m)^\s*timezone\s*:\s*['\"]?([^\s#'\"]+)",
                    path.read_text(encoding="utf-8"),
                )
                timezone_name = match.group(1) if match else ""
            except (OSError, UnicodeError):
                timezone_name = ""
    try:
        return ZoneInfo(timezone_name or "Asia/Shanghai")
    except (ValueError, KeyError):
        print(
            f"[WARN] Invalid monitor timezone {timezone_name!r}; "
            "falling back to Asia/Shanghai",
            file=sys.stderr,
        )
        return ZoneInfo("Asia/Shanghai")


# 交换机采集脚本及归档文件名使用 UTC；页面统一显示为项目所在时区。
SOURCE_TZ    = timezone.utc
DISPLAY_TZ   = load_display_timezone()
ENVIRONMENT_SCOPE = "all"


def selected_environments(scope: str) -> tuple[str, ...]:
    if scope == "air":
        return ("air",)
    if scope == "prod":
        return ("production",)
    return ("air", "production")


def selected_ztp_environments(scope: str) -> tuple[str, ...]:
    """Include unclassified runtime observations only on the combined page."""
    if scope == "all":
        return ("air", "production", "unknown")
    return selected_environments(scope)

# ── SPX 链路配置（以太网 SPX 交换机）──────────────────────────────────────────
SPX_DIFF_HOURS   = [1, 4, 12, 24, 48, 72, 168]
SPX_KEY_COLS     = 2
SPX_MAX_SNAPS    = 80
SPX_WATCH_FIELDS = [
    "Effective-Error",
    "Carrier-Transitions",
    "ECN-Marked",
    "PFC-Receive",
    "PFC-Send",
]

# ── IB 链路配置（InfiniBand 交换机）──────────────────────────────────────────
IBL_DIFF_HOURS   = [1, 4, 12, 24, 48, 72, 168]
IBL_KEY_COLS     = 2
IBL_MAX_SNAPS    = 80
IBL_WATCH_FIELDS = [
    "Effective-Error",
    "Carrier-Down-Count",
    "QP1-Drops-Receive",
    "QP1-Drops-Transmit",
]

# ── NVLink 链路配置（NVSwitch）────────────────────────────────────────────────
NVL_DIFF_HOURS   = [1, 4, 12, 24, 48, 72, 168]
NVL_KEY_COLS     = 2
NVL_MAX_SNAPS    = 80
NVL_WATCH_FIELDS = [
    "Effective-Error",
    "Carrier-Down-Count",
    "RX-Physical-Errors",
    "TX-Physical-Errors",
]

# ── 日志 ──────────────────────────────────────────────────────────────────────
def log(msg: str) -> None:
    line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {msg}"
    print(line, flush=True)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


@contextmanager
def generation_lock(path: Path = GENERATION_LOCK):
    """Serialize all readers/builders that publish the shared monitor page."""
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise OSError(f"invalid monitor generation lock: {path}")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def atomic_write_text(path: Path, content: str) -> None:
    """Publish HTML atomically so Apache never serves a partially written page."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        try:
            existing = path.stat()
        except OSError:
            existing = None
        if existing is not None:
            os.chown(temporary, existing.st_uid, existing.st_gid)
        os.replace(temporary, path)
        directory_fd = os.open(
            path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _diff_label(h: int) -> str:
    """将小时数转为显示标签：整天数用 Xd，否则用 Xh。"""
    return f"{h // 24}d" if h % 24 == 0 else f"{h}h"


def load_ztp_inventory(path: Path = DEVICES_CSV) -> dict[str, dict[str, str]]:
    """Return current type/template metadata used to enrich older ZTP reports."""
    paths = [path]
    try:
        result = {}
        for inventory_path in paths:
            if not inventory_path.is_file():
                continue
            with inventory_path.open(
                newline="", encoding="utf-8-sig", errors="replace"
            ) as stream:
                result.update({
                    str(row.get("hostname") or "").strip().casefold(): {
                        "hostname": str(row.get("hostname") or "").strip(),
                        "type": str(row.get("type") or "").strip(),
                        "template": str(row.get("template") or "").strip(),
                        "eth0_ip": str(row.get("eth0_ip") or "").strip(),
                        "eth0_mac": str(row.get("eth0_mac") or "").strip(),
                        "eth1_ip": str(row.get("eth1_ip") or "").strip(),
                        "eth1_mac": str(row.get("eth1_mac") or "").strip(),
                    }
                    for row in csv.DictReader(stream)
                    if str(row.get("hostname") or "").strip()
                })
        production = [
            (hostname, value) for hostname, value in result.items()
            if value.get("type") in {"eth", "eth_spx", "spx"}
        ]
        for hostname, value in result.items():
            if value.get("type") != "air" or value.get("template"):
                # AIR 清单经常使用通用 oob-leaf 模板；若对应 Production
                # 设备明确属于 OOBofOOB，分类仍应跟随真实设备角色。
                if value.get("type") != "air":
                    continue
            matches = [
                (name, candidate) for name, candidate in production
                if hostname.endswith(name)
            ]
            if matches:
                _name, source = max(matches, key=lambda item: len(item[0]))
                source_template = source.get("template", "")
                if not value.get("template") or "oobofoob" in source_template.casefold():
                    value["template"] = source_template
        return result
    except (OSError, UnicodeError, csv.Error):
        return {}


def load_dynamic_air_inventory(path: Path = DEVICES_CSV) -> list[dict[str, str]]:
    """Return AIR-only topology devices, including unresolved DHCP clients.

    These devices intentionally do not exist in the static project inventory
    when they have no Production counterpart.  Switch Status still needs their
    identity so it can render an explicit Missing placeholder before a DHCP
    lease (and therefore an SSH target) is available.
    """
    try:
        active_source = None
        try:
            if path.resolve() == DEVICES_CSV.resolve() and ACTIVE_AIR_JSON.is_file():
                active_source = ACTIVE_AIR_JSON
        except OSError:
            pass
        return dynamic_air_devices(
            path.resolve(),
            air_json=active_source,
        )
    except (OSError, UnicodeError, csv.Error, ValueError):
        return []


def load_ztp_status(
    directory: Path = ZTP_STATUS_DIR, inventory: Path = DEVICES_CSV,
    scope: str = "all",
) -> dict:
    """分别读取 AIR 与 Production 的最新结构化报告并合并设备。"""
    if not directory.is_dir():
        return {"available": False, "source": "（无数据）", "generated_at": "—",
                "project": "—", "devices": [], "counts": {}}

    metadata = load_ztp_inventory(inventory)
    dynamic_metadata = {
        str(item.get("hostname") or "").casefold(): item
        for item in load_dynamic_air_inventory(inventory)
        if str(item.get("hostname") or "").strip()
    }
    expected_metadata = dict(metadata)
    for hostname, item in dynamic_metadata.items():
        expected_metadata[hostname] = {
            "hostname": str(item.get("hostname") or ""),
            "type": "air", "template": str(item.get("template") or ""),
            "eth0_ip": str(item.get("ip") or ""),
            "eth0_mac": str(item.get("mac") or ""),
            "dynamic_dhcp": True,
            "address_source": str(item.get("address_source") or "unresolved"),
            "runtime_issue": str(item.get("issue") or ""),
        }
    current_by_mac = {}
    for item in metadata.values():
        for field in ("eth0_mac", "eth1_mac"):
            mac_plain = re.sub(
                r"[^0-9a-f]", "", str(item.get(field) or "").casefold()
            )
            if re.fullmatch(r"[0-9a-f]{12}", mac_plain):
                current_by_mac[mac_plain] = item
    reports = []
    seen: set[Path] = set()
    errors = []
    for report_path in directory.glob("*/report.json"):
        try:
            resolved = report_path.resolve()
            if resolved in seen:
                continue
            seen.add(resolved)
            report = json.loads(report_path.read_text(encoding="utf-8"))
            devices = report.get("devices", [])
            if not isinstance(devices, list):
                raise ValueError("devices 必须是列表")
            enriched = []
            for original in devices:
                if not isinstance(original, dict):
                    continue
                device = dict(original)
                hostname_key = str(device.get("hostname") or "").casefold()
                current = expected_metadata.get(hostname_key)
                promoted_from_unbound = False
                if current is None and device.get("unbound_identity"):
                    report_mac = re.sub(
                        r"[^0-9a-f]", "", str(device.get("mac") or "").casefold()
                    )
                    current = current_by_mac.get(report_mac)
                    promoted_from_unbound = current is not None
                # Historical/imported reports may contain topology placeholders
                # or a pre-promotion alias no longer present in the current
                # inventory.  Current inventory/MAC resolution defines the
                # dashboard population; stale report members are ignored.
                if current is None and not device.get("unbound_identity"):
                    continue
                if current is None:
                    enriched.append(device)
                    continue
                if promoted_from_unbound:
                    dynamic_ip = str(device.get("ip") or "")
                    device["hostname"] = str(current.get("hostname") or device.get("hostname") or "")
                    device["type"] = str(current.get("type") or device.get("type") or "")
                    device["template"] = str(current.get("template") or "")
                    if current.get("eth0_ip"):
                        device["ip"] = current["eth0_ip"]
                    if current.get("eth0_mac"):
                        device["mac"] = current["eth0_mac"]
                    if dynamic_ip and dynamic_ip != str(device.get("ip") or ""):
                        device["dynamic_lease_ips"] = [dynamic_ip]
                    device["promotion_pending"] = True
                    device["unbound_identity"] = False
                    device["identity_pending"] = False
                    device["address_source"] = "dhcp-lease-transition"
                    device["trigger_source"] = "inventory_promotion"
                    for item in (device.get("stages") or {}).values():
                        if isinstance(item, dict):
                            item["success_index"] = 0
                    device["overall"] = "warning"
                    issues = device.setdefault("issues", [])
                    issues.append({
                        "code": "STATIC_PROMOTION_PENDING",
                        "severity": "warning",
                        "message": (
                            "此前未绑定的 DHCP MAC 已匹配当前项目设备；等待通过同一 release "
                            "的 DHCP/YAML/MAC 链接重新执行 ZTP。"
                        ),
                    })
                if current.get("type"):
                    device["type"] = current["type"]
                if current.get("template"):
                    device["template"] = current["template"]
                if current.get("dynamic_dhcp"):
                    device["dynamic_dhcp"] = True
                    device["address_source"] = current.get("address_source", "unresolved")
                    if current.get("eth0_ip"):
                        device["ip"] = current["eth0_ip"]
                    if current.get("eth0_mac"):
                        device["mac"] = current["eth0_mac"]
                # A current static AIR row supersedes a historical AIR-only
                # dynamic report.  Do not keep painting the old lease yellow
                # or classifying the canonical device as a default-config
                # client while waiting for the next monitor snapshot.
                if (
                    current.get("type") == "air"
                    and device.get("dynamic_dhcp")
                    and not current.get("dynamic_dhcp")
                ):
                    if current.get("eth0_ip"):
                        device["ip"] = current["eth0_ip"]
                    if current.get("eth0_mac"):
                        device["mac"] = current["eth0_mac"]
                    device.pop("dynamic_dhcp", None)
                    device.pop("address_source", None)
                    device.pop("runtime_issue", None)
                    device.pop("ip_probe", None)
                    device["promotion_pending"] = True
                    device["trigger_source"] = "inventory_promotion"
                    for item in (device.get("stages") or {}).values():
                        if isinstance(item, dict):
                            item["success_index"] = 0
                    device["overall"] = "warning"
                    issues = device.setdefault("issues", [])
                    if not any(
                        isinstance(issue, dict)
                        and issue.get("code") == "STATIC_PROMOTION_PENDING"
                        for issue in issues
                    ):
                        issues.append({
                            "code": "STATIC_PROMOTION_PENDING",
                            "severity": "warning",
                            "message": (
                                "设备已进入专属静态清单，等待手工 ZTP/reset 应用专属 YAML。"
                            ),
                        })
                enriched.append(device)
            # A historical report can contain both a planned canonical
            # placeholder and its DHCP-discovered alias.  Promotion maps both
            # to the same hostname; retain exactly one row, preferring the
            # promotion row because it carries the old default-ZTP evidence
            # and the required dedicated-config warning.
            deduplicated = {}
            for device in enriched:
                key = (
                    ztp_environment(device),
                    str(device.get("hostname") or "").casefold(),
                )
                existing = deduplicated.get(key)
                score = (
                    1 if device.get("promotion_pending") else 0,
                    int((device.get("progress") or {}).get("done") or 0),
                    len(device.get("events") or []),
                )
                existing_score = (
                    1 if existing and existing.get("promotion_pending") else 0,
                    int(((existing or {}).get("progress") or {}).get("done") or 0),
                    len((existing or {}).get("events") or []),
                )
                if existing is None or score > existing_score:
                    deduplicated[key] = device
            enriched = list(deduplicated.values())
            generated_at = str(report.get("generated_at") or "")
            try:
                sort_time = datetime.fromisoformat(
                    generated_at.replace("Z", "+00:00")
                ).timestamp()
            except ValueError:
                sort_time = report_path.stat().st_mtime
            reports.append((sort_time, report_path, report, enriched))
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            errors.append(f"{report_path}: {exc}")

    environments = selected_ztp_environments(scope)
    try:
        include_current_placeholders = inventory.resolve() == DEVICES_CSV.resolve()
    except OSError:
        include_current_placeholders = False
    selected = {}
    for environment in environments:
        candidates = [
            item for item in reports
            if any(ztp_environment(device) == environment for device in item[3])
        ]
        if candidates:
            selected[environment] = max(
                candidates, key=lambda item: (item[0], item[1].parent.name)
            )
    if not selected:
        detail = errors[-1] if errors else "ztp/status 下尚无有效监控报告。"
        return {"available": False, "source": "（无数据）", "generated_at": "—",
                "project": "—", "devices": [], "counts": {}, "error": detail}

    devices = []
    sources = {}
    environment_updates = {}
    projects = []
    for environment in environments:
        if environment not in selected:
            continue
        _sort_time, report_path, report, report_devices = selected[environment]
        generated_at = str(report.get("generated_at") or "—")
        sources[environment] = str(report_path)
        environment_updates[environment] = generated_at
        project = str(report.get("project") or "")
        if project and project not in projects:
            projects.append(project)
        for original in report_devices:
            if ztp_environment(original) != environment:
                continue
            device = dict(original)
            device["_report_generated_at"] = generated_at
            device["_report_source"] = str(report_path)
            devices.append(device)

    # Keep the page aligned with the current project even when the newest
    # imported report predates a newly discovered or newly planned device.
    # It starts as pending until 12-ztp-monitor writes real evidence.
    seen_devices = {
        str(device.get("hostname") or "").casefold() for device in devices
    }
    stage_names = (
        "dhcp", "bootstrap", "config_http", "ssh", "network", "version",
        "config_apply", "ssh_keys", "complete",
    )
    for hostname_key, current in expected_metadata.items():
        if not include_current_placeholders:
            break
        device_type = str(current.get("type") or "").casefold()
        if device_type not in {"air", "eth", "eth_spx", "spx", "ib", "nvl"}:
            continue
        environment = "air" if device_type == "air" else "production"
        if environment not in environments or hostname_key in seen_devices:
            continue
        original_hostname = str(current.get("hostname") or hostname_key)
        pending = {
            "hostname": original_hostname, "type": device_type,
            "template": str(current.get("template") or ""),
            "ip": str(current.get("eth0_ip") or ""),
            "mac": str(current.get("eth0_mac") or ""),
            "dynamic_dhcp": bool(current.get("dynamic_dhcp")),
            "address_source": str(current.get("address_source") or ""),
            "ztp_round": 1, "overall": "pending", "observed_at": "",
            "stages": {
                name: {"status": "pending", "detail": "", "timestamp": "",
                       "success_index": 0}
                for name in stage_names
            },
            "progress": {"done": 0, "total": len(stage_names), "percent": 0},
            "issues": [], "_report_generated_at": "",
            "_report_source": "current-inventory-placeholder",
        }
        runtime_issue = str(current.get("runtime_issue") or "")
        if runtime_issue:
            pending["issues"].append({
                "code": "DYNAMIC_ADDRESS_CONFLICT", "severity": "warning",
                "message": runtime_issue,
            })
        devices.append(pending)
        seen_devices.add(hostname_key)

    counts: dict[str, int] = {}
    for device in devices:
        overall = str(device.get("overall", "unknown"))
        counts[overall] = counts.get(overall, 0) + 1
    newest_update = max(
        environment_updates.values(),
        key=lambda value: format_ztp_write_time(value),
        default="—",
    )
    return {
        "available": True,
        "source": "；".join(
            f"{environment.upper()}: {path}"
            for environment, path in sources.items()
        ),
        "sources": sources, "environment_updates": environment_updates,
        "generated_at": newest_update,
        "project": " / ".join(projects) or "—", "devices": devices,
        "counts": counts,
    }


ZTP_DEVICE_GROUPS = (
    ("oobofoob", "OOBofOOB"),
    ("border_oob", "OOB / Border"),
    ("tan", "TAN"),
    ("ib_nvl", "IB / NVL"),
    ("other", "其他"),
)
ZTP_ENVIRONMENTS = (
    ("air", "AIR"),
    ("production", "Production"),
    ("unknown", "Unknown / 未归类"),
)


def format_ztp_write_time(value: object) -> str:
    """Format the report write time in the dashboard display timezone."""
    raw = str(value or "").strip()
    if not raw or raw == "—":
        return "—"
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=SOURCE_TZ)
        displayed = parsed.astimezone(DISPLAY_TZ)
        offset = displayed.strftime("%z")
        formatted_offset = f"{offset[:3]}:{offset[3:]}" if offset else ""
        return f'{displayed.strftime("%Y-%m-%d %H:%M:%S")} UTC{formatted_offset}'
    except ValueError:
        return raw


def ztp_environment(device: dict) -> str:
    """Return the explicit environment without guessing unknown as production."""
    explicit = str(device.get("environment") or "").strip().casefold()
    if explicit == "prod":
        return "production"
    if explicit in {"air", "production", "unknown"}:
        return explicit
    hostname = str(device.get("hostname") or "").casefold()
    device_type = str(device.get("type") or "").casefold()
    return "air" if device_type == "air" or hostname.startswith("air-") else "production"


def ztp_device_group(device: dict) -> str:
    """Classify the ordered ZTP waves using names for Ethernet and type for NVOS."""
    hostname = str(device.get("hostname") or "").casefold()
    template = str(device.get("template") or "").casefold()
    device_type = str(device.get("type") or "").casefold()
    if "oobofoob" in hostname or "oobofoob" in template:
        return "oobofoob"
    if "tan" in hostname or "tan" in template:
        return "tan"
    if device_type in {"ib", "nvl"}:
        return "ib_nvl"
    if ("oob" in hostname or "border" in hostname
            or "oob" in template or "border" in template):
        return "border_oob"
    return "other"


def ztp_completed(device: dict) -> bool:
    """Return whether a device has successfully completed the ZTP workflow."""
    stages = device.get("stages")
    if isinstance(stages, dict):
        complete = stages.get("complete")
        if isinstance(complete, dict) and complete.get("status"):
            if str(complete.get("status")).casefold() != "success":
                return False
            # Reports produced before per-cycle indices existed are accepted
            # as legacy current state.  An explicit index=0 is different: the
            # current monitor deliberately cleared stale evidence (notably
            # while a factory reset is waiting for a reboot/new DHCP cycle).
            if "success_index" not in complete:
                return True
            try:
                ztp_round = max(1, int(device.get("ztp_round", 1)))
                return int(complete.get("success_index") or 0) == ztp_round
            except (TypeError, ValueError):
                return False
    # Older reports did not always include the complete stage details.
    return str(device.get("overall") or "").casefold() == "success"


def render_ztp_status_rows(status: dict) -> str:
    if not status.get("available"):
        detail = status.get("error", "ztp/status 下尚无监控报告。")
        return (f'<tr class="ztp-empty"><td colspan="17">'
                f'{escape(str(detail))}</td></tr>')
    labels = {
        "pending": "等待", "running": "进行中", "success": "成功",
        "warning": "警告", "failed": "失败", "unknown": "未知",
        "not_applicable": "不适用", "skipped": "跳过",
    }
    def badge(value: str, ztp_round: int = 0, extra_class: str = "") -> str:
        safe = value if value in labels else "unknown"
        suffix = str(ztp_round) if ztp_round > 0 else ""
        classes = f"ztp-state ztp-{safe}"
        if extra_class:
            classes += f" {extra_class}"
        return f'<span class="{classes}">{labels[safe]}{suffix}</span>'
    write_time = format_ztp_write_time(status.get("generated_at"))
    grouped = {
        environment: {name: [] for name, _label in ZTP_DEVICE_GROUPS}
        for environment, _label in ZTP_ENVIRONMENTS
    }
    for device in status.get("devices", []):
        grouped[ztp_environment(device)][ztp_device_group(device)].append(device)
    rows = []
    for environment, environment_label in ZTP_ENVIRONMENTS:
        environment_count = sum(len(devices) for devices in grouped[environment].values())
        environment_completed = sum(
            ztp_completed(device)
            for devices in grouped[environment].values()
            for device in devices
        )
        rows.append(
            f'<tr class="ztp-environment" data-environment="{environment}" '
            f'role="button" tabindex="0" aria-expanded="true" '
            f'onclick="toggleZtpEnvironment(this)" '
            f'onkeydown="handleZtpToggleKey(event,this,\'environment\')">'
            f'<td colspan="17">{escape(environment_label)} '
            f'<span>{environment_completed}/{environment_count} 台</span></td></tr>'
        )
        for group_name, group_label in ZTP_DEVICE_GROUPS:
            group_id = f"{environment}__{group_name}"
            devices = sorted(
                grouped[environment][group_name],
                key=lambda device: str(device.get("hostname", "")).casefold(),
            )
            group_completed = sum(ztp_completed(device) for device in devices)
            rows.append(
                f'<tr class="ztp-group" data-environment="{environment}" '
                f'data-group="{group_id}" role="button" tabindex="0" '
                f'aria-expanded="true" onclick="toggleZtpGroup(this)" '
                f'onkeydown="handleZtpToggleKey(event,this,\'group\')">'
                f'<td colspan="17">{escape(group_label)} '
                f'<span>{group_completed}/{len(devices)} 台</span></td></tr>'
            )
            for device in devices:
                rows.append(_render_ztp_device_row(
                    device, group_id, labels, badge, environment, write_time,
                ))
    rows.append('<tr id="ztp-no-match" class="ztp-empty hidden"><td colspan="17">没有符合筛选条件的设备。</td></tr>')
    return "".join(rows)


def _render_ztp_device_row(
    device: dict, group_name: str, labels: dict, badge, environment: str,
    write_time: str,
) -> str:
        stages = device.get("stages", {})
        try:
            ztp_round = max(1, int(device.get("ztp_round", 1)))
        except (TypeError, ValueError):
            ztp_round = 1
        reset_cycle = str(device.get("manual_operation") or "") == "reset"
        dynamic_dhcp = str(device.get("dynamic_dhcp") or "").strip().casefold()
        is_dynamic_dhcp = dynamic_dhcp in {"1", "true", "yes"}
        is_unbound_identity = bool(device.get("unbound_identity"))
        is_managed_discovery = bool(device.get("managed_ztp"))
        promotion_pending = bool(device.get("promotion_pending"))
        dynamic_lease_ips = {
            str(value).strip() for value in device.get("dynamic_lease_ips", [])
            if str(value).strip()
        }
        ztp_transport_ips = {
            str(value).strip() for value in device.get("ztp_transport_ips", [])
            if str(value).strip()
        }
        def state(name: str) -> str:
            item = stages.get(name, {})
            has_success_index = "success_index" in item
            try:
                success_index = max(0, int(item.get("success_index", 0)))
            except (TypeError, ValueError):
                success_index = 0
            raw_status = str(item.get("status", "unknown"))
            # Only reports that genuinely predate success_index get the
            # round-1 compatibility fallback.  In current reports index=0 is
            # an explicit "not proven for this cycle" marker.
            index_is_current = (
                success_index == ztp_round if has_success_index else True
            )
            stale_success = (
                raw_status in {"success", "warning", "skipped"}
                and not index_is_current
            )
            badge_index = (
                ztp_round if stale_success and reset_cycle
                else 0 if stale_success
                else success_index
            )
            if (reset_cycle and not success_index
                    and raw_status in {"pending", "running", "unknown"}):
                badge_index = ztp_round
            detail = str(item.get("detail") or "")
            dynamic_success = (
                name == "dhcp"
                and (is_dynamic_dhcp or any(
                    address in detail for address in dynamic_lease_ips
                ))
                and raw_status == "success" and not stale_success
            )
            status_badge = badge(
                "pending" if stale_success else raw_status,
                badge_index,
                "ztp-dhcp-dynamic" if dynamic_success else "",
            )
            event_time = format_ztp_write_time(item.get("timestamp"))
            visible_event_time = "—" if stale_success else event_time
            event_time_html = (
                f'<span class="ztp-event-time">'
                f'{escape(visible_event_time)}</span>'
            )
            title_parts = []
            if stale_success:
                if success_index:
                    title_parts.append(
                        f"上一轮成功 index={success_index}；等待第 {ztp_round} 轮新证据"
                    )
                else:
                    title_parts.append(f"等待第 {ztp_round} 轮新成功证据")
            if event_time != "—":
                title_parts.append(f"事件时间：{event_time}")
            if detail:
                title_parts.append(detail)
            if dynamic_success:
                title_parts.append("地址由动态 DHCP 分配")
            if not title_parts:
                return status_badge + event_time_html
            return (
                f'<span class="ztp-stage-event" title="'
                f'{escape("；".join(title_parts), quote=True)}">{status_badge}</span>'
                f'{event_time_html}'
            )
        issues = device.get("issues", [])
        issue_text = []
        for issue in issues:
            issue_time = format_ztp_write_time(issue.get("timestamp"))
            time_prefix = f"[{issue_time}] " if issue_time != "—" else ""
            text = f"{time_prefix}{issue.get('code', 'UNKNOWN')}: {issue.get('message', '')}"
            diagnostics = issue.get("diagnostics") or []
            if diagnostics:
                text += "；" + "；".join(str(item) for item in diagnostics)
            issue_text.append(text)
        diagnosis_text = "；".join(issue_text) or "-"
        overall = str(device.get("overall", "unknown"))
        trigger_source = str(device.get("trigger_source") or "automatic")
        trigger_source_label = {
            "manual_web": "页面手工",
            "manual_cli": "CLI 手工",
            "manual_reset_web": "页面重置",
            "manual_reset_cli": "CLI 重置",
            "automatic": "自动",
            "inventory_promotion": "静态转正",
        }.get(trigger_source, trigger_source)
        complete_stage = stages.get("complete", {})
        complete_has_index = (
            isinstance(complete_stage, dict)
            and "success_index" in complete_stage
        )
        try:
            complete_index = int(complete_stage.get("success_index") or 0)
        except (TypeError, ValueError, AttributeError):
            complete_index = 0
        complete_is_current = (
            isinstance(complete_stage, dict)
            and str(complete_stage.get("status") or "") in {"success", "warning"}
            and (
                complete_index == ztp_round
                or not complete_has_index
            )
        )
        device_write_time = (
            format_ztp_write_time(complete_stage.get("timestamp"))
            if complete_is_current else "—"
        )
        observed_raw = device.get("observed_at") or device.get("_report_generated_at")
        device_observed_time = (
            format_ztp_write_time(observed_raw) if observed_raw else write_time
        )
        progress = device.get("progress", {}).get("percent", 0)
        time_sync = (
            device.get("time_sync")
            if isinstance(device.get("time_sync"), dict) else {}
        )
        time_status = str(time_sync.get("status") or "unknown")
        try:
            time_offset = float(time_sync.get("offset_seconds"))
        except (TypeError, ValueError):
            time_offset = None
        time_label = (
            "同步" if time_status == "success"
            else f"{time_offset:+.1f}s" if time_offset is not None
            else "无法检查"
        )
        time_title = str(time_sync.get("detail") or "尚未取得可信时间测量")
        time_checked_at = format_ztp_write_time(time_sync.get("checked_at"))
        if time_checked_at != "—":
            time_title += f"；检查时间：{time_checked_at}"
        time_badge_status = (
            "success" if time_status == "success"
            else "warning" if time_status == "warning" else "unknown"
        )
        time_sync_html = (
            f'<span class="ztp-stage-event" title="{escape(time_title, quote=True)}">'
            f'<span class="ztp-state ztp-{time_badge_status}">{escape(time_label)}</span>'
            '</span>'
            f'<span class="ztp-event-time">{escape(time_checked_at)}</span>'
        )
        ip_probe = device.get("ip_probe") if isinstance(device.get("ip_probe"), dict) else {}
        candidates = ip_probe.get("candidates") if isinstance(ip_probe.get("candidates"), list) else []
        if not candidates:
            configured_ip = str(device.get("ip") or "").strip()
            candidates = (
                [configured_ip] if configured_ip else list(dict.fromkeys([
                    *device.get("ssh_ips", []), *sorted(ztp_transport_ips),
                ]))
            )
        attempts = ip_probe.get("attempts") if isinstance(ip_probe.get("attempts"), list) else []
        interfaces = (
            ip_probe.get("interfaces")
            if isinstance(ip_probe.get("interfaces"), dict) else {}
        )
        attempted = {
            str(item.get("ip", "")): str(item.get("status", "")).casefold()
            for item in attempts if isinstance(item, dict) and item.get("ip")
        }
        connected_ip = str(ip_probe.get("connected_ip") or "")
        rendered_ips = []
        for candidate in dict.fromkeys(str(value) for value in candidates if value):
            transit_candidate = candidate in ztp_transport_ips
            interface_name = str(interfaces.get(candidate) or (
                "ZTP transit" if transit_candidate else
                "eth0" if candidate == str(device.get("ip") or "") else "SVI"
            ))
            dynamic_primary = (
                is_dynamic_dhcp
                and candidate == str(device.get("ip") or "")
            )
            dynamic_candidate = (
                dynamic_primary or candidate in dynamic_lease_ips or transit_candidate
            )
            if attempted.get(candidate) == "failed":
                css_class = "ztp-ip-failed"
                title = (
                    "ZTP transit 临时地址探测失败" if transit_candidate else
                    "动态 DHCP 地址探测失败" if dynamic_candidate else
                    "该地址探测失败"
                )
            elif dynamic_candidate:
                css_class = "ztp-ip-dynamic"
                if transit_candidate:
                    title = (
                        "清单未配置 eth0 地址；当前 ZTP transit 地址已通过双重 MAC 校验并用于临时采集"
                        if candidate == connected_ip or attempted.get(candidate) == "success"
                        else "清单未配置 eth0 地址；这是当前 ZTP transit 临时地址，尚未成功采集"
                    )
                else:
                    title = (
                        "管理地址由动态 DHCP 分配，且已用于成功采集"
                        if candidate == connected_ip or attempted.get(candidate) == "success"
                        else "管理地址由动态 DHCP 分配，尚未记录探测结果"
                    )
            elif candidate == connected_ip or attempted.get(candidate) == "success":
                css_class = "ztp-ip-success"
                title = "该地址探测成功并用于采集"
            else:
                css_class = "ztp-ip-neutral"
                title = "该地址尚未探测或报告未记录结果"
            rendered_ips.append(
                f'<span class="ztp-ip {css_class}" title="{title}">'
                f'<span class="ztp-ip-interface">{escape(interface_name)}:</span> '
                f'{escape(candidate)}</span>'
            )
        if rendered_ips:
            ip_html = "".join(rendered_ips)
        elif is_dynamic_dhcp:
            ip_html = (
                '<span class="ztp-ip ztp-ip-neutral" '
                'title="动态 DHCP 尚未分配或监控尚未解析到租约地址">'
                'DHCP 未分配</span>'
            )
        else:
            ip_html = "—"
        search = " ".join(str(value) for value in (
            device.get("hostname", ""), device.get("type", ""), *candidates,
            device.get("mac", ""), overall, f"round {ztp_round}",
            device.get("platform_family", ""), device.get("product", ""),
            device.get("serial", ""),
            trigger_source, trigger_source_label,
            time_label, time_title,
            device_write_time, device_observed_time,
            *issue_text,
        )).lower()
        reset_button = ""
        if str(device.get("type") or "").casefold() in {"eth", "eth_spx", "spx", "air"}:
            reset_button = (
                f'<button class="manual-reset-button" type="button" disabled '
                f'data-hostname="{escape(str(device.get("hostname", "")), quote=True)}" '
                f'data-device-type="{escape(str(device.get("type", "")), quote=True)}" '
                f'onclick="requestManualReset(this)">手工重置</button>'
            )
        if is_unbound_identity:
            action_text = (
                "DHCP 重新获取（先绑定）" if is_managed_discovery else "需要人工识别"
            )
            action_title = (
                "设备已由平台指纹进入默认 ZTP；先把 MAC 绑定到真实设备并重新 load"
                if is_managed_discovery else
                "平台指纹未知，管理服务器未下发 ZTP；请通过 console/物理连接人工识别"
            )
            operation_html = (
                '<button class="manual-ztp-button" type="button" disabled '
                'data-manual-eligible="false" '
                f'data-managed-discovery="{str(is_managed_discovery).lower()}" '
                f'data-hostname="{escape(str(device.get("hostname", "")), quote=True)}" '
                f'data-device-type="{escape(str(device.get("type", "")), quote=True)}" '
                f'title="{escape(action_title, quote=True)}">{action_text}</button>'
                '<button class="time-sync-button" type="button" disabled '
                'title="设备尚未绑定可信身份，不能远程修改时间">时间同步</button>'
            )
        else:
            primary_action = "renew" if promotion_pending else "trigger"
            primary_label = "重新获取 DHCP/ZTP" if promotion_pending else "手工 ZTP"
            primary_handler = (
                "requestManualRenew(this)" if promotion_pending
                else "requestManualZtp(this)"
            )
            renew_effective = (
                "reset"
                if promotion_pending
                and str(device.get("type") or "").casefold()
                in {"eth", "eth_spx", "spx", "air"}
                and dynamic_lease_ips
                else "ztp"
            )
            operation_html = (
                f'<button class="manual-ztp-button" type="button" disabled '
                f'data-manual-eligible="true" '
                f'data-default-action="{primary_action}" '
                f'data-renew-effective="{renew_effective}" '
                f'data-hostname="{escape(str(device.get("hostname", "")), quote=True)}" '
                f'data-device-type="{escape(str(device.get("type", "")), quote=True)}" '
                f'onclick="{primary_handler}">{primary_label}</button>{reset_button}'
                f'<button class="time-sync-button" type="button" disabled '
                f'data-hostname="{escape(str(device.get("hostname", "")), quote=True)}" '
                f'data-device-type="{escape(str(device.get("type", "")), quote=True)}" '
                f'onclick="requestTimeSync(this)">时间同步</button>'
            )
        return (
            f'<tr class="ztp-row" data-environment="{environment}" '
            f'data-group="{group_name}" '
            f'data-hostname="{escape(str(device.get("hostname", "")), quote=True)}" '
            f'data-ztp-round="{ztp_round}" '
            f'data-trigger-source="{escape(trigger_source, quote=True)}" '
            f'data-trigger-id="{escape(str(device.get("trigger_id") or ""), quote=True)}" '
            f'data-manual-operation="{escape(str(device.get("manual_operation") or ""), quote=True)}" '
            f'data-manual-cycle-marker="{escape(str(device.get("manual_cycle_marker") or ""), quote=True)}" '
            f'data-cycle-started-at="{escape(str(device.get("cycle_started_at") or ""), quote=True)}" '
            f'data-reset-reboot-observed="{str(bool(device.get("reset_reboot_observed"))).lower()}" '
            f'data-search="{escape(search, quote=True)}">'
            f'<td>{escape(str(device.get("hostname", "")))}</td>'
            f'<td>{escape(str(device.get("type", "")))}</td>'
            f'<td class="ztp-ip-cell">{ip_html}</td>'
            f'<td>{escape(str(device.get("mac", "")))}</td>'
            f'<td data-ztp-stage="dhcp">{state("dhcp")}</td>'
            f'<td data-ztp-stage="bootstrap">{state("bootstrap")}</td>'
            f'<td data-ztp-stage="config_http">{state("config_http")}</td>'
            f'<td data-ztp-stage="ssh">{state("ssh")}</td>'
            f'<td data-ztp-stage="network">{state("network")}</td>'
            f'<td data-ztp-stage="version">{state("version")}</td>'
            f'<td data-ztp-stage="config_apply">{state("config_apply")}</td>'
            f'<td data-ztp-stage="ssh_keys">{state("ssh_keys")}</td>'
            f'<td data-ztp-stage="complete">{state("complete")}</td>'
            f'<td data-ztp-stage="progress"><strong>{escape(str(progress))}%</strong><div class="ztp-progress">'
            f'<i style="width:{max(0, min(100, int(progress or 0)))}%"></i></div></td>'
            f'<td data-time-sync="status">{time_sync_html}</td>'
            f'<td data-ztp-stage="overall"><div class="ztp-overall-meta">'
            f'<div class="ztp-meta-row ztp-overall-result">{badge(overall, ztp_round)}'
            f'<span class="ztp-write-time">来源：{escape(trigger_source_label)}</span></div>'
            f'<div class="ztp-meta-row"><span class="ztp-write-time">检查：{escape(device_observed_time)}</span>'
            f'<span class="ztp-diagnosis" title="{escape(" | ".join(issue_text), quote=True)}">'
            f'原因：{escape(diagnosis_text)}</span></div></div></td>'
            f'<td>{operation_html}</td></tr>'
        )


def read_host_csv(path: Path, types: set) -> list:
    """读取设备 CSV，按 type 列过滤并返回 hostname 列表。"""
    if not path.is_file():
        return []
    hosts = []
    # 项目清单可能包含由 Excel/macOS 写入的非 UTF-8 备注字符；hostname、
    # type、template 都是 ASCII 字段，替换无效备注字节不会影响设备识别。
    with open(path, newline="", encoding="utf-8-sig", errors="replace") as f:
        reader = csv.reader(f)
        try:
            header = [h.strip().lower() for h in next(reader)]
        except StopIteration:
            return []
        try:
            hc = header.index("hostname")
            tc = header.index("type")
        except ValueError:
            return []
        for row in reader:
            if len(row) <= max(hc, tc):
                continue
            h = row[hc].strip()
            t = row[tc].strip().lower()
            if h and not h.startswith("#") and t in types:
                hosts.append(h)
    return hosts


def match_inventory_metadata(
    hostname: str, inventory: dict[str, dict[str, str]],
) -> dict[str, str]:
    """按完整主机名或去除机架前缀后的后缀匹配设备清单。"""
    normalized = hostname.casefold()
    exact = inventory.get(normalized)
    if exact is not None:
        return exact
    hostname_is_air = is_air_hostname(hostname)
    matches = [
        (name, value) for name, value in inventory.items()
        if is_air_hostname(name) == hostname_is_air
        and normalized.endswith("-" + name)
    ]
    return max(matches, key=lambda item: len(item[0]))[1] if matches else {}


def host_matched(log_host: str, info_hostnames) -> bool:
    """检查 log 主机名是否与任意 info 主机名精确或后缀匹配（ETH 设备名带机架前缀）。"""
    lh = log_host.upper()
    log_is_air = is_air_hostname(log_host)
    for hn in info_hostnames:
        if is_air_hostname(hn) != log_is_air:
            continue
        hu = hn.upper()
        if hu == lh or hu.endswith("-" + lh):
            return True
    return False


def make_missing_switch(hostname: str, sw_type: str) -> dict:
    """为未采集到 info 数据的设备创建占位信息字典。"""
    return {
        "hostname": hostname, "sw_type": sw_type, "system_type": "",
        "collect_time": "", "version": "", "health": "missing",
        "collection_attempted": True,
        "collection_attempt_time": "",
        "collection_error": "本批次未返回采集文件",
        "temperature": [], "temperature_details": [], "temp_max": None,
        "transceiver_temps": {},
        "interfaces_up": 0, "interfaces_total": 0, "interfaces_down": [],
        "interfaces_down_count": 0,
        "bgp_established": 0, "bgp_total": 0,
        "evpn_bond_up": 0, "evpn_bond_total": 0, "evpn_bond_details": [],
        "mlag_bond_up": 0, "mlag_bond_total": 0, "mlag_bond_details": [],
        "ib_asic_count": 0, "ib_asic_type": "",
        "model": "", "serial": "", "asic": "",
        "bios_version": "", "ssd_version": "",
        "asic_version": "",
        "asic_temperatures": [], "psu_temperatures": [],
        "asic_temperature_details": [], "psu_temperature_details": [],
        "cpu_use": None, "disk_use": {}, "mem_use": None,
        "ntp_sync": None, "uptime": "",
        "psu_ok": 0, "psu_fail": 0, "fan_ok": 0, "fan_fail": 0,
    }


def runtime_switch_placeholder(device: dict, *, platform_group: str) -> dict:
    """Build a non-success Switch Status row for one unbound DHCP identity.

    ``platform_group=cumulus`` is eligible for the Ethernet collector after its
    default bootstrap installs the project key.  Every other platform remains
    in a separate unbound/unclassified section: the dashboard must preserve the
    observation, but it must not imply that SSH collection was attempted.
    """
    platform = str(device.get("platform_family") or "unknown").casefold()
    hostname = str(device.get("hostname") or "").strip()
    sw_type = "ETH" if platform_group == "cumulus" else (
        "NVOS" if platform == "nvos" else "UNKNOWN"
    )
    placeholder = make_missing_switch(hostname, sw_type)
    placeholder.update({
        "environment": ztp_environment(device),
        "dynamic_dhcp": True,
        "management_ip": str(device.get("ip") or ""),
        "template": str(device.get("template") or "default"),
        "model": str(device.get("product") or ""),
        "serial": str(device.get("serial") or ""),
        "collection_attempted": False,
        "collection_attempt_time": format_ztp_write_time(
            device.get("observed_at") or device.get("_report_generated_at")
        ),
    })
    lease_state = str(device.get("lease_state") or "").strip()
    if platform_group == "cumulus":
        placeholder["collection_error"] = (
            "待绑定 Cumulus 已保留占位；当前没有可用的 "
            "Switch Status 采集归档"
        )
    elif platform == "nvos":
        placeholder["collection_error"] = (
            "NVOS 平台已识别，但项目身份尚未绑定；"
            "未发起 Switch Status SSH 采集"
        )
    else:
        placeholder["collection_error"] = (
            "平台未知，等待 console/物理连接人工识别；"
            "未发起 Switch Status SSH 采集"
        )
    if lease_state and lease_state not in {"active", "observed"}:
        placeholder["collection_error"] += f"；DHCP lease={lease_state}"
    return placeholder


def infer_device_role(hostname: str) -> str:
    """根据设备名识别 Leaf/Spine；无法可靠判断时返回空字符串。

    支持完整角色词、兼容的 EDIBS/EDIBLE 编码、常见 SP/LF 简写和 TOR。
    """
    name = hostname.strip().upper()
    if not name:
        return ""

    # 明文命名优先，避免缩写规则覆盖明确角色。
    if "SPINE" in name:
        return "Spine"
    if "LEAF" in name:
        return "Leaf"

    # 兼容既有命名：...EDIBS01 = IB Spine；...EDIBLE01 = IB Leaf。
    if re.search(r"EDIBS\d*$", name):
        return "Spine"
    if re.search(r"EDIBLE\d*$", name):
        return "Leaf"

    # 常见角色缩写需要位于分隔符之后，降低普通单词误匹配概率。
    if re.search(r"(?:^|[-_.])SP(?:[-_.]?\d+)?$", name):
        return "Spine"
    if re.search(r"(?:^|[-_.])LF(?:[-_.]?\d+)?$", name):
        return "Leaf"

    # TOR（Top of Rack）在当前网络设计中属于 Leaf 层。
    if re.search(r"(?:^|[-_.])TOR(?:[-_.]?\d+)?$", name):
        return "Leaf"
    return ""


_ROLE_ORDER = {
    "Firewall": 0,
    "Border": 1,
    "Spine": 2,
    "Core": 3,
    "Leaf": 4,
    "Other": 99,
}


def switch_role_group(hostname: str) -> str:
    """Return the display role used below an Ethernet network category."""
    explicit = infer_device_role(hostname)
    if explicit:
        return explicit
    name = hostname.strip().upper()
    if "BORDER" in name:
        return "Border"
    if "FIREWALL" in name or re.search(r"(?:^|[-_.])FW(?:[-_.]?\d+)?$", name):
        return "Firewall"
    if "CORE" in name:
        return "Core"
    return "Other"


def group_switches_by_role(switches: list[dict]) -> list[tuple[str, list[dict]]]:
    """Group a network category by role with stable network-layer ordering."""
    grouped: dict[str, list[dict]] = {}
    for switch in switches:
        grouped.setdefault(switch_role_group(switch["hostname"]), []).append(switch)
    return sorted(
        grouped.items(),
        key=lambda item: (_ROLE_ORDER.get(item[0], 98), _nat_key(item[0])),
    )


# ══════════════════════════════════════════════════════════════════════════════
# TOPOLOGY VALIDATION XLSX 解析
# ══════════════════════════════════════════════════════════════════════════════

_XLSX_NS = {"x": "http://schemas.openxmlformats.org/spreadsheetml/2006/main"}
_REL_NS = {"r": "http://schemas.openxmlformats.org/package/2006/relationships"}
_DOC_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_TOPOLOGY_SHEETS = (
    ("Matching", "Matching_Links"),
    ("Miswired", "Miswired_Links"),
    ("Missing", "Missing_Links"),
    ("Undefined", "Undefined_Links"),
)
_TOPOLOGY_FILTER_MODES = (
    ("contains", "Contains"),
    ("not_contains", "Not Contains"),
    ("equals", "Equals"),
    ("not_equals", "Not Equals"),
    ("starts_with", "Starts With"),
    ("ends_with", "Ends With"),
    ("regex", "Regex Pattern"),
)


def _topology_filter_options() -> str:
    return "".join(
        f'<option value="{value}">{label}</option>'
        for value, label in _TOPOLOGY_FILTER_MODES
    )


def find_latest_topology_report(directory: Path, network: str) -> Optional[Path]:
    """按网络类型和修改时间返回最新验证报告，忽略 Excel 锁文件。"""
    network_patterns = {
        "ethernet": ("*ethernet-topology-validation.xlsx",),
        "infiniband": (
            "*iblinkinfo*-topology-validation.xlsx",
            "*ibdiagnet*-topology-validation.xlsx",
            "*infiniband-topology-validation.xlsx",
        ),
    }
    patterns = network_patterns.get(network)
    if patterns is None:
        raise ValueError(f"Unsupported topology network: {network}")
    candidates = {
        path
        for pattern in patterns
        for path in directory.glob(pattern)
    }
    files = [
        path for path in candidates
        if path.is_file() and not path.name.startswith("~$")
    ]
    return max(files, key=lambda path: (path.stat().st_mtime_ns, path.name)) if files else None


def find_topology_reports(directory: Path, network: str) -> list[Path]:
    """按修改时间倒序返回指定网络的全部验证报告。"""
    network_patterns = {
        "ethernet": ("*ethernet-topology-validation.xlsx",),
        "infiniband": (
            "*iblinkinfo*-topology-validation.xlsx",
            "*ibdiagnet*-topology-validation.xlsx",
            "*infiniband-topology-validation.xlsx",
        ),
    }
    patterns = network_patterns.get(network)
    if patterns is None:
        raise ValueError(f"Unsupported topology network: {network}")
    candidates = {
        path
        for pattern in patterns
        for path in directory.glob(pattern)
        if path.is_file() and not path.name.startswith("~$")
    }
    return sorted(
        candidates,
        key=lambda path: (path.stat().st_mtime_ns, path.name),
        reverse=True,
    )


def load_latest_diagram(directory: Path, html_pattern: str) -> dict:
    """返回匹配指定模式的最新 HTML 内嵌地址和文件信息。"""
    files = [
        path for path in directory.glob(html_pattern)
        if path.is_file() and not path.name.startswith("~$")
    ]
    if not files:
        return {"path": None, "source": "（无数据）", "href": "", "modified": "—"}
    path = max(files, key=lambda item: (item.stat().st_mtime_ns, item.name))
    modified = datetime.fromtimestamp(path.stat().st_mtime, DISPLAY_TZ).strftime(
        "%Y-%m-%d %H:%M:%S"
    )
    return {
        "path": path,
        "source": path.name,
        "href": "99-output-p2p/" + quote(path.name),
        "modified": modified,
    }


def ensure_latest_diagram(
    directory: Path,
    dot_pattern: str,
    html_pattern: str,
    preferred_stem: str = "",
) -> tuple[dict, bool]:
    """确保最新匹配的 DOT 有对应 HTML，并返回页面信息及是否重新生成。"""
    dot_files = [
        path for path in directory.glob(dot_pattern)
        if path.is_file() and not path.name.startswith("~$")
    ]
    if not dot_files:
        return load_latest_diagram(directory, html_pattern), False

    preferred_dot = (
        directory / f"{preferred_stem}{dot_pattern[1:]}"
        if preferred_stem and dot_pattern.startswith("*") else None
    )
    dot_path = (
        preferred_dot
        if preferred_dot is not None and preferred_dot.is_file()
        else max(dot_files, key=lambda item: (item.stat().st_mtime_ns, item.name))
    )
    html_path = dot_path.with_suffix(".html")
    generated = (
        not html_path.is_file()
        or dot_path.stat().st_mtime_ns > html_path.stat().st_mtime_ns
    )
    if generated:
        convert_dot_to_html(dot_path, output=html_path)

    modified = datetime.fromtimestamp(
        html_path.stat().st_mtime, DISPLAY_TZ
    ).strftime("%Y-%m-%d %H:%M:%S")
    return {
        "path": html_path,
        "source": html_path.name,
        "href": "99-output-p2p/" + quote(html_path.name),
        "modified": modified,
    }, generated


def preferred_p2p_stem() -> str:
    """返回 setup 所选真实 P2P Excel 的文件名前缀。"""
    try:
        if P2P_INPUT_LINK.is_file():
            return P2P_INPUT_LINK.resolve().stem
    except OSError:
        pass
    return ""


def _xlsx_col_index(cell_ref: str) -> int:
    letters = re.match(r"[A-Z]+", cell_ref.upper())
    if not letters:
        return 0
    value = 0
    for char in letters.group(0):
        value = value * 26 + ord(char) - 64
    return value - 1


def _xlsx_cell_value(cell: ET.Element, shared_strings: list[str]) -> object:
    cell_type = cell.get("t", "")
    if cell_type == "inlineStr":
        return "".join(node.text or "" for node in cell.findall(".//x:t", _XLSX_NS))
    value_node = cell.find("x:v", _XLSX_NS)
    if value_node is None or value_node.text is None:
        return ""
    raw = value_node.text
    if cell_type == "s":
        try:
            return shared_strings[int(raw)]
        except (ValueError, IndexError):
            return raw
    if cell_type in {"str", "e"}:
        return raw
    if cell_type == "b":
        return "Yes" if raw == "1" else "No"
    try:
        number = float(raw)
        return int(number) if number.is_integer() else number
    except ValueError:
        return raw


def read_xlsx_tables(path: Path) -> dict[str, list[list[object]]]:
    """使用 Python 标准库读取 XLSX 中有值的单元格和公式缓存结果。"""
    with zipfile.ZipFile(path) as archive:
        shared_strings: list[str] = []
        if "xl/sharedStrings.xml" in archive.namelist():
            shared_root = ET.fromstring(archive.read("xl/sharedStrings.xml"))
            shared_strings = [
                "".join(node.text or "" for node in item.findall(".//x:t", _XLSX_NS))
                for item in shared_root.findall("x:si", _XLSX_NS)
            ]

        workbook = ET.fromstring(archive.read("xl/workbook.xml"))
        relationships = ET.fromstring(archive.read("xl/_rels/workbook.xml.rels"))
        targets = {
            rel.get("Id", ""): rel.get("Target", "")
            for rel in relationships.findall("r:Relationship", _REL_NS)
        }
        tables: dict[str, list[list[object]]] = {}
        for sheet in workbook.findall("x:sheets/x:sheet", _XLSX_NS):
            name = sheet.get("name", "")
            rel_id = sheet.get(f"{{{_DOC_REL}}}id", "")
            target = targets.get(rel_id, "")
            if not target:
                continue
            member = target.lstrip("/")
            if not member.startswith("xl/"):
                member = "xl/" + member
            root = ET.fromstring(archive.read(member))
            rows: list[list[object]] = []
            for row in root.findall("x:sheetData/x:row", _XLSX_NS):
                values: dict[int, object] = {}
                for cell in row.findall("x:c", _XLSX_NS):
                    values[_xlsx_col_index(cell.get("r", "A1"))] = _xlsx_cell_value(
                        cell, shared_strings
                    )
                if values:
                    rows.append([values.get(index, "") for index in range(max(values) + 1)])
            tables[name] = rows
        return tables


def load_topology_report(path: Path) -> dict:
    """读取单个拓扑验证工作簿。"""
    tables = read_xlsx_tables(path)
    summary_rows = tables.get("Summary", [])
    summary = {
        str(row[0]).strip(): row[1] if len(row) > 1 else ""
        for row in summary_rows[1:] if row and str(row[0]).strip()
    }
    sections = []
    counts = {}
    for label, sheet_name in _TOPOLOGY_SHEETS:
        rows = tables.get(sheet_name, [])
        headers = [str(value) for value in rows[0]] if rows else []
        data_rows = sorted(
            rows[1:] if rows else [], key=air_first_row_key,
        )
        counts[label] = len(data_rows)
        sections.append({
            "label": label, "sheet": sheet_name,
            "headers": headers, "rows": data_rows,
        })
    result = str(summary.get("Validation Result") or "").strip().upper()
    if not result:
        result = (
            "PASS"
            if all(counts.get(label, 0) == 0 for label in ("Miswired", "Missing", "Undefined"))
            else "FAIL"
        )
    return {
        "path": path,
        "source": path.name,
        "href": "99-output-p2p/" + quote(path.name),
        "generated": str(summary.get("Generated Local") or summary.get("Generated UTC") or "—"),
        "result": result,
        "summary": summary,
        "sections": sections,
        "counts": counts,
    }


def topology_row_environment(row: list[object]) -> str:
    return "air" if any(is_air_hostname(value) for value in row) else "production"


def topology_report_environments(report: dict) -> set[str]:
    """优先使用 -air 文件标记，否则从报告行判断所属环境。"""
    source = str(report.get("source", ""))
    if re.search(r"(?:^|[-_])air(?:[-_.]|$)", source, re.IGNORECASE):
        return {"air"}
    environments = {
        topology_row_environment(row)
        for section in report.get("sections", [])
        for row in section.get("rows", [])
    }
    if environments:
        return environments
    return {"production"}


def load_topology_validation(directory: Path, network: str, scope: str = "all") -> dict:
    """分别选取 AIR/Production 最新报告并合并环境内的结果。"""
    paths = find_topology_reports(directory, network)
    if not paths:
        return {
            "path": None, "source": "（无数据）", "generated": "—",
            "result": "NO DATA", "summary": {}, "sections": [], "counts": {},
            "sources": {}, "downloads": [],
        }

    environments = selected_environments(scope)
    selected: dict[str, dict] = {}
    for path in paths:
        report = load_topology_report(path)
        for environment in topology_report_environments(report):
            if environment in environments:
                selected.setdefault(environment, report)
        if len(selected) == len(environments):
            break

    sections = []
    counts = {label: 0 for label, _sheet in _TOPOLOGY_SHEETS}
    for label, sheet_name in _TOPOLOGY_SHEETS:
        headers: list[str] = []
        rows: list[list[object]] = []
        environment_rows: dict[str, list[list[object]]] = {
            "air": [], "production": [],
        }
        for environment in environments:
            report = selected.get(environment)
            if report is None:
                continue
            section = next(
                (item for item in report["sections"] if item["label"] == label),
                None,
            )
            if section is None:
                continue
            if not headers:
                headers = section["headers"]
            report_environments = topology_report_environments(report)
            selected_rows = [
                row for row in section["rows"]
                if (
                    report_environments == {environment}
                    or topology_row_environment(row) == environment
                )
            ]
            environment_rows[environment].extend(selected_rows)
            rows.extend(selected_rows)
        rows.sort(key=air_first_row_key)
        counts[label] = len(rows)
        sections.append({
            "label": label, "sheet": sheet_name,
            "headers": headers, "rows": rows,
            "environment_rows": environment_rows,
        })

    unique_reports = []
    seen_sources = set()
    for environment in environments:
        report = selected.get(environment)
        if report and report["source"] not in seen_sources:
            unique_reports.append(report)
            seen_sources.add(report["source"])
    results = {report["result"] for report in unique_reports}
    result = (
        "FAIL" if "FAIL" in results
        else "ERROR" if "ERROR" in results
        else "PASS" if results and results == {"PASS"}
        else "NO DATA"
    )
    source_labels = {
        environment: report["source"] for environment, report in selected.items()
    }
    generated_labels = {
        environment: report["generated"] for environment, report in selected.items()
    }
    source = "；".join(
        f'{"AIR" if environment == "air" else "Production"}: {source_labels[environment]}'
        for environment in environments if environment in source_labels
    )
    generated = "；".join(
        f'{"AIR" if environment == "air" else "Production"}: {generated_labels[environment]}'
        for environment in environments if environment in generated_labels
    )
    downloads = []
    for report in unique_reports:
        report_environments = [
            "AIR" if environment == "air" else "Production"
            for environment, selected_report in selected.items()
            if selected_report is report
        ]
        downloads.append({
            "label": "/".join(report_environments),
            "href": report["href"],
        })
    first_report = unique_reports[0] if unique_reports else None
    return {
        "path": first_report["path"] if first_report else None,
        "source": source or "（无数据）",
        "generated": generated or "—",
        "result": result,
        "summary": {},
        "sections": sections,
        "counts": counts,
        "sources": source_labels,
        "downloads": downloads,
    }


def render_topology_tables(
    topology: dict,
    prefix: str,
    hidden_headers: tuple[str, ...] = (),
) -> tuple[str, list[str]]:
    """将四类验证结果渲染为独立表格，并返回可筛选状态列表。"""
    blocks: list[str] = []
    statuses: set[str] = set()
    hidden = {header.strip().casefold() for header in hidden_headers}
    source_sections = topology.get("sections", [])
    expanded_sections = []
    for environment, environment_label in (("air", "AIR"), ("production", "Production")):
        environment_count = sum(
            len(
                section.get("environment_rows", {}).get(environment, [])
                if "environment_rows" in section
                else [
                    row for row in section.get("rows", [])
                    if topology_row_environment(row) == environment
                ]
            )
            for section in source_sections
        )
        expanded_sections.append({
            "_environment": environment,
            "_environment_label": environment_label,
            "_environment_count": environment_count,
        })
        if environment_count == 0:
            continue
        for section in source_sections:
            environment_section = dict(section)
            environment_section["rows"] = (
                section.get("environment_rows", {}).get(environment, [])
                if "environment_rows" in section
                else [
                    row for row in section.get("rows", [])
                    if topology_row_environment(row) == environment
                ]
            )
            expanded_sections.append(environment_section)

    for section in expanded_sections:
        if "_environment" in section:
            blocks.append(
                f'<div class="topo-environment" '
                f'data-environment="{section["_environment"]}">'
                f'{section["_environment_label"]}（{section["_environment_count"]} 条）'
                f'</div>'
            )
            continue
        headers = section["headers"]
        rows = sorted(section["rows"], key=air_first_row_key)
        label = section["label"]
        visible_indices = [
            index for index, header in enumerate(headers)
            if header.strip().casefold() not in hidden
        ]
        visible_headers = [headers[index] for index in visible_indices]
        status_index = next(
            (index for index, header in enumerate(headers) if header.strip().lower() == "status"),
            None,
        )
        head_html = "".join(
            f"<th>{escape(header)}</th>" for header in visible_headers
        )
        mode_options = _topology_filter_options()
        filter_html = "".join(
            f'<th><div class="topo-col-filter-wrap">'
            f'<select class="topo-col-mode" data-col="{index}" '
            f'aria-label="{escape(header, quote=True)} 过滤方式" '
            f'onchange="filterTopology(\'{escape(prefix, quote=True)}\')">'
            f'{mode_options}</select>'
            f'<input class="topo-col-filter" data-col="{index}" type="text" '
            f'aria-label="过滤 {escape(header, quote=True)}" placeholder="过滤；!排除…" '
            f'oninput="filterTopology(\'{escape(prefix, quote=True)}\')"></div></th>'
            for index, header in enumerate(visible_headers)
        )
        body_rows = []
        for row in rows:
            padded = list(row) + [""] * (len(headers) - len(row))
            status = str(padded[status_index]).strip() if status_index is not None else ""
            if status:
                statuses.add(status)
            visible_values = [padded[index] for index in visible_indices]
            search_text = " ".join(str(value) for value in visible_values).casefold()
            cells = "".join(
                f"<td>{escape(str(value))}</td>" for value in visible_values
            )
            body_rows.append(
                f'<tr class="topo-row" data-category="{label.casefold()}" '
                f'data-status="{escape(status.casefold(), quote=True)}" '
                f'data-search="{escape(search_text, quote=True)}">{cells}</tr>'
            )
        colspan = max(1, len(visible_headers))
        if body_rows:
            body_rows.append(
                f'<tr class="topo-no-match hidden"><td colspan="{colspan}">'
                '没有符合当前过滤条件的记录。</td></tr>'
            )
        else:
            body_rows.append(
                f'<tr class="topo-empty"><td colspan="{colspan}">No {escape(label)} links.</td></tr>'
            )
        blocks.append(
            f'<section class="topo-section" data-category="{label.casefold()}">'
            f'<h3 role="button" tabindex="0" aria-expanded="true" '
            f'onclick="toggleTopologySection(this)" '
            f'onkeydown="handleTopologySectionKey(event, this)">'
            f'<span class="topo-collapse-icon">▾</span>'
            f'<span class="topo-section-title">{escape(section["sheet"])}</span>'
            f'<span class="topo-section-count" data-total="{len(rows)}">{len(rows)}</span></h3>'
            f'<div class="topo-table-wrap"><table class="topo-tbl">'
            f'<thead><tr>{head_html}</tr><tr class="topo-filter-row">{filter_html}</tr></thead>'
            f'<tbody>{"".join(body_rows)}</tbody>'
            f'</table></div></section>'
        )
    return "".join(blocks), sorted(statuses, key=str.casefold)


def render_topology_panel(
    topology: dict,
    panel_name: str,
    title: str,
    hidden_headers: tuple[str, ...] = (),
) -> str:
    """渲染一个网络的拓扑验证页签，四类结果在同一页内连续展示。"""
    prefix = f"{panel_name}-topo"
    tables, statuses = render_topology_tables(topology, prefix, hidden_headers)
    counts = topology.get("counts", {})
    result = topology.get("result", "NO DATA")
    result_cls = (
        "topo-pass" if result == "PASS"
        else "topo-fail" if result == "FAIL"
        else "topo-unknown"
    )
    status_options = "".join(
        f'<option value="{escape(status.casefold(), quote=True)}">{escape(status)}</option>'
        for status in statuses
    )
    downloads = topology.get("downloads") or (
        [{"label": "", "href": topology.get("href", "")}]
        if topology.get("path") else []
    )
    download = "".join(
        f'<a class="dl-btn topo-download" href="{escape(item["href"], quote=True)}" '
        f'download>⬇ 下载{escape(item.get("label", ""))} XLSX</a>'
        for item in downloads
    )
    if not tables:
        tables = (
            f'<div class="topo-no-data">99-output-p2p/ 下没有 {escape(title)} '
            'topology-validation.xlsx 文件。</div>'
        )
    return f'''<!-- {escape(title)} Topology Validation -->
<div id="panel-{panel_name}" class="panel topo-panel">
  <div class="topo-summary">
    <span class="topo-source">
      <strong>{escape(title)}</strong>
      &nbsp;·&nbsp; 最新报告：<strong>{escape(topology.get('source', '（无数据）'))}</strong>
      &nbsp;·&nbsp; 生成时间：<strong>{escape(topology.get('generated', '—'))}</strong>
    </span>
    <span class="topo-result {result_cls}">{escape(result)}</span>
    <span class="topo-count topo-matching">Matching {counts.get('Matching', 0)}</span>
    <span class="topo-count topo-miswired">Miswired {counts.get('Miswired', 0)}</span>
    <span class="topo-count topo-missing">Missing {counts.get('Missing', 0)}</span>
    <span class="topo-count topo-undefined">Undefined {counts.get('Undefined', 0)}</span>
    {download}
  </div>
  <div class="topo-toolbar">
    <label>搜索：
      <select id="{prefix}-search-mode" onchange="filterTopology('{prefix}')">
        {_topology_filter_options()}
      </select>
      <input id="{prefix}-search" class="link-search" type="text"
             placeholder="设备 / 接口 / 对端；!排除…" oninput="filterTopology('{prefix}')">
    </label>
    <label>结果：
      <select id="{prefix}-category" onchange="filterTopology('{prefix}')">
        <option value="all">全部</option>
        <option value="matching">Matching</option>
        <option value="miswired">Miswired</option>
        <option value="missing">Missing</option>
        <option value="undefined">Undefined</option>
      </select>
    </label>
    <label>状态：
      <select id="{prefix}-status" onchange="filterTopology('{prefix}')">
        <option value="all">全部</option>
        {status_options}
      </select>
    </label>
    <button id="{prefix}-clear" class="topo-clear-btn" type="button"
            onclick="resetTopologyFilters('{prefix}')" disabled>清除过滤</button>
    <span id="{prefix}-row-info" class="row-info"></span>
  </div>
  <div class="topo-content">{tables}</div>
</div>'''


def render_diagram_panel(
    diagram: dict,
    panel_id: str,
    title: str,
    expected_pattern: str,
) -> str:
    """使用 iframe 在仪表板内嵌一个独立拓扑 HTML。"""
    source = escape(diagram.get("source", "（无数据）"))
    modified = escape(diagram.get("modified", "—"))
    if diagram.get("path"):
        href = escape(diagram.get("href", ""), quote=True)
        content = (
            f'<iframe class="p2p-frame" src="{href}" title="{escape(title, quote=True)}" '
            f'loading="lazy"></iframe>'
        )
        open_link = (
            f'<a class="dl-btn p2p-open" href="{href}" target="_blank" '
            f'rel="noopener">在新窗口打开</a>'
        )
    else:
        content = (
            '<div class="p2p-no-data">99-output-p2p/ 下没有 '
            f'{escape(expected_pattern)} 文件。</div>'
        )
        open_link = ""
    return f'''<div id="panel-{escape(panel_id, quote=True)}" class="panel p2p-panel">
  <div class="p2p-toolbar">
    <span>{escape(title)}：<strong>{source}</strong>&nbsp; · &nbsp;修改时间：<strong>{modified}</strong></span>
    {open_link}
  </div>
  <div class="p2p-frame-wrap">{content}</div>
</div>'''


# ══════════════════════════════════════════════════════════════════════════════
# ETH-INFO 解析
# ══════════════════════════════════════════════════════════════════════════════

def find_latest_tar(info_dir: Path) -> Optional[Path]:
    """返回指定目录下最新的每小时 tar.gz（排除 daily 打包）。"""
    tars = sorted(
        (p for p in info_dir.glob("*.tar.gz") if "daily" not in p.name),
        key=lambda p: p.name,
        reverse=True,
    )
    return tars[0] if tars else None


def find_latest_eth_tars(info_dir: Path) -> dict[str, Path]:
    """Return the newest AIR and Production hourly Ethernet archives."""
    archives = [
        path for path in info_dir.glob("*.tar.gz")
        if "daily" not in path.name.casefold()
    ]
    grouped = {"air": [], "production": []}
    for path in archives:
        environment = None
        try:
            with tarfile.open(path, "r:gz") as archive:
                member = next(
                    (item for item in archive.getmembers()
                     if Path(item.name).name == "collection.json" and item.size <= 65536),
                    None,
                )
                if member is not None:
                    stream = archive.extractfile(member)
                    if stream is not None:
                        value = json.loads(stream.read().decode("utf-8")).get("environment")
                        environment = "production" if value == "prod" else value
        except (OSError, tarfile.TarError, UnicodeDecodeError, json.JSONDecodeError):
            environment = None
        if environment not in grouped:
            environment = (
                "air" if re.search(r"[-_]air\.tar\.gz$", path.name, re.IGNORECASE)
                else "production"
            )
        grouped[environment].append(path)
    result = {}
    if grouped["air"]:
        result["air"] = max(grouped["air"], key=lambda path: path.name)
    if grouped["production"]:
        result["production"] = max(grouped["production"], key=lambda path: path.name)
    return result


def extract_info_files(tar_path: Path) -> dict[str, str]:
    """返回 {hostname: content} ── 来自 tar.gz 内所有 *.info 文件。"""
    result = {}
    with tarfile.open(tar_path, "r:gz") as tf:
        for member in tf.getmembers():
            if not member.name.endswith(".info"):
                continue
            hostname = os.path.basename(member.name)[:-5]  # 去掉 .info
            f = tf.extractfile(member)
            if f:
                result[hostname] = f.read().decode("utf-8", errors="replace")
    return result


def split_sections(content: str) -> dict[str, str]:
    """将 .info 文件按 '# Execute Command: xxx' 分块，返回 {cmd: output}。"""
    sections: dict[str, str] = {}
    parts = re.split(r"#{4,}\n# Execute Command: (.+?)\n#{4,}", content)
    i = 1
    while i + 1 < len(parts):
        sections[parts[i].strip()] = parts[i + 1]
        i += 2
    return sections


def _fixed_width_columns(
    header: str, labels: tuple[str, ...],
) -> dict[str, tuple[int, Optional[int]]]:
    """Return fixed-width slices keyed by label, independent of column order."""
    starts = {label: header.find(label) for label in labels}
    if any(position < 0 for position in starts.values()):
        return {}
    ordered = sorted((position, label) for label, position in starts.items())
    return {
        label: (position, ordered[index + 1][0] if index + 1 < len(ordered) else None)
        for index, (position, label) in enumerate(ordered)
    }


def _fixed_width_value(
    line: str, columns: dict[str, tuple[int, Optional[int]]], label: str,
) -> str:
    start, end = columns[label]
    return line[start:end].strip()


def parse_evpn_multihoming_bonds(text: str) -> list[dict[str, object]]:
    """Parse local bond rows from ``nv show evpn multihoming esi``.

    A local EVPN multihoming bond is UP only when it has at least one remote
    VTEP and its flags contain the ordered health sequence ``lr*bsA``.  FRR
    may insert the designated-forwarder flag ``f`` between ``r`` and ``*``;
    consequently ``lrf*bsA`` is healthy as well.  Remote-only ESI rows and
    continuation rows for additional VTEPs are intentionally ignored.
    """
    lines = text.splitlines()
    header_index = next((
        index for index, line in enumerate(lines)
        if "ESInterface" in line and "RemoteVTEPs" in line and "Flags" in line
    ), None)
    if header_index is None:
        return []
    columns = _fixed_width_columns(
        lines[header_index],
        ("ESI", "ESInterface", "NHG", "RemoteVTEPs", "Flags"),
    )
    if not columns:
        return []

    records: list[dict[str, object]] = []
    current_local: Optional[dict[str, object]] = None
    for line in lines[header_index + 1:]:
        if not line.strip() or re.fullmatch(r"[-\s]+", line):
            continue
        esi = _fixed_width_value(line, columns, "ESI")
        interface = _fixed_width_value(line, columns, "ESInterface")
        remote_value = _fixed_width_value(line, columns, "RemoteVTEPs")
        remote_vteps = [
            value for value in re.split(r"[,\s]+", remote_value)
            if value and value not in {"-", "—"}
        ]
        if not re.fullmatch(r"(?:[0-9a-f]{2}:){9}[0-9a-f]{2}", esi, re.IGNORECASE):
            if current_local is not None and not interface and remote_vteps:
                current_local["remote_vteps"].extend(remote_vteps)
            continue
        current_local = None
        if not interface.casefold().startswith("bond"):
            continue
        flags = _fixed_width_value(line, columns, "Flags")
        current_local = {
            "interface": interface,
            "remote_vteps": remote_vteps,
            "flags": flags,
        }
        records.append(current_local)
    required_flags = {"l", "r", "*", "b", "s", "A"}
    for record in records:
        record["up"] = bool(record["remote_vteps"]) and required_flags.issubset(
            set(str(record["flags"]))
        )
    return records


def parse_clag_bonds(text: str) -> list[dict[str, object]]:
    """Parse the ``CLAG Interfaces`` fixed-width table from ``clagctl``."""
    lines = text.splitlines()
    header_index = next((
        index for index, line in enumerate(lines)
        if "Our Interface" in line and "Peer Interface" in line and "CLAG Id" in line
    ), None)
    if header_index is None:
        return []
    labels = ("Our Interface", "Peer Interface", "CLAG Id", "Conflicts", "Proto-Down Reason")
    columns = _fixed_width_columns(lines[header_index], labels)
    if not columns:
        # Older clagctl versions can omit the two diagnostic columns.
        labels = ("Our Interface", "Peer Interface", "CLAG Id")
        columns = _fixed_width_columns(lines[header_index], labels)
    if not columns:
        return []

    records: list[dict[str, object]] = []
    invalid = {"", "-", "—", "none", "n/a"}
    for line in lines[header_index + 1:]:
        if not line.strip() or re.fullmatch(r"[-\s]+", line):
            continue
        interface = _fixed_width_value(line, columns, "Our Interface")
        if not interface.casefold().startswith("bond"):
            continue
        peer_interface = _fixed_width_value(line, columns, "Peer Interface")
        clag_id = _fixed_width_value(line, columns, "CLAG Id")
        peer_valid = peer_interface.casefold() not in invalid
        id_valid = clag_id.casefold() not in invalid
        records.append({
            "interface": interface,
            "peer_interface": peer_interface,
            "clag_id": clag_id,
            "conflicts": _fixed_width_value(line, columns, "Conflicts")
            if "Conflicts" in columns else "",
            "proto_down_reason": _fixed_width_value(line, columns, "Proto-Down Reason")
            if "Proto-Down Reason" in columns else "",
            "up": peer_valid and id_valid,
        })
    return records


def parse_nv_kv(text: str) -> dict[str, str]:
    """
    解析 'nv show' 输出的表格格式：
      - 键从列 0 开始，无前导空格
      - 键与值之间用 2 个以上空格分隔
      - 以空格或短横线开头的行（表头/分隔行）跳过
    实际格式示例：
      serial-number  VN052MJMFCBNV613602H
      asic-model     Spectrum-4
      system-type    SN5610
    """
    d: dict[str, str] = {}
    for line in text.splitlines():
        if not line or line[0] in (" ", "\t"):  # 跳过表头（前导空格）
            continue
        s = line.rstrip()
        if re.match(r"^[-\s]+$", s):           # 跳过分隔行
            continue
        parts = re.split(r"\s{2,}", s, maxsplit=1)
        if len(parts) == 2:
            key = parts[0].strip().lower()
            val = parts[1].strip()
            if key and val:
                d[key] = val
    return d


def parse_temp_table_details(text: str) -> list[dict]:
    """
    解析温度表格，保留设备返回的 Max/Crit 阈值与 State。
    表格格式：
      Name                       Cur Temp (°C)  Crit Temp  Max Temp  Min Temp  State
      -------------------------  -------------  ...
      Asic-Temp-Sensor           64.0           120.0      ...
    """
    results = []
    in_data = False
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        if "Cur Temp" in s or ("Name" in s and "State" in s):
            in_data = True
            continue
        if re.match(r"^[-\s]+$", s):
            continue                        # 分隔行
        if not in_data:
            continue
        # 每行：SensorName   cur_temp   crit   max   min   state
        parts = re.split(r"\s{2,}", s)
        if len(parts) < 2:
            continue
        try:
            current = float(parts[1].strip())
        except ValueError:
            continue

        def optional_float(index: int) -> Optional[float]:
            if index >= len(parts):
                return None
            try:
                return float(parts[index].strip())
            except ValueError:
                return None

        results.append({
            "name": parts[0].strip(),
            "current": current,
            "critical": optional_float(2),
            "maximum": optional_float(3),
            "minimum": optional_float(4),
            "state": parts[5].strip().casefold() if len(parts) > 5 else "",
        })
    return results


def parse_temp_table(text: str) -> list:
    """Compatibility view returning ``(sensor_name, current_temp)`` tuples."""
    return [
        (sensor["name"], sensor["current"])
        for sensor in parse_temp_table_details(text)
    ]


def parse_firmware_versions(text: str) -> tuple[str, str, str]:
    """从 ``nv show platform firmware`` 提取 BIOS、SSD 和 ASIC 版本。"""
    bios = ""
    ssd = ""
    asic = ""
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        component = parts[0].upper()
        if component == "BIOS":
            bios = parts[1]
        elif component == "SSD":
            ssd = parts[1]
        elif component == "ASIC" or component.startswith(("SPECTRUM", "QUANTUM")):
            asic = parts[1]
    return bios, ssd, asic


def parse_ntp_sync(text: str) -> Optional[bool]:
    """从 timedatectl 解析系统时钟同步状态。"""
    match = re.search(
        r"^\s*System clock synchronized:\s*(yes|no)\s*$",
        text,
        re.IGNORECASE | re.MULTILINE,
    )
    if not match:
        return None
    return match.group(1).lower() == "yes"


def parse_cpu_use(text: str) -> Optional[float]:
    """解析 top 的 CPU idle；多帧输出取最后一帧。"""
    idle_values: list[float] = []
    for line in text.splitlines():
        match = re.search(r"([0-9]+(?:[.,][0-9]+)?)\s*%?\s*(?:id|idle)\b", line, re.IGNORECASE)
        if match and ("cpu" in line.lower() or "%cpu" in line.lower()):
            idle_values.append(float(match.group(1).replace(",", ".")))
    if not idle_values:
        return None
    return max(0.0, min(100.0, 100.0 - idle_values[-1]))


def parse_disk_use(text: str) -> Optional[int]:
    """解析单个 ``df -P <path>`` 输出中的 Use%。"""
    for line in reversed(text.splitlines()):
        matches = re.findall(r"(\d+)%", line)
        if matches:
            return int(matches[-1])
    return None


def parse_archive_time_utc(path: Path) -> Optional[datetime]:
    """从 YYYYMMDD-HHMM 归档名解析采集批次的 UTC 时间。"""
    match = re.match(
        r"^(\d{8})-(\d{4})(?:[-_](?:air|prod|production))?(?:\.tar\.gz)?$",
        path.name, re.IGNORECASE,
    )
    if not match:
        return None
    try:
        return datetime.strptime(
            match.group(1) + match.group(2), "%Y%m%d%H%M"
        ).replace(tzinfo=SOURCE_TZ)
    except ValueError:
        return None


def format_collection_batch_time(value: Optional[datetime]) -> str:
    """Format an archive batch timestamp in the project display timezone."""
    if value is None:
        return ""
    return value.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")


def parse_timedate_timezone(text: str):
    """从 timedatectl 输出读取设备配置的时区；无法识别时返回 None。"""
    match = re.search(r"^\s*Time zone:\s+(\S+)", text, re.MULTILINE)
    if not match:
        return None
    try:
        return ZoneInfo(match.group(1))
    except (KeyError, ValueError):
        # 精简系统可能缺少 zoneinfo 数据，继续尝试括号内的 +0800 偏移。
        offset_match = re.search(
            r"^\s*Time zone:.*\([^)]+,\s*([+-])(\d{2})(\d{2})\)",
            text,
            re.MULTILINE,
        )
        if not offset_match:
            return None
        minutes = int(offset_match.group(2)) * 60 + int(offset_match.group(3))
        if offset_match.group(1) == "-":
            minutes = -minutes
        return timezone(timedelta(minutes=minutes))


def convert_collect_time(
    value: str,
    expected_utc: Optional[datetime] = None,
    device_tz=None,
) -> str:
    """把设备写入的采集时间规范为页面时区。

    不同交换机可能把 ``date`` 输出为 UTC 或项目本地时间。若归档批次时间
    可用，则分别按 UTC 和 DISPLAY_TZ 解释原值，选择与批次时间最接近者，
    从而避免已经是 UTC+8 的 Ethernet 时间再次加八小时。
    """
    value = value.strip()
    try:
        naive_time = datetime.strptime(value, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        return value
    if device_tz is not None:
        return naive_time.replace(tzinfo=device_tz).astimezone(DISPLAY_TZ).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

    utc_candidate = naive_time.replace(tzinfo=SOURCE_TZ)
    local_candidate = naive_time.replace(tzinfo=DISPLAY_TZ).astimezone(SOURCE_TZ)
    source_time = utc_candidate
    if expected_utc is not None:
        source_time = min(
            (utc_candidate, local_candidate),
            key=lambda candidate: abs((candidate - expected_utc).total_seconds()),
        )
    return source_time.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")


def parse_disk_filesystems(text: str) -> dict[str, int]:
    """解析 ``df -PT``，返回真实文件系统的 {挂载点: 使用率}。

    根文件系统始终保留；其他 tmpfs、proc、sysfs 等内存/虚拟文件系统不属于
    磁盘分区，因此不会进入 Switch Status。loop 设备通常是 snap、镜像或只读
    挂载，也不作为设备磁盘容量展示。
    """
    pseudo_types = {
        "tmpfs", "devtmpfs", "proc", "sysfs", "devpts", "cgroup",
        "cgroup2", "securityfs", "pstore", "debugfs", "tracefs",
        "configfs", "fusectl", "mqueue", "hugetlbfs", "ramfs",
        "efivarfs", "squashfs", "nsfs", "autofs",
    }
    # Cumulus Linux mounts internal system images below /mnt. They are not
    # operator-managed data partitions and only add noise to Disk Use.
    hidden_mountpoints = {"/mnt/cl-etc", "/mnt/cl-system-2"}
    result: dict[str, int] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 7 or parts[0].lower() == "filesystem":
            continue
        device = parts[0]
        fs_type = parts[1].lower()
        mountpoint = parts[-1]
        use_match = re.fullmatch(r"(\d+)%", parts[-2])
        if not use_match:
            continue
        if device.startswith("/dev/loop"):
            continue
        if mountpoint in hidden_mountpoints:
            continue
        if mountpoint != "/" and fs_type in pseudo_types:
            continue
        result[mountpoint] = int(use_match.group(1))
    return result


def parse_memory_use(text: str) -> Optional[float]:
    """解析 ``free -b``/``free -h``，按 total-available 计算使用率。"""
    def memory_value(value: str) -> float:
        match = re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([KMGTPE]?)(?:i?B?)?", value, re.IGNORECASE)
        if not match:
            raise ValueError(value)
        scale = "KMGTPE".find(match.group(2).upper()) + 1 if match.group(2) else 0
        return float(match.group(1)) * (1024 ** scale)

    for line in text.splitlines():
        if not re.match(r"^\s*Mem:\s+", line, re.IGNORECASE):
            continue
        values = line.split()[1:]
        try:
            total = memory_value(values[0])
            used = total - memory_value(values[5]) if len(values) >= 6 else memory_value(values[1])
        except (ValueError, IndexError):
            return None
        if total <= 0:
            return None
        return max(0.0, min(100.0, used * 100.0 / total))
    return None


def parse_transceiver_temperatures(
    text: str,
) -> dict[str, tuple[float, Optional[float]]]:
    """解析模块当前温度及high alarm threshold，单位均为摄氏度。

    detail输出为缩进的YAML风格文本。顶层键是模块名（例如 ``sw72``
    或 ``swp1``），模块的 ``temperature`` 块内还有一个同名数值字段。
    一个模块可能服务多个breakout接口，因此这里只保存模块到温度的映射，
    接口展开由 ``transceiver_reading_for_interface`` 处理。
    """
    results: dict[str, tuple[float, Optional[float]]] = {}
    module = ""
    in_temperature = False
    current: Optional[float] = None
    high_threshold: Optional[float] = None

    def save_reading() -> None:
        if module and current is not None:
            results[module.lower()] = (current, high_threshold)

    for line in text.splitlines():
        top = re.match(r"^(\S+):\s*$", line)
        if top:
            save_reading()
            module = top.group(1)
            in_temperature = False
            current = None
            high_threshold = None
            continue
        if not module:
            continue
        if re.match(r"^\s{2}temperature\s*:\s*$", line, re.IGNORECASE):
            in_temperature = True
            continue
        if in_temperature:
            value = re.match(
                r"^\s{4,}temperature\s*:\s*([-+]?\d+(?:\.\d+)?)\s*(?:°?\s*C)?\s*$",
                line,
                re.IGNORECASE,
            )
            if value:
                current = float(value.group(1))
                continue
            high = re.match(
                r"^\s{4,}high-alarm-threshold\s*:\s*([-+]?\d+(?:\.\d+)?)\s*(?:°?\s*C)?\s*$",
                line,
                re.IGNORECASE,
            )
            if high:
                high_threshold = float(high.group(1))
                continue
            elif line.strip() and len(line) - len(line.lstrip()) <= 2:
                save_reading()
                in_temperature = False

    save_reading()
    return results


def transceiver_module_for_interface(interface: str) -> str:
    """把breakout接口名规范化为其共享的物理模块名。"""
    name = interface.strip().lower()
    for pattern in (r"^(swp\d+)s\d+$", r"^(sw\d+)p\d+$"):
        match = re.match(pattern, name)
        if match:
            return match.group(1)
    return name


def transceiver_reading_for_interface(
    hostname: str,
    interface: str,
    temps_by_host: dict[str, dict[str, tuple[float, Optional[float]]]],
) -> Optional[tuple[float, Optional[float]]]:
    """按设备及端口查当前温度和high threshold。"""
    host_key = ""
    target = hostname.lower()
    for candidate in temps_by_host:
        normalized = candidate.lower()
        if normalized == target or normalized.endswith("-" + target):
            host_key = candidate
            break
    if not host_key:
        return None

    module = transceiver_module_for_interface(interface)
    return temps_by_host[host_key].get(module)


def parse_inventory(text: str) -> dict:
    """
    解析 nv show platform inventory，提取 PSU 和 FAN 状态。
    表格格式：
      Component   HW Version  Model  Serial  State  Type
      PSU1        A3          ...    ...     ok     psu
      PSU1/FAN1   ...         ...    ...     ok     fan
      FAN1        ...         ...    ...     ok     fan
    """
    psu_ok = 0; psu_fail = 0
    fan_ok = 0; fan_fail = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or re.match(r"^[-\s]+$", s):
            continue
        parts = s.split()
        if not parts:
            continue
        first = parts[0]
        if not first[-1].isdigit():         # 第一字段必须以数字结尾
            continue
        ok = bool(re.search(r"\bok\b", s, re.IGNORECASE))
        if first.startswith("PSU"):         # 大写 PSU 才算真正 PSU
            if ok: psu_ok += 1
            else:  psu_fail += 1
        elif first.upper().startswith("FAN"):
            if ok: fan_ok += 1
            else:  fan_fail += 1
    return {"psu_ok": psu_ok, "psu_fail": psu_fail, "fan_ok": fan_ok, "fan_fail": fan_fail}


def parse_info_file(
    hostname: str,
    content: str,
    expected_collect_utc: Optional[datetime] = None,
) -> dict:
    """解析单个 .info 文件（ETH 或 IB），返回结构化信息字典。"""
    info: dict = {
        "hostname":          hostname,
        "sw_type":           "UNKNOWN",   # "ETH" or "IB"
        "system_type":       "",
        "collect_time":      "",
        "collection_attempt_time": "",
        "collection_error": "",
        "version":           "",
        "health":            "unknown",
        "temperature":       [],           # [(sensor_name, float_val), ...]
        "temperature_details": [],         # current/max/critical/state per sensor
        "temp_max":          None,
        # {physical_module: (temperature_celsius, high_alarm_threshold)}
        "transceiver_temps": {},
        "interfaces_up":     0,
        "interfaces_total":  0,
        "interfaces_down":   [],
        "interfaces_down_count": 0,
        "bgp_established":   0,
        "bgp_total":         0,
        "evpn_bond_up":      0,
        "evpn_bond_total":   0,
        "evpn_bond_details": [],
        "mlag_bond_up":      0,
        "mlag_bond_total":   0,
        "mlag_bond_details": [],
        "ib_asic_count":     0,            # IB only: ASIC 数量
        "ib_asic_type":      "",           # IB only: Quantum3 等
        "model":             "",
        "serial":            "",
        "asic":              "",
        "bios_version":       "",
        "ssd_version":        "",
        "asic_version":       "",
        "asic_temperatures":  [],
        "psu_temperatures":   [],
        "asic_temperature_details": [],
        "psu_temperature_details": [],
        "cpu_use":            None,
        "disk_use":           {},
        "mem_use":            None,
        "ntp_sync":           None,
        "uptime":             "",
        "psu_ok":            0,
        "psu_fail":          0,
        "fan_ok":            0,
        "fan_fail":          0,
    }

    # ── 文件头块 ──────────────────────────────────────────────────────────────
    m = re.search(r"Switch Type:\s+(\w+)\s*(?:\(([^)]+)\))?", content)
    if m:
        info["sw_type"]     = m.group(1)
        info["system_type"] = m.group(2) or ""
        # 兼容旧 .info 文件：MSN* 和 AIR VX 曾被采集器写成 UNKNOWN。
        # VX 是虚拟 Ethernet 交换机，接口/BGP/资源均按 ETH 规则解析；
        # health 则保留 nv show system health 的原始结果（包括 Not OK）。
        if info["sw_type"] == "UNKNOWN" and re.match(
            r"(?:MSN|VX$)", info["system_type"], re.IGNORECASE,
        ):
            info["sw_type"] = "ETH"
        # 规范化：sw-info.sh 写入 NVLINK，统一改为 NVL
        if info["sw_type"] == "NVLINK":
            info["sw_type"] = "NVL"
    secs = split_sections(content)
    device_tz = parse_timedate_timezone(secs.get("timedatectl", ""))
    m = re.search(r"Collect Time:\s+(.+)", content)
    if m:
        info["collect_time"] = convert_collect_time(
            m.group(1), expected_collect_utc, device_tz
        )

    # ── nv show platform ──────────────────────────────────────────────────────
    # 实际格式（多空格分隔，键无前导空格）：
    #   serial-number  VN052MJMFCBNV613602H
    #   asic-model     Spectrum-4
    #   system-type    SN5610
    plat = parse_nv_kv(secs.get("nv show platform", ""))
    info["model"]  = plat.get("system-type") or info["system_type"] or ""
    info["serial"] = plat.get("serial-number", "")
    info["asic"]   = plat.get("asic-model", "")

    # ── nv show platform inventory ─────────────────────────────────────────
    inv = parse_inventory(secs.get("nv show platform inventory", ""))
    info["psu_ok"]   = inv["psu_ok"]
    info["psu_fail"] = inv["psu_fail"]
    info["fan_ok"]   = inv["fan_ok"]
    info["fan_fail"] = inv["fan_fail"]

    # ── nv show system version ────────────────────────────────────────────────
    # 实际格式（多空格分隔）：
    #   product-release  5.16.5
    ver_kv = parse_nv_kv(secs.get("nv show system version", ""))
    info["version"] = ver_kv.get("product-release", "")

    # ── nv show platform firmware ────────────────────────────────────────────
    (
        info["bios_version"],
        info["ssd_version"],
        info["asic_version"],
    ) = parse_firmware_versions(
        secs.get("nv show platform firmware", "")
    )

    # fallback: nv show system image 的 description 字段
    if not info["version"]:
        for line in secs.get("nv show system image", "").splitlines():
            m2 = re.match(r"^\s+description\s+(.+)", line)
            if m2:
                info["version"] = m2.group(1).strip()
                break

    # ── Linux resource usage ─────────────────────────────────────────────────
    # 新采集命令使用稳定、可机器解析的格式；同时兼容尚未更新的旧归档。
    cpu_text = (
        secs.get("env LC_ALL=C top -bn2 -d 1", "")
        or secs.get("LC_ALL=C top -bn2 -d 1", "")
        or secs.get("top -bn2 -d 1", "")
    )
    info["cpu_use"] = parse_cpu_use(cpu_text)
    info["disk_use"] = parse_disk_filesystems(secs.get("df -PT", ""))
    if not info["disk_use"]:
        # 兼容旧采集归档中分别查询 / 和 /var 或使用 df -h 的格式。
        root_use = parse_disk_use(secs.get("df -P /", ""))
        var_use = parse_disk_use(secs.get("df -P /var", ""))
        if root_use is None:
            root_use = parse_disk_use(secs.get("df -h", ""))
        if root_use is not None:
            info["disk_use"]["/"] = root_use
        if var_use is not None:
            info["disk_use"]["/var"] = var_use
    info["mem_use"] = parse_memory_use(
        secs.get("free -b", "") or secs.get("free -h", "")
    )
    info["ntp_sync"] = parse_ntp_sync(secs.get("timedatectl", ""))
    info["uptime"] = secs.get("uptime -p", "").strip().splitlines()[0] \
        if secs.get("uptime -p", "").strip() else ""

    # ── nv show system health ─────────────────────────────────────────────────
    # 实际格式：status      OK
    health_kv = parse_nv_kv(secs.get("nv show system health", ""))
    info["health"] = health_kv.get("status", "unknown").lower()

    # ── nv show platform environment temperature ──────────────────────────────
    # 实际格式：Asic-Temp-Sensor  64.0  120.0  105.0  5  ok
    temperature_details = parse_temp_table_details(
        secs.get("nv show platform environment temperature", "")
    )
    temps = [
        (sensor["name"], sensor["current"])
        for sensor in temperature_details
    ]
    info["temperature"] = temps
    info["temperature_details"] = temperature_details
    info["asic_temperatures"] = [
        value for name, value in temps if re.search(r"\bASIC", name, re.IGNORECASE)
    ]
    info["psu_temperatures"] = [
        value for name, value in temps
        if re.search(r"\bPSU(?:\d+)?(?:[-_/ ]|$)", name, re.IGNORECASE)
    ]
    info["asic_temperature_details"] = [
        sensor for sensor in temperature_details
        if re.search(r"\bASIC", sensor["name"], re.IGNORECASE)
    ]
    info["psu_temperature_details"] = [
        sensor for sensor in temperature_details
        if re.search(r"\bPSU(?:\d+)?(?:[-_/ ]|$)", sensor["name"], re.IGNORECASE)
    ]
    if temps:
        info["temp_max"] = max(v for _, v in temps)

    # ── nv show platform transceiver detail ──────────────────────────────────
    info["transceiver_temps"] = parse_transceiver_temperatures(
        secs.get("nv show platform transceiver detail", "")
    )

    # ── nv show interface ─────────────────────────────────────────────────────
    up = 0; total = 0; downs: list[str] = []

    if info["sw_type"] == "ETH":
        # ETH 格式：Interface  Admin Status  Oper Status  ...
        #   swp1s0  up  up  400G  9216  swp  ...
        for line in secs.get("nv show interface", "").splitlines():
            m2 = re.match(r"^(swp\S+)\s+(up|down)\s+(up|down|carrier|no-carrier)\b",
                          line.strip(), re.IGNORECASE)
            if m2:
                total += 1
                if m2.group(3).lower() == "up":
                    up += 1
                elif m2.group(2).lower() == "up":
                    # Only flag an operational fault.  Interfaces an
                    # administrator intentionally disabled remain part of the
                    # total denominator, but do not inflate the red counter.
                    downs.append(m2.group(1))
    else:
        # IB 格式：Interface  State  Speed  MTU  Type  ...  Logical State  Physical State
        #   sw1p1  up  800G  4096  ib  ...  Active  LinkUp
        for line in secs.get("nv show interface", "").splitlines():
            m2 = re.match(r"^(sw\d+p\d+)\s+(up|down)\b", line.strip(), re.IGNORECASE)
            if m2:
                total += 1
                if re.search(r"\bActive\b", line):
                    up += 1
                elif m2.group(2).lower() == "up":
                    downs.append(m2.group(1))

    info["interfaces_up"]    = up
    info["interfaces_total"] = total
    info["interfaces_down_count"] = len(downs)
    info["interfaces_down"]  = downs[:20]

    if info["sw_type"] == "ETH":
        # ── nv show vrf default router bgp neighbor ────────────────────────────
        # 格式：swp64s0  Border01  4200081001  established  8 days, ...
        bgp_est = 0; bgp_total = 0
        in_bgp_table = False
        for line in secs.get("nv show vrf default router bgp neighbor", "").splitlines():
            s = line.strip()
            if not s:
                continue
            if re.match(r"^Neighbor\s+Hostname\s+AS\b", s):
                in_bgp_table = True
                continue
            if not in_bgp_table or re.match(r"^[-\s]+$", s):
                continue
            if re.match(r"^\S+\s+\S+\s+\d+\s+\w+", s):
                bgp_total += 1
                parts = re.split(r"\s+", s)
                if len(parts) >= 4 and parts[3].lower() == "established":
                    bgp_est += 1
        info["bgp_established"] = bgp_est
        info["bgp_total"]       = bgp_total

        evpn_bonds = parse_evpn_multihoming_bonds(
            secs.get("nv show evpn multihoming esi", "")
        )
        mlag_bonds = parse_clag_bonds(secs.get("clagctl", ""))
        info["evpn_bond_total"] = len(evpn_bonds)
        info["evpn_bond_up"] = sum(bool(item["up"]) for item in evpn_bonds)
        info["evpn_bond_details"] = evpn_bonds
        info["mlag_bond_total"] = len(mlag_bonds)
        info["mlag_bond_up"] = sum(bool(item["up"]) for item in mlag_bonds)
        info["mlag_bond_details"] = mlag_bonds
    else:
        # ── nv show ib device ─────────────────────────────────────────────────
        # 格式：ASIC1  Quantum3  infiniband-default  28:01:CD:...  30
        asic_count = 0; asic_type = ""
        for line in secs.get("nv show ib device", "").splitlines():
            m2 = re.match(r"^(ASIC\d+)\s+(\S+)\s+", line.strip())
            if m2:
                asic_count += 1
                if not asic_type:
                    asic_type = m2.group(2)
        info["ib_asic_count"] = asic_count
        info["ib_asic_type"]  = asic_type

    return info


def render_bond_multihoming_summary(sw: dict, *, compact: bool = False) -> str:
    """Render EVPN-MH and MLAG bond health without conflating the two sources."""
    if sw.get("sw_type") != "ETH":
        return '<span class="na">N/A</span>'

    summaries: list[str] = []
    for prefix, label in (("evpn", "EVPN"), ("mlag", "MLAG")):
        total = int(sw.get(f"{prefix}_bond_total") or 0)
        if not total:
            continue
        up = int(sw.get(f"{prefix}_bond_up") or 0)
        detail_lines = []
        for item in sw.get(f"{prefix}_bond_details") or []:
            state = "UP" if item.get("up") else "DOWN"
            if prefix == "evpn":
                remote_vteps = item.get("remote_vteps") or []
                remote_text = ", ".join(str(value) for value in remote_vteps) \
                    if isinstance(remote_vteps, list) else str(remote_vteps)
                evidence = (
                    f"RemoteVTEPs={remote_text or '—'}, "
                    f"Flags={item.get('flags') or '—'}"
                )
            else:
                evidence = (
                    f"Peer Interface={item.get('peer_interface') or '—'}, "
                    f"CLAG Id={item.get('clag_id') or '—'}, "
                    f"Conflicts={item.get('conflicts') or '—'}, "
                    f"Proto-Down={item.get('proto_down_reason') or '—'}"
                )
            detail_lines.append(f"{item.get('interface')}: {state} ({evidence})")
        css_class = "i-ok" if up == total else "i-warn"
        suffix = "" if compact else " UP"
        summaries.append(
            f'<span class="{css_class}" title="{escape(chr(10).join(detail_lines))}">'
            f'{label} {up}/{total}{suffix}</span>'
        )
    return "<br>".join(summaries) if summaries else "—"


def render_eth_card(sw: dict) -> str:
    """生成单台交换机的 HTML 卡片。"""
    hostname = escape(sw["hostname"])
    hostname_chars = max(1, len(sw["hostname"]))
    sw_type  = escape(sw["sw_type"])
    role     = infer_device_role(sw["hostname"])
    type_tag = escape(f'{sw["sw_type"]} · {role}' if role else sw["sw_type"])
    model    = escape(sw["model"] or sw["system_type"] or "—")
    serial   = escape(sw["serial"] or "—")
    asic     = escape(sw["asic"] or "—")
    version  = escape(sw["version"] or "—")
    c_time   = escape(
        sw.get("collect_time") or sw.get("collection_attempt_time") or "—"
    )

    h = sw["health"].lower()
    h_cls = {"ok": "h-ok", "error": "h-err", "warning": "h-warn", "missing": "h-miss"}.get(h, "h-unk")
    h_lbl = "MISSING" if h == "missing" else (h.upper() if h else "N/A")

    if h == "missing":
        attempted = bool(sw.get("collection_attempted", True))
        collection_label = "失败" if attempted else "未发起"
        collection_class = "collect-fail" if attempted else "collect-pending"
        if sw["sw_type"] == "IB":
            hdr_cls = "sw-hdr-ib"
        elif sw["sw_type"] == "NVL":
            hdr_cls = "sw-hdr-nv"
        else:
            hdr_cls = ""
        cat_key, _ = classify_host(
            sw["hostname"], sw["sw_type"], sw["health"], sw.get("template", ""),
            bool(sw.get("dynamic_dhcp")),
        )
        return f"""
<div class="sw-card sw-card-miss" style="--hostname-ch:{hostname_chars}"
     data-hn="{hostname.lower()}" data-cat="{cat_key}">
  <div class="sw-hdr {hdr_cls}">
    <span class="sw-name" title="{hostname}">{hostname}</span>
    <div class="sw-hdr-meta">
      <span class="sw-type-tag">{type_tag}</span>
      <span class="h-badge {h_cls}">{h_lbl}</span>
    </div>
  </div>
  <div class="sw-miss-body">
    <div class="miss-warn">&#9888;</div>
    <div class="collect-result {collection_class}">{collection_label} · {c_time}</div>
    <div class="miss-sub">{escape(sw.get("collection_error") or "本批次未返回采集文件")}</div>
  </div>
</div>"""

    if sw["temperature"]:
        temperature_details = sw.get("temperature_details") or [
            {"name": name, "current": value, "critical": None,
             "maximum": None, "state": ""}
            for name, value in sw["temperature"]
        ]
        severity = {"t-ok": 0, "t-warn": 1, "t-crit": 2}
        t_cls = max(
            (temperature_status_class(sensor) for sensor in temperature_details),
            key=lambda css_class: severity[css_class],
        )
        t_detail = escape("\n".join(
            temperature_sensor_title(sensor) for sensor in temperature_details[:8]
        ))
        mt = max(float(sensor["current"]) for sensor in temperature_details)
        t_html = (f'<span class="{t_cls}" title="{t_detail}">'
                  f'{mt:.0f}°C ({len(temperature_details)} sensors)</span>')
    else:
        t_html = "—"

    if sw["interfaces_total"]:
        up, total = sw["interfaces_up"], sw["interfaces_total"]
        downs = sw["interfaces_down"]
        down_count = int(sw.get("interfaces_down_count", len(downs)) or 0)
        i_cls = "i-warn" if down_count else "i-ok"
        i_html = f'<span class="{i_cls}">{up}/{total} up</span>'
        if down_count:
            down_detail = "Admin up / Oper down:\n" + "\n".join(downs)
            if down_count > len(downs):
                down_detail += f"\n… plus {down_count - len(downs)} more"
            i_html += (f' <span class="i-down" title="{escape(down_detail)}">'
                       f'({down_count} down)</span>')
    else:
        i_html = "—"

    # BGP / IB ASIC 行（按交换机类型显示不同内容）
    if sw["sw_type"] == "ETH":
        if sw["bgp_total"]:
            bgp_down = max(0, sw["bgp_total"] - sw["bgp_established"])
            bgp_cls = "i-ok" if not bgp_down else "i-warn"
            extra_lbl  = "BGP Peers"
            extra_html = f'<span class="{bgp_cls}">{sw["bgp_established"]}/{sw["bgp_total"]} established</span>'
            if bgp_down:
                extra_html += f' <span class="i-down">({bgp_down} down)</span>'
        else:
            extra_lbl  = "BGP Peers"
            extra_html = "—"
    elif sw["sw_type"] == "NVL":
        extra_lbl  = "NVLink"
        extra_html = "—"
    else:
        cnt = sw.get("ib_asic_count", 0)
        typ = escape(sw.get("ib_asic_type", ""))
        extra_lbl  = "IB ASICs"
        extra_html = f"{cnt} × {typ}" if cnt else "—"

    bond_row = ""
    if sw["sw_type"] == "ETH":
        bond_row = (
            '<div class="sw-r"><span class="sw-k">EVPN/MLAG Bond</span>'
            f'<span>{render_bond_multihoming_summary(sw)}</span></div>'
        )

    # PSU 状态
    psu_ok   = sw.get("psu_ok", 0)
    psu_fail = sw.get("psu_fail", 0)
    psu_total = psu_ok + psu_fail
    if psu_total:
        psu_cls  = "i-warn" if psu_fail else "i-ok"
        psu_html = f'<span class="{psu_cls}">{psu_ok}/{psu_total} ok</span>'
        if psu_fail:
            psu_html += f' <span class="i-down">({psu_fail} FAIL)</span>'
    else:
        psu_html = "—"

    # 卡片头颜色：ETH 深蓝，IB 紫色，NV 深维
    if sw["sw_type"] == "IB":
        hdr_cls = "sw-hdr-ib"
    elif sw["sw_type"] == "NVL":
        hdr_cls = "sw-hdr-nv"
    else:
        hdr_cls = ""

    cat_key, _ = classify_host(
        sw["hostname"], sw["sw_type"], sw["health"], sw.get("template", ""),
        bool(sw.get("dynamic_dhcp")),
    )
    return f"""
<div class="sw-card" style="--hostname-ch:{hostname_chars}"
     data-hn="{hostname.lower()}" data-cat="{cat_key}">
  <div class="sw-hdr {hdr_cls}">
    <span class="sw-name" title="{hostname}">{hostname}</span>
    <div class="sw-hdr-meta">
      <span class="sw-type-tag">{type_tag}</span>
      <span class="h-badge {h_cls}">{h_lbl}</span>
    </div>
  </div>
  <div class="sw-body">
    <div class="sw-r"><span class="sw-k">Model</span><span>{model}</span></div>
    <div class="sw-r"><span class="sw-k">Serial</span><span>{serial}</span></div>
    <div class="sw-r"><span class="sw-k">ASIC</span><span>{asic}</span></div>
    <div class="sw-r"><span class="sw-k">SW Version</span><span class="sw-ver">{version}</span></div>
    <div class="sw-r"><span class="sw-k">Temperature</span><span>{t_html}</span></div>
    <div class="sw-r"><span class="sw-k">Interfaces</span><span>{i_html}</span></div>
    <div class="sw-r"><span class="sw-k">PSU</span><span>{psu_html}</span></div>
    <div class="sw-r"><span class="sw-k">{extra_lbl}</span><span>{extra_html}</span></div>
    {bond_row}
    <div class="sw-r sw-r-last"><span class="sw-k">采集</span><span class="collect-result collect-ok">成功 · {c_time}</span></div>
  </div>
</div>"""


# ── 列表视图辅助 ──────────────────────────────────────────────────────────────

_ETH_CATEGORIES: list[tuple[str, str]] = [
    ("missing", "未采集 · 可能掉线"),
    ("oob2",  "OOBofOOB"),
    ("oob",   "OOB / Border"),
    ("tan",   "TAN"),
    ("spx",   "SPX"),
    ("other", "其他"),
]

SWITCH_LIST_COLUMN_COUNT = 21

_IB_CATEGORIES: list[tuple[str, str]] = [
    ("missing", "未采集 · 可能掉线"),
    ("ib-spine", "Spine"),
    ("ib-leaf",  "Leaf"),
    ("other",    "其他"),
]

_UNBOUND_CATEGORIES: list[tuple[str, str]] = [
    ("other", "其他"),
]

def extract_nvlink_group(hostname: str) -> Optional[tuple[str, str]]:
    """从 ``<组名>-nvswNN`` 主机名提取稳定的 NVSwitch 组 key 和显示名。"""
    match = re.match(r"^(.+?)[-_.]?nvsw\d+$", hostname.strip(), re.IGNORECASE)
    if not match:
        return None
    label = match.group(1).rstrip("-_.")
    if not label:
        return None
    normalized = re.sub(r"[^a-z0-9]+", "-", label.lower()).strip("-")
    return (f"nv-group-{normalized}", label)


def build_nvlink_categories(switches: list[dict]) -> list[tuple[str, str]]:
    """按主机名前缀动态生成 NVLink 子类，通常每个子类包含 nvsw01..09。"""
    groups: dict[str, str] = {}
    has_missing = False
    has_other = False
    for sw in switches:
        if sw.get("health") == "missing":
            has_missing = True
            continue
        group = extract_nvlink_group(sw["hostname"])
        if group:
            groups.setdefault(*group)
        else:
            has_other = True
    categories: list[tuple[str, str]] = []
    if has_missing:
        categories.append(("missing", "未采集 · 可能掉线"))
    categories.extend(sorted(groups.items(), key=lambda item: _nat_key(item[1])))
    if has_other:
        categories.append(("other", "其他"))
    return categories


def classify_host(
    hostname: str, sw_type: str = "ETH", health: str = "", template: str = "",
    dynamic_dhcp: bool = False,
) -> tuple[str, str]:
    """根据主机名和交换机类型返回 (cat_key, cat_label)。"""
    hn = hostname.upper()
    if health == "missing" and not dynamic_dhcp:
        return ("missing", "未采集 · 可能掉线")
    role = infer_device_role(hostname)
    if sw_type == "NVL":
        group = extract_nvlink_group(hostname)
        if group:
            return group
        return ("other", "其他")
    if sw_type == "IB":
        if role == "Spine":
            return ("ib-spine", "Spine")
        if role == "Leaf":
            return ("ib-leaf", "Leaf")
        return ("other", "其他")
    # ETH 分类规则
    if "OOBOFOOB" in hn or "oobofoob" in template.casefold():
        return ("oob2", "OOBofOOB")
    if ("OOB" in hn or "BORDER" in hn
            or "oob" in template.casefold() or "border" in template.casefold()):
        return ("oob", "OOB")
    if "TAN" in hn or "tan" in template.casefold():
        return ("tan", "TAN")
    if "CF" in hn or "CL" in hn or "CS" in hn:
        return ("spx", "SPX")
    return ("other", "其他")


def _nat_key(s: str) -> list:
    return [int(c) if c.isdigit() else c.lower() for c in re.split(r"(\d+)", s)]


def is_air_hostname(value: object) -> bool:
    return str(value or "").strip().casefold().startswith("air-")


def switch_environment(switch: dict) -> str:
    """Return the switch environment, preferring its collection source.

    Collection provenance is authoritative because AIR and Production can
    reuse management IPs.  Hostname is only a fallback for non-collector data
    that has no explicit environment field.
    """
    explicit = str(switch.get("environment") or "").strip().casefold()
    if explicit == "prod":
        return "production"
    if explicit in {"air", "production", "unknown"}:
        return explicit
    return "air" if is_air_hostname(switch.get("hostname")) else "production"


def air_first_hostname_key(value: object) -> tuple:
    text = str(value or "")
    return (0 if is_air_hostname(text) else 1, _nat_key(text))


def air_first_row_key(row: list[object]) -> tuple:
    values = [str(value or "") for value in row]
    is_air = any(is_air_hostname(value) for value in values)
    return (0 if is_air else 1, tuple(value.casefold() for value in values))


def format_temperature_values(values: list[float]) -> str:
    """把同类传感器温度四舍五入为整数并用斜杠连接。"""
    if not values:
        return "—"
    return "/".join(f"{value:.0f}°C" for value in values)


def temperature_status_class(sensor: dict) -> str:
    """Color one sensor using the device-reported Max/Crit thresholds."""
    current = float(sensor.get("current", 0))
    state = str(sensor.get("state") or "").strip().casefold()
    critical = sensor.get("critical")
    maximum = sensor.get("maximum")
    if state and state not in {"ok", "normal"}:
        return "t-crit"
    if critical is not None and current >= float(critical):
        return "t-crit"
    if maximum is not None and current >= float(maximum):
        return "t-warn"
    if critical is not None or maximum is not None:
        return "t-ok"
    # Compatibility for old archives that did not retain threshold columns.
    if current >= 85:
        return "t-crit"
    if current >= 70:
        return "t-warn"
    return "t-ok"


def temperature_sensor_title(sensor: dict) -> str:
    fields = [f'{sensor.get("name") or "Sensor"}: {float(sensor["current"]):.1f}°C']
    if sensor.get("maximum") is not None:
        fields.append(f'Max {float(sensor["maximum"]):.1f}°C')
    if sensor.get("critical") is not None:
        fields.append(f'Crit {float(sensor["critical"]):.1f}°C')
    if sensor.get("state"):
        fields.append(f'State {sensor["state"]}')
    return " · ".join(fields)


def render_temperature_values(details: list[dict], values: list[float]) -> str:
    """Render each ASIC/PSU sensor with its own device-provided thresholds."""
    sensors = details or [
        {"name": "Sensor", "current": value, "critical": None,
         "maximum": None, "state": ""}
        for value in values
    ]
    if not sensors:
        return "—"
    return "/".join(
        f'<span class="{temperature_status_class(sensor)}" '
        f'title="{escape(temperature_sensor_title(sensor))}">'
        f'{float(sensor["current"]):.0f}°C</span>'
        for sensor in sensors
    )


def use_percent_display(value: float | int) -> tuple[str, str]:
    """Return the displayed percentage and its shared utilization class."""
    text = f"{float(value):.0f}%"
    displayed = int(text[:-1])
    if displayed >= 75:
        return text, "use-crit"
    if displayed >= 31:
        return text, "use-warn"
    return text, "use-ok"


def render_use_percent(value: Optional[float | int]) -> str:
    """Render CPU/memory utilization using the list-view thresholds."""
    if value is None:
        return "—"
    text, css_class = use_percent_display(value)
    return f'<span class="{css_class}">{text}</span>'


def render_sw_list_row(sw: dict) -> str:
    """生成列表视图的单行 <tr>。"""
    hostname  = escape(sw["hostname"])
    serial    = escape(sw.get("serial") or "—")
    model     = escape(sw["model"] or sw["system_type"] or "—")
    version   = escape(sw["version"] or "—")
    bios_ver  = escape(sw.get("bios_version") or "—")
    ssd_ver   = escape(sw.get("ssd_version") or "—")
    asic_ver  = escape(sw.get("asic_version") or "—")
    asic_temp = render_temperature_values(
        sw.get("asic_temperature_details", []),
        sw.get("asic_temperatures", []),
    )
    psu_temp = render_temperature_values(
        sw.get("psu_temperature_details", []),
        sw.get("psu_temperatures", []),
    )
    c_time    = escape(
        sw.get("collect_time") or sw.get("collection_attempt_time") or "—"
    )
    cpu_use   = sw.get("cpu_use")
    mem_use   = sw.get("mem_use")
    cpu_html  = render_use_percent(cpu_use)
    mem_html  = render_use_percent(mem_use)
    disk_use  = sw.get("disk_use", {})
    disk_paths = sorted(
        disk_use,
        key=lambda path: (path != "/", path.count("/"), _nat_key(path)),
    )
    disk_parts = []
    for path in disk_paths:
        use_text, use_class = use_percent_display(disk_use[path])
        disk_parts.append(
            f'<span class="disk-use-item {use_class}">'
            f'{{ {escape(path)}: {use_text} }}</span>'
        )
    disk_html = "  ".join(disk_parts) if disk_parts else "—"
    ntp_sync = sw.get("ntp_sync")
    if ntp_sync is True:
        ntp_html = '<span class="i-ok">Yes</span>'
    elif ntp_sync is False:
        ntp_html = '<span class="i-warn">No</span>'
    else:
        ntp_html = "—"
    uptime = escape(sw.get("uptime") or "—")

    h = sw["health"].lower()
    h_cls = {"ok": "h-ok", "error": "h-err", "warning": "h-warn", "missing": "h-miss"}.get(h, "h-unk")
    h_lbl = "MISSING" if h == "missing" else (h.upper() if h else "N/A")

    if h == "missing":
        reason = escape(sw.get("collection_error") or "本批次未返回采集文件")
        attempted = bool(sw.get("collection_attempted", True))
        collection_label = "失败" if attempted else "未发起"
        collection_class = "collect-fail" if attempted else "collect-pending"
        missing_summary = (
            "未采集到数据 — 设备可能已掉线"
            if attempted else "未发起采集 — 待绑定或待人工识别"
        )
        collection_html = (
            f'<span class="collect-result {collection_class}">{collection_label} · {c_time}</span>'
            f'<span class="collect-reason">{reason}</span>'
        )
        cat_key, _ = classify_host(
            sw["hostname"], sw["sw_type"], sw["health"], sw.get("template", ""),
            bool(sw.get("dynamic_dhcp")),
        )
        return (
            f'<tr class="lst-row lst-row-miss" data-hn="{hostname.lower()}" data-cat="{cat_key}">'
            f'<td class="lst-hn">{hostname}</td>'
            f'<td class="lst-num">{serial}</td>'
            f'<td colspan="{SWITCH_LIST_COLUMN_COUNT - 5}" style="color:#9b2335;font-style:italic">{missing_summary}</td>'
            f'<td><span class="h-badge {h_cls}">{h_lbl}</span></td>'
            f'<td class="lst-num">{uptime}</td>'
            f'<td class="collect-cell">{collection_html}</td>'
            f'</tr>\n'
        )

    if sw["interfaces_total"]:
        up, total = sw["interfaces_up"], sw["interfaces_total"]
        downs = sw["interfaces_down"]
        down_count = int(sw.get("interfaces_down_count", len(downs)) or 0)
        i_cls  = "i-warn" if down_count else "i-ok"
        i_html = f'<span class="{i_cls}">{up}/{total}</span>'
        if down_count:
            down_detail = "Admin up / Oper down:\n" + "\n".join(downs)
            if down_count > len(downs):
                down_detail += f"\n… plus {down_count - len(downs)} more"
            i_html += (f' <span class="i-down" title="{escape(down_detail)}">'
                       f'({down_count}↓)</span>')
    else:
        i_html = "—"

    psu_ok    = sw.get("psu_ok", 0)
    psu_fail  = sw.get("psu_fail", 0)
    psu_total = psu_ok + psu_fail
    if psu_total:
        psu_cls  = "i-warn" if psu_fail else "i-ok"
        psu_html = f'<span class="{psu_cls}">{psu_ok}/{psu_total}</span>'
        if psu_fail:
            psu_html += f' <span class="i-down">({psu_fail}↓)</span>'
    else:
        psu_html = "—"

    fan_ok    = sw.get("fan_ok", 0)
    fan_fail  = sw.get("fan_fail", 0)
    fan_total = fan_ok + fan_fail
    if fan_total:
        fan_cls  = "i-warn" if fan_fail else "i-ok"
        fan_html = f'<span class="{fan_cls}">{fan_ok}/{fan_total}</span>'
        if fan_fail:
            fan_html += f' <span class="i-down">({fan_fail}↓)</span>'
    else:
        fan_html = "—"

    if sw["sw_type"] == "ETH":
        if sw["bgp_total"]:
            bgp_down = max(0, sw["bgp_total"] - sw["bgp_established"])
            bgp_cls  = "i-ok" if not bgp_down else "i-warn"
            bgp_html = f'<span class="{bgp_cls}">{sw["bgp_established"]}/{sw["bgp_total"]}</span>'
            if bgp_down:
                bgp_html += f' <span class="i-down">({bgp_down}↓)</span>'
        else:
            bgp_html = "—"
    elif sw["sw_type"] == "NVL":
        bgp_html = '<span class="na">N/A</span>'
    else:
        bgp_html = '<span class="na">N/A</span>'
    bond_html = render_bond_multihoming_summary(sw, compact=True)

    cat_key, _ = classify_host(
        sw["hostname"], sw["sw_type"], sw["health"], sw.get("template", ""),
        bool(sw.get("dynamic_dhcp")),
    )
    return (
        f'<tr class="lst-row" data-hn="{hostname.lower()}" data-cat="{cat_key}">'
        f'<td class="lst-hn">{hostname}</td>'
        f'<td class="lst-num">{serial}</td>'
        f'<td class="lst-model">{model}</td>'
        f'<td class="lst-num">{version}</td>'
        f'<td class="lst-num">{bios_ver}</td>'
        f'<td class="lst-num">{ssd_ver}</td>'
        f'<td class="lst-num">{asic_ver}</td>'
        f'<td class="lst-num">{asic_temp}</td>'
        f'<td class="lst-num">{psu_temp}</td>'
        f'<td class="lst-num">{psu_html}</td>'
        f'<td class="lst-num">{fan_html}</td>'
        f'<td class="lst-num">{cpu_html}</td>'
        f'<td class="lst-num">{disk_html}</td>'
        f'<td class="lst-num">{mem_html}</td>'
        f'<td class="lst-num">{ntp_html}</td>'
        f'<td class="lst-num">{i_html}</td>'
        f'<td class="lst-num">{bgp_html}</td>'
        f'<td class="lst-num">{bond_html}</td>'
        f'<td class="lst-num"><span class="h-badge {h_cls}">{h_lbl}</span></td>'
        f'<td class="lst-num">{uptime}</td>'
        f'<td class="collect-cell"><span class="collect-result collect-ok">成功 · {c_time}</span></td>'
        f'</tr>\n'
    )


def build_switch_list_html(
    switches: list[dict],
    categories: list[tuple[str, str]],
    sw_type: str = "ETH",
    group_environments: bool = True,
) -> str:
    """将交换机按分类分组，生成含子类标题行的列表 <tr> 片段。空分类仍显示标题。"""
    groups: dict[str, list[dict]] = {}
    for sw in switches:
        key, _ = classify_host(
            sw["hostname"], sw_type, sw.get("health", ""), sw.get("template", ""),
            bool(sw.get("dynamic_dhcp")),
        )
        groups.setdefault(key, []).append(sw)

    html = ""
    environments = (
        (("air", "AIR"), ("production", "Production"))
        if sw_type == "ETH" and group_environments else (("all", ""),)
    )
    for environment, environment_label in environments:
        environment_switches = [
            sw for sw in switches
            if environment == "all"
            or switch_environment(sw) == environment
        ]
        if sw_type == "ETH" and group_environments:
            html += (
                f'<tr class="lst-env" data-environment="{environment}" '
                f'role="button" tabindex="0" aria-expanded="true" '
                f'onclick="toggleListEnvironment(this)" '
                f'onkeydown="handleListEnvironmentKey(event, this)">'
                f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">{environment_label}（{len(environment_switches)}）</td></tr>\n'
            )
        for cat_key, cat_label in categories:
            sws = [
                sw for sw in groups.get(cat_key, []) if sw in environment_switches
            ]
            if cat_key == "missing" and not sws:
                continue
            sws_sorted = sorted(sws, key=lambda s: air_first_hostname_key(s["hostname"]))
            cat_cls = "lst-cat lst-cat-miss" if cat_key == "missing" else "lst-cat"
            html += (
                f'<tr class="{cat_cls}" data-cat="{cat_key}" onclick="toggleCat(this)">'
                f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">{escape(cat_label)}（{len(sws_sorted)}）</td></tr>\n'
            )
            for role, role_switches in group_switches_by_role(sws_sorted):
                html += (
                    f'<tr class="lst-role" data-role="{escape(role.casefold())}">'
                    f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">{escape(role)}（{len(role_switches)}）</td></tr>\n'
                )
                html += "".join(render_sw_list_row(sw) for sw in role_switches)
    return html


def build_switch_cards_html(
    switches: list[dict],
    categories: list[tuple[str, str]],
    sw_type: str,
    group_environments: bool = True,
) -> str:
    """按角色/用途子类组织卡片，并为每个子类生成可折叠标题。"""
    if not switches:
        return ""
    groups: dict[str, list[dict]] = {}
    for sw in switches:
        key, _ = classify_host(
            sw["hostname"], sw_type, sw.get("health", ""), sw.get("template", ""),
            bool(sw.get("dynamic_dhcp")),
        )
        groups.setdefault(key, []).append(sw)

    html = ""
    environments = (
        (("air", "AIR"), ("production", "Production"))
        if sw_type == "ETH" and group_environments else (("all", ""),)
    )
    for environment, environment_label in environments:
        environment_switches = [
            sw for sw in switches
            if environment == "all"
            or switch_environment(sw) == environment
        ]
        if sw_type == "ETH" and group_environments:
            html += (
                f'<section class="card-env-group" data-environment="{environment}">'
                f'<div class="card-env" data-environment="{environment}" '
                f'role="button" tabindex="0" '
                f'aria-expanded="true" onclick="toggleCardEnvironment(this)" '
                f'onkeydown="handleCardEnvironmentKey(event, this)">'
                f'{environment_label}（{len(environment_switches)}）</div>'
                f'<div class="card-env-content">'
            )
        for cat_key, cat_label in categories:
            sws = sorted(
                (sw for sw in groups.get(cat_key, []) if sw in environment_switches),
                key=lambda sw: air_first_hostname_key(sw["hostname"]),
            )
            if cat_key == "missing" and not sws:
                continue
            cat_class = "card-cat card-cat-miss" if cat_key == "missing" else "card-cat"
            html += (
                f'<div class="{cat_class}" data-cat="{cat_key}" role="button" tabindex="0" '
                f'aria-expanded="true" onclick="toggleCardCat(this)" '
                f'onkeydown="handleCardCatKey(event, this)">'
                f'{escape(cat_label)}（{len(sws)}）</div>'
            )
            for role, role_switches in group_switches_by_role(sws):
                html += (
                    f'<div class="card-role" data-role="{escape(role.casefold())}">'
                    f'{escape(role)}（{len(role_switches)}）</div>'
                )
                html += "".join(render_eth_card(sw) for sw in role_switches)
        if sw_type == "ETH" and group_environments:
            html += "</div></section>"
    return html


# ══════════════════════════════════════════════════════════════════════════════
# SPX-LINK 解析
# ══════════════════════════════════════════════════════════════════════════════

def parse_snap_ts(stem: str) -> Optional[datetime]:
    m = re.match(r"^(\d{4})(\d{2})(\d{2})-(\d{2})(\d{2})$", stem)
    if not m:
        return None
    utc_time = datetime(
        int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]),
        tzinfo=timezone.utc,
    )
    return utc_time.astimezone(DISPLAY_TZ).replace(tzinfo=None)


def format_link_value(header: str, value: str) -> str:
    """格式化Link Monitor显示值；Time列去掉小数秒。"""
    if header == "Time":
        match = re.fullmatch(r"(\d{2}:\d{2}:\d{2})(?:\.\d+)?", value)
        if match:
            return match.group(1)
    return value


def valid_link_interface(value: str) -> bool:
    """判断CSV第二列是否为三类Link Monitor支持的真实接口名。"""
    return bool(re.fullmatch(r"(?:swp\d+(?:s\d+)?|sw\d+p\d+|acp\d+)", value, re.IGNORECASE))


def _looks_like_ber(value: str) -> bool:
    return bool(re.fullmatch(r"[-+]?\d+(?:\.\d+)?E[-+]?\d+", value, re.IGNORECASE))


def _looks_numeric(value: str) -> bool:
    if value == "":
        return True
    try:
        float(value)
        return True
    except ValueError:
        return False


def normalize_link_row(headers: list[str], row: list[str]) -> Optional[list[str]]:
    """校验并按表头恢复旧采集器产生的短行，拒绝拼接超长行。"""
    if len(row) < 3 or len(row) > len(headers):
        return None
    if not valid_link_interface(row[1]):
        return None

    # SPX数据包含日期、时间和peer，字段缺失后无法可靠判断错位位置；
    # 新旧有效快照本身均为完整13列，因此只接受精确列数。
    if "Oper-Status" in headers:
        status_index = headers.index("Oper-Status")
        return row if (
            len(row) == len(headers)
            and row[status_index].lower() in {"up", "down"}
        ) else None

    state = row[-1].lower()
    if state not in {"up", "down"}:
        return None

    middle = row[2:-1]

    if "Carrier-Down-Count" in headers:  # InfiniBand
        values = ["", "", "", "", ""]
        if middle and _looks_like_ber(middle[0]):
            values[0] = middle.pop(0)
            if middle:
                values[1] = middle.pop(0)
        elif len(middle) >= 2 and middle[0] == "0":
            # BER缺失但Effective-Error仍存在。
            values[1] = middle.pop(0)

        if middle:
            values[2] = middle.pop(0)  # Carrier-Down-Count
        if middle:
            values[3] = middle.pop(0)  # QP1-Drops-Receive
        if middle:
            values[4] = middle.pop(0)  # QP1-Drops-Transmit
        if middle:
            return None
        if any(not _looks_numeric(value) for value in values[1:]):
            return None
        return row[:2] + values + [row[-1]]

    if "Link-Downed" in headers:  # NVLink
        values = ["", "", "", ""]
        if middle and _looks_like_ber(middle[0]):
            values[0] = middle.pop(0)
            if middle:
                values[1] = middle.pop(0)
        elif len(middle) >= 3 and middle[0] == "0":
            values[1] = middle.pop(0)

        if middle:
            values[2] = middle.pop(0)  # Link-Downed
        if middle:
            values[3] = middle.pop(0)  # QP1-Drops
        if middle:
            return None
        if any(not _looks_numeric(value) for value in values[1:]):
            return None
        return row[:2] + values + [row[-1]]

    return row if len(row) == len(headers) else None


def split_concatenated_link_row(headers: list[str], row: list[str]) -> list[list[str]]:
    """从超长损坏行中提取仍可识别的 ``Hostname,Interface,...`` 片段。"""
    if len(row) <= len(headers):
        return [row]
    starts = [
        i for i in range(len(row) - 1)
        if re.fullmatch(r"[A-Za-z][A-Za-z0-9._-]*", row[i])
        and valid_link_interface(row[i + 1])
    ]
    return [row[start:end] for start, end in zip(starts, starts[1:] + [len(row)])]


def load_csv_snap(path: Path) -> tuple[list[str], dict[tuple, list[str]]]:
    headers: list[str] = []
    data: dict[tuple, list[str]] = {}
    first = True
    with open(path, newline="", encoding="utf-8", errors="replace") as f:
        # 部分采集文件包含NUL或多个设备输出拼接产生的残缺行。清除NUL，
        # 再由接口名校验过滤错位字段，避免它们被渲染成表格顶部的设备组。
        for row in csv.reader((line.replace("\0", "") for line in f)):
            row = [c.strip() for c in row]
            if not row or all(c == "" for c in row) or row[0].startswith("#"):
                continue
            if first:
                headers = row
                first = False
                continue
            key_cols = SPX_KEY_COLS  # always 2 for both SPX and IB
            candidates = split_concatenated_link_row(headers, row) if headers else []
            for candidate in candidates:
                normalized = normalize_link_row(headers, candidate)
                if normalized is None:
                    continue
                row_is_air = is_air_hostname(normalized[0] if normalized else "")
                if ENVIRONMENT_SCOPE == "air" and not row_is_air:
                    continue
                if ENVIRONMENT_SCOPE == "prod" and row_is_air:
                    continue
                key = tuple(normalized[:key_cols])
                previous = data.get(key)
                # 损坏快照可能重复同一端口；保留字段最完整的一条，避免后续
                # 残缺行覆盖前面已经取得的BER和计数器数据。
                if previous is None or sum(bool(v) for v in normalized[2:]) > sum(
                    bool(v) for v in previous[2:]
                ):
                    data[key] = normalized
    return headers, data


def find_closest(snaps, target: datetime, tol: timedelta = timedelta(minutes=45)):
    best_ts, best_data, best_d = None, None, tol + timedelta(seconds=1)
    for ts, _, data in snaps:
        d = abs(ts - target)
        if d < best_d:
            best_d, best_ts, best_data = d, ts, data
    return best_ts, best_data


def get_inc(old, cur, col_idx):
    if old is None:
        return None
    ov = old[col_idx] if col_idx < len(old) else ""
    nv = cur[col_idx] if col_idx < len(cur) else ""
    try:
        return float(nv) - float(ov)
    except (ValueError, TypeError):
        return f"{ov}→{nv}" if ov != nv else 0


def nat_key(k: tuple) -> list:
    def _nat(s: str) -> list:
        return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", s)]
    return [_nat(p) for p in k]


def build_link_content(snaps, headers, latest, latest_ts,
                       diff_hours, watch_fields, transceiver_temps=None,
                       show_transceiver_temp=True):
    """返回 (thead_html, tbody_html, stats)。通用于 SPX 和 IB link。"""
    transceiver_temps = transceiver_temps or {}
    if len(headers) < 2:
        empty_tbody = '<tr><td colspan="1" style="padding:20px;text-align:center;color:#6c757d">最新快照为空，无法解析表头。</td></tr>'
        return "<tr><th>（空快照）</th></tr>", empty_tbody, {"changed": 0, "new": 0, "removed": 0, "same": 0}, []
    key_cols = 2
    # 确定历史参考点
    hist = []
    for h in diff_hours:
        ts, data = find_closest(snaps, latest_ts - timedelta(hours=h))
        hist.append((h, ts, data))

    all_keys: set[tuple] = set(latest.keys())
    for _, _, d in snaps:
        if d:
            all_keys.update(d.keys())
    sorted_keys = sorted(
        all_keys,
        key=lambda key: (0 if is_air_hostname(key[0]) else 1, nat_key(key)),
    )

    # 状态和对端信息紧跟Interface，其他指标保持原始CSV顺序。
    priority_headers = ("Oper-Status", "State", "Peer", "Peer-Interface")
    priority_indexes = [headers.index(h) for h in priority_headers if h in headers]
    remaining_indexes = [
        i for i in range(key_cols, len(headers)) if i not in priority_indexes
    ]
    data_indexes = priority_indexes + remaining_indexes
    data_hdrs = [headers[i] for i in data_indexes]
    wf_present = [f for f in watch_fields if f in headers]
    wf_idx = {f: headers.index(f) for f in wf_present}
    n_wf = len(wf_present)
    state_idx = next(
        (headers.index(name) for name in ("Oper-Status", "State") if name in headers),
        None,
    )

    # ── 表头 ─────────────────────────────────────────────────────────────────
    extra_key_cols = 1 if show_transceiver_temp else 0
    temp_th = (
        '<th rowspan="2" class="sc" onclick="srt(this,1)">Transceiver Temp</th>'
        if show_transceiver_temp else ""
    )
    key_ths = (
        f'<th rowspan="2" class="sc" onclick="srt(this,0)">{escape(headers[0])}</th>'
        f'{temp_th}'
        f'<th rowspan="2" class="sc" onclick="srt(this,{1 + extra_key_cols})">'
        f'{escape(headers[1])}</th>'
    )
    data_ths = "".join(
        f'<th rowspan="2" class="sc{"  wf-th" if h in watch_fields else ""}" '
        f'onclick="srt(this,{key_cols+extra_key_cols+i})">{escape(h)}</th>'
        for i, h in enumerate(data_hdrs)
    )
    time_ths = "".join(
        f'<th class="diff-th" colspan="{n_wf}">'
        f'{_diff_label(h)}:&nbsp;<small>'
        f'{"From " + ts.strftime("%Y/%m/%d %H:%M:%S") if ts else "From n/a"}'
        f'</small></th>'
        for h, ts, _ in hist
    )
    short = {
        "Effective-Error":     "Eff-Err",
        "Carrier-Transitions": "Carrier",
        "ECN-Marked":          "ECN",
        "PFC-Receive":         "PFC-Rx",
        "PFC-Send":            "PFC-Tx",
        "Carrier-Down-Count":  "Carrier↓",
        "QP1-Drops-Receive":   "QP1-Rx",
        "QP1-Drops-Transmit":  "QP1-Tx",
    }
    sub_ths = "".join(
        f'<th class="diff-sub" title="{escape(wf)}">{escape(short.get(wf, wf))}</th>'
        for _ in hist for wf in wf_present
    )
    thead_html = f"<tr>{key_ths}{data_ths}{time_ths}</tr><tr>{sub_ths}</tr>"

    # ── 数据行：可能含 AIR 的 Ethernet/SPX 表统一先按环境分组 ────────────────
    rows: list[str] = []
    stats = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    prev_dev = None
    prev_environment = None
    environment_device_counts = {
        environment: len({key[0] for key in sorted_keys if (
            "air" if is_air_hostname(key[0]) else "production"
        ) == environment})
        for environment in ("air", "production")
    }
    environment_colspan = (
        key_cols + extra_key_cols + len(data_hdrs) + len(diff_hours) * n_wf
    )
    if environment_device_counts["air"] == 0:
        rows.append(
            f'<tr class="link-env" data-environment="air">'
            f'<td colspan="{environment_colspan}">AIR（0 台）</td></tr>'
        )

    for key in sorted_keys:
        cur   = latest.get(key)
        alive = cur is not None
        dev, port = key[0], key[1]
        environment = "air" if is_air_hostname(dev) else "production"

        if environment != prev_environment:
            rows.append(
                f'<tr class="link-env" data-environment="{environment}">'
                f'<td colspan="{environment_colspan}">'
                f'{"AIR" if environment == "air" else "Production"}'
                f'（{environment_device_counts[environment]} 台）</td></tr>'
            )
            prev_environment = environment
            prev_dev = None

        if dev != prev_dev:
            ncol = key_cols + extra_key_cols + len(data_hdrs) + len(diff_hours) * n_wf
            rows.append(
                f'<tr class="grp" data-environment="{environment}" data-dev="{escape(dev)}">'
                f'<td colspan="{ncol}">{escape(dev)}</td></tr>'
            )
            prev_dev = dev

        temp_td = ""
        if show_transceiver_temp:
            reading = transceiver_reading_for_interface(dev, port, transceiver_temps)
            if reading is None:
                temp_td = '<td class="c-temp temp-na">—</td>'
            else:
                module_temp, high_threshold = reading
                temp_text = f"{module_temp:.0f}°C"
                if high_threshold is None:
                    temp_td = (
                        f'<td class="c-temp temp-no-threshold" '
                        f'title="High alarm threshold unavailable">{temp_text}</td>'
                    )
                else:
                    temp_class = "temp-alarm" if module_temp >= high_threshold else "temp-ok"
                    temp_td = (
                        f'<td class="c-temp {temp_class}" '
                        f'title="High alarm threshold: {high_threshold:.0f}°C">'
                        f'{temp_text}</td>'
                    )
        key_tds = (
            f'<td class="c-dev">{escape(dev)}</td>'
            f'{temp_td}'
            f'<td class="c-port">{escape(port)}</td>'
        )
        if alive:
            data_tds = "".join(
                f"<td>{escape(format_link_value(headers[i], cur[i] if i < len(cur) else ''))}</td>"
                for i in data_indexes
            )
        else:
            data_tds = "".join('<td class="na">—</td>' for _ in data_hdrs)

        diff_tds: list[str] = []
        row_changed = False

        for h, h_ts, h_data in hist:
            old = h_data.get(key) if h_data is not None else None
            for wf in wf_present:
                if h_data is None:
                    diff_tds.append('<td class="inc-na">n/a</td>')
                    continue
                if not alive:
                    diff_tds.append(
                        '<td class="inc-rm">DEL</td>' if old is not None
                        else '<td class="inc-zero">—</td>'
                    )
                    if old is not None:
                        row_changed = True
                    continue
                if old is None:
                    diff_tds.append('<td class="inc-new">NEW</td>')
                    row_changed = True
                    continue
                inc = get_inc(old, cur, wf_idx[wf])
                if inc is None or inc == 0:
                    diff_tds.append('<td class="inc-zero">—</td>')
                elif isinstance(inc, str):
                    diff_tds.append(f'<td class="inc-txt">{escape(inc)}</td>')
                    row_changed = True
                elif inc > 0:
                    disp = f"+{int(inc)}" if inc == int(inc) else f"+{inc:.4g}"
                    diff_tds.append(f'<td class="inc-pos">{disp}</td>')
                    row_changed = True
                else:
                    disp = f"{int(inc)}" if inc == int(inc) else f"{inc:.4g}"
                    diff_tds.append(f'<td class="inc-neg">{disp}</td>')
                    row_changed = True

        if not alive:
            row_cls = "r-rm"
            stats["removed"] += 1
        elif row_changed:
            row_cls = "r-chg"
            stats["changed"] += 1
        else:
            row_cls = ""
            stats["same"] += 1

        rows.append(
            f'<tr class="{row_cls}" data-environment="{environment}" '
            f'data-dev="{escape(dev)}" data-port="{escape(port)}" '
            f'data-state="{escape(cur[state_idx].strip().lower() if alive and state_idx is not None and state_idx < len(cur) else "")}">'
            f"{key_tds}{data_tds}{''.join(diff_tds)}</tr>"
        )

    if environment_device_counts["production"] == 0:
        rows.append(
            f'<tr class="link-env" data-environment="production">'
            f'<td colspan="{environment_colspan}">Production（0 台）</td></tr>'
        )

    return thead_html, "".join(rows), stats, hist


# ══════════════════════════════════════════════════════════════════════════════
# HTML 生成
# ══════════════════════════════════════════════════════════════════════════════

def build_html(
    eth_cards: dict,
    eth_source: str,
    eth_count: int,
    ib_cards: str,
    ib_source: str,
    ib_count: int,
    eth_list: dict,
    ib_list: str,
    spx_thead: str,
    spx_tbody: str,
    spx_stats: dict,
    spx_latest_ts: Optional[datetime],
    spx_snap_count: int,
    ibl_thead: str,
    ibl_tbody: str,
    ibl_stats: dict,
    ibl_latest_ts: Optional[datetime],
    ibl_snap_count: int,
    nv_cards: str,
    nv_source: str,
    nv_count: int,
    nv_list: str,
    nvl_thead: str,
    nvl_tbody: str,
    nvl_stats: dict,
    nvl_latest_ts: Optional[datetime],
    nvl_snap_count: int,
    ethernet_topology: dict,
    infiniband_topology: dict,
    ethernet_diagram: dict,
    air_diagram: dict,
    ztp_status: dict,
) -> str:
    gen_time      = datetime.now(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M:%S")
    spx_ts_str    = spx_latest_ts.strftime("%Y-%m-%d %H:%M") if spx_latest_ts else "—"
    ibl_ts_str    = ibl_latest_ts.strftime("%Y-%m-%d %H:%M") if ibl_latest_ts else "—"
    spx_diff_opts = "".join(f'<option value="{h}">{_diff_label(h)}</option>' for h in SPX_DIFF_HOURS)
    ibl_diff_opts = "".join(f'<option value="{h}">{_diff_label(h)}</option>' for h in IBL_DIFF_HOURS)
    nvl_diff_opts = "".join(f'<option value="{h}">{_diff_label(h)}</option>' for h in NVL_DIFF_HOURS)
    nvl_ts_str    = nvl_latest_ts.strftime("%Y-%m-%d %H:%M") if nvl_latest_ts else "—"
    ethernet_topology_panel = render_topology_panel(
        ethernet_topology,
        "etop",
        "Ethernet",
        hidden_headers=("B Oper", "B Remote Host", "B Remote Port"),
    )
    infiniband_topology_panel = render_topology_panel(
        infiniband_topology, "itop", "InfiniBand"
    )
    ethernet_diagram_panel = render_diagram_panel(
        ethernet_diagram, "p2p", "最新 Ethernet 拓扑图", "*-lldpq.html"
    )
    air_diagram_panel = render_diagram_panel(
        air_diagram, "air", "最新 AIR 拓扑图", "*-air.html"
    )
    ztp_rows = render_ztp_status_rows(ztp_status)
    ztp_counts = ztp_status.get("counts", {})
    ztp_summary = " · ".join(
        f"{label} {ztp_counts.get(name, 0)}"
        for name, label in (("success", "成功"), ("running", "进行中"),
                            ("warning", "警告"), ("failed", "失败"),
                            ("pending", "等待"))
    )
    ztp_update_summary = " · ".join(
        f"{label}: {format_ztp_write_time(ztp_status.get('environment_updates', {}).get(environment))}"
        for environment, label in ZTP_ENVIRONMENTS
    )
    switch_list_headers = (
        "<th>主机名</th><th>SN</th><th>型号</th><th>SW 版本</th>"
        "<th>BIOS 版本</th><th>SSD 版本</th><th>ASIC 版本</th>"
        "<th>ASIC 温度</th><th>PSU 温度</th>"
        "<th>PSU</th><th>FAN</th><th>CPU Use</th><th>Disk Use</th><th>Mem Use</th>"
        "<th>NTP Sync</th><th>接口</th><th>BGP</th>"
        "<th>EVPN/MLAG Bond</th><th>健康</th>"
        "<th>Uptime</th><th>采集</th>"
    )
    # 卡片视图始终显示三类设备的分组行头；没有采集数据时明确显示 (0)，
    # 但不在分组下面渲染占位卡片或提示文本。
    section_attrs = (
        'role="button" tabindex="0" aria-expanded="true" '
        'onclick="toggleCardSection(this)" '
        'onkeydown="handleCardSectionKey(event, this)"'
    )
    air_eth_count = int(eth_cards.get("air_count", 0))
    production_eth_count = int(eth_cards.get("production_count", 0))
    air_unbound_count = int(eth_cards.get("unbound_air_count", 0))
    production_unbound_count = int(
        eth_cards.get("unbound_production_count", 0)
    )
    unknown_eth_count = int(eth_cards.get("unknown_count", 0))
    unknown_unbound_count = int(eth_cards.get("unbound_unknown_count", 0))
    air_count = air_eth_count + air_unbound_count
    production_count = (
        production_eth_count + ib_count + nv_count + production_unbound_count
    )
    unknown_count = unknown_eth_count + unknown_unbound_count

    def card_switch_section(label: str, count: int, content: str, cls: str = "") -> str:
        return (
            f'<div class="section-divider {cls}" {section_attrs}>{label} ({count})</div>'
            f'{content}'
        )

    def card_environment(environment: str, label: str, count: int, content: str) -> str:
        return (
            f'<section class="card-env-group" data-environment="{environment}">'
            f'<div class="card-env" data-environment="{environment}" role="button" '
            f'tabindex="0" aria-expanded="true" onclick="toggleCardEnvironment(this)" '
            f'onkeydown="handleCardEnvironmentKey(event, this)">{label}（{count}）</div>'
            f'<div class="card-env-content">{content}</div></section>'
        )

    switch_cards_html = (
        card_environment(
            "air", "AIR", air_count,
            card_switch_section(
                "Ethernet Switches", air_eth_count, str(eth_cards.get("air", "")),
            )
            + card_switch_section(
                "未绑定 / 未分类设备（其他）", air_unbound_count,
                str(eth_cards.get("unbound_air", "")),
            ),
        )
        + card_environment(
            "production", "Production", production_count,
            card_switch_section(
                "Ethernet Switches", production_eth_count,
                str(eth_cards.get("production", "")),
            )
            + card_switch_section("InfiniBand Switches", ib_count, ib_cards, "ib-divider")
            + card_switch_section("NVLink Switches", nv_count, nv_cards, "nv-divider")
            + card_switch_section(
                "未绑定 / 未分类设备（其他）",
                production_unbound_count,
                str(eth_cards.get("unbound_production", "")),
            ),
        )
        + card_environment(
            "unknown", "Unknown / 未归类", unknown_count,
            card_switch_section(
                "Ethernet Switches", unknown_eth_count,
                str(eth_cards.get("unknown", "")),
            )
            + card_switch_section(
                "未绑定 / 未归类设备（其他）", unknown_unbound_count,
                str(eth_cards.get("unbound_unknown", "")),
            ),
        )
    )

    list_environment_attrs = (
        'role="button" tabindex="0" aria-expanded="true" '
        'onclick="toggleListEnvironment(this)" '
        'onkeydown="handleListEnvironmentKey(event, this)"'
    )

    def list_switch_section(label: str, count: int, content: str, cls: str = "") -> str:
        repeat = (
            f'<tr class="lst-repeat-head">{switch_list_headers}</tr>'
            if content else ""
        )
        return (
            f'<tr class="lst-sec {cls}" role="button" tabindex="0" '
            f'aria-expanded="true" onclick="toggleListSwitchType(this)" '
            f'onkeydown="handleListSwitchTypeKey(event, this)">'
            f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">{label} ({count})</td></tr>{repeat}{content}'
        )

    switch_list_html = (
        f'<tr class="lst-env" data-environment="air" {list_environment_attrs}>'
        f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">AIR（{air_count}）</td></tr>'
        + list_switch_section(
            "ETHERNET SWITCHES", air_eth_count, str(eth_list.get("air", "")),
        )
        + list_switch_section(
            "未绑定 / 未分类设备（其他）", air_unbound_count,
            str(eth_list.get("unbound_air", "")),
        )
        + f'<tr class="lst-env" data-environment="production" {list_environment_attrs}>'
        f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">Production（{production_count}）</td></tr>'
        + list_switch_section(
            "ETHERNET SWITCHES", production_eth_count,
            str(eth_list.get("production", "")),
        )
        + list_switch_section("INFINIBAND SWITCHES", ib_count, ib_list, "lst-sec-ib")
        + list_switch_section("NVLINK SWITCHES", nv_count, nv_list, "lst-sec-nv")
        + list_switch_section(
            "未绑定 / 未分类设备（其他）",
            production_unbound_count,
            str(eth_list.get("unbound_production", "")),
        )
        + f'<tr class="lst-env" data-environment="unknown" {list_environment_attrs}>'
        f'<td colspan="{SWITCH_LIST_COLUMN_COUNT}">Unknown / 未归类（{unknown_count}）</td></tr>'
        + list_switch_section(
            "ETHERNET SWITCHES", unknown_eth_count,
            str(eth_list.get("unknown", "")),
        )
        + list_switch_section(
            "未绑定 / 未分类设备（其他）", unknown_unbound_count,
            str(eth_list.get("unbound_unknown", "")),
        )
    )
    def auto_refresh_control(tab: str) -> str:
        return f"""
    <label class="auto-refresh" data-refresh-tab="{tab}"
           title="单独控制当前页面的自动刷新">
      <input class="auto-refresh-toggle" type="checkbox">
      <span>Auto-Refresh</span>
      <input class="auto-refresh-seconds" type="number" min="2" max="3600"
             step="1" value="15" aria-label="自动刷新间隔（秒）">
      <span>s</span>
      <span class="auto-refresh-countdown" aria-live="polite"></span>
    </label>
    """

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Network Monitor Dashboard</title>
<style>
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
  --bg:       #f0f2f5;
  --hdr-bg:   #1a2535;
  --accent:   #3b7dd8;
  --border:   #dde1e7;
  --th-bg:    #263548;
  --th-fg:    #e8edf3;
  --grp-bg:   #dde4ee;
  --chg-bg:   #fff8e1; --chg-fg: #7a5500;
  --new-bg:   #e8f5e9; --new-fg: #1b5e20;
  --rm-bg:    #fdecea; --rm-fg:  #7f1d1d;
  --font:     'Segoe UI', system-ui, -apple-system, sans-serif;
}}
body {{
  font-family: var(--font);
  background: var(--bg);
  color: #212529;
  display: flex;
  flex-direction: column;
  height: 100vh;
  overflow: hidden;
}}
/* ── 顶栏 ── */
#topbar {{
  background: var(--hdr-bg);
  color: #e8edf3;
  padding: 11px 20px;
  display: flex;
  align-items: center;
  gap: 16px;
  flex-shrink: 0;
  flex-wrap: wrap;
}}
#topbar h1 {{ font-size: 16px; font-weight: 700; letter-spacing: .02em; }}
#topbar .meta {{ font-size: 11px; color: #6d9ed4; flex: 1; }}
.auto-refresh {{
  display:inline-flex; align-items:center; gap:6px; padding:4px 8px;
  border:1px solid #c7d0db; border-radius:5px; background:#f8fafc;
  color:#40505f; font-size:12px; font-weight:600; white-space:nowrap;
}}
.auto-refresh-toggle {{ width:15px; height:15px; accent-color:var(--accent); cursor:pointer; }}
.auto-refresh-seconds {{
  width:58px !important; min-width:58px !important; padding:3px 5px !important;
  border:1px solid #aeb9c6 !important; border-radius:4px; font-size:12px;
}}
.auto-refresh-countdown {{ min-width:34px; color:#64748b; font-weight:500; }}
/* ── 选项卡 ── */
#tabs {{
  background: #fff;
  border-bottom: 1px solid var(--border);
  display: flex;
  flex-shrink: 0;
  overflow-x: auto;
}}
.tab {{
  padding: 10px 24px;
  border: none;
  border-bottom: 3px solid transparent;
  background: none;
  cursor: pointer;
  font-size: 14px;
  font-weight: 600;
  color: #6c757d;
  transition: color .12s;
}}
.tab.active {{ color: var(--accent); border-bottom-color: var(--accent); }}
.tab:hover  {{ color: var(--accent); }}
/* ── 面板容器 ── */
.panel {{ display: none; flex: 1; flex-direction: column; overflow: hidden; }}
.panel.active {{ display: flex; }}
/* ═══════ Tab 1: 交换机状态 ═══════ */
#eth-toolbar {{
  background: #fff;
  border-bottom: 1px solid var(--border);
  padding: 9px 18px;
  display: flex;
  align-items: center;
  gap: 12px;
  flex-shrink: 0;
}}
#eth-toolbar .eth-meta {{ font-size: 12px; color: #6c757d; flex: 1; }}
#eth-search {{
  padding: 5px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 13px;
  width: 220px;
}}
#eth-search:focus {{ outline: none; border-color: var(--accent); }}
#card-grid {{
  flex: 1;
  overflow-y: auto;
  padding: 16px 20px;
  display: flex;
  flex-wrap: wrap;
  gap: 16px;
  align-content: flex-start;
}}
.section-divider {{
  width: 100%;
  padding: 6px 2px 4px;
  font-size: 11px;
  font-weight: 700;
  color: #5a6472;
  text-transform: uppercase;
  letter-spacing: .1em;
  border-bottom: 2px solid #c8d0dc;
  cursor: pointer;
  user-select: none;
}}
.section-divider::before {{ content: '▾'; display: inline-block; width: 16px; }}
.section-divider.collapsed::before {{ content: '▸'; }}
.section-divider:focus {{ outline: 2px solid var(--accent); outline-offset: 2px; }}
.section-hidden {{ display: none !important; }}
.ib-divider {{ color: #6b3e9e; border-color: #c4a8e0; margin-top: 12px; }}
.nv-divider {{ color: #1a7a4a; border-color: #88c9a8; margin-top: 12px; }}
.card-cat {{
  width: 100%;
  margin-top: 2px;
  padding: 5px 10px;
  background: #e8ecf1;
  border-left: 3px solid #8a99ab;
  color: #4a5568;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .06em;
  text-transform: uppercase;
  cursor: pointer;
  user-select: none;
}}
.card-env {{
  background:#263548; color:#fff; border-left:5px solid #3b7dd8;
  padding:9px 12px; font-size:14px; font-weight:800; cursor:pointer;
  user-select:none;
}}
.card-env::before {{ content:'▾'; display:inline-block; width:18px; color:#c8d5e3; }}
.card-env.collapsed::before {{ content:'▸'; }}
.card-env:focus {{ outline:2px solid var(--accent); outline-offset:1px; }}
.card-env-group {{ width:100%; min-width:0; margin-top:8px; }}
.card-env-content {{
  display:flex; flex-wrap:wrap; gap:16px; align-content:flex-start; padding-top:10px;
}}
.card-env-content.env-collapsed {{ display:none; }}
.lst-env td {{
  background:#263548 !important; color:#fff !important; font-size:14px;
  font-weight:800 !important; border-left:5px solid #3b7dd8; cursor:pointer;
}}
.lst-env td::before {{ content:'▾'; display:inline-block; width:18px; color:#c8d5e3; }}
.lst-env.collapsed td::before {{ content:'▸'; }}
.lst-env:focus {{ outline:2px solid var(--accent); outline-offset:-2px; }}
.lst-env-hidden {{ display:none !important; }}
.card-cat::before {{ content: '▾'; display: inline-block; width: 16px; }}
.card-cat.collapsed::before {{ content: '▸'; }}
.card-cat:focus {{ outline: 2px solid var(--accent); outline-offset: 1px; }}
.card-cat-miss {{ background: #fff0f0; border-color: #e74c3c; color: #9b2335; }}
.card-cat-hidden {{ display: none !important; }}
.card-role {{
  width: 100%;
  margin: 0 0 -6px 14px;
  padding: 3px 10px;
  border-left: 3px solid #b7c3d1;
  color: #657184;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: .04em;
}}
.card-role.card-cat-hidden {{ display: none !important; }}
.sw-card {{
  background: #fff;
  border: 1px solid var(--border);
  border-radius: 8px;
  width: clamp(320px, calc(var(--hostname-ch, 16) * 9px + 170px), 520px);
  max-width: calc(100vw - 40px);
  box-sizing: border-box;
  box-shadow: 0 1px 4px rgba(0,0,0,.06);
  overflow: hidden;
}}
.sw-card.hidden {{ display: none; }}
.sw-hdr {{
  background: var(--hdr-bg);
  color: #e8edf3;
  padding: 10px 14px;
  display: flex;
  align-items: flex-start;
  justify-content: space-between;
  gap: 10px;
}}
.sw-hdr-ib {{ background: #4a2870; }}
.sw-hdr-nv {{ background: #0d5c35; }}
.sw-name {{
  font-size: 14px;
  font-weight: 700;
  line-height: 20px;
  min-width: 0;
  flex: 1 1 auto;
  white-space: nowrap;
}}
.sw-hdr-meta {{
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 7px;
  flex-shrink: 0;
  margin-left: auto;
}}
.sw-type-tag {{
  font-size: 10px;
  background: rgba(255,255,255,.15);
  border-radius: 4px;
  padding: 1px 6px;
  letter-spacing: .04em;
}}
.h-badge {{
  font-size: 10px;
  font-weight: 700;
  padding: 2px 7px;
  border-radius: 4px;
  letter-spacing: .04em;
}}
.h-ok   {{ background: #27ae60; color: #fff; }}
.h-err  {{ background: #e74c3c; color: #fff; }}
.h-warn {{ background: #f39c12; color: #fff; }}
.h-unk  {{ background: #95a5a6; color: #fff; }}
.h-miss {{ background: #7f1d1d; color: #fca5a5; }}
.sw-card-miss {{ border: 2px solid #e74c3c; box-shadow: 0 0 8px rgba(231,76,60,.25); }}
.sw-miss-body {{
  padding: 24px 14px;
  text-align: center;
  background: #fff5f5;
  color: #9b2335;
  font-weight: 600;
  font-size: 13px;
}}
.miss-warn {{ font-size: 28px; color: #e74c3c; margin-bottom: 6px; }}
.miss-sub  {{ font-size: 11px; color: #c0392b; margin-top: 4px; font-weight: 400; }}
.collect-cell {{ min-width: 180px; white-space: normal !important; }}
.collect-result {{ display:inline-block; font-weight:700; border-radius:4px; padding:2px 7px; }}
.collect-ok {{ color:#176b39; background:#dcfce7; border:1px solid #86d6a2; }}
.collect-fail {{ color:#a31515; background:#fee2e2; border:1px solid #ef9a9a; }}
.collect-pending {{ color:#805800; background:#fff0c2; border:1px solid #e2c35d; }}
.collect-reason {{ display:block; margin-top:4px; color:#a31515; font-size:11px; line-height:1.35; }}
.sw-body {{ padding: 10px 14px; }}
.sw-r {{
  display: flex;
  align-items: baseline;
  padding: 4px 0;
  border-bottom: 1px solid #f0f2f5;
  font-size: 13px;
  gap: 6px;
}}
.sw-r-last {{ border-bottom: none; }}
.sw-k {{ font-size: 11px; color: #6c757d; min-width: 72px; flex-shrink: 0; }}
.sw-ver {{ font-family: monospace; font-size: 12px; }}
.sw-time {{ font-size: 11px; color: #6c757d; }}
.t-ok   {{ color: #27ae60; }}
.t-warn {{ color: #d4860a; font-weight: 600; }}
.t-crit {{ color: #c0392b; font-weight: 700; }}
.use-ok   {{ color: #27ae60; font-weight: 600; }}
.use-warn {{ color: #9a6700; font-weight: 600; }}
.use-crit {{ color: #c0392b; font-weight: 700; }}
.disk-use-item {{ display: inline-block; margin-right: 4px; }}
.i-ok   {{ color: #27ae60; }}
.i-warn {{ color: #e67e22; font-weight: 600; }}
.i-down {{ color: #e74c3c; font-size: 12px; cursor: help; }}
/* ── 视图切换 ── */
.view-toggle {{ display: flex; gap: 4px; }}
.vtbtn {{
  padding: 4px 12px; border: 1px solid var(--border); border-radius: 4px;
  background: #fff; cursor: pointer; font-size: 13px; color: #6c757d;
}}
.vtbtn.active {{ background: var(--accent); color: #fff; border-color: var(--accent); }}
/* ── 列表视图 ── */
#list-view {{ flex: 1; overflow: auto; }}
.lst-tbl {{ border-collapse: collapse; font-size: 13px; white-space: nowrap; }}
.lst-tbl tr.lst-repeat-head th {{
  background: var(--th-bg); color: var(--th-fg);
  padding: 8px 12px; text-align: center; white-space: nowrap;
  border-right: 1px solid #3a4f63;
  position: relative;
  z-index: 1;
  border-top: 1px solid #3a4f63;
  border-bottom: 1px solid #3a4f63;
}}
.lst-tbl tr.lst-sec td {{
  background: #1e2d3e; color: #8fb0d0; font-weight: 700;
  font-size: 11px; letter-spacing: .1em; text-transform: uppercase;
  padding: 8px 12px; border-bottom: 2px solid #c8d0dc;
  cursor:pointer; user-select:none;
}}
.lst-tbl tr.lst-sec td::before {{ content:'▾'; display:inline-block; width:16px; }}
.lst-tbl tr.lst-sec.collapsed td::before {{ content:'▸'; }}
.lst-switch-hidden {{ display:none !important; }}
.lst-tbl tr.lst-sec-ib td {{ background: #2d1654; color: #c4a8e0; border-color: #c4a8e0; }}
.lst-tbl tr.lst-sec-nv td {{ background: #0a3320; color: #88c9a8; border-color: #88c9a8; }}
.lst-tbl tr.lst-sec-ib td,
.lst-tbl tr.lst-sec-nv td {{ border-top: 10px solid var(--bg); }}
.lst-tbl tr.lst-cat-miss td {{
  background: #3d0e0e; color: #fca5a5;
  font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
  padding: 5px 12px 4px; border-bottom: 1px solid #e74c3c;
}}
.lst-tbl tr.lst-cat-miss td::before {{ content: '&#9888; '; }}
.lst-tbl tr.lst-row-miss td {{ background: #fff5f5 !important; color: #9b2335; }}
.lst-tbl tr.lst-cat {{
  cursor: pointer; user-select: none;
}}
.lst-tbl tr.lst-cat td {{
  background: #e8ecf1; color: #4a5568; font-weight: 700;
  font-size: 11px; letter-spacing: .06em; text-transform: uppercase;
  padding: 5px 12px 4px; border-bottom: 1px solid #c8d0dc;
}}
.lst-tbl tr.lst-cat td::before {{ content: '▾ '; font-size: 10px; }}
.lst-tbl tr.lst-cat.collapsed td::before {{ content: '▸ '; }}
.lst-tbl tr.lst-role td {{
  background: #f3f5f8; color: #657184; font-weight: 700;
  font-size: 11px; letter-spacing: .04em;
  padding: 4px 12px 3px 26px; border-bottom: 1px solid #dde3ea;
}}
.lst-tbl tr.lst-row td {{
  padding: 6px 12px; border-bottom: 1px solid #eee; white-space: nowrap;
  text-align: center;
}}
.lst-tbl tr.lst-row:nth-child(even) td {{ background: #f8f9fa; }}
.lst-tbl tr.lst-row:hover td {{ background: #e9ecef; }}
.lst-hn  {{ font-weight: 600; font-family: monospace; font-size: 12px; }}
.lst-model {{ white-space: nowrap; }}
.lst-asic  {{ font-size: 11px; color: #6c757d; }}
.lst-num   {{ text-align: center; white-space: nowrap; }}
tr.lst-row.hidden   {{ display: none; }}
tr.lst-cat.hidden   {{ display: none; }}
tr.lst-role.hidden  {{ display: none; }}
tr.lst-role.cat-hidden {{ display: none; }}
tr.lst-row.cat-hidden {{ display: none; }}
/* ═══════ Tab 2/3: 链路监控（共用） ═══════ */
.link-topbar {{
  background: var(--hdr-bg);
  color: #e8edf3;
  padding: 8px 18px;
  display: flex;
  align-items: center;
  gap: 14px;
  flex-shrink: 0;
  flex-wrap: wrap;
}}
.link-topbar .link-meta {{ font-size: 11px; color: #6d9ed4; flex: 1; }}
.bdg {{
  padding: 2px 10px;
  border-radius: 10px;
  font-size: 12px;
  font-weight: 600;
  cursor: pointer;
  white-space: nowrap;
}}
.bdg-chg  {{ background: var(--chg-bg); color: var(--chg-fg); }}
.bdg-new  {{ background: var(--new-bg); color: var(--new-fg); }}
.bdg-rm   {{ background: var(--rm-bg);  color: var(--rm-fg);  }}
.bdg-same {{ background: #e2e3e5;       color: #383d41; }}
.bdg.active {{ outline: 2px solid #fff; outline-offset: 1px; }}
.link-toolbar {{
  background: #fff;
  border-bottom: 1px solid var(--border);
  padding: 8px 16px;
  display: flex;
  align-items: center;
  gap: 10px;
  flex-shrink: 0;
  flex-wrap: wrap;
}}
.link-toolbar label {{ font-size: 13px; }}
.link-search {{
  padding: 5px 10px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 13px;
  width: 210px;
}}
.link-search:focus {{ outline: none; border-color: var(--accent); }}
select {{
  padding: 5px 8px;
  border: 1px solid var(--border);
  border-radius: 4px;
  font-size: 13px;
}}
.row-info {{ font-size: 12px; color: #6c757d; margin-left: auto; }}
.dl-btn {{
  padding: 5px 12px;
  border: none;
  border-radius: 4px;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
  background: var(--accent);
  color: #fff;
}}
.dl-btn:hover {{ background: #2d66b8; }}
.down-btn {{
  padding: 5px 12px;
  border: 1px solid #dc3545;
  border-radius: 4px;
  background: #fff;
  color: #b42332;
  font-size: 13px;
  font-weight: 600;
  cursor: pointer;
}}
.down-btn:hover {{ background: #fff1f2; }}
.down-btn.active {{ background: #dc3545; color: #fff; }}
.link-wrap {{ flex: 1; overflow: auto; }}
.link-tbl {{
  width: max-content;
  table-layout: auto;
  border-collapse: collapse;
  font-size: 13px;
}}
.link-tbl thead th {{
  position: sticky;
  background: var(--th-bg);
  color: var(--th-fg);
  padding: 7px 10px;
  text-align: center;
  white-space: nowrap;
  border-right: 1px solid #3a4f63;
  cursor: pointer;
  user-select: none;
  z-index: 2;
}}
.col-resizer {{
  position: absolute;
  top: 0;
  right: -3px;
  width: 7px;
  height: 100%;
  cursor: col-resize;
  z-index: 8;
  touch-action: none;
}}
.col-resizer:hover, body.col-resizing .col-resizer {{
  border-right: 2px solid #69a7ef;
}}
body.col-resizing {{ cursor: col-resize; user-select: none; }}
.link-tbl thead tr:first-child th {{ top: 0;    z-index: 3; height: 36px; }}
.link-tbl thead tr:last-child  th {{ top: 36px; z-index: 2; font-size: 11px; font-weight: 500; }}
.link-tbl thead th:hover {{ background: #3a4f63; }}
.link-tbl thead th.sa::after {{ content: ' ▲'; font-size: 9px; }}
.link-tbl thead th.sd::after {{ content: ' ▼'; font-size: 9px; }}
.diff-th  {{ background: #1c2e42 !important; border-right-color: #2c4058 !important;
             text-align: center; font-size: 13px !important; font-weight: 700 !important;
             border-left: 2px solid #3a4f63 !important; }}
.diff-sub {{ background: #1c2e42 !important; color: #8fb0d0 !important;
             font-size: 11px !important; border-left: 1px solid #2c4058 !important; }}
.wf-th {{ border-bottom: 3px solid #f0c040; }}
tr.grp td {{
  background: var(--grp-bg);
  font-weight: 700;
  font-size: 13px;
  padding: 5px 10px;
  text-align: left;
  cursor: pointer;
  letter-spacing: .02em;
}}
.link-env td {{
  background:#263548 !important; color:#fff; font-size:14px; font-weight:800;
  border-left:5px solid #3b7dd8; padding:8px 10px !important;
}}
tr.grp td::before {{ content: '▾ '; font-size: 11px; }}
tr.grp.collapsed td::before {{ content: '▸ '; }}
.link-tbl tbody tr:not(.grp):nth-child(even) {{ background: #f8f9fa; }}
.link-tbl tbody tr:not(.grp):hover {{ background: #e9ecef; }}
.link-tbl td {{
  padding: 5px 10px;
  border-bottom: 1px solid #eee;
  white-space: nowrap;
  text-align: center;
}}
.c-dev  {{ font-weight: 600; }}
.c-port {{ font-family: monospace; }}
.c-temp {{ font-weight: 700; text-align: center; }}
.temp-ok {{ color: #1b5e20; background: #e8f5e9; }}
.temp-alarm {{ color: #8b0000; background: #ffcdd2; }}
.temp-no-threshold {{ color: #6c757d; }}
.temp-na {{ color: #adb5bd; font-weight: 400; }}
.na     {{ color: #adb5bd; }}
tr.r-chg {{ background: var(--chg-bg) !important; color: var(--chg-fg); }}
tr.r-new {{ background: var(--new-bg) !important; color: var(--new-fg); }}
tr.r-rm  {{ background: var(--rm-bg)  !important; color: var(--rm-fg); opacity:.85; }}
.inc-zero {{ color: #b0b8c1; text-align: center; }}
.inc-pos  {{ background: #fff59d; color: #4a3800; text-align: center;
             font-weight: 600; padding: 4px 6px; }}
.inc-neg  {{ background: #fdecea; color: #7f1d1d; text-align: center;
             font-weight: 600; padding: 4px 6px; }}
.inc-new  {{ background: var(--new-bg); color: var(--new-fg);
             font-weight: 700; text-align: center; }}
.inc-rm   {{ background: var(--rm-bg);  color: var(--rm-fg);
             font-weight: 700; text-align: center; }}
.inc-na   {{ color: #ced4da; text-align: center; }}
.inc-txt  {{ background: #fff8e1; color: #7a5500; font-size: 11px; text-align: center; }}
tr.hidden     {{ display: none; }}
tr.grp-hidden {{ display: none; }}
/* ═══════ Topology Validation ═══════ */
.topo-summary {{
  background: #fff; border-bottom: 1px solid var(--border); padding: 12px 18px;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap; flex-shrink: 0;
}}
.topo-source {{ font-size: 12px; color: #6c757d; flex: 1; min-width: 280px; }}
.topo-environment {{
  background:#263548; color:#fff; border-left:5px solid #3b7dd8;
  padding:10px 14px; margin:12px 0 8px; font-size:15px; font-weight:800;
}}
.topo-result {{ padding: 4px 12px; border-radius: 12px; font-size: 12px; font-weight: 700; }}
.topo-pass {{ background: #dff3e5; color: #176b35; }}
.topo-fail {{ background: #fde2e2; color: #a61b2b; }}
.topo-unknown {{ background: #e9ecef; color: #59636e; }}
.topo-count {{ padding: 3px 10px; border-radius: 10px; font-size: 12px; font-weight: 600; }}
.topo-matching {{ background: #e8f5e9; color: #1b5e20; }}
.topo-miswired {{ background: #fff3cd; color: #7a5500; }}
.topo-missing {{ background: #fdecea; color: #7f1d1d; }}
.topo-undefined {{ background: #e7f1ff; color: #174f8a; }}
.topo-download {{ text-decoration: none; display: inline-block; }}
.topo-toolbar {{
  background: #fff; border-bottom: 1px solid var(--border); padding: 8px 16px;
  display: flex; align-items: center; gap: 12px; flex-wrap: wrap; flex-shrink: 0;
}}
.topo-toolbar label {{ font-size: 13px; }}
.topo-content {{ flex: 1; overflow: auto; padding: 14px 18px 24px; }}
.topo-section {{ margin-bottom: 18px; }}
.topo-section.hidden {{ display: none; }}
.topo-section.collapsed .topo-table-wrap {{ display: none; }}
.topo-section h3 {{
  padding: 7px 10px; background: #dde4ee; color: #394657; font-size: 13px;
  border-left: 4px solid var(--accent); position: sticky; top: 0; z-index: 4;
  cursor: pointer; user-select: none; display: flex; align-items: center; gap: 6px;
}}
.topo-section h3:focus-visible {{ outline: 2px solid var(--accent); outline-offset: -2px; }}
.topo-collapse-icon {{ color: #536273; width: 12px; text-align: center; }}
.topo-section.collapsed .topo-collapse-icon {{ transform: rotate(-90deg); }}
.topo-section-title {{ color: #394657; font-weight: 700; }}
.topo-section-count {{ color: #6c757d; font-weight: 500; margin-left: 2px; }}
.topo-table-wrap {{
  overflow: auto; max-height: 65vh; background: #fff; scrollbar-gutter: stable;
  border: 1px solid #d8dee5; border-top: 0;
}}
.topo-tbl {{ width: max-content; min-width: 100%; border-collapse: collapse; font-size: 12px; }}
.topo-tbl th {{
  position: sticky; top: 0; z-index: 3; background: var(--th-bg); color: var(--th-fg);
  padding: 7px 10px; text-align: center; white-space: nowrap; border-right: 1px solid #3a4f63;
}}
.topo-filter-row th {{
  top: 31px; padding: 4px 6px; background: #3b4f63; z-index: 3;
}}
.topo-col-filter-wrap {{
  display: flex; flex-direction: column; align-items: stretch; gap: 3px;
  width: 116px; margin: 0 auto;
}}
.topo-col-mode {{
  width: 100%; min-width: 0; padding: 3px 4px; border: 1px solid #7c8b99; border-radius: 3px;
  background: #eef3f7; color: #263442; font-size: 10px;
}}
.topo-col-filter {{
  box-sizing: border-box; width: 100%; min-width: 0; max-width: none;
  padding: 4px 6px; border: 1px solid #7c8b99; border-radius: 3px;
  background: #fff; color: #263442; font-size: 11px; font-weight: 400;
}}
.topo-col-filter::placeholder {{ color: #8c969f; }}
.topo-col-filter:focus {{ outline: 2px solid #8ec5ff; border-color: #2d83c5; }}
.topo-col-filter.filter-active, .link-search.filter-active {{
  border-color: #2d83c5; background: #eaf5ff;
}}
.topo-col-filter.filter-invalid, .link-search.filter-invalid {{
  border-color: #dc3545; outline: 2px solid #ffb4bc; background: #fff1f2;
}}
.topo-clear-btn {{
  padding: 5px 10px; border: 1px solid #9aa6b2; border-radius: 4px;
  background: #fff; color: #40505f; cursor: pointer; font-size: 12px;
}}
.topo-clear-btn:hover:not(:disabled) {{ background: #eaf2fa; border-color: #5e8dbb; }}
.topo-clear-btn:disabled {{ opacity: .45; cursor: default; }}
.topo-tbl td {{
  padding: 5px 9px; border-bottom: 1px solid #eee; text-align: center;
  white-space: nowrap; max-width: 620px; overflow-wrap: anywhere;
}}
.topo-tbl td:nth-last-child(2) {{ white-space: normal; text-align: left; }}
.topo-tbl tbody tr:nth-child(even) {{ background: #f8f9fa; }}
.topo-tbl tbody tr:hover {{ background: #e9ecef; }}
.topo-row.hidden {{ display: none; }}
.topo-empty td, .topo-no-match td, .topo-no-data {{
  padding: 24px; text-align: center; color: #6c757d;
}}
/* ═══════ Ethernet / AIR Diagram ═══════ */
.p2p-toolbar {{
  background: #fff; border-bottom: 1px solid var(--border); padding: 9px 16px;
  display: flex; align-items: center; gap: 14px; flex-wrap: wrap; flex-shrink: 0;
  color: #5b6570; font-size: 12px;
}}
.p2p-toolbar span {{ flex: 1; min-width: 280px; }}
.p2p-open {{ text-decoration: none; display: inline-block; }}
.p2p-frame-wrap {{ flex: 1; min-height: 0; background: #08111f; }}
.p2p-frame {{ width: 100%; height: 100%; border: 0; display: block; background: #08111f; }}
.p2p-no-data {{
  height: 100%; display: grid; place-items: center; color: #6c757d; background: #f4f6f8;
}}
/* ═══════ ZTP Status ═══════ */
.ztp-toolbar {{ background:#fff; border-bottom:1px solid var(--border); padding:9px 16px;
  display:flex; align-items:center; gap:16px; flex-wrap:wrap; font-size:12px; color:#5b6570; }}
.ztp-toolbar .ztp-meta {{ flex:1; min-width:360px; }}
.ztp-toolbar input {{ width:280px; padding:6px 9px; border:1px solid #ccd2da; border-radius:4px; }}
.ztp-monitor-control {{ display:flex; align-items:center; gap:7px; }}
.ztp-monitor-control button {{ border:1px solid #8290a3; border-radius:4px; padding:6px 10px;
  background:#fff; color:#26364a; cursor:pointer; font-weight:600; }}
.ztp-monitor-control button.running {{ border-color:#c33; color:#a31515; }}
.ztp-monitor-control button.paused {{ border-color:#27834c; color:#176b39; }}
.ztp-monitor-control button:disabled {{ opacity:.55; cursor:not-allowed; }}
.ztp-monitor-state {{ min-width:64px; font-weight:600; color:#5b6570; }}
.manual-ztp-button {{ border:1px solid #b36b00; border-radius:4px; padding:5px 8px;
  background:#fff8e8; color:#8a4d00; cursor:pointer; font-weight:700; white-space:nowrap; }}
.manual-ztp-button:disabled {{ opacity:.5; cursor:not-allowed; }}
.manual-ztp-button.running {{ background:#fff0c2; }}
.manual-reset-button {{ border:1px solid #9b2c2c; border-radius:4px; padding:5px 8px;
  margin-left:5px; background:#fff1f1; color:#7b1f1f; cursor:pointer; font-weight:700; white-space:nowrap; }}
.manual-reset-button:disabled {{ opacity:.5; cursor:not-allowed; }}
.manual-reset-button.running {{ background:#ffd6d6; }}
.time-sync-button {{ border:1px solid #2672a8; border-radius:4px; padding:5px 8px;
  margin-left:5px; background:#eef7ff; color:#155a8a; cursor:pointer; font-weight:700; white-space:nowrap; }}
.time-sync-button:disabled {{ opacity:.5; cursor:not-allowed; }}
.time-sync-button.running {{ background:#dceeff; }}
.ztp-wrap {{ flex:1; overflow:auto; padding:12px; }}
.ztp-tbl {{ width:100%; border-collapse:collapse; background:#fff; font-size:12px; white-space:nowrap; }}
.ztp-tbl th {{ position:sticky; top:0; z-index:2; background:var(--th-bg); color:var(--th-fg);
  padding:8px 7px; text-align:center; border:1px solid #415066; }}
.ztp-tbl th.ztp-sortable {{ cursor:pointer; user-select:none; padding-right:20px; }}
.ztp-tbl th.ztp-sortable:hover {{ color:var(--accent); }}
.ztp-tbl th.ztp-sortable::after {{ content:'⇅'; position:absolute; right:6px; color:#9aa4ae; }}
.ztp-tbl th.ztp-sortable[aria-sort="ascending"]::after {{ content:'▲'; color:var(--accent); }}
.ztp-tbl th.ztp-sortable[aria-sort="descending"]::after {{ content:'▼'; color:var(--accent); }}
.ztp-tbl td {{ padding:7px; border:1px solid var(--border); text-align:center; vertical-align:middle; }}
.ztp-ip-cell {{ min-width:118px; }}
.ztp-ip {{ display:block; width:max-content; padding:2px 6px; margin:1px auto;
  border-radius:9px; font-weight:700; line-height:1.35; }}
.ztp-ip-success {{ color:#08783e; background:#dff7e9; border:1px solid #a8e3c2; }}
.ztp-ip-dynamic {{ color:#805800; background:#fff0c2; border:1px solid #e2c35d; }}
.ztp-ip-failed {{ color:#b42318; background:#fee4e2; border:1px solid #f5b7b1; }}
.ztp-ip-neutral {{ color:#59636e; background:#eef1f4; border:1px solid #d5dbe1; }}
.ztp-ip-interface {{ font-weight:700; }}
.ztp-tbl tbody tr:nth-child(even) {{ background:#f8f9fa; }}
.ztp-tbl tbody tr:hover {{ background:#eaf2fd; }}
.ztp-tbl .ztp-environment td {{ position:sticky; left:0; background:#26384d; color:#fff;
  padding:10px 9px 10px 30px; font-size:14px; font-weight:750; letter-spacing:.2px;
  border-color:#26384d; cursor:pointer; text-align:left; }}
.ztp-tbl .ztp-environment td::before {{ content:'▾'; position:absolute; left:10px; color:#c8d5e3; }}
.ztp-tbl .ztp-environment.collapsed td::before {{ content:'▸'; }}
.ztp-tbl .ztp-environment td span {{ margin-left:8px; color:#c8d5e3; font-size:11px; font-weight:600; }}
.ztp-tbl .ztp-environment:hover {{ background:transparent; }}
.ztp-tbl .ztp-group td {{ position:sticky; left:0; background:#dfe7f1; color:#26384d;
  padding:8px 10px 8px 42px; font-size:13px; font-weight:700; border-color:#b8c5d3;
  cursor:pointer; text-align:left; }}
.ztp-tbl .ztp-group td::before {{ content:'▾'; position:absolute; left:25px; color:#66788a; }}
.ztp-tbl .ztp-group.collapsed td::before {{ content:'▸'; }}
.ztp-tbl .ztp-group td span {{ margin-left:8px; color:#66788a; font-size:11px; font-weight:600; }}
.ztp-tbl .ztp-group:hover {{ background:transparent; }}
.ztp-collapsed-by-environment,.ztp-collapsed-by-group {{ display:none !important; }}
.ztp-state {{ display:inline-block; min-width:44px; padding:2px 6px; border-radius:10px;
  text-align:center; font-size:11px; font-weight:700; }}
.ztp-stage-event {{ display:block; }}
.ztp-event-time {{ display:block; margin-top:3px; color:#737d88; font-size:9.5px;
  font-variant-numeric:tabular-nums; line-height:1.2; white-space:nowrap; }}
.ztp-success {{ color:#176b36; background:#dcf5e5; }} .ztp-running {{ color:#145c9e; background:#dceeff; }}
.ztp-dhcp-dynamic {{ color:#805800; background:#fff0c2; border:1px solid #e2c35d; }}
.ztp-warning {{ color:#805800; background:#fff0c2; }} .ztp-failed {{ color:#a12626; background:#fde1e1; }}
.ztp-pending,.ztp-unknown,.ztp-not_applicable {{ color:#5f6872; background:#e9edf1; }}
.ztp-skipped {{ color:#5f6872; background:#e9edf1; border:1px dashed #aab4bf; }}
.ztp-progress {{ margin:4px auto 0; width:72px; height:4px; background:#dde3ea; border-radius:3px; overflow:hidden; }}
.ztp-progress i {{ display:block; height:100%; background:var(--accent); }}
.ztp-overall-meta {{ display:flex; flex-direction:column; align-items:center; justify-content:center;
  gap:4px; min-width:260px; }}
.ztp-meta-row {{ display:flex; align-items:center; justify-content:center; gap:14px; }}
.ztp-overall-result {{ gap:8px; }}
.ztp-write-time {{ margin:0; color:#6b7280; font-size:11px; white-space:nowrap; }}
.ztp-diagnosis {{ margin:0; max-width:320px; white-space:normal; text-align:center;
  color:#5f6872; line-height:1.35; }}
.ztp-empty td {{ padding:28px; text-align:center; color:#6c757d; }}
.hidden {{ display:none !important; }}
</style>
</head>
<body>

<div id="topbar">
  <h1>Network Monitor Dashboard</h1>
  <span class="meta">生成时间：{gen_time}</span>
</div>

<div id="tabs">
  <button class="tab"        onclick="switchTab('ztp')">ZTP Status</button>
  <button class="tab"        onclick="switchTab('eth')">Switch Status</button>
  <button class="tab"        onclick="switchTab('etop')">Eth Link Validation</button>
  <button class="tab"        onclick="switchTab('spx')">SPX Link Monitor</button>
  <button class="tab"        onclick="switchTab('itop')">IB Link Validation</button>
  <button class="tab"        onclick="switchTab('ibl')">IB Link Monitor</button>
  <button class="tab"        onclick="switchTab('nvl')">NVLink Monitor</button>
  <button class="tab"        onclick="switchTab('p2p')">Ethernet Diagram</button>
  <button class="tab"        onclick="switchTab('air')">AIR Diagram</button>
</div>

<!-- ═══ Tab 1: 交换机状态 ═══ -->
<div id="panel-eth" class="panel">
  <div id="eth-toolbar">
    <span class="eth-meta">
      ETH：<strong>{eth_count} 台</strong>
      &nbsp;·&nbsp;
      IB：<strong>{ib_count} 台</strong>
      &nbsp;·&nbsp;
      NV：<strong>{nv_count} 台</strong>
      &nbsp;·&nbsp;
      未绑定/未分类：<strong>{air_unbound_count + production_unbound_count + unknown_unbound_count} 台</strong>
      <br>ETH 数据源：<strong>{escape(eth_source)}</strong>
    </span>
    <span class="ztp-monitor-control">
      <button id="switch-collect-button" type="button" onclick="requestSwitchCollection()" disabled>检查中…</button>
      <span id="switch-collect-state" class="ztp-monitor-state" aria-live="polite">未知</span>
    </span>
    {auto_refresh_control('eth')}
    <input id="eth-search" type="text" placeholder="按主机名筛选…" oninput="filterCards()">
    <div class="view-toggle">
      <button id="btn-card" class="vtbtn active" onclick="setView('card')">卡片</button>
      <button id="btn-list" class="vtbtn"        onclick="setView('list')">列表</button>
    </div>
  </div>
  <div id="card-grid">
    {switch_cards_html}
  </div>
  <div id="list-view" style="display:none">
    <table class="lst-tbl">
      <tbody id="lst-body">
        {switch_list_html}
      </tbody>
    </table>
  </div>
</div>

<!-- ═══ Tab 2: SPX 链路 ═══ -->
<div id="panel-spx" class="panel">
  <div id="spx-topbar" class="link-topbar">
    <span class="link-meta">
      最新快照：<strong>{spx_ts_str}</strong>
      &nbsp;·&nbsp; 共 {spx_snap_count} 个快照（近3天）
    </span>
    <span class="bdg bdg-chg" onclick="spx.filterBadge('chg')">{spx_stats['changed']} 变化</span>
    <span class="bdg bdg-new" onclick="spx.filterBadge('new')">{spx_stats['new']} 新增</span>
    <span class="bdg bdg-rm"  onclick="spx.filterBadge('rm')" >{spx_stats['removed']} 消失</span>
    <span class="bdg bdg-same"onclick="spx.filterBadge('same')">{spx_stats['same']} 无变化</span>
    {auto_refresh_control('spx')}
  </div>
  <div id="spx-toolbar" class="link-toolbar">
    <label>搜索：
      <input id="spx-search" class="link-search" type="text"
             placeholder="设备名 / 端口…" oninput="spx.applyFilters()">
    </label>
    <label>显示：
      <select id="spx-show-sel" onchange="spx.applyFilters()">
        <option value="all">全部</option>
        <option value="changes">仅变化行</option>
      </select>
    </label>
    <label>高亮时间窗：
      <select id="spx-hl-sel" onchange="spx.applyFilters()">
        <option value="0">任意变化</option>
        {spx_diff_opts}
      </select>
    </label>
    <button id="spx-down-btn" class="down-btn" onclick="spx.toggleDown()">Down Interfaces</button>
    <span id="spx-row-info" class="row-info"></span>
    <button class="dl-btn" onclick="spx.downloadCsv(false)">⬇ 导出 CSV</button>
    <button class="dl-btn" onclick="spx.downloadCsv(true)">⬇ 仅导出变化</button>
  </div>
  <div id="spx-wrap" class="link-wrap">
    <table id="spx-tbl" class="link-tbl">
      <thead>{spx_thead}</thead>
      <tbody id="spx-tbody">{spx_tbody}</tbody>
    </table>
  </div>
</div>

<!-- ═══ Tab 3: IB 链路 ═══ -->
<div id="panel-ibl" class="panel">
  <div id="ibl-topbar" class="link-topbar">
    <span class="link-meta">
      最新快照：<strong>{ibl_ts_str}</strong>
      &nbsp;·&nbsp; 共 {ibl_snap_count} 个快照（近3天）
    </span>
    <span class="bdg bdg-chg" onclick="ibl.filterBadge('chg')">{ibl_stats['changed']} 变化</span>
    <span class="bdg bdg-new" onclick="ibl.filterBadge('new')">{ibl_stats['new']} 新增</span>
    <span class="bdg bdg-rm"  onclick="ibl.filterBadge('rm')" >{ibl_stats['removed']} 消失</span>
    <span class="bdg bdg-same"onclick="ibl.filterBadge('same')">{ibl_stats['same']} 无变化</span>
    {auto_refresh_control('ibl')}
  </div>
  <div id="ibl-toolbar" class="link-toolbar">
    <label>搜索：
      <input id="ibl-search" class="link-search" type="text"
             placeholder="设备名 / 端口…" oninput="ibl.applyFilters()">
    </label>
    <label>显示：
      <select id="ibl-show-sel" onchange="ibl.applyFilters()">
        <option value="all">全部</option>
        <option value="changes">仅变化行</option>
      </select>
    </label>
    <label>高亮时间窗：
      <select id="ibl-hl-sel" onchange="ibl.applyFilters()">
        <option value="0">任意变化</option>
        {ibl_diff_opts}
      </select>
    </label>
    <button id="ibl-down-btn" class="down-btn" onclick="ibl.toggleDown()">Down Interfaces</button>
    <span id="ibl-row-info" class="row-info"></span>
    <button class="dl-btn" onclick="ibl.downloadCsv(false)">⬇ 导出 CSV</button>
    <button class="dl-btn" onclick="ibl.downloadCsv(true)">⬇ 仅导出变化</button>
  </div>
  <div id="ibl-wrap" class="link-wrap">
    <table id="ibl-tbl" class="link-tbl">
      <thead>{ibl_thead}</thead>
      <tbody id="ibl-tbody">{ibl_tbody}</tbody>
    </table>
  </div>
</div>

<!-- ═══ Tab 4: NVLink ═══ -->
<div id="panel-nvl" class="panel">
  <div id="nvl-topbar" class="link-topbar">
    <span class="link-meta">
      最新快照：<strong>{nvl_ts_str}</strong>
      &nbsp;·&nbsp; 共 {nvl_snap_count} 个快照（近3天）
    </span>
    <span class="bdg bdg-chg" onclick="nvl.filterBadge('chg')">{nvl_stats['changed']} 变化</span>
    <span class="bdg bdg-new" onclick="nvl.filterBadge('new')">{nvl_stats['new']} 新增</span>
    <span class="bdg bdg-rm"  onclick="nvl.filterBadge('rm')" >{nvl_stats['removed']} 消失</span>
    <span class="bdg bdg-same"onclick="nvl.filterBadge('same')">{nvl_stats['same']} 无变化</span>
    {auto_refresh_control('nvl')}
  </div>
  <div id="nvl-toolbar" class="link-toolbar">
    <label>搜索：
      <input id="nvl-search" class="link-search" type="text"
             placeholder="设备名 / 端口…" oninput="nvl.applyFilters()">
    </label>
    <label>显示：
      <select id="nvl-show-sel" onchange="nvl.applyFilters()">
        <option value="all">全部</option>
        <option value="changes">仅变化行</option>
      </select>
    </label>
    <label>高亮时间窗：
      <select id="nvl-hl-sel" onchange="nvl.applyFilters()">
        <option value="0">任意变化</option>
        {nvl_diff_opts}
      </select>
    </label>
    <button id="nvl-down-btn" class="down-btn" onclick="nvl.toggleDown()">Down Interfaces</button>
    <span id="nvl-row-info" class="row-info"></span>
    <button class="dl-btn" onclick="nvl.downloadCsv(false)">⬇ 导出 CSV</button>
    <button class="dl-btn" onclick="nvl.downloadCsv(true)">⬇ 仅导出变化</button>
  </div>
  <div id="nvl-wrap" class="link-wrap">
    <table id="nvl-tbl" class="link-tbl">
      <thead>{nvl_thead}</thead>
      <tbody id="nvl-tbody">{nvl_tbody}</tbody>
    </table>
  </div>
</div>

<!-- ═══ ZTP Status ═══ -->
<div id="panel-ztp" class="panel">
  <div class="ztp-toolbar">
    <span class="ztp-meta">
      项目：<strong>{escape(str(ztp_status.get('project', '—')))}</strong>
      &nbsp;·&nbsp; 写入时间：<strong>{escape(ztp_update_summary)}</strong>
      &nbsp;·&nbsp; {ztp_summary}
    </span>
    <span class="ztp-monitor-control">
      <button id="ztp-monitor-toggle" type="button" onclick="toggleZtpMonitor()" disabled>检查中…</button>
      <span id="ztp-monitor-state" class="ztp-monitor-state" aria-live="polite">未知</span>
    </span>
    <span id="manual-ztp-state" class="ztp-monitor-state" aria-live="polite">手工 ZTP：检查中…</span>
    {auto_refresh_control('ztp')}
    <input id="ztp-search" type="text" placeholder="设备 / IP / MAC / 问题…" oninput="filterZtpStatus()">
  </div>
  <div class="ztp-wrap">
    <table id="ztp-tbl" class="ztp-tbl">
      <thead><tr>
        <th class="ztp-sortable" onclick="sortZtpStatus(0,'text')">设备</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(1,'text')">类型</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(2,'ip')">IP</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(3,'text')">MAC</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(4,'status')">DHCP</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(5,'status')">Bootstrap</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(6,'status')">YAML 下载</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(7,'status')">SSH</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(8,'status')">网络</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(9,'status')">版本</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(10,'status')">YAML Apply</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(11,'status')">SSH Key</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(12,'status')">完成</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(13,'number')">进度</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(14,'status')">时间同步</th>
        <th class="ztp-sortable" onclick="sortZtpStatus(15,'status')">总体 / 诊断</th>
        <th>操作</th>
      </tr></thead>
      <tbody>{ztp_rows}</tbody>
    </table>
  </div>
</div>

<!-- ═══ Tab 5-6: Topology Validation ═══ -->
{ethernet_topology_panel}
{infiniband_topology_panel}
{ethernet_diagram_panel}
{air_diagram_panel}

<script>
// ── Auto-Refresh（两个 Status + 三个 Monitor 页面）──────────────────────────
const TAB_NAMES = ['ztp','eth','etop','spx','itop','ibl','nvl','p2p','air'];
const AUTO_REFRESH_TABS = new Set(['ztp','eth','spx','ibl','nvl']);
const AUTO_REFRESH_KEY = 'network-monitor:auto-refresh';
const ACTIVE_TAB_KEY = 'network-monitor:active-tab';
const SWITCH_VIEW_KEY = 'network-monitor:switch-view:' + window.location.pathname;
const COLLAPSE_STATE_KEY = 'network-monitor:collapse-state:' + window.location.pathname;
const COLLAPSE_TOGGLE_SELECTOR = [
  '.ztp-environment', '.ztp-group', '.section-divider', '.card-env',
  '.card-cat', '.lst-env', '.lst-sec', '.lst-cat', '.topo-section > h3',
  'tr.grp',
].join(',');
const autoRefreshSettings = Object.fromEntries(
  Array.from(AUTO_REFRESH_TABS, tab => [tab, {{enabled: true, seconds: 15}}])
);
let autoRefreshTimer = null;
let autoRefreshCountdownTimer = null;
let autoRefreshDeadline = 0;
const ZTP_CONTROL_URL = '/cgi-bin/ztp-monitor-control';
const SWITCH_COLLECTION_URL = '/cgi-bin/switch-collection-control';
const MANUAL_ZTP_URL = '/cgi-bin/manual-ztp-control';
const MANUAL_ZTP_INTENTS_KEY = 'monitor.manualZtpIntents.v1:'
  + {json.dumps(f"{ENVIRONMENT_SCOPE}|{ztp_status.get('project', '')}")};
let ztpMonitorState = 'unknown';
let switchCollectionState = 'unknown';
let manualZtpStates = {{}};
let manualZtpIntents = loadManualZtpIntents();
let manualZtpPollTimer = null;
const PAGE_SOURCE_TIME_ZONE = {json.dumps(getattr(DISPLAY_TZ, 'key', str(DISPLAY_TZ)))};

function sourceWallTimeToDate(dateText, timeText) {{
  const dateParts = dateText.replaceAll('/', '-').split('-').map(Number);
  const timeParts = timeText.split(':').map(Number);
  const target = Date.UTC(
    dateParts[0], dateParts[1] - 1, dateParts[2],
    timeParts[0], timeParts[1], timeParts[2] || 0
  );
  let guess = target;
  const formatter = new Intl.DateTimeFormat('en-CA', {{
    timeZone: PAGE_SOURCE_TIME_ZONE, year: 'numeric', month: '2-digit',
    day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit',
    hourCycle: 'h23',
  }});
  for (let attempt = 0; attempt < 3; attempt += 1) {{
    const parts = Object.fromEntries(
      formatter.formatToParts(new Date(guess))
        .filter(part => part.type !== 'literal')
        .map(part => [part.type, Number(part.value)])
    );
    const represented = Date.UTC(
      parts.year, parts.month - 1, parts.day,
      parts.hour, parts.minute, parts.second
    );
    const correction = target - represented;
    guess += correction;
    if (correction === 0) break;
  }}
  return new Date(guess);
}}

function localTimeText(date, includeSeconds = true) {{
  const pad = value => String(value).padStart(2, '0');
  const offsetMinutes = -date.getTimezoneOffset();
  const sign = offsetMinutes >= 0 ? '+' : '-';
  const absoluteOffset = Math.abs(offsetMinutes);
  const seconds = includeSeconds ? `:${{pad(date.getSeconds())}}` : '';
  return `${{date.getFullYear()}}-${{pad(date.getMonth() + 1)}}-${{pad(date.getDate())}} `
    + `${{pad(date.getHours())}}:${{pad(date.getMinutes())}}${{seconds}} `
    + `UTC${{sign}}${{pad(Math.floor(absoluteOffset / 60))}}:${{pad(absoluteOffset % 60)}}`;
}}

function convertDisplayedTimes(root = document.body) {{
  if (!root) return;
  const pattern = /(\\d{{4}}[-/]\\d{{2}}[-/]\\d{{2}})[ T](\\d{{2}}:\\d{{2}}(?::\\d{{2}})?)(?:(?:\\s*UTC)?([+-]\\d{{2}}:\\d{{2}})|(Z))?/g;
  const convert = text => String(text).replace(pattern, (match, dateText, timeText, offset, zulu) => {{
    const isoDate = dateText.replaceAll('/', '-');
    const date = offset || zulu
      ? new Date(`${{isoDate}}T${{timeText}}${{zulu ? 'Z' : offset}}`)
      : sourceWallTimeToDate(isoDate, timeText);
    return Number.isNaN(date.valueOf()) ? match : localTimeText(date, timeText.length === 8);
  }});
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {{
    acceptNode(node) {{
      const parent = node.parentElement;
      if (!parent || ['SCRIPT', 'STYLE', 'TEXTAREA'].includes(parent.tagName))
        return NodeFilter.FILTER_REJECT;
      pattern.lastIndex = 0;
      const matched = pattern.test(node.nodeValue || '');
      pattern.lastIndex = 0;
      return matched
        ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_REJECT;
    }},
  }});
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  nodes.forEach(node => {{ node.nodeValue = convert(node.nodeValue); }});
  root.querySelectorAll('[title]').forEach(element => {{
    element.title = convert(element.title);
  }});
  root.querySelectorAll('.ztp-event-time').forEach(element => {{
    const full = String(element.textContent || '').trim();
    const match = full.match(
      /^(\\d{{4}})-(\\d{{2}})-(\\d{{2}}) (\\d{{2}}:\\d{{2}}:\\d{{2}})(?: UTC[+-]\\d{{2}}:\\d{{2}})?$/
    );
    if (!match) return;
    if (!element.title) element.title = full;
    element.textContent = `${{match[2]}}-${{match[3]}} ${{match[4]}}`;
  }});
}}

function storageGet(key) {{
  try {{ return window.localStorage.getItem(key); }} catch (_error) {{ return null; }}
}}

function storageSet(key, value) {{
  try {{ window.localStorage.setItem(key, value); }} catch (_error) {{ /* unavailable */ }}
}}

function collapseEnvironment(element) {{
  if (element.dataset.environment) return element.dataset.environment;
  const group = element.closest('.card-env-group[data-environment]');
  if (group) return group.dataset.environment || 'all';
  let previous = element.previousElementSibling;
  while (previous) {{
    if (previous.classList?.contains('lst-env'))
      return previous.dataset.environment || 'all';
    previous = previous.previousElementSibling;
  }}
  return 'all';
}}

function collapseLabel(element) {{
  const title = element.querySelector?.('.topo-section-title');
  const raw = title?.textContent || element.cells?.[0]?.textContent || element.textContent || '';
  return raw.replace(/[（(]\\s*\\d+(?:\\s*\\/\\s*\\d+)?(?:\\s*台)?\\s*[）)]\\s*$/, '')
    .replace(/\\s+/g, ' ').trim().toLowerCase();
}}

function collapseStateKey(element) {{
  const panel = element.closest('.panel')?.id || 'page';
  if (element.classList.contains('ztp-environment'))
    return `${{panel}}|ztp-environment|${{element.dataset.environment || ''}}`;
  if (element.classList.contains('ztp-group'))
    return `${{panel}}|ztp-group|${{element.dataset.group || ''}}`;
  if (element.matches('.topo-section > h3')) {{
    const section = element.closest('.topo-section');
    return `${{panel}}|topology|${{section?.dataset.category || ''}}|${{collapseLabel(element)}}`;
  }}
  if (element.classList.contains('card-env') || element.classList.contains('lst-env'))
    return `${{panel}}|${{element.classList.contains('card-env') ? 'card-env' : 'list-env'}}|${{collapseEnvironment(element)}}`;
  if (element.classList.contains('card-cat') || element.classList.contains('lst-cat'))
    return `${{panel}}|${{element.classList.contains('card-cat') ? 'card-cat' : 'list-cat'}}|${{collapseEnvironment(element)}}|${{element.dataset.cat || collapseLabel(element)}}`;
  if (element.classList.contains('section-divider') || element.classList.contains('lst-sec'))
    return `${{panel}}|${{element.classList.contains('section-divider') ? 'card-section' : 'list-section'}}|${{collapseEnvironment(element)}}|${{collapseLabel(element)}}`;
  if (element.classList.contains('grp'))
    return `${{panel}}|link-group|${{element.dataset.dev || collapseLabel(element)}}`;
  return '';
}}

function isCollapseElementClosed(element) {{
  if (element.matches('.topo-section > h3'))
    return element.closest('.topo-section')?.classList.contains('collapsed') || false;
  return element.classList.contains('collapsed');
}}

function loadCollapseState() {{
  const raw = storageGet(COLLAPSE_STATE_KEY);
  if (!raw) return {{}};
  try {{
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === 'object' ? parsed : {{}};
  }} catch (_error) {{
    return {{}};
  }}
}}

function saveCollapseElement(element) {{
  const key = collapseStateKey(element);
  if (!key) return;
  const state = loadCollapseState();
  if (isCollapseElementClosed(element)) state[key] = true;
  else delete state[key];
  storageSet(COLLAPSE_STATE_KEY, JSON.stringify(state));
}}

function initCollapsePersistence() {{
  const state = loadCollapseState();
  document.querySelectorAll(COLLAPSE_TOGGLE_SELECTOR).forEach(element => {{
    const key = collapseStateKey(element);
    if (key && state[key] && !isCollapseElementClosed(element)) element.click();
  }});
  const remember = event => {{
    const element = event.target.closest?.(COLLAPSE_TOGGLE_SELECTOR);
    if (element) window.setTimeout(() => saveCollapseElement(element), 0);
  }};
  document.addEventListener('click', remember);
  document.addEventListener('keydown', event => {{
    if (event.key === 'Enter' || event.key === ' ') remember(event);
  }});
}}

function normalizeRefreshSeconds(value) {{
  const parsed = Number.parseInt(String(value), 10);
  return Number.isFinite(parsed) ? Math.min(3600, Math.max(2, parsed)) : 15;
}}

function activeTabName() {{
  return document.querySelector('.panel.active')?.id.replace(/^panel-/, '') || 'ztp';
}}

function tabFromLocation() {{
  const value = window.location.hash.replace(/^#/, '').trim().toLowerCase();
  return TAB_NAMES.includes(value) ? value : '';
}}

function reloadActiveTab() {{
  const tab = activeTabName();
  storageSet(ACTIVE_TAB_KEY, tab);
  if (window.location.hash !== '#' + tab)
    window.history.replaceState(null, '', window.location.pathname + window.location.search + '#' + tab);
  window.location.reload();
}}

function refreshSettings(tab = activeTabName()) {{
  return autoRefreshSettings[tab] || {{enabled: false, seconds: 15}};
}}

function setRefreshStatus(tab, text) {{
  const node = document.querySelector(
    `.auto-refresh[data-refresh-tab="${{tab}}"] .auto-refresh-countdown`
  );
  if (node) node.textContent = text;
}}

function syncRefreshControls() {{
  document.querySelectorAll('.auto-refresh[data-refresh-tab]').forEach(control => {{
    const settings = refreshSettings(control.dataset.refreshTab);
    const toggle = control.querySelector('.auto-refresh-toggle');
    const seconds = control.querySelector('.auto-refresh-seconds');
    if (toggle) toggle.checked = settings.enabled;
    if (seconds) {{
      seconds.value = String(settings.seconds);
      seconds.disabled = !settings.enabled;
    }}
  }});
}}

function saveRefreshSettings() {{
  storageSet(AUTO_REFRESH_KEY, JSON.stringify(autoRefreshSettings));
}}

function clearRefreshTimers() {{
  if (autoRefreshTimer !== null) window.clearTimeout(autoRefreshTimer);
  if (autoRefreshCountdownTimer !== null) window.clearInterval(autoRefreshCountdownTimer);
  autoRefreshTimer = null;
  autoRefreshCountdownTimer = null;
}}

function updateRefreshCountdown() {{
  const tab = activeTabName();
  const settings = refreshSettings(tab);
  if (!settings.enabled) {{ setRefreshStatus(tab, 'Off'); return; }}
  if (!AUTO_REFRESH_TABS.has(tab)) return;
  const remaining = Math.max(0, Math.ceil((autoRefreshDeadline - Date.now()) / 1000));
  setRefreshStatus(tab, `${{remaining}}s`);
}}

function scheduleAutoRefresh() {{
  clearRefreshTimers();
  syncRefreshControls();
  const tab = activeTabName();
  if (!AUTO_REFRESH_TABS.has(tab)) return;
  const settings = refreshSettings(tab);
  if (!settings.enabled) {{ setRefreshStatus(tab, 'Off'); return; }}
  autoRefreshDeadline = Date.now() + settings.seconds * 1000;
  updateRefreshCountdown();
  autoRefreshCountdownTimer = window.setInterval(updateRefreshCountdown, 250);
  autoRefreshTimer = window.setTimeout(reloadActiveTab, settings.seconds * 1000);
}}

function initAutoRefresh() {{
  const saved = storageGet(AUTO_REFRESH_KEY);
  if (saved) {{
    try {{
      const settings = JSON.parse(saved);
      for (const tab of AUTO_REFRESH_TABS) {{
        if (!settings[tab]) continue;
        autoRefreshSettings[tab] = {{
          enabled: settings[tab].enabled !== false,
          seconds: normalizeRefreshSeconds(settings[tab].seconds),
        }};
      }}
    }} catch (_error) {{ /* use per-tab defaults */ }}
  }}
  document.querySelectorAll('.auto-refresh-toggle').forEach(input => {{
    input.addEventListener('change', event => {{
      const tab = event.currentTarget.closest('.auto-refresh')?.dataset.refreshTab;
      if (!tab || !autoRefreshSettings[tab]) return;
      autoRefreshSettings[tab].enabled = event.currentTarget.checked;
      saveRefreshSettings();
      scheduleAutoRefresh();
    }});
  }});
  document.querySelectorAll('.auto-refresh-seconds').forEach(input => {{
    input.addEventListener('change', event => {{
      const tab = event.currentTarget.closest('.auto-refresh')?.dataset.refreshTab;
      if (!tab || !autoRefreshSettings[tab]) return;
      autoRefreshSettings[tab].seconds = normalizeRefreshSeconds(event.currentTarget.value);
      saveRefreshSettings();
      scheduleAutoRefresh();
    }});
  }});
  const savedTab = tabFromLocation() || storageGet(ACTIVE_TAB_KEY) || 'ztp';
  switchTab(TAB_NAMES.includes(savedTab) ? savedTab : 'ztp', false);
}}

function renderZtpMonitorControl(payload) {{
  const button = document.getElementById('ztp-monitor-toggle');
  const label = document.getElementById('ztp-monitor-state');
  const alive = payload?.process_alive === true;
  ztpMonitorState = alive ? (payload?.state === 'paused' ? 'paused' : 'running') : 'stopped';
  if (button) button.classList.remove('running', 'paused');
  if (ztpMonitorState === 'running') {{
    if (button) {{ button.textContent = '结束 ZTP 监控'; button.classList.add('running'); button.disabled = false; }}
    if (label) label.textContent = '运行中';
  }} else if (ztpMonitorState === 'paused') {{
    if (button) {{ button.textContent = '开始 ZTP 监控'; button.classList.add('paused'); button.disabled = false; }}
    if (label) label.textContent = '已暂停';
  }} else {{
    if (button) {{ button.textContent = '监控未运行'; button.disabled = true; }}
    if (label) label.textContent = '需运行 load';
  }}
}}

async function refreshZtpMonitorControl() {{
  try {{
    const response = await fetch(ZTP_CONTROL_URL, {{cache: 'no-store'}});
    if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
    renderZtpMonitorControl(await response.json());
    return true;
  }} catch (error) {{
    const button = document.getElementById('ztp-monitor-toggle');
    const label = document.getElementById('ztp-monitor-state');
    if (button) {{ button.textContent = '控制不可用'; button.disabled = true; }}
    if (label) label.textContent = String(error.message || error);
    return false;
  }}
}}

async function toggleZtpMonitor() {{
  const button = document.getElementById('ztp-monitor-toggle');
  if (!button || !['running', 'paused'].includes(ztpMonitorState)) return;
  button.disabled = true;
  const action = ztpMonitorState === 'running' ? 'stop' : 'start';
  try {{
    const response = await fetch(ZTP_CONTROL_URL, {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'ZTPMonitorControl',
      }},
      body: `action=${{encodeURIComponent(action)}}`,
      cache: 'no-store',
    }});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
    renderZtpMonitorControl(payload);
  }} catch (error) {{
    window.alert(`ZTP 监控控制失败：${{error.message || error}}`);
    await refreshZtpMonitorControl();
  }}
}}

async function requestSwitchCollection() {{
  const button = document.getElementById('switch-collect-button');
  if (!button || ['stopped', 'stopping'].includes(switchCollectionState)) return;
  const action = ['queued', 'collecting'].includes(switchCollectionState) ? 'stop' : 'collect';
  button.disabled = true;
  button.textContent = action === 'stop' ? '停止中…' : '提交中…';
  try {{
    const response = await fetch(SWITCH_COLLECTION_URL, {{
      method: 'POST',
      headers: {{
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-Requested-With': 'SwitchCollectionControl',
      }},
      body: `action=${{action}}`,
      cache: 'no-store',
    }});
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
    renderSwitchCollectionControl(payload);
    window.setTimeout(pollSwitchCollection, 1000);
  }} catch (error) {{
    window.alert(`Switch Status 收集失败：${{error.message || error}}`);
    await refreshSwitchCollectionControl();
  }}
}}

function renderSwitchCollectionControl(payload) {{
  const button = document.getElementById('switch-collect-button');
  const label = document.getElementById('switch-collect-state');
  if (!button || !label) return;
  const alive = payload?.process_alive === true;
  switchCollectionState = alive ? (payload?.state || 'idle') : 'stopped';
  if (['queued', 'collecting'].includes(switchCollectionState)) {{
    button.textContent = '停止收集';
    button.disabled = false;
    label.textContent = '收集中';
  }} else if (switchCollectionState === 'stopping') {{
    button.textContent = '停止中…';
    button.disabled = true;
    label.textContent = '正在停止管理服务器上的收集任务';
  }} else if (switchCollectionState === 'stopped') {{
    button.textContent = '收集服务未运行';
    button.disabled = true;
    label.textContent = '需运行 load';
  }} else {{
    button.textContent = '立即收集 Switch Status';
    button.disabled = false;
    if (switchCollectionState === 'success') {{
      if (payload?.cooldown_skipped) {{
        label.textContent = `30 分钟冷却中：复用 ${{payload?.last_success_at || '最近成功结果'}}；`
          + `下次允许 ${{payload?.next_allowed_at || '—'}}`;
      }} else {{
        label.textContent = `上次成功：${{payload?.finished_at || payload?.updated_at || '—'}}`;
      }}
    }} else if (switchCollectionState === 'failed') {{
      label.textContent = `上次失败：${{payload?.reason || '未知原因'}}`;
    }} else {{
      label.textContent = '可手工采集';
    }}
  }}
  convertDisplayedTimes(label);
}}

async function refreshSwitchCollectionControl() {{
  try {{
    const response = await fetch(SWITCH_COLLECTION_URL, {{cache: 'no-store'}});
    if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
    renderSwitchCollectionControl(await response.json());
    return true;
  }} catch (error) {{
    const button = document.getElementById('switch-collect-button');
    const label = document.getElementById('switch-collect-state');
    switchCollectionState = 'stopped';
    if (button) {{ button.textContent = '收集控制不可用'; button.disabled = true; }}
    if (label) label.textContent = String(error.message || error);
    return false;
  }}
}}

async function pollSwitchCollection() {{
  if (!await refreshSwitchCollectionControl()) return;
  if (['queued', 'collecting', 'stopping'].includes(switchCollectionState)) {{
    window.setTimeout(pollSwitchCollection, 2000);
  }} else if (switchCollectionState === 'success') {{
    reloadActiveTab();
  }}
}}

const MANUAL_ZTP_PREVIEW_STATES = new Set([
  'preview_queued', 'previewing', 'cancel_queued'
]);
const MANUAL_ZTP_OPERATION_STATES = new Set([
  'confirm_queued', 'queued', 'running', 'ztp_running'
]);
const TIME_SYNC_BUSY_STATES = new Set([
  'time_sync_queued', 'time_sync_running'
]);
const MANUAL_ZTP_BUSY_STATES = new Set([
  ...MANUAL_ZTP_PREVIEW_STATES, ...MANUAL_ZTP_OPERATION_STATES,
  ...TIME_SYNC_BUSY_STATES
]);
const manualPreviewPromptKeys = new Set();

function loadManualZtpIntents() {{
  try {{
    const value = JSON.parse(storageGet(MANUAL_ZTP_INTENTS_KEY) || '{{}}');
    return value && typeof value === 'object' && !Array.isArray(value) ? value : {{}};
  }} catch (_error) {{ return {{}}; }}
}}

function saveManualZtpIntents() {{
  storageSet(MANUAL_ZTP_INTENTS_KEY, JSON.stringify(manualZtpIntents));
}}

function manualZtpIntent(hostname) {{
  if (manualZtpIntents[hostname]) return manualZtpIntents[hostname];
  const wanted = hostname.toLowerCase();
  const key = Object.keys(manualZtpIntents)
    .find(item => item.toLowerCase() === wanted);
  return key ? manualZtpIntents[key] : null;
}}

function setManualZtpIntent(hostname, intent) {{
  Object.keys(manualZtpIntents).forEach(key => {{
    if (key.toLowerCase() === hostname.toLowerCase()) delete manualZtpIntents[key];
  }});
  if (intent) manualZtpIntents[hostname] = {{hostname, ...intent}};
  saveManualZtpIntents();
}}

function manualZtpStatusIsCurrent(device, intent) {{
  const expectedOperationId = String(intent?.operation_id || '');
  const expectedTriggerId = String(intent?.trigger_id || '');
  if (expectedOperationId && expectedTriggerId
      && device?.operation_id && device?.trigger_id)
    return String(device.operation_id) === expectedOperationId
      && String(device.trigger_id) === expectedTriggerId;
  if (MANUAL_ZTP_BUSY_STATES.has(device?.state)) return true;
  const previousStatusTime = String(intent?.prior_status_updated_at || '');
  const currentStatusTime = String(device?.updated_at || '');
  if (previousStatusTime && currentStatusTime)
    return previousStatusTime !== currentStatusTime;
  const statusTime = Date.parse(device?.updated_at || device?.requested_at || '');
  const requestTime = Date.parse(intent?.requested_at || '');
  return Number.isFinite(statusTime) && Number.isFinite(requestTime)
    && statusTime >= requestTime - 2000;
}}

function manualZtpDeviceState(hostname) {{
  if (manualZtpStates[hostname]) return manualZtpStates[hostname];
  const wanted = hostname.toLowerCase();
  const key = Object.keys(manualZtpStates).find(item => item.toLowerCase() === wanted);
  return key ? manualZtpStates[key] : {{state: 'idle', hostname}};
}}

function manualTriggerSourceLabel(deviceState = {{}}, isReset = false) {{
  const source = String(deviceState?.trigger_source || 'manual_web');
  if (source.endsWith('_cli')) return isReset ? 'CLI 重置' : 'CLI 手工';
  return isReset ? '页面重置' : '页面手工';
}}

function resetReportMatchesIntent(row, deviceState = {{}}) {{
  if (String(deviceState?.operation || '') !== 'reset') return false;
  if (String(row?.dataset?.manualOperation || '') !== 'reset') return false;
  if (!String(row?.dataset?.triggerSource || '').startsWith('manual_reset_')) return false;

  // CLI operations expose a durable operation/trigger id.  Web-triggered
  // resets currently meet at their server timestamps, so use the accepted
  // cycle marker and the worker's command boundary as the fallback.
  const reportTriggerId = String(row?.dataset?.triggerId || '');
  const expectedTriggerId = String(
    deviceState?.trigger_id || deviceState?.operation_id || ''
  );
  if (reportTriggerId && expectedTriggerId)
    return reportTriggerId === expectedTriggerId;

  const reportMarkerText = String(
    row?.dataset?.manualCycleMarker || row?.dataset?.cycleStartedAt || ''
  );
  const priorMarker = String(deviceState?.prior_manual_cycle_marker || '');
  const reportMarker = Date.parse(reportMarkerText);
  const priorMarkerTime = Date.parse(priorMarker);
  if (Number.isFinite(reportMarker) && Number.isFinite(priorMarkerTime))
    return reportMarker > priorMarkerTime;

  const boundaryText = String(
    deviceState?.command_finished_at || deviceState?.started_at
      || deviceState?.requested_at || ''
  );
  const boundary = Date.parse(boundaryText);
  return Number.isFinite(reportMarker) && Number.isFinite(boundary)
    && reportMarker >= boundary - 5000;
}}

function resetManualZtpRow(hostname, deviceState = {{}}, force = false) {{
  const row = Array.from(document.querySelectorAll('.ztp-row[data-hostname]'))
    .find(item => item.dataset.hostname.toLowerCase() === hostname.toLowerCase());
  if (!row) return;
  const renderedRound = Number(row.dataset.ztpRound || 0);
  const baselineRound = Number(deviceState?.baseline_round ?? renderedRound);
  const currentRound = Number(deviceState?.current_round || 0);
  const isReset = String(deviceState?.operation || '') === 'reset';
  const deviceType = String(
    row.querySelector('.manual-ztp-button')?.dataset?.deviceType || ''
  ).toLowerCase();
  const directCumulusBootstrap = !isReset
    && ['', 'eth', 'eth_spx', 'spx', 'air'].includes(deviceType);
  // A reset intentionally uses baseline=0/expected=1.  Therefore the old
  // report's round 1 does not prove progress.  Keep the waiting overlay until
  // the rendered report carries this reset's accepted cycle marker; from that
  // point onward the report is authoritative and may reveal stages gradually.
  if (!force && isReset && resetReportMatchesIntent(row, deviceState)) return;
  if (!force && !isReset && renderedRound > baselineRound) return;
  const pending = '<span class="ztp-state ztp-pending">等待</span>'
    + '<span class="ztp-event-time">—</span>';
  row.querySelectorAll('[data-ztp-stage]').forEach(cell => {{
    const stage = cell.dataset.ztpStage;
    const expected = Number(deviceState?.expected_round || (isReset ? 1 : baselineRound + 1));
    const sourceLabel = manualTriggerSourceLabel(deviceState, isReset);
    if (stage === 'dhcp') {{
      cell.innerHTML = directCumulusBootstrap
        ? `<span class="ztp-state ztp-skipped">跳过${{expected}}</span><span class="ztp-event-time">—</span>`
        : `<span class="ztp-state ztp-pending">等待${{expected}}</span><span class="ztp-event-time">—</span>`;
    }} else if (stage === 'progress') {{
      cell.innerHTML = '<strong>0%</strong><div class="ztp-progress"><i style="width:0%"></i></div>';
    }} else if (stage === 'overall') {{
      cell.innerHTML = '<div class="ztp-overall-meta">'
        + `<div class="ztp-meta-row ztp-overall-result"><span class="ztp-state ztp-running">${{isReset ? '重置中' : '进行中'}}${{expected}}</span><span class="ztp-write-time">来源：${{sourceLabel}}</span></div>`
        + `<div class="ztp-meta-row"><span class="ztp-write-time">检查：等待状态刷新</span><span class="ztp-diagnosis">原因：${{isReset ? '手工重置：等待系统重启并重新进入 ZTP' : '手工 ZTP：等待新一轮状态'}}</span></div>`
        + '</div>';
    }} else {{
      cell.innerHTML = `<span class="ztp-state ztp-pending">等待${{expected}}</span><span class="ztp-event-time">—</span>`;
    }}
  }});
}}

function renderManualZtpFailureRow(hostname, deviceState) {{
  const row = Array.from(document.querySelectorAll('.ztp-row[data-hostname]'))
    .find(item => item.dataset.hostname.toLowerCase() === hostname.toLowerCase());
  if (!row) return;
  const renderedRound = Number(row.dataset.ztpRound || 0);
  const expectedRound = Number(deviceState?.expected_round || 0);
  const isReset = String(deviceState?.operation || '') === 'reset';
  const sourceLabel = manualTriggerSourceLabel(deviceState, isReset);
  if (!expectedRound || (!isReset && expectedRound <= renderedRound)) return;
  const pending = '<span class="ztp-state ztp-pending">等待</span>'
    + '<span class="ztp-event-time">—</span>';
  row.querySelectorAll('[data-ztp-stage]').forEach(cell => {{
    const stage = cell.dataset.ztpStage;
    if (stage === 'dhcp') return;
    if (stage === 'bootstrap') {{
      cell.innerHTML = '<span class="ztp-state ztp-failed">失败</span>'
        + `<span class="ztp-event-time">${{deviceState?.updated_at || '—'}}</span>`;
    }} else if (stage === 'progress') {{
      cell.innerHTML = '<strong>0%</strong><div class="ztp-progress"><i style="width:0%"></i></div>';
    }} else if (stage === 'overall') {{
      cell.innerHTML = '<div class="ztp-overall-meta">'
        + `<div class="ztp-meta-row ztp-overall-result"><span class="ztp-state ztp-failed">失败${{expectedRound}}</span><span class="ztp-write-time">来源：${{sourceLabel}}</span></div>`
        + `<div class="ztp-meta-row"><span class="ztp-write-time">检查：${{deviceState?.updated_at || '—'}}</span><span class="ztp-diagnosis"></span></div>`
        + '</div>';
      const diagnosis = cell.querySelector('.ztp-diagnosis');
      if (diagnosis) {{
        diagnosis.textContent = '原因：' + (
          deviceState?.reason || (isReset ? '手工重置触发失败' : '手工 ZTP 触发失败')
        );
        diagnosis.title = diagnosis.textContent;
      }}
      convertDisplayedTimes(cell);
    }} else {{
      cell.innerHTML = pending;
    }}
  }});
}}

function renderManualZtpControl(payload) {{
  const label = document.getElementById('manual-ztp-state');
  const buttons = Array.from(document.querySelectorAll('.manual-ztp-button'));
  const alive = payload?.process_alive === true;
  manualZtpStates = alive && payload?.devices ? payload.devices : {{}};
  const activeDevices = [];
  const timeSyncDevices = [];
  const previewDevices = [];
  const cancellingDevices = [];
  buttons.forEach(button => {{
    const hostname = button.dataset.hostname || '';
    const manualEligible = button.dataset.manualEligible !== 'false';
    const managedDiscovery = button.dataset.managedDiscovery === 'true';
    const row = button.closest('.ztp-row');
    const resetButton = row?.querySelector('.manual-reset-button');
    const timeSyncButton = row?.querySelector('.time-sync-button');
    const renderedRound = Number(row?.dataset.ztpRound || 0);
    const device = manualZtpDeviceState(hostname);
    const workerBusy = MANUAL_ZTP_BUSY_STATES.has(device?.state);
    const previewBusy = MANUAL_ZTP_PREVIEW_STATES.has(device?.state);
    const operationBusy = MANUAL_ZTP_OPERATION_STATES.has(device?.state);
    const timeSyncBusy = TIME_SYNC_BUSY_STATES.has(device?.state);
    const previewReady = device?.state === 'preview_ready';
    const canceling = device?.state === 'cancel_queued';
    let intent = manualZtpIntent(hostname);
    const timeSyncOperation = timeSyncBusy
      || String(device?.operation || '') === 'time-sync'
      || String(device?.requested_operation || '') === 'time-sync';
    // Time synchronization is an independent maintenance action: it must not
    // create or retain a manual-ZTP intent, otherwise resetManualZtpRow() will
    // incorrectly blank the completed round and render every stage as the next
    // round's "waiting" state.  Clearing here also repairs stale browser
    // storage created by older pages after their next status refresh.
    if (timeSyncOperation && intent) {{
      setManualZtpIntent(hostname, null);
      intent = null;
    }}
    if ((previewBusy || operationBusy || previewReady) && !intent) {{
      const workerReset = String(device?.operation || '') === 'reset';
      intent = {{
        hostname,
        baseline_round: Number(device?.baseline_round ?? (workerReset ? 0 : renderedRound)),
        expected_round: Number(device?.expected_round || (workerReset ? 1 : renderedRound + 1)),
        trigger_source: device?.trigger_source || 'manual_web',
        operation: device?.operation || 'ztp',
        requested_operation: device?.requested_operation || 'trigger',
        operation_id: device?.operation_id || '',
        trigger_id: device?.trigger_id || '',
        phase: canceling ? 'cancel'
          : ((previewBusy || previewReady) ? 'preview' : 'confirm'),
        requested_at: device?.requested_at || device?.started_at
          || device?.updated_at || new Date().toISOString(),
        prior_manual_cycle_marker: String(row?.dataset?.manualCycleMarker || ''),
        prior_trigger_id: String(row?.dataset?.triggerId || ''),
      }};
      setManualZtpIntent(hostname, intent);
    }}
    if (intent && manualZtpStatusIsCurrent(device, intent)) {{
      const expected = Number(intent.expected_round || 0);
      const completed = Number(device?.completed_round || 0);
      const statusExpected = Number(device?.expected_round || 0);
      if ((device?.state === 'success' && completed >= expected)
          || ['failed', 'cancelled'].includes(device?.state)) {{
        setManualZtpIntent(hostname, null);
        intent = null;
      }}
    }}
    const intentConfirmed = String(intent?.phase || '') === 'confirm';
    const active = operationBusy || intentConfirmed;
    const previewing = previewBusy
      || (String(intent?.phase || '') === 'preview' && !previewReady);
    button.disabled = !alive || !manualEligible || active || previewing || timeSyncBusy;
    button.classList.toggle('running', active);
    if (resetButton) {{
      resetButton.disabled = !alive || active || previewing || previewReady || timeSyncBusy;
      resetButton.classList.toggle('running', active && String((intent || device)?.operation || '') === 'reset');
    }}
    if (timeSyncButton) {{
      timeSyncButton.disabled = !alive || !manualEligible || workerBusy;
      timeSyncButton.classList.toggle('running', timeSyncBusy);
      timeSyncButton.textContent = timeSyncBusy ? '同步中…'
        : (device?.state === 'time_sync_success' ? '再次同步'
          : (device?.state === 'failed' && device?.operation === 'time-sync'
            ? '重试时间同步' : '时间同步'));
    }}
    const failedAttempt = (
      device?.state === 'failed'
      && (String(device?.operation || '') === 'reset'
          || Number(device?.expected_round || 0) > renderedRound)
    );
    const activeSource = String((intent || device)?.trigger_source || 'manual_web');
    const activeOperation = String((intent || device)?.operation || 'ztp');
    const idleLabel = button.dataset.defaultAction === 'renew'
      ? '重新获取 DHCP/ZTP' : '手工 ZTP';
    if (!manualEligible) {{
      button.textContent = managedDiscovery
        ? 'DHCP 重新获取（先绑定）' : '需要人工识别';
    }} else {{
      button.textContent = previewing
        ? (canceling ? '正在取消预检…' : '正在生成差异…')
        : previewReady ? '查看差异并确认'
        : active
        ? (activeOperation === 'reset' ? 'ZTP不可用' : (activeSource === 'manual_cli' ? 'CLI执行中…' : 'ZTP执行中…'))
        : failedAttempt ? `重试${{idleLabel}}` : idleLabel;
    }}
    if (resetButton) resetButton.textContent = active
      ? (activeOperation === 'reset' ? '重置执行中…' : '重置不可用')
      : (failedAttempt && activeOperation === 'reset' ? '重试手工重置' : '手工重置');
    if (active) {{
      const view = {{...(intent || {{}}), ...(operationBusy ? device : {{}})}};
      resetManualZtpRow(hostname, view);
      activeDevices.push({{...view, hostname}});
    }} else if (timeSyncBusy) {{
      timeSyncDevices.push({{...device, hostname}});
    }} else if (failedAttempt) renderManualZtpFailureRow(hostname, device);
    if (previewReady) {{
      previewDevices.push({{button, device, intent}});
    }}
    if (canceling) cancellingDevices.push({{button, device, intent}});
  }});
  if (!label) return;
  if (!alive) label.textContent = '手工 ZTP：需运行 load';
  else if (activeDevices.length) {{
    const names = activeDevices.map(device => device.hostname).filter(Boolean);
      const resetting = activeDevices.filter(device => String(device.operation || '') === 'reset').length;
      label.textContent = `${{resetting ? '重置/ZTP' : 'ZTP'}} 执行中：${{activeDevices.length}} 台（${{names.join('、')}}）`;
  }} else if (timeSyncDevices.length) {{
    label.textContent = `交换机时间同步中：${{timeSyncDevices.map(item => item.hostname).join('、')}}`;
  }} else if (cancellingDevices.length) {{
    label.textContent = `正在取消配置差异预检：${{cancellingDevices.length}} 台`;
  }} else if (previewDevices.length) {{
    label.textContent = `配置差异预检完成，等待确认：${{previewDevices.length}} 台`;
  }} else {{
    const terminal = Object.values(manualZtpStates)
      .filter(device => ['success', 'failed'].includes(device?.state))
      .sort((a, b) => String(b.updated_at || '').localeCompare(String(a.updated_at || '')))[0];
    if (terminal?.state === 'success')
      label.textContent = terminal.operation === 'reset'
        ? `重置后 ZTP 已完成：${{terminal.hostname || ''}}（第 ${{terminal.completed_round || terminal.expected_round || '?'}} 轮）`
        : `ZTP 已完成：${{terminal.hostname || ''}}（第 ${{terminal.completed_round || terminal.expected_round || '?'}} 轮）`;
    else if (terminal?.state === 'failed')
      label.textContent = `手工${{terminal.operation === 'reset' ? '重置' : ' ZTP'}}失败：${{terminal.hostname || ''}}：${{terminal.reason || '未知原因'}}`;
    else label.textContent = '手工 ZTP：可用';
  }}
  convertDisplayedTimes(label);
  if (activeDevices.length && manualZtpPollTimer === null)
    scheduleManualZtpPoll(2000);
  previewDevices.forEach(item => {{
    if (!item.intent) return;
    const key = `${{item.device.operation_id || ''}}|${{item.device.trigger_id || ''}}`;
    if (!key || manualPreviewPromptKeys.has(key)) return;
    window.setTimeout(() => confirmManualPreview(item.button, item.device), 0);
  }});
}}

async function refreshManualZtpControl() {{
  try {{
    const response = await fetch(MANUAL_ZTP_URL, {{cache: 'no-store'}});
    if (!response.ok) throw new Error(`HTTP ${{response.status}}`);
    renderManualZtpControl(await response.json());
    return true;
  }} catch (error) {{
    manualZtpStates = {{}};
    renderManualZtpControl({{process_alive:false, devices:{{}}}});
    const label = document.getElementById('manual-ztp-state');
    if (label) label.textContent = `手工 ZTP 控制不可用：${{error.message || error}}`;
    return false;
  }}
}}

async function requestManualZtp(button) {{
  return requestManualOperation(button, 'trigger');
}}

async function requestManualReset(button) {{
  return requestManualOperation(button, 'reset');
}}

async function requestManualRenew(button) {{
  return requestManualOperation(button, 'renew');
}}

async function requestTimeSync(button) {{
  if (!button || button.disabled) return;
  const hostname = button.dataset.hostname || '';
  if (!window.confirm(
      `将通过身份校验后的 SSH，在 ${{hostname}} 上执行固定无参数 helper，`
      + '从已渲染的管理服务器 ZTP URL 读取 HTTP Date 并设置系统时间；完成后会独立复测。继续？'
  )) return;
  button.disabled = true;
  try {{
    const payload = await postManualZtpControl(
      `action=time-sync&hostname=${{encodeURIComponent(hostname)}}`
    );
    renderManualZtpControl(payload);
    scheduleManualZtpPoll(1000);
  }} catch (error) {{
    window.alert(`时间同步提交失败：${{error.message || error}}`);
    await refreshManualZtpControl();
  }}
}}

async function postManualZtpControl(body) {{
  const response = await fetch(MANUAL_ZTP_URL, {{
    method: 'POST',
    headers: {{
      'Content-Type': 'application/x-www-form-urlencoded',
      'X-Requested-With': 'ManualZTPControl',
    }},
    body,
    cache: 'no-store',
  }});
  const payload = await response.json();
  if (!response.ok) throw new Error(payload.error || `HTTP ${{response.status}}`);
  return payload;
}}

async function confirmManualPreview(button, suppliedDevice = null, force = false) {{
  if (!button) return;
  const hostname = button.dataset.hostname || '';
  const device = suppliedDevice || manualZtpDeviceState(hostname);
  if (device?.state !== 'preview_ready') return;
  const operationId = String(device.operation_id || '');
  const triggerId = String(device.trigger_id || '');
  if (!operationId || !triggerId) {{
    window.alert('预检结果缺少 operation_id/trigger_id，拒绝确认，请重新预检。');
    return;
  }}
  const promptKey = `${{operationId}}|${{triggerId}}`;
  if (!force && manualPreviewPromptKeys.has(promptKey)) return;
  manualPreviewPromptKeys.add(promptKey);
  const summary = device.diff_summary || {{}};
  const paths = Array.isArray(summary.changed_paths) ? summary.changed_paths : [];
  const warnings = Array.isArray(summary.warnings) ? summary.warnings : [];
  const pathText = paths.length
    ? paths.slice(0, 80).map(path => `  - ${{path}}`).join('\\n')
      + (summary.truncated ? '\\n  - …（其余路径已省略）' : '')
    : '  - 无结构差异';
  const runtimeMatch = summary.runtime_matches_latest;
  const runtimeMatchText = runtimeMatch === true ? '是'
    : (runtimeMatch === false ? '否' : '未知');
  const reasonText = String(summary.comparison_reason || device.comparison_reason || '');
  const warningText = warnings.length
    ? `\\n警告：\\n${{warnings.map(item => `  - ${{item}}`).join('\\n')}}`
    : '';
  const effective = String(device.effective_operation || device.operation || 'ztp');
  const requested = String(device.requested_operation || 'trigger');
  const effectText = effective === 'reset'
    ? '实际操作：nv action reset system factory-default force；系统配置和日志会被清除，设备随后重启。'
    : (['ib', 'nvl'].includes(String(button.dataset.deviceType || '').toLowerCase())
      ? '实际操作：NVOS ZTP force；会重新经历 DHCP/NVOS bootstrap。'
      : '实际操作：Cumulus 手工 bootstrap；不会伪造 DHCP 阶段。');
  const accepted = window.confirm(
    `只读预检已完成：${{hostname}}\n`
    + `请求：${{requested}}；${{effectText}}\n`
    + '比较来源：设备当前 nv config show 的规范化 NVUE 配置\\n'
    + `设备当前运行配置是否与 latest 一致：${{runtimeMatchText}}\n`
    + (reasonText ? `原因：${{reasonText}}\n` : '')
    + `当前运行态新增行 ${{summary.added_lines || 0}}，删除行 ${{summary.removed_lines || 0}}${{warningText}}\n\n`
    + `当前运行配置变化路径（不显示配置值）：\n${{pathText}}\n\n`
    + '确认后后台会用同一 ID 和服务端指纹重新预检；任何运行态配置、applied receipt、发布或身份变化都会拒绝执行。继续？'
  );
  if (!accepted) {{
    button.disabled = true;
    try {{
      const payload = await postManualZtpControl(
        `action=cancel&hostname=${{encodeURIComponent(hostname)}}`
        + `&operation_id=${{encodeURIComponent(operationId)}}`
        + `&trigger_id=${{encodeURIComponent(triggerId)}}`
      );
      setManualZtpIntent(hostname, null);
      manualPreviewPromptKeys.delete(promptKey);
      renderManualZtpControl(payload);
      scheduleManualZtpPoll(500);
    }} catch (error) {{
      manualPreviewPromptKeys.delete(promptKey);
      window.alert(`取消预检失败：${{error.message || error}}`);
      await refreshManualZtpControl();
    }}
    return;
  }}
  button.disabled = true;
  try {{
    const payload = await postManualZtpControl(
      `action=confirm&hostname=${{encodeURIComponent(hostname)}}`
      + `&operation_id=${{encodeURIComponent(operationId)}}`
      + `&trigger_id=${{encodeURIComponent(triggerId)}}`
    );
    const row = button.closest('.ztp-row');
    const isReset = effective === 'reset';
    const renderedRound = Number(row?.dataset.ztpRound || 0);
    const intent = {{
      state: 'confirm_queued', phase: 'confirm',
      baseline_round: isReset ? 0 : renderedRound,
      expected_round: isReset ? 1 : renderedRound + 1,
      trigger_source: isReset ? 'manual_reset_web' : 'manual_web',
      operation: effective, requested_operation: requested,
      operation_id: operationId, trigger_id: triggerId,
      requested_at: device.requested_at || new Date().toISOString(),
      prior_status_updated_at: String(device.updated_at || ''),
      prior_manual_cycle_marker: String(row?.dataset?.manualCycleMarker || ''),
      prior_trigger_id: String(row?.dataset?.triggerId || ''),
    }};
    setManualZtpIntent(hostname, intent);
    resetManualZtpRow(hostname, intent, true);
    renderManualZtpControl(payload);
    scheduleManualZtpPoll(1000);
  }} catch (error) {{
    manualPreviewPromptKeys.delete(promptKey);
    window.alert(`确认提交失败：${{error.message || error}}`);
    await refreshManualZtpControl();
  }}
}}

async function requestManualOperation(button, action) {{
  if (!button || button.disabled) return;
  const hostname = button.dataset.hostname || '';
  const type = button.dataset.deviceType || '';
  const existing = manualZtpDeviceState(hostname);
  if (existing?.state === 'preview_ready')
    return confirmManualPreview(button, existing, true);
  const approximateEffective = (
    action === 'reset'
    || (action === 'renew' && button.dataset.renewEffective === 'reset')
  ) ? 'reset' : 'ztp';
  const isReset = approximateEffective === 'reset';
  const row = button.closest('.ztp-row');
  const priorStatusUpdatedAt = String(
    manualZtpDeviceState(hostname)?.updated_at || ''
  );
  const priorManualCycleMarker = String(row?.dataset?.manualCycleMarker || '');
  const priorTriggerId = String(row?.dataset?.triggerId || '');
  const operationLabel = action === 'renew' ? '重新获取 DHCP/ZTP'
    : action === 'reset' ? '手工重置' : '手工 ZTP';
  if (!window.confirm(
      `即将对 ${{hostname}} 开始只读预检（${{operationLabel}}）。\n`
      + '本阶段只核验 release/MAC/SSH 并比较 nv config show，不会修改或重启设备。继续？'
  )) return;
  button.disabled = true;
  try {{
    const payload = await postManualZtpControl(
      `action=preview&operation=${{action}}&hostname=${{encodeURIComponent(hostname)}}`
    );
    const request = payload.request || {{}};
    const renderedRound = Number(row?.dataset.ztpRound || 0);
    const baselineRound = isReset ? 0 : renderedRound;
    const intent = {{
      state: 'preview_queued', phase: 'preview', baseline_round: baselineRound,
      expected_round: isReset ? 1 : baselineRound + 1,
      trigger_source: isReset ? 'manual_reset_web' : 'manual_web',
      operation: approximateEffective, requested_operation: action,
      operation_id: String(request.operation_id || ''),
      trigger_id: String(request.trigger_id || ''),
      requested_at: new Date().toISOString(),
      prior_status_updated_at: priorStatusUpdatedAt,
      prior_manual_cycle_marker: priorManualCycleMarker,
      prior_trigger_id: priorTriggerId,
    }};
    setManualZtpIntent(hostname, intent);
    renderManualZtpControl(payload);
    scheduleManualZtpPoll(1000);
  }} catch (error) {{
    window.alert(`${{operationLabel}}预检提交失败：${{error.message || error}}`);
    await refreshManualZtpControl();
  }}
}}

async function pollManualZtp() {{
  if (!await refreshManualZtpControl()) return;
  const busy = Object.values(manualZtpStates)
    .some(device => MANUAL_ZTP_BUSY_STATES.has(device?.state))
    || Object.keys(manualZtpIntents).length > 0;
  if (busy) scheduleManualZtpPoll(2000);
  else reloadActiveTab();
}}

function scheduleManualZtpPoll(delay) {{
  if (manualZtpPollTimer !== null) window.clearTimeout(manualZtpPollTimer);
  manualZtpPollTimer = window.setTimeout(() => {{
    manualZtpPollTimer = null;
    pollManualZtp();
  }}, delay);
}}

// ── 选项卡切换 ───────────────────────────────────────────────────────────────
function switchTab(name, persist = true) {{
  document.querySelectorAll('.tab').forEach((b, i) =>
    b.classList.toggle('active', TAB_NAMES[i] === name));
  document.querySelectorAll('.panel').forEach(p =>
    p.classList.toggle('active', p.id === 'panel-' + name));
  if (persist) {{
    storageSet(ACTIVE_TAB_KEY, name);
    window.history.replaceState(
      null, '', window.location.pathname + window.location.search + '#' + name
    );
  }}
  scheduleAutoRefresh();
}}

function filterZtpStatus() {{
  const q = (document.getElementById('ztp-search')?.value || '').trim().toLowerCase();
  let visible = 0;
  document.querySelectorAll('#panel-ztp .ztp-row').forEach(row => {{
    const show = !q || (row.dataset.search || '').includes(q);
    row.classList.toggle('hidden', !show);
    if (show) visible++;
  }});
  document.querySelectorAll('#panel-ztp .ztp-group').forEach(group => {{
    const hasVisible = Array.from(document.querySelectorAll(
      `#panel-ztp .ztp-row[data-group="${{group.dataset.group}}"]`
    )).some(row => !row.classList.contains('hidden'));
    group.classList.toggle('hidden', !hasVisible);
  }});
  document.querySelectorAll('#panel-ztp .ztp-environment').forEach(environment => {{
    const hasVisible = Array.from(document.querySelectorAll(
      `#panel-ztp .ztp-row[data-environment="${{environment.dataset.environment}}"]`
    )).some(row => !row.classList.contains('hidden'));
    environment.classList.toggle('hidden', !hasVisible);
  }});
  document.getElementById('ztp-no-match')?.classList.toggle('hidden', visible !== 0);
}}

function toggleZtpEnvironment(header) {{
  const environment = header.dataset.environment;
  const collapsed = !header.classList.contains('collapsed');
  header.classList.toggle('collapsed', collapsed);
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  document.querySelectorAll(
    `#panel-ztp .ztp-group[data-environment="${{environment}}"],` +
    `#panel-ztp .ztp-row[data-environment="${{environment}}"]`
  ).forEach(element =>
    element.classList.toggle('ztp-collapsed-by-environment', collapsed));
}}

function toggleZtpGroup(header) {{
  const group = header.dataset.group;
  const collapsed = !header.classList.contains('collapsed');
  header.classList.toggle('collapsed', collapsed);
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  document.querySelectorAll(
    `#panel-ztp .ztp-row[data-group="${{group}}"]`
  ).forEach(row => row.classList.toggle('ztp-collapsed-by-group', collapsed));
}}

function handleZtpToggleKey(event, header, level) {{
  if (event.key !== 'Enter' && event.key !== ' ') return;
  event.preventDefault();
  if (level === 'environment') toggleZtpEnvironment(header);
  else toggleZtpGroup(header);
}}

function sortZtpStatus(column, type) {{
  const table = document.getElementById('ztp-tbl');
  if (!table) return;
  const header = table.tHead?.rows[0]?.cells[column];
  if (!header) return;
  const ascending = header.getAttribute('aria-sort') !== 'ascending';
  table.querySelectorAll('thead th').forEach(th => th.removeAttribute('aria-sort'));
  header.setAttribute('aria-sort', ascending ? 'ascending' : 'descending');

  const statusRank = {{'失败':0, '警告':1, '进行中':2, '等待':3,
                      '未知':4, '不适用':5, '成功':6}};
  const valueOf = row => {{
    const cell = row.cells[column];
    if (!cell) return '';
    if (type === 'status') {{
      const state = cell.querySelector('.ztp-state');
      if (state?.classList.contains('ztp-failed')) return statusRank['失败'];
      if (state?.classList.contains('ztp-warning')) return statusRank['警告'];
      if (state?.classList.contains('ztp-running')) return statusRank['进行中'];
      if (state?.classList.contains('ztp-pending')) return statusRank['等待'];
      if (state?.classList.contains('ztp-unknown')) return statusRank['未知'];
      if (state?.classList.contains('ztp-success')) return statusRank['成功'];
      const label = state?.textContent.trim() || '';
      return statusRank[label] ?? 99;
    }}
    const value = cell.textContent.trim();
    if (type === 'number') return Number.parseFloat(value) || 0;
    if (type === 'ip') {{
      const parts = value.split('.');
      return parts.length === 4 && parts.every(part => /^\\d+$/.test(part))
        ? parts.reduce((number, part) => number * 256 + Number(part), 0)
        : Number.MAX_SAFE_INTEGER;
    }}
    return value;
  }};
  const body = table.tBodies[0];
  const groups = Array.from(body.querySelectorAll('.ztp-group'));
  groups.forEach(group => {{
    const rows = Array.from(body.querySelectorAll(
      `.ztp-row[data-group="${{group.dataset.group}}"]`
    ));
    rows.forEach((row, index) => row.dataset.sortIndex ??= String(index));
    rows.sort((left, right) => {{
      const leftAir = left.cells[0]?.textContent.trim().toUpperCase().startsWith('AIR-') ? 0 : 1;
      const rightAir = right.cells[0]?.textContent.trim().toUpperCase().startsWith('AIR-') ? 0 : 1;
      if (leftAir !== rightAir) return leftAir - rightAir;
      const a = valueOf(left), b = valueOf(right);
      let result = typeof a === 'number'
        ? a - b
        : String(a).localeCompare(String(b), undefined, {{numeric:true, sensitivity:'base'}});
      if (!result) result = Number(left.dataset.sortIndex) - Number(right.dataset.sortIndex);
      return ascending ? result : -result;
    }});
    let cursor = group;
    rows.forEach(row => {{ cursor.after(row); cursor = row; }});
  }});
  const empty = document.getElementById('ztp-no-match');
  if (empty) body.appendChild(empty);
}}

function toggleTopologySection(header) {{
  const section = header.closest('.topo-section');
  if (!section) return;
  const collapsed = section.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
}}

function handleTopologySectionKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleTopologySection(header);
  }}
}}

function matchesTopologyFilter(actual, rawFilter, requestedMode = 'contains', input = null) {{
  const filter = (rawFilter || '').trim();
  if (input) input.classList.remove('filter-invalid');
  if (!filter) return true;
  const shorthandExclude = filter.startsWith('!') || filter.startsWith('！');
  const wanted = (shorthandExclude ? filter.slice(1) : filter).trim();
  if (!wanted) return true;
  const mode = shorthandExclude ? 'not_contains' : requestedMode;
  const actualText = actual || '';
  const actualFolded = actualText.toLowerCase();
  const wantedFolded = wanted.toLowerCase();
  switch (mode) {{
    case 'not_contains': return !actualFolded.includes(wantedFolded);
    case 'equals':       return actualFolded === wantedFolded;
    case 'not_equals':   return actualFolded !== wantedFolded;
    case 'starts_with':  return actualFolded.startsWith(wantedFolded);
    case 'ends_with':    return actualFolded.endsWith(wantedFolded);
    case 'regex':
      try {{ return new RegExp(wanted, 'i').test(actualText); }}
      catch (_) {{ if (input) input.classList.add('filter-invalid'); return false; }}
    default:             return actualFolded.includes(wantedFolded);
  }}
}}

function hasTopologyFilterTerm(rawFilter) {{
  const filter = (rawFilter || '').trim();
  return filter.replace(/^[!！]/, '').trim() !== '';
}}

function resetTopologyFilters(prefix) {{
  const panel = document.getElementById('panel-' + prefix.split('-')[0]);
  if (!panel) return;
  const search = document.getElementById(prefix + '-search');
  if (search) search.value = '';
  const searchMode = document.getElementById(prefix + '-search-mode');
  if (searchMode) searchMode.value = 'contains';
  for (const suffix of ['category', 'status']) {{
    const select = document.getElementById(prefix + '-' + suffix);
    if (select) select.value = 'all';
  }}
  panel.querySelectorAll('.topo-col-filter').forEach(input => {{
    input.value = '';
    input.classList.remove('filter-active', 'filter-invalid');
  }});
  panel.querySelectorAll('.topo-col-mode').forEach(select => {{
    select.value = 'contains';
  }});
  filterTopology(prefix);
}}

function filterTopology(prefix) {{
  const panel = document.getElementById('panel-' + prefix.split('-')[0]);
  if (!panel) return;
  const searchInput = document.getElementById(prefix + '-search');
  const search = searchInput?.value || '';
  const searchMode = document.getElementById(prefix + '-search-mode')?.value || 'contains';
  const category = document.getElementById(prefix + '-category')?.value || 'all';
  const status = document.getElementById(prefix + '-status')?.value || 'all';
  const searchActive = hasTopologyFilterTerm(search);
  if (searchInput) searchInput.classList.toggle('filter-active', searchActive);
  let visible = 0, total = 0;
  panel.querySelectorAll('.topo-section').forEach(section => {{
    const sectionCategory = section.dataset.category || '';
    const categoryOk = category === 'all' || category === sectionCategory;
    let sectionVisible = 0;
    const dataRows = section.querySelectorAll('tr.topo-row');
    const columnFilters = Array.from(section.querySelectorAll('.topo-col-filter'));
    const hasColumnFilter = columnFilters.some(input => hasTopologyFilterTerm(input.value));
    columnFilters.forEach(input =>
      input.classList.toggle('filter-active', hasTopologyFilterTerm(input.value)));
    dataRows.forEach(row => {{
      const statusOk = status === 'all' || status === (row.dataset.status || '');
      const searchOk = matchesTopologyFilter(
        row.dataset.search || '', search, searchMode, searchInput
      );
      const columnsOk = columnFilters.every(input => {{
        const index = Number(input.dataset.col);
        const actual = row.cells[index]?.textContent || '';
        const mode = section.querySelector(
          `.topo-col-mode[data-col="${{index}}"]`
        )?.value || 'contains';
        return matchesTopologyFilter(actual, input.value, mode, input);
      }});
      const show = categoryOk && statusOk && searchOk && columnsOk;
      row.classList.toggle('hidden', !show);
      total++;
      if (show) {{ visible++; sectionVisible++; }}
    }});
    const noMatch = section.querySelector('.topo-no-match');
    if (noMatch) noMatch.classList.toggle('hidden', !(hasColumnFilter && sectionVisible === 0));
    const showEmpty = categoryOk && dataRows.length === 0 && !hasTopologyFilterTerm(search)
      && status === 'all' && !hasColumnFilter;
    section.classList.toggle(
      'hidden', !categoryOk || (sectionVisible === 0 && !showEmpty && !hasColumnFilter)
    );
    const count = section.querySelector('.topo-section-count');
    if (count) {{
      const filtered = searchActive || hasColumnFilter || status !== 'all';
      count.textContent = filtered ? `${{sectionVisible}} / ${{dataRows.length}}` : dataRows.length;
    }}
  }});
  const anyColumnFilter = Array.from(panel.querySelectorAll('.topo-col-filter'))
    .some(input => hasTopologyFilterTerm(input.value));
  const anyModeChanged = Array.from(panel.querySelectorAll('.topo-col-mode'))
    .some(select => select.value !== 'contains');
  const clear = document.getElementById(prefix + '-clear');
  if (clear) clear.disabled = !(
    searchActive || searchMode !== 'contains' || category !== 'all' || status !== 'all'
    || anyColumnFilter || anyModeChanged
  );
  const info = document.getElementById(prefix + '-row-info');
  if (info) info.textContent = `${{visible}} / ${{total}} 条`;
}}

// ── Tab1: 视图切换 ───────────────────────────────────────────────────────────
function setView(v, persist = true) {{
  const isCard = v === 'card';
  document.getElementById('card-grid').style.display  = isCard ? '' : 'none';
  document.getElementById('list-view').style.display  = isCard ? 'none' : '';
  document.getElementById('btn-card').classList.toggle('active', isCard);
  document.getElementById('btn-list').classList.toggle('active', !isCard);
  if (persist) storageSet(SWITCH_VIEW_KEY, isCard ? 'card' : 'list');
  filterCards();
}}

// ── Tab1: 卡片分组折叠 ──────────────────────────────────────────────────────
function toggleCardSection(header) {{
  const collapsed = header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  let sibling = header.nextElementSibling;
  while (sibling && !sibling.classList.contains('section-divider')) {{
    sibling.classList.toggle('section-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }}
}}

function handleCardSectionKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleCardSection(header);
  }}
}}

// ── Tab1: AIR / Production 大类折叠 ───────────────────────────────────────
function toggleCardEnvironment(header) {{
  const collapsed = header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  header.nextElementSibling?.classList.toggle('env-collapsed', collapsed);
}}

function handleCardEnvironmentKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleCardEnvironment(header);
  }}
}}

function toggleListEnvironment(header) {{
  const collapsed = header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  let sibling = header.nextElementSibling;
  while (sibling && !sibling.classList.contains('lst-env')) {{
    sibling.classList.toggle('lst-env-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }}
}}

function handleListEnvironmentKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleListEnvironment(header);
  }}
}}

function toggleListSwitchType(header) {{
  const collapsed = header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  let sibling = header.nextElementSibling;
  while (sibling && !sibling.classList.contains('lst-sec') &&
         !sibling.classList.contains('lst-env')) {{
    sibling.classList.toggle('lst-switch-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }}
}}

function handleListSwitchTypeKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleListSwitchType(header);
  }}
}}

// ── Tab1: 卡片子类折叠 ────────────────────────────────────────────────────
function toggleCardCat(header) {{
  const collapsed = header.classList.toggle('collapsed');
  header.setAttribute('aria-expanded', collapsed ? 'false' : 'true');
  let sibling = header.nextElementSibling;
  while (sibling && !sibling.classList.contains('card-cat') &&
         !sibling.classList.contains('card-env') &&
         !sibling.classList.contains('section-divider')) {{
    if (sibling.classList.contains('sw-card') || sibling.classList.contains('card-role'))
      sibling.classList.toggle('card-cat-hidden', collapsed);
    sibling = sibling.nextElementSibling;
  }}
}}

function handleCardCatKey(event, header) {{
  if (event.key === 'Enter' || event.key === ' ') {{
    event.preventDefault();
    toggleCardCat(header);
  }}
}}

// ── Tab1: 子类折叠 ───────────────────────────────────────────────────────────
function toggleCat(tr) {{
  tr.classList.toggle('collapsed');
  const hide = tr.classList.contains('collapsed');
  let sib = tr.nextElementSibling;
  while (sib && !sib.classList.contains('lst-cat') && !sib.classList.contains('lst-sec') &&
         !sib.classList.contains('lst-env')) {{
    if (sib.classList.contains('lst-row') || sib.classList.contains('lst-role'))
      sib.classList.toggle('cat-hidden', hide);
    sib = sib.nextElementSibling;
  }}
}}

// ── Tab1: 筛选（卡片 + 列表同步）────────────────────────────────────────────
function filterCards() {{
  const q = document.getElementById('eth-search').value.toLowerCase();
  // 卡片视图
  document.querySelectorAll('.sw-card').forEach(c =>
    c.classList.toggle('hidden', !!q && !c.dataset.hn.includes(q)));
  // 搜索时只保留至少有一张匹配卡片的子类标题。
  document.querySelectorAll('.card-cat').forEach(cat => {{
    if (!q) {{ cat.classList.remove('hidden'); return; }}
    let sib = cat.nextElementSibling, hasMatch = false;
    while (sib && !sib.classList.contains('card-cat') &&
           !sib.classList.contains('card-env') &&
           !sib.classList.contains('section-divider')) {{
      if (sib.classList.contains('sw-card') && !sib.classList.contains('hidden'))
        hasMatch = true;
      sib = sib.nextElementSibling;
    }}
    cat.classList.toggle('hidden', !hasMatch);
  }});
  document.querySelectorAll('.card-role').forEach(role => {{
    if (!q) {{ role.classList.remove('hidden'); return; }}
    let sibling = role.nextElementSibling, hasMatch = false;
    while (sibling && !sibling.classList.contains('card-role') &&
           !sibling.classList.contains('card-cat') &&
           !sibling.classList.contains('card-env') &&
           !sibling.classList.contains('section-divider')) {{
      if (sibling.classList.contains('sw-card') && !sibling.classList.contains('hidden'))
        hasMatch = true;
      sibling = sibling.nextElementSibling;
    }}
    role.classList.toggle('hidden', !hasMatch);
  }});
  document.querySelectorAll('.card-env-group').forEach(group => {{
    if (!q) {{ group.classList.remove('hidden'); return; }}
    const hasMatch = Array.from(group.querySelectorAll('.sw-card'))
      .some(card => !card.classList.contains('hidden'));
    group.classList.toggle('hidden', !hasMatch);
  }});
  // 列表视图：过滤数据行
  document.querySelectorAll('tr.lst-row').forEach(r =>
    r.classList.toggle('hidden', !!q && !(r.dataset.hn || '').includes(q)));
  // 有搜索词时：隐藏所有行均被过滤的分类标题；无搜索词时：全部显示
  document.querySelectorAll('tr.lst-cat').forEach(cat => {{
    if (!q) {{ cat.classList.remove('hidden'); return; }}
    let sib = cat.nextElementSibling, hasMatch = false;
    while (sib && !sib.classList.contains('lst-cat') && !sib.classList.contains('lst-sec') &&
           !sib.classList.contains('lst-env')) {{
      if (sib.classList.contains('lst-row') && !sib.classList.contains('hidden')) hasMatch = true;
      sib = sib.nextElementSibling;
    }}
    cat.classList.toggle('hidden', !hasMatch);
  }});
  document.querySelectorAll('tr.lst-role').forEach(role => {{
    if (!q) {{ role.classList.remove('hidden'); return; }}
    let sibling = role.nextElementSibling, hasMatch = false;
    while (sibling && !sibling.classList.contains('lst-role') &&
           !sibling.classList.contains('lst-cat') &&
           !sibling.classList.contains('lst-sec') &&
           !sibling.classList.contains('lst-env')) {{
      if (sibling.classList.contains('lst-row') && !sibling.classList.contains('hidden'))
        hasMatch = true;
      sibling = sibling.nextElementSibling;
    }}
    role.classList.toggle('hidden', !hasMatch);
  }});
  document.querySelectorAll('tr.lst-env').forEach(environment => {{
    if (!q) {{ environment.classList.remove('hidden'); return; }}
    let sibling = environment.nextElementSibling, hasMatch = false;
    while (sibling && !sibling.classList.contains('lst-env')) {{
      if (sibling.classList.contains('lst-row') &&
          !sibling.classList.contains('hidden')) hasMatch = true;
      sibling = sibling.nextElementSibling;
    }}
    environment.classList.toggle('hidden', !hasMatch);
  }});
}}

// ── Tab2/3: 链路通用逻辑工厂 ─────────────────────────────────────────────────
function makeCtx(pfx) {{
  let badge = null;
  let downOnly = false;
  let scol = -1, sdir = 1;

  function filterBadge(cls) {{
    badge = (badge === cls) ? null : cls;
    document.querySelectorAll('#' + pfx + '-topbar .bdg')
      .forEach(b => b.classList.remove('active'));
    if (badge)
      document.querySelector('#' + pfx + '-topbar .bdg-' + badge)?.classList.add('active');
    applyFilters();
  }}

  function toggleDown() {{
    downOnly = !downOnly;
    document.getElementById(pfx + '-down-btn').classList.toggle('active', downOnly);
    applyFilters();
  }}

  function applyFilters() {{
    const q     = document.getElementById(pfx + '-search').value.toLowerCase();
    const show  = document.getElementById(pfx + '-show-sel').value;
    const tbody = document.getElementById(pfx + '-tbody');
    const rows  = tbody.querySelectorAll('tr:not(.grp):not(.link-env)');
    let vis = 0, total = 0;
    const devVis = {{}};
    rows.forEach(tr => {{
      const dev = tr.dataset.dev || '', port = tr.dataset.port || '';
      const cls = tr.className;
      const matchQ    = !q || dev.toLowerCase().includes(q) || port.toLowerCase().includes(q);
      const matchShow = show !== 'changes' ||
        cls.includes('r-chg') || cls.includes('r-new') || cls.includes('r-rm');
      const matchDown = !downOnly || (tr.dataset.state || '').toLowerCase() === 'down';
      let matchBadge = true;
      if (badge === 'chg')  matchBadge = cls.includes('r-chg');
      if (badge === 'new')  matchBadge = cls.includes('r-new');
      if (badge === 'rm')   matchBadge = cls.includes('r-rm');
      if (badge === 'same') matchBadge =
        !cls.includes('r-chg') && !cls.includes('r-new') && !cls.includes('r-rm');
      const ok = matchQ && matchShow && matchBadge && matchDown;
      total++;
      if (tr.classList.contains('grp-hidden')) {{
        // 折叠行：不改变可见性，但仍需参与 devVis 判断以保留 group 标题
        if (ok) devVis[dev] = true;
        return;
      }}
      tr.classList.toggle('hidden', !ok);
      if (ok) {{ vis++; devVis[dev] = true; }}
    }});
    tbody.querySelectorAll('tr.grp').forEach(g =>
      g.classList.toggle('hidden', !devVis[g.dataset.dev || '']));
    tbody.querySelectorAll('tr.link-env').forEach(env => {{
      const name = env.dataset.environment || '';
      const hasVisible = Array.from(tbody.querySelectorAll('tr.grp')).some(
        group => group.dataset.environment === name && !group.classList.contains('hidden')
      );
      const filtering = !!q || show !== 'all' || downOnly || badge !== null;
      env.classList.toggle('hidden', !hasVisible && filtering);
    }});
    document.getElementById(pfx + '-row-info').textContent =
      `${{vis}} / ${{total}} 端口`;
  }}

  function natCmp(a, b) {{
    const re = /(\\d+)|(\\D+)/g;
    const pa = a.match(re) || [], pb = b.match(re) || [];
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {{
      if (i >= pa.length) return -1;
      if (i >= pb.length) return  1;
      const na = parseInt(pa[i], 10), nb = parseInt(pb[i], 10);
      if (!isNaN(na) && !isNaN(nb)) {{ if (na !== nb) return na - nb; }}
      else {{ const c = pa[i].localeCompare(pb[i]); if (c) return c; }}
    }}
    return 0;
  }}

  function doSort(th, col) {{
    sdir = (scol === col) ? -sdir : 1;
    scol = col;
    document.getElementById(pfx + '-tbl').querySelectorAll('thead th')
      .forEach(t => t.classList.remove('sa','sd'));
    th.classList.add(sdir === 1 ? 'sa' : 'sd');
    const tbody = document.getElementById(pfx + '-tbody');
    const environments = [];
    let currentEnvironment = null, cur = null;
    Array.from(tbody.children).forEach(tr => {{
      if (tr.classList.contains('link-env')) {{
        currentEnvironment = {{header:tr, groups:[]}};
        environments.push(currentEnvironment);
        cur = null;
      }} else if (tr.classList.contains('grp')) {{
        if (!currentEnvironment) {{
          currentEnvironment = {{header:null, groups:[]}};
          environments.push(currentEnvironment);
        }}
        cur = {{grp:tr, rows:[]}};
        currentEnvironment.groups.push(cur);
      }}
      else if (cur) cur.rows.push(tr);
    }});
    environments.forEach(environment => {{
      environment.groups.forEach(g => {{
        g.rows.sort((a,b) => {{
          const ta = a.querySelectorAll('td')[col]?.textContent || '';
          const tb = b.querySelectorAll('td')[col]?.textContent || '';
          return natCmp(ta, tb) * sdir;
        }});
      }});
    }});
    while (tbody.firstChild) tbody.removeChild(tbody.firstChild);
    environments.forEach(environment => {{
      if (environment.header) tbody.appendChild(environment.header);
      environment.groups.forEach(g => {{
        tbody.appendChild(g.grp);
        g.rows.forEach(r => tbody.appendChild(r));
      }});
    }});
  }}

  function downloadCsv(changesOnly) {{
    const tbl = document.getElementById(pfx + '-tbl');
    const ths = Array.from(tbl.querySelectorAll('thead th'));
    const hdr = ths.map(th => '"' + th.textContent
      .replace(/\\r?\\n/g,' ').replace(/"/g,'""').trim() + '"').join(',');
    const lines = [hdr];
    document.querySelectorAll(
      '#' + pfx + '-tbody tr:not(.grp):not(.link-env):not(.hidden)'
    ).forEach(tr => {{
      if (changesOnly) {{
        const c = tr.className;
        if (!c.includes('r-chg') && !c.includes('r-new') && !c.includes('r-rm')) return;
      }}
      lines.push(Array.from(tr.querySelectorAll('td'))
        .map(td => '"' + td.textContent
          .replace(/\\r?\\n/g,' ').replace(/"/g,'""').trim() + '"').join(','));
    }});
    const ts   = new Date().toISOString().replace(/[:.]/g,'-').slice(0,19);
    const name = (changesOnly ? pfx + '-changes-' : pfx + '-export-') + ts + '.csv';
    const a = Object.assign(document.createElement('a'), {{
      href: URL.createObjectURL(
        new Blob([lines.join('\\r\\n')], {{type:'text/csv;charset=utf-8;'}})),
      download: name,
    }});
    document.body.appendChild(a); a.click(); document.body.removeChild(a);
  }}

  function initCollapse() {{
    document.querySelectorAll('#' + pfx + '-tbody tr.grp').forEach(g => {{
      g.addEventListener('click', () => {{
        const dev = g.dataset.dev;
        const col = g.classList.toggle('collapsed');
        document.querySelectorAll(
          '#' + pfx + '-tbody tr[data-dev="' + CSS.escape(dev) + '"]:not(.grp)'
        ).forEach(r => {{
          r.classList.toggle('grp-hidden', col);
          if (col) r.classList.add('hidden');
        }});
        if (!col) applyFilters();
      }});
    }});
  }}

  return {{ filterBadge, toggleDown, applyFilters, srt: doSort, downloadCsv, initCollapse }};
}}

const spx = makeCtx('spx');
const ibl = makeCtx('ibl');
const nvl = makeCtx('nvl');

// ── 列排序入口（被 thead onclick="srt(this,N)" 调用）─────────────────────────
function srt(th, col) {{
  const panel = th.closest('.panel');
  if (panel && panel.id === 'panel-ibl') ibl.srt(th, col);
  else if (panel && panel.id === 'panel-nvl') nvl.srt(th, col);
  else spx.srt(th, col);
}}

// ── 所有列表表头拖拽调整列宽 ────────────────────────────────────────────────
function initColumnResize() {{
  document.querySelectorAll(
    '.lst-tbl tr.lst-repeat-head th, .link-tbl thead th, .topo-tbl thead tr:first-child th'
  ).forEach(th => {{
    if (th.querySelector(':scope > .col-resizer')) return;
    const handle = document.createElement('span');
    handle.className = 'col-resizer';
    handle.title = '拖动调整列宽；双击恢复自动宽度';
    th.appendChild(handle);

    handle.addEventListener('mousedown', event => {{
      event.preventDefault();
      event.stopPropagation();
      const startX = event.clientX;
      const startWidth = th.getBoundingClientRect().width;
      document.body.classList.add('col-resizing');

      const move = e => {{
        const width = Math.max(48, startWidth + e.clientX - startX);
        th.style.width = width + 'px';
        th.style.minWidth = width + 'px';
        th.style.maxWidth = width + 'px';
      }};
      const stop = () => {{
        document.removeEventListener('mousemove', move);
        document.removeEventListener('mouseup', stop);
        document.body.classList.remove('col-resizing');
      }};
      document.addEventListener('mousemove', move);
      document.addEventListener('mouseup', stop);
    }});

    handle.addEventListener('click', event => {{
      event.preventDefault();
      event.stopPropagation();
    }});
    handle.addEventListener('dblclick', event => {{
      event.preventDefault();
      event.stopPropagation();
      th.style.removeProperty('width');
      th.style.removeProperty('min-width');
      th.style.removeProperty('max-width');
    }});
  }});
}}

// ── 初始化 ────────────────────────────────────────────────────────────────────
initAutoRefresh();
setView(storageGet(SWITCH_VIEW_KEY) === 'list' ? 'list' : 'card', false);
refreshZtpMonitorControl();
refreshSwitchCollectionControl();
refreshManualZtpControl();
convertDisplayedTimes();
document.querySelectorAll('iframe').forEach(frame => {{
  frame.addEventListener('load', () => {{
    try {{ convertDisplayedTimes(frame.contentDocument?.body); }}
    catch (_error) {{ /* a future cross-origin diagram remains isolated */ }}
  }});
}});
initColumnResize();
spx.initCollapse();
ibl.initCollapse();
nvl.initCollapse();
initCollapsePersistence();
spx.applyFilters();
ibl.applyFilters();
nvl.applyFilters();
filterTopology('etop-topo');
filterTopology('itop-topo');
</script>
</body>
</html>"""


# ══════════════════════════════════════════════════════════════════════════════
# 主函数
# ══════════════════════════════════════════════════════════════════════════════

def _generate_monitor_html(scope: str = "all") -> None:
    global ENVIRONMENT_SCOPE
    ENVIRONMENT_SCOPE = scope
    log("=== generate-monitor-html start ===")
    log(f"[ENV] 页面数据范围: {scope}")

    ztp_status = load_ztp_status(scope=scope)
    if ztp_status.get("available"):
        log(f"[ZTP] 读取最新报告: {ztp_status['source']}")
    else:
        log(f"[ZTP] 无可用报告: {ztp_status.get('error', ZTP_STATUS_DIR)}")

    # ── ETH-INFO ─────────────────────────────────────────────────────────────
    eth_cards  = {
        "air": "", "production": "", "unknown": "",
        "air_count": 0, "production_count": 0, "unknown_count": 0,
        "unbound_air": "", "unbound_production": "", "unbound_unknown": "",
        "unbound_air_count": 0, "unbound_production_count": 0,
        "unbound_unknown_count": 0,
    }
    eth_list   = {
        "air": "", "production": "", "unknown": "",
        "unbound_air": "", "unbound_production": "", "unbound_unknown": "",
    }
    rendered_eth_names = {"air": set(), "production": set(), "unknown": set()}
    eth_source = "（无数据）"
    eth_count  = 0
    eth_transceiver_temps: dict[
        str, dict[str, tuple[float, Optional[float]]]
    ] = {}
    dynamic_air_inventory = (
        load_dynamic_air_inventory(ETH_LOG)
        if "air" in selected_environments(scope) else []
    )
    dynamic_air_metadata = {
        str(device.get("hostname") or "").casefold(): device
        for device in dynamic_air_inventory
        if str(device.get("hostname") or "").strip()
    }
    runtime_cumulus_inventory = [
        device for device in ztp_status.get("devices", [])
        if isinstance(device, dict)
        and bool(device.get("unbound_identity"))
        and bool(device.get("managed_ztp"))
        and str(device.get("platform_family") or "").casefold() == "cumulus"
        and ztp_environment(device) in selected_ztp_environments(scope)
    ]
    runtime_cumulus_metadata = {
        str(device.get("hostname") or "").casefold(): device
        for device in runtime_cumulus_inventory
        if str(device.get("hostname") or "").strip()
    }
    runtime_unclassified_inventory = [
        device for device in ztp_status.get("devices", [])
        if isinstance(device, dict)
        and bool(device.get("unbound_identity"))
        and str(device.get("platform_family") or "").casefold() != "cumulus"
        and ztp_environment(device) in selected_ztp_environments(scope)
        and str(device.get("hostname") or "").strip()
    ]
    if dynamic_air_inventory:
        resolved_count = sum(bool(device.get("ip")) for device in dynamic_air_inventory)
        log(
            f"[ETH-AIR] 动态设备元数据: {len(dynamic_air_inventory)} 台 "
            f"(已解析地址 {resolved_count}，未解析 "
            f"{len(dynamic_air_inventory) - resolved_count})"
        )

    if ETH_INFO_DIR.is_dir():
        tar_paths = find_latest_eth_tars(ETH_INFO_DIR)
        if tar_paths:
            switch_infos = []
            source_labels = []
            try:
                for environment in selected_environments(scope):
                    tar_path = tar_paths.get(environment)
                    if tar_path is None:
                        log(f"[ETH-{environment.upper()}] 未找到归档")
                        continue
                    info_files = extract_info_files(tar_path)
                    log(
                        f"[ETH-{environment.upper()}] 读取最新归档: {tar_path.name} "
                        f"({len(info_files)} 个 .info 文件)"
                    )
                    source_labels.append(
                        f"{'AIR' if environment == 'air' else 'Production'}: {tar_path.name}"
                    )
                    archive_time_utc = parse_archive_time_utc(tar_path)
                    parsed_switches = [
                        parse_info_file(hostname, content, archive_time_utc)
                        for hostname, content in info_files.items()
                    ]
                    # 本区块的数据源就是 Ethernet 归档。AIR 的虚拟平台输出
                    # 无法可靠推断系统类型时也必须与 Production 一样显示 ETH。
                    for switch in parsed_switches:
                        switch["sw_type"] = "ETH"
                        switch["collection_attempt_time"] = format_collection_batch_time(
                            archive_time_utc
                        )
                        # Archive provenance remains authoritative even though
                        # hostname is now also environment-specific.
                        switch["environment"] = environment
                    switch_infos.extend(parsed_switches)
                eth_source = "；".join(source_labels) or "（无数据）"
                eth_count = len(switch_infos)
                eth_transceiver_temps = {
                    sw["hostname"]: sw["transceiver_temps"]
                    for sw in switch_infos if sw["transceiver_temps"]
                }
                inventory = load_ztp_inventory(ETH_LOG)
                for hostname, device in dynamic_air_metadata.items():
                    inventory.setdefault(hostname, {
                        "type": "air",
                        "template": str(device.get("template") or ""),
                    })
                for hostname, device in runtime_cumulus_metadata.items():
                    inventory.setdefault(hostname, {
                        "hostname": str(device.get("hostname") or ""),
                        "type": "pending_eth",
                        "template": str(device.get("template") or "default"),
                        "eth0_ip": str(device.get("ip") or ""),
                        "eth0_mac": str(device.get("mac") or ""),
                        "dynamic_dhcp": "true",
                    })
                allowed_by_environment = {
                    "air": {
                        hostname for hostname, value in inventory.items()
                        if value.get("type") in {"air", "pending_eth"}
                    },
                    "production": {
                        hostname for hostname, value in inventory.items()
                        if value.get("type") in {"eth", "eth_spx", "spx", "pending_eth"}
                    },
                }
                current_switch_infos = []
                for switch in switch_infos:
                    environment = switch_environment(switch)
                    hostname_key = str(switch.get("hostname") or "").casefold()
                    if hostname_key not in allowed_by_environment.get(environment, set()):
                        log(
                            f"[ETH-{environment.upper()}] 忽略不在当前清单中的旧归档设备: "
                            f"{switch.get('hostname', '')}"
                        )
                        continue
                    current_switch_infos.append(switch)
                switch_infos = current_switch_infos
                for switch in switch_infos:
                    current = match_inventory_metadata(switch["hostname"], inventory)
                    switch["template"] = current.get("template", "")
                    runtime_device = runtime_cumulus_metadata.get(
                        str(switch.get("hostname") or "").casefold()
                    )
                    if runtime_device is not None:
                        switch["dynamic_dhcp"] = True
                        switch["management_ip"] = str(runtime_device.get("ip") or "")
                # Each archive is compared only with its own type-filtered
                # slice of the unified inventory.
                expected_sources = {
                    "air": (ETH_LOG, {"air"}),
                    "production": (ETH_LOG, {"eth", "eth_spx", "spx"}),
                }
                for environment, (inventory_path, device_types) in expected_sources.items():
                    if environment not in selected_environments(scope):
                        continue
                    archive_path = tar_paths.get(environment)
                    expected_hostnames = (
                        read_host_csv(inventory_path, device_types)
                        if archive_path is not None else []
                    )
                    if environment == "air":
                        expected_hostnames.extend(
                            str(device.get("hostname") or "")
                            for device in dynamic_air_inventory
                            if str(device.get("hostname") or "").strip()
                        )
                    expected_hostnames.extend(
                        str(device.get("hostname") or "")
                        for device in runtime_cumulus_inventory
                        if ztp_environment(device) == environment
                        and str(device.get("hostname") or "").strip()
                    )
                    if not expected_hostnames:
                        continue
                    found_names = {
                        sw["hostname"] for sw in switch_infos
                        if switch_environment(sw) == environment
                    }
                    seen_expected: set[str] = set()
                    for hostname in expected_hostnames:
                        hostname_key = hostname.casefold()
                        if hostname_key in seen_expected:
                            continue
                        seen_expected.add(hostname_key)
                        if host_matched(hostname, found_names):
                            continue
                        log(f"[ETH-{environment.upper()}] 缺失设备: {hostname}")
                        dynamic_device = (
                            dynamic_air_metadata.get(hostname_key)
                            if environment == "air" and hostname_key in dynamic_air_metadata
                            else runtime_cumulus_metadata.get(hostname_key)
                        )
                        if archive_path is None and dynamic_device is not None:
                            # Another environment may already have an archive,
                            # which brings execution into this branch even
                            # though this environment has never been collected.
                            # Preserve the distinction between "not attempted"
                            # and a real missing member in an existing batch.
                            missing = runtime_switch_placeholder(
                                dynamic_device, platform_group="cumulus",
                            )
                            if environment == "air" and hostname_key in dynamic_air_metadata:
                                missing["collection_error"] = (
                                    "AIR-only Cumulus 身份已由 AIR JSON/baseline 绑定；"
                                    "当前没有可用的 Switch Status 采集归档"
                                )
                        else:
                            missing = make_missing_switch(hostname, "ETH")
                        missing["environment"] = environment
                        if archive_path is not None:
                            missing["collection_attempt_time"] = format_collection_batch_time(
                                parse_archive_time_utc(archive_path)
                            )
                        missing["template"] = inventory.get(
                            hostname_key, {}
                        ).get("template", "")
                        if dynamic_device is not None:
                            missing["dynamic_dhcp"] = True
                            missing["management_ip"] = str(dynamic_device.get("ip") or "")
                            if not dynamic_device.get("ip"):
                                if archive_path is None:
                                    missing["collection_error"] += "；动态 DHCP 地址尚未解析"
                                else:
                                    missing["collection_error"] = (
                                        "动态 DHCP 地址尚未解析；本批次未返回采集文件"
                                    )
                        switch_infos.append(missing)
                switch_infos.sort(key=lambda s: air_first_hostname_key(s["hostname"]))
                eth_count = len(switch_infos)
                environment_switches = {
                    "air": [sw for sw in switch_infos if switch_environment(sw) == "air"],
                    "production": [
                        sw for sw in switch_infos
                        if switch_environment(sw) == "production"
                    ],
                }
                for environment, items in environment_switches.items():
                    rendered_eth_names[environment] = {
                        str(item.get("hostname") or "").casefold() for item in items
                    }
                    eth_cards[f"{environment}_count"] = len(items)
                    eth_cards[environment] = build_switch_cards_html(
                        items, _ETH_CATEGORIES, "ETH", group_environments=False,
                    )
                    eth_list[environment] = build_switch_list_html(
                        items, _ETH_CATEGORIES, "ETH", group_environments=False,
                    )
            except Exception as e:
                log(f"[ETH] 解析失败: {e}")
                eth_cards["production"] = f'<p style="padding:20px;color:#c0392b">解析 eth-info 时出错: {escape(str(e))}</p>'
        else:
            log("[ETH] 未找到 AIR 或 Production tar.gz 文件")
    else:
        log(f"[ETH] 目录不存在: {ETH_INFO_DIR}")

    # Runtime Cumulus identities must remain visible before the first Ethernet
    # archive exists.  When an archive was parsed above, only add names that it
    # did not already contain; this also prevents a stale synthetic alias from
    # creating a second card after canonical MAC promotion.
    runtime_eth_candidates: list[tuple[dict, bool]] = [
        (device, False) for device in runtime_cumulus_inventory
    ] + [
        (device, True) for device in dynamic_air_inventory
    ]
    for environment in selected_ztp_environments(scope):
        extra_switches = []
        for device, is_air_baseline in runtime_eth_candidates:
            if ztp_environment(device) != environment:
                continue
            hostname = str(device.get("hostname") or "").strip()
            hostname_key = hostname.casefold()
            if not hostname or hostname_key in rendered_eth_names[environment]:
                continue
            missing = runtime_switch_placeholder(device, platform_group="cumulus")
            if is_air_baseline:
                missing["collection_error"] = (
                    "AIR-only Cumulus 身份已由 AIR JSON/baseline 绑定；"
                    "当前没有可用的 Switch Status 采集归档"
                )
            extra_switches.append(missing)
            rendered_eth_names[environment].add(hostname_key)
            log(f"[ETH-{environment.upper()}] 无归档动态占位: {hostname}")
        if not extra_switches:
            continue
        extra_switches.sort(key=lambda item: air_first_hostname_key(item["hostname"]))
        eth_cards[environment] += build_switch_cards_html(
            extra_switches, _ETH_CATEGORIES, "ETH", group_environments=False,
        )
        eth_list[environment] += build_switch_list_html(
            extra_switches, _ETH_CATEGORIES, "ETH", group_environments=False,
        )
        eth_cards[f"{environment}_count"] += len(extra_switches)
        eth_count += len(extra_switches)

    # NVOS identities that have not been bound to a project hostname, and true
    # unknown DHCP clients, are observations rather than collector targets.
    # Keep them in an explicit environment-scoped Other section and never place
    # them under a formal Ethernet/IB/NVLink inventory.
    for environment in selected_ztp_environments(scope):
        placeholders = [
            runtime_switch_placeholder(device, platform_group="unclassified")
            for device in runtime_unclassified_inventory
            if ztp_environment(device) == environment
        ]
        placeholders.sort(key=lambda item: air_first_hostname_key(item["hostname"]))
        eth_cards[f"unbound_{environment}_count"] = len(placeholders)
        eth_cards[f"unbound_{environment}"] = build_switch_cards_html(
            placeholders, _UNBOUND_CATEGORIES, "UNKNOWN",
            group_environments=False,
        )
        eth_list[f"unbound_{environment}"] = build_switch_list_html(
            placeholders, _UNBOUND_CATEGORIES, "UNKNOWN",
            group_environments=False,
        )

    # ── IB-INFO ──────────────────────────────────────────────────────────────
    ib_cards  = ""
    ib_list   = ""
    ib_source = "（无数据）"
    ib_count  = 0
    ib_transceiver_temps: dict[
        str, dict[str, tuple[float, Optional[float]]]
    ] = {}

    if IB_INFO_DIR.is_dir():
        tar_path = find_latest_tar(IB_INFO_DIR)
        if tar_path:
            log(f"[IB] 读取最新归档: {tar_path.name}")
            ib_source = tar_path.name
            try:
                info_files = extract_info_files(tar_path)
                ib_count   = len(info_files)
                log(f"[IB] 找到 {ib_count} 个 .info 文件")
                archive_time_utc = parse_archive_time_utc(tar_path)
                switch_infos = [
                    parse_info_file(hn, content, archive_time_utc)
                    for hn, content in info_files.items()
                ]
                for switch in switch_infos:
                    switch["collection_attempt_time"] = format_collection_batch_time(
                        archive_time_utc
                    )
                ib_transceiver_temps = {
                    sw["hostname"]: sw["transceiver_temps"]
                    for sw in switch_infos if sw["transceiver_temps"]
                }
                ib_log_hosts = read_host_csv(IB_LOG, {"ib"}) if info_files else []
                found_names = {sw["hostname"] for sw in switch_infos}
                for lh in ib_log_hosts:
                    if not host_matched(lh, found_names):
                        log(f"[IB] 缺失设备: {lh}")
                        missing = make_missing_switch(lh, "IB")
                        missing["collection_attempt_time"] = format_collection_batch_time(
                            archive_time_utc
                        )
                        switch_infos.append(missing)
                switch_infos.sort(key=lambda s: air_first_hostname_key(s["hostname"]))
                ib_count = len(switch_infos)
                ib_cards = build_switch_cards_html(switch_infos, _IB_CATEGORIES, "IB")
                ib_list  = build_switch_list_html(switch_infos, _IB_CATEGORIES, "IB")
            except Exception as e:
                log(f"[IB] 解析失败: {e}")
                ib_cards = f'<p style="padding:20px;color:#c0392b">解析 ib-info 时出错: {escape(str(e))}</p>'
        else:
            log("[IB] 未找到 tar.gz 文件")
    else:
        log(f"[IB] 目录不存在: {IB_INFO_DIR}")

    # ── SPX-LINK ──────────────────────────────────────────────────────────────
    spx_thead      = "<tr><th>（无数据）</th></tr>"
    spx_tbody      = '<tr><td colspan="1" style="padding:20px;text-align:center;color:#6c757d">spx-link/ 目录下没有 CSV 文件。</td></tr>'
    spx_stats      = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    spx_latest_ts  = None
    spx_snap_count = 0

    if SPX_LINK_DIR.is_dir():
        cutoff = datetime.now() - timedelta(days=3)
        csv_paths = sorted(
            (p for p in SPX_LINK_DIR.glob("*.csv")
             if (ts := parse_snap_ts(p.stem)) is not None and ts >= cutoff),
            key=lambda p: p.name,
            reverse=True,
        )[:SPX_MAX_SNAPS]
        log(f"[SPX] 找到 {len(csv_paths)} 个近3天 CSV 文件")
        spx_snap_count = len(csv_paths)

        if csv_paths:
            snaps = []
            for p in csv_paths:
                ts = parse_snap_ts(p.stem)
                if ts is None:
                    continue
                try:
                    headers, data = load_csv_snap(p)
                    snaps.append((ts, p, data))
                except Exception as e:
                    log(f"[SPX] 加载 {p.name} 失败: {e}")

            if snaps:
                snaps.sort(key=lambda x: x[0], reverse=True)
                spx_latest_ts = snaps[0][0]
                # 优先选有有效表头的最新快照（跳过空文件）
                latest_path = next((p for _, p, _ in snaps if len(load_csv_snap(p)[0]) >= 2), None)
                if latest_path is None:
                    log("[SPX] 所有快照均为空，跳过")
                else:
                    headers, latest_data = load_csv_snap(latest_path)
                    log(f"[SPX] 最新快照: {latest_path.name}  ({len(latest_data)} 行)")
                    spx_thead, spx_tbody, spx_stats, _ = build_link_content(
                        snaps, headers, latest_data, spx_latest_ts,
                        SPX_DIFF_HOURS, SPX_WATCH_FIELDS, eth_transceiver_temps,
                    )
            else:
                log("[SPX] 没有有效快照")
    else:
        log(f"[SPX] 目录不存在: {SPX_LINK_DIR}")

    # ── IB-LINK ───────────────────────────────────────────────────────────────
    ibl_thead      = "<tr><th>（无数据）</th></tr>"
    ibl_tbody      = '<tr><td colspan="1" style="padding:20px;text-align:center;color:#6c757d">ib-link/ 目录下没有 CSV 文件。</td></tr>'
    ibl_stats      = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    ibl_latest_ts  = None
    ibl_snap_count = 0

    if IBL_LINK_DIR.is_dir():
        cutoff = datetime.now() - timedelta(days=3)
        csv_paths = sorted(
            (p for p in IBL_LINK_DIR.glob("*.csv")
             if (ts := parse_snap_ts(p.stem)) is not None and ts >= cutoff),
            key=lambda p: p.name,
            reverse=True,
        )[:IBL_MAX_SNAPS]
        log(f"[IB-LINK] 找到 {len(csv_paths)} 个近3天 CSV 文件")
        ibl_snap_count = len(csv_paths)

        if csv_paths:
            snaps = []
            for p in csv_paths:
                ts = parse_snap_ts(p.stem)
                if ts is None:
                    continue
                try:
                    headers, data = load_csv_snap(p)
                    snaps.append((ts, p, data))
                except Exception as e:
                    log(f"[IB-LINK] 加载 {p.name} 失败: {e}")

            if snaps:
                snaps.sort(key=lambda x: x[0], reverse=True)
                ibl_latest_ts = snaps[0][0]
                latest_path = next((p for _, p, _ in snaps if len(load_csv_snap(p)[0]) >= 2), None)
                if latest_path is None:
                    log("[IB-LINK] 所有快照均为空，跳过")
                else:
                    headers, latest_data = load_csv_snap(latest_path)
                    log(f"[IB-LINK] 最新快照: {latest_path.name}  ({len(latest_data)} 行)")
                    ibl_thead, ibl_tbody, ibl_stats, _ = build_link_content(
                        snaps, headers, latest_data, ibl_latest_ts,
                        IBL_DIFF_HOURS, IBL_WATCH_FIELDS, ib_transceiver_temps,
                    )
            else:
                log("[IB-LINK] 没有有效快照")
    else:
        log(f"[IB-LINK] 目录不存在: {IBL_LINK_DIR}")

    # ── NV-INFO ──────────────────────────────────────────────────────────────
    nv_cards  = ""
    nv_list   = ""
    nv_source = "（无数据）"
    nv_count  = 0

    if NV_INFO_DIR.is_dir():
        tar_path = find_latest_tar(NV_INFO_DIR)
        if tar_path:
            log(f"[NV] 读取最新归档: {tar_path.name}")
            nv_source = tar_path.name
            try:
                info_files = extract_info_files(tar_path)
                nv_count   = len(info_files)
                log(f"[NV] 找到 {nv_count} 个 .info 文件")
                archive_time_utc = parse_archive_time_utc(tar_path)
                switch_infos = [
                    parse_info_file(hn, content, archive_time_utc)
                    for hn, content in info_files.items()
                ]
                for switch in switch_infos:
                    switch["collection_attempt_time"] = format_collection_batch_time(
                        archive_time_utc
                    )
                nv_log_hosts = read_host_csv(NV_LOG, {"nvl"}) if info_files else []
                found_names = {sw["hostname"] for sw in switch_infos}
                for lh in nv_log_hosts:
                    if not host_matched(lh, found_names):
                        log(f"[NV] 缺失设备: {lh}")
                        missing = make_missing_switch(lh, "NVL")
                        missing["collection_attempt_time"] = format_collection_batch_time(
                            archive_time_utc
                        )
                        switch_infos.append(missing)
                switch_infos.sort(key=lambda s: air_first_hostname_key(s["hostname"]))
                nv_count = len(switch_infos)
                nv_categories = build_nvlink_categories(switch_infos)
                nv_cards = build_switch_cards_html(switch_infos, nv_categories, "NVL")
                nv_list  = build_switch_list_html(switch_infos, nv_categories, "NVL")
            except Exception as e:
                log(f"[NV] 解析失败: {e}")
                nv_cards = f'<p style="padding:20px;color:#c0392b">解析 nvsw-info 时出错: {escape(str(e))}</p>'
        else:
            log("[NV] 未找到 tar.gz 文件")
    else:
        log(f"[NV] 目录不存在: {NV_INFO_DIR}")

    # ── NVL-LINK ──────────────────────────────────────────────────────────────
    nvl_thead      = "<tr><th>（无数据）</th></tr>"
    nvl_tbody      = '<tr><td colspan="1" style="padding:20px;text-align:center;color:#6c757d">nvsw-link/ 目录下没有 CSV 文件。</td></tr>'
    nvl_stats      = {"changed": 0, "new": 0, "removed": 0, "same": 0}
    nvl_latest_ts  = None
    nvl_snap_count = 0

    if NVL_LINK_DIR.is_dir():
        cutoff = datetime.now() - timedelta(days=3)
        csv_paths = sorted(
            (p for p in NVL_LINK_DIR.glob("*.csv")
             if (ts := parse_snap_ts(p.stem)) is not None and ts >= cutoff),
            key=lambda p: p.name,
            reverse=True,
        )[:NVL_MAX_SNAPS]
        log(f"[NVL-LINK] 找到 {len(csv_paths)} 个近3天 CSV 文件")
        nvl_snap_count = len(csv_paths)

        if csv_paths:
            snaps = []
            for p in csv_paths:
                ts = parse_snap_ts(p.stem)
                if ts is None:
                    continue
                try:
                    headers, data = load_csv_snap(p)
                    snaps.append((ts, p, data))
                except Exception as e:
                    log(f"[NVL-LINK] 加载 {p.name} 失败: {e}")

            if snaps:
                snaps.sort(key=lambda x: x[0], reverse=True)
                nvl_latest_ts = snaps[0][0]
                latest_path = next((p for _, p, _ in snaps if len(load_csv_snap(p)[0]) >= 2), None)
                if latest_path is None:
                    log("[NVL-LINK] 所有快照均为空，跳过")
                else:
                    headers, latest_data = load_csv_snap(latest_path)
                    log(f"[NVL-LINK] 最新快照: {latest_path.name}  ({len(latest_data)} 行)")
                    nvl_thead, nvl_tbody, nvl_stats, _ = build_link_content(
                        snaps, headers, latest_data, nvl_latest_ts,
                        NVL_DIFF_HOURS, NVL_WATCH_FIELDS,
                        show_transceiver_temp=False,
                    )
            else:
                log("[NVL-LINK] 没有有效快照")
    else:
        log(f"[NVL-LINK] 目录不存在: {NVL_LINK_DIR}")

    # ── 拓扑验证报告 ─────────────────────────────────────────────────────────
    topology_reports = {}
    for network in ("ethernet", "infiniband"):
        try:
            report = load_topology_validation(P2P_OUTPUT_DIR, network, scope=scope)
            topology_reports[network] = report
            if report.get("path"):
                log(f"[TOPOLOGY-{network.upper()}] 最新报告: {report['source']}")
            else:
                log(f"[TOPOLOGY-{network.upper()}] 未找到验证报告")
        except (OSError, ValueError, KeyError, zipfile.BadZipFile, ET.ParseError) as exc:
            log(f"[TOPOLOGY-{network.upper()}] 读取失败: {exc}")
            topology_reports[network] = {
                "path": None, "source": "（读取失败）", "generated": "—",
                "result": "ERROR", "summary": {}, "sections": [], "counts": {},
            }

    # ── Ethernet 拓扑图 ─────────────────────────────────────────────────────
    diagram_stem = preferred_p2p_stem()
    try:
        ethernet_diagram, diagram_generated = ensure_latest_diagram(
            P2P_OUTPUT_DIR, "*-lldpq.dot", "*-lldpq.html", diagram_stem
        )
        if ethernet_diagram.get("path"):
            action = "已生成" if diagram_generated else "使用现有文件"
            log(
                f"[ETHERNET-DIAGRAM] {action}: "
                f"{ethernet_diagram['source']}"
            )
        else:
            log("[ETHERNET-DIAGRAM] 未找到 *-lldpq.dot 或 *lldpq.html")
    except (OSError, UnicodeError, ValueError) as exc:
        log(f"[ETHERNET-DIAGRAM] 生成或读取失败: {exc}")
        ethernet_diagram = {
            "path": None, "source": "（读取失败）", "href": "", "modified": "—",
        }

    # ── AIR 拓扑图 ──────────────────────────────────────────────────────────
    try:
        air_diagram, air_diagram_generated = ensure_latest_diagram(
            P2P_OUTPUT_DIR, "*-air.dot", "*-air.html", diagram_stem
        )
        if air_diagram.get("path"):
            action = "已生成" if air_diagram_generated else "使用现有文件"
            log(f"[AIR-DIAGRAM] {action}: {air_diagram['source']}")
        else:
            log("[AIR-DIAGRAM] 未找到 *-air.dot 或 *-air.html")
    except (OSError, UnicodeError, ValueError) as exc:
        log(f"[AIR-DIAGRAM] 生成或读取失败: {exc}")
        air_diagram = {
            "path": None, "source": "（读取失败）", "href": "", "modified": "—",
        }

    # AIR currently contains Cumulus simulation devices only. Explicit scope
    # must not leak Production-only IB/NVL collection data. The Ethernet
    # diagram is generated from the project P2P design rather than collected
    # runtime data, so it remains available in both AIR and Production views.
    empty_diagram = {"path": None, "source": "（当前环境未选择）", "href": "", "modified": "—"}
    if scope == "air":
        ib_cards = ib_list = nv_cards = nv_list = ""
        ib_count = nv_count = 0
        ibl_thead = nvl_thead = "<tr><th>（当前环境未选择）</th></tr>"
        ibl_tbody = nvl_tbody = '<tr><td>Production 数据未选择。</td></tr>'
        topology_reports["infiniband"] = {
            "path": None, "source": "（当前环境未选择）", "generated": "—",
            "result": "NO DATA", "summary": {}, "sections": [], "counts": {},
            "sources": {}, "downloads": [],
        }
    elif scope == "prod":
        eth_cards["air"] = ""
        eth_cards["air_count"] = 0
        eth_list["air"] = ""
        air_diagram = empty_diagram

    # ── 写出 HTML ────────────────────────────────────────────────────────────
    html = build_html(
        eth_cards, eth_source, eth_count,
        ib_cards,  ib_source,  ib_count,
        eth_list,  ib_list,
        spx_thead, spx_tbody, spx_stats, spx_latest_ts, spx_snap_count,
        ibl_thead, ibl_tbody, ibl_stats, ibl_latest_ts, ibl_snap_count,
        nv_cards,  nv_source,  nv_count,
        nv_list,
        nvl_thead, nvl_tbody, nvl_stats, nvl_latest_ts, nvl_snap_count,
        topology_reports["ethernet"],
        topology_reports["infiniband"],
        ethernet_diagram,
        air_diagram,
        ztp_status,
    )
    atomic_write_text(OUTPUT, html)
    log(f"完成 → {OUTPUT}  ({len(html):,} 字节)")
    log("=== generate-monitor-html end ===")


def main(scope: str = "all") -> None:
    """Build and atomically publish one coherent monitor page."""
    with generation_lock():
        _generate_monitor_html(scope)


def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="汇总 ZTP、Ethernet、InfiniBand 和 NVLink 采集数据并生成 monitor.html。"
    )
    environment = parser.add_mutually_exclusive_group()
    environment.add_argument("--type", choices=("all", "prod", "air"), dest="scope")
    environment.add_argument("--air", action="store_const", const="air", dest="scope")
    environment.add_argument("--prod", action="store_const", const="prod", dest="scope")
    parser.set_defaults(scope="all")
    return parser.parse_args(argv)


if __name__ == "__main__":
    main(parse_args().scope)
