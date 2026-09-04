#!/usr/bin/env python3
"""Validate, activate and prepare one DAY0 deployment project end to end.

The script deliberately separates reversible preparation from the final service
start. Apache and DHCP start with ``--start-services`` or unless the operator
declines the default-yes service prompt. A second default-yes bounded prompt
starts the detached ZTP status monitor after the load flow succeeds.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass, replace
from datetime import datetime
import getpass
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import secrets
import select
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile

try:
    import yaml
except ModuleNotFoundError:
    yaml = None


HERE = Path(__file__).resolve().parent
HTTP_ROOT = HERE.parent
TOOLS_DIR = HTTP_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
from project_contract import (
    GLOBAL_SCHEMA_VERSION,
    detect_global_schema_version,
    normalize_v2_mlag_policy,
    normalize_v2_vrr_policy,
    parse_device_csv_layout,
    require_device_csv_row_width,
    validate_ztp_url_prefix,
)
from deployment_lock import (
    DeploymentLockError,
    acquire_lock_path_descriptor,
    inherited_lock_subprocess_kwargs,
    release_lock_descriptor,
)
TEMPLATE_DIR = HERE / "template"
IMAGE_DIR = HTTP_ROOT / "image"
ZTP_DIR = HTTP_ROOT / "ztp"
INFRA_DIR = HTTP_ROOT / "infra"
SETUP_SCRIPT = HERE / "01-a-setup.py"
ZTP_MONITOR_SCRIPT = HERE / "12-ztp-monitor.py"
ZTP_MONITOR_HTML_SCRIPT = HTTP_ROOT / "monitor/generate-monitor-html.py"
ZTP_MONITOR_CONTROL_SOURCE = HTTP_ROOT / "monitor/ztp-monitor-control.cgi"
ZTP_MONITOR_CONTROL_DEST = Path("/usr/lib/cgi-bin/ztp-monitor-control")
SWITCH_COLLECTION_WORKER = HTTP_ROOT / "monitor/switch-collection-worker.py"
SWITCH_COLLECTION_CONTROL_SOURCE = HTTP_ROOT / "monitor/switch-collection-control.cgi"
SWITCH_COLLECTION_CONTROL_DEST = Path("/usr/lib/cgi-bin/switch-collection-control")
MANUAL_ZTP_WORKER = HTTP_ROOT / "monitor/manual-ztp-worker.py"
MANUAL_ZTP_CONTROL_SOURCE = HTTP_ROOT / "monitor/manual-ztp-control.cgi"
MANUAL_ZTP_CONTROL_DEST = Path("/usr/lib/cgi-bin/manual-ztp-control")
APACHE_PUBLIC_BOUNDARY_CONF = Path(
    "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
)
APACHE_PUBLIC_BOUNDARY_SHA256 = (
    "bcb8cb2cd56a15e0415225dd7ed80546c78767ffcea16bbde68e985ecd40aee1"
)
MANIFEST = ZTP_DIR / ".setup_manifest"
DEPLOYMENT_LOCK = HTTP_ROOT / ".deployment.lock"
ZTP_PREFIX_MARKER = HTTP_ROOT / ".ztp-prefix-publication.json"
PROMPT_TIMEOUT = 15
DEFAULT_ZTP_MONITOR_INTERVAL = 30
VALID_TYPES = {"eth", "eth_spx", "spx", "ib", "nvl", "server", "air"}
BOOTSTRAP_BY_ROLE = {
    "air_oobofoob": "ztp-bootstrap_oobofoob.sh",
    "air_oob": "ztp-bootstrap_oob.sh",
    "prod_oobofoob": "ztp-bootstrap_oobofoob.sh",
    "prod_oob": "ztp-bootstrap_oob.sh",
}
SERVICE_IP_PRIORITY = (
    "air_oob", "air_oobofoob", "prod_oob", "prod_oobofoob",
)
ROLES_BY_BOOTSTRAP = {
    "ztp-bootstrap_oob.sh": ("air_oob", "prod_oob"),
    "ztp-bootstrap_oobofoob.sh": ("air_oobofoob", "prod_oobofoob"),
}
PROFILE_BY_BOOTSTRAP = {
    "ztp-bootstrap_oob.sh": "oob",
    "ztp-bootstrap_oobofoob.sh": "oobofoob",
}
BOOTSTRAP_BY_PROFILE = {
    profile: bootstrap for bootstrap, profile in PROFILE_BY_BOOTSTRAP.items()
}
SUBNET_BASE_COLUMNS = {
    "shared_network", "subnet", "netmask", "range_start", "range_end", "routers",
}
SUBNET_ZTP_COLUMNS = {"ztp_service_ip", "cumulus_profile", "nvos_ztp"}
LEGACY_SUBNET_URL_COLUMNS = {"bootfile_name", "cumulus_provision_url"}
SAFE_HOSTNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
DEVICE_HEADER_PREFIX = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
)


class LoadError(RuntimeError):
    pass


@dataclass
class PreparedParentRelease:
    """A fully written parent manifest waiting for its single atomic commit."""

    destination: Path
    temporary: Path
    release_id: str
    committed: bool = False


@dataclass(frozen=True)
class ServiceRuntimeState:
    """The enabled/active bits which service-start rollback must restore."""

    enabled: bool
    active: bool


@dataclass(frozen=True)
class ZtpPrefixPublicationSnapshot:
    """Recoverable state spanning prefix publication through parent commit."""

    marker: bytes | None
    links: dict[Path, tuple[str, str | None]]


@dataclass(frozen=True)
class GlobalSettings:
    dhcp_enabled: bool
    dhcp_package: str
    http_enabled: bool
    http_package: str
    http_root: Path
    ztp_enabled: bool
    ztp_prefix: str
    ztp_ips: dict[str, tuple[str, ...]]
    versions: dict[str, str]
    boot_ips: tuple[str, ...] = ()
    schema_version: int = GLOBAL_SCHEMA_VERSION

    @property
    def service_ips(self) -> tuple[str, ...]:
        """All distinct HTTP/ZTP addresses derived from declarative subnet rows."""
        values = [
            address
            for role in SERVICE_IP_PRIORITY
            for address in self.ztp_ips.get(role, ())
        ]
        values.extend(self.boot_ips)
        return tuple(dict.fromkeys(values))


@dataclass(frozen=True)
class ProjectInputs:
    global_file: Path
    devices_file: Path
    subnet_file: Path
    p2p_file: Path
    device_types: frozenset[str]
    pubkeys: tuple[Path, ...]
    settings: GlobalSettings


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(2, 58 - len(title)))


def ok(message: str) -> None:
    print(f"[OK] {message}")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def acquire_deployment_lock(*, exclusive: bool = True) -> int:
    """Acquire the process-wide deployment gate without waiting.

    Child generators publish their own ``latest`` links before the parent
    ``current-release.json`` commit.  Holding this lock across the whole load
    keeps every cooperating manual/GUI operation outside that short window.
    """
    try:
        return acquire_lock_path_descriptor(
            DEPLOYMENT_LOCK, exclusive=exclusive, create=True,
        )
    except DeploymentLockError as exc:
        raise LoadError(
            "另一个 load 或人工 ZTP/重置操作正在使用部署 release；"
            "请等待其完成后重试"
        ) from exc


def release_deployment_lock(descriptor: int | None) -> None:
    release_lock_descriptor(descriptor)


def runtime_os() -> str:
    """Return the host OS name used to gate Linux-only service operations."""
    return platform.system() or "Unknown"


def supports_local_ztp_services(os_name: str | None = None) -> bool:
    """Apache/ISC DHCP/infra service management is intentionally Linux-only."""
    return (os_name or runtime_os()).casefold() == "linux"


def run(
    command: list[str], *, cwd: Path | None = None, dry_run: bool = False,
    inherited_lock_descriptor: int | None = None,
) -> None:
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(f"[DRY] ({cwd or Path.cwd()}) {display}")
        return
    print(f"[RUN] ({cwd or Path.cwd()}) {display}")
    result = subprocess.run(
        command, cwd=cwd,
        **inherited_lock_subprocess_kwargs(inherited_lock_descriptor),
    )
    if result.returncode != 0:
        raise LoadError(f"命令执行失败（exit={result.returncode}）：{display}")


def shlex_quote(value: str) -> str:
    import shlex
    return shlex.quote(value)


def sudo_command(*args: str) -> list[str]:
    return [*([] if os.geteuid() == 0 else ["sudo"]), *args]


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def resolve_project(argument: str) -> Path:
    project = Path(argument).expanduser()
    if not project.is_absolute():
        if project.parts and project.parts[0] == HERE.name:
            project = Path(*project.parts[1:])
        project = HERE / project
    project = project.resolve()
    if not _inside(project, HERE) or project == HERE:
        raise LoadError(f"部署目录必须是 {HERE} 下的独立项目目录：{project}")
    return project


def _meaningful_entries(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return [item for item in directory.iterdir() if item.name not in {".DS_Store"}]


def initialize_from_template(project: Path, dry_run: bool = False) -> None:
    if not TEMPLATE_DIR.is_dir():
        raise LoadError(f"项目模板不存在：{TEMPLATE_DIR}")
    initializing = not project.exists() or not _meaningful_entries(project)
    if initializing:
        print(f"[INIT] 从 {TEMPLATE_DIR} 创建项目模板：{project}")
    else:
        print(
            f"[SYNC] 按 {TEMPLATE_DIR} 补齐项目模板合同：{project}"
            "（仅补缺失项，不覆盖已有内容）"
        )
    if dry_run:
        return
    project.mkdir(parents=True, exist_ok=True)
    for source in sorted(TEMPLATE_DIR.rglob("*")):
        relative = source.relative_to(TEMPLATE_DIR)
        destination = project / relative
        if source.is_symlink():
            destination.parent.mkdir(parents=True, exist_ok=True)
            if not destination.exists() and not destination.is_symlink():
                destination.symlink_to(os.readlink(source))
        elif source.is_dir():
            destination.mkdir(parents=True, exist_ok=True)
        elif not destination.exists():
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)


def _nonempty_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise LoadError(f"缺少 {label}：{path.name}")
    if path.stat().st_size == 0:
        raise LoadError(f"{label} 大小为 0：{path.name}；请准备真实内容后再次执行 load")


def _nonempty_release_file(path: Path, label: str) -> None:
    """Require an immutable-by-alias release control file.

    Release manifests and completion markers are trust anchors.  Following a
    symlink, or accepting a multiply linked inode, would let an out-of-tree
    pathname or another name mutate the bytes after the child release gate.
    """
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LoadError(f"缺少 {label}：{path.name}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LoadError(
            f"{label} 必须是非符号链接、单硬链接的普通文件：{path}"
        )
    if metadata.st_size == 0:
        raise LoadError(f"{label} 大小为 0：{path.name}")


def _enabled(value: object, label: str) -> bool:
    text = str(value or "").strip().casefold()
    if text not in {"enabled", "disabled"}:
        raise LoadError(f"{label} 必须是 enabled 或 disabled")
    return text == "enabled"


def _version_key(value: str) -> tuple[int, ...]:
    numbers = tuple(int(item) for item in re.findall(r"\d+", value))
    if not numbers:
        raise LoadError(f"无法识别版本号：{value!r}")
    return numbers


def _version_filename(value: str) -> str:
    parts = re.findall(r"\d+", value)
    if not parts:
        raise LoadError(f"无法识别版本号：{value!r}")
    return "-".join(parts)


def _validate_ztp_prefix(value: object) -> str:
    """Return the one canonical URL path prefix accepted by every generator."""
    try:
        return validate_ztp_url_prefix(value)
    except ValueError as exc:
        raise LoadError(str(exc)) from exc


def _prepare_subnet_reader(reader: csv.DictReader) -> None:
    """Normalize a subnet header and enforce the new fail-closed CSV contract."""
    fields = [str(field or "").strip() for field in (reader.fieldnames or [])]
    if len(fields) != len(set(fields)):
        raise LoadError("DHCP subnet CSV 存在重复列名")
    legacy = sorted(
        field for field in fields
        if field.casefold() in LEGACY_SUBNET_URL_COLUMNS
    )
    if legacy:
        raise LoadError(
            "DHCP subnet CSV 仍包含已废弃 URL 列："
            + ", ".join(legacy)
            + "；请改用 ztp_service_ip,cumulus_profile,nvos_ztp"
        )
    missing = sorted((SUBNET_BASE_COLUMNS | SUBNET_ZTP_COLUMNS) - set(fields))
    if missing:
        raise LoadError(f"DHCP subnet CSV 缺少列：{', '.join(missing)}")
    reader.fieldnames = fields


def _parse_subnet_ztp_fields(
    row: dict[str, object], lineno: int,
) -> tuple[str, str, str]:
    """Validate one declarative endpoint row and return canonical values."""
    profile = str(row.get("cumulus_profile") or "").strip().casefold()
    nvos_ztp = str(row.get("nvos_ztp") or "").strip().casefold()
    raw_ip = str(row.get("ztp_service_ip") or "").strip()
    if profile not in {"oob", "oobofoob", "none"}:
        raise LoadError(
            f"DHCP subnet CSV 第 {lineno} 行 cumulus_profile={profile!r} 无效；"
            "只允许 oob/oobofoob/none"
        )
    if nvos_ztp not in {"yes", "no"}:
        raise LoadError(
            f"DHCP subnet CSV 第 {lineno} 行 nvos_ztp={nvos_ztp!r} 无效；"
            "只允许 yes/no"
        )
    service_ip = ""
    if raw_ip:
        try:
            address = ipaddress.IPv4Address(raw_ip)
        except ipaddress.AddressValueError as exc:
            raise LoadError(
                f"DHCP subnet CSV 第 {lineno} 行 ztp_service_ip={raw_ip!r} "
                "不是有效 IPv4"
            ) from exc
        if address.is_unspecified or address.is_multicast:
            raise LoadError(
                f"DHCP subnet CSV 第 {lineno} 行 ztp_service_ip={address} "
                "不是可用单播地址"
            )
        service_ip = str(address)
    if (profile in BOOTSTRAP_BY_PROFILE or nvos_ztp == "yes") and not service_ip:
        raise LoadError(
            f"DHCP subnet CSV 第 {lineno} 行启用了平台 ZTP，"
            "但 ztp_service_ip 为空"
        )
    if profile == "none" and nvos_ztp == "no" and service_ip:
        raise LoadError(
            f"DHCP subnet CSV 第 {lineno} 行未启用任何平台 ZTP，"
            "ztp_service_ip 必须为空"
        )
    return service_ip, profile, nvos_ztp


def load_global(path: Path) -> GlobalSettings:
    _nonempty_file(path, "global.yaml")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise LoadError(f"global YAML 语法错误：{exc}") from exc
    if not isinstance(data, dict):
        raise LoadError("global.yaml 顶层必须是 mapping")
    try:
        schema_version = detect_global_schema_version(data)
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    if "schema_version" not in data:
        print("[WARN] 01-global.yaml 缺少 schema_version；按旧版 schema 1 兼容读取")
    try:
        common = data["common"]
        mgmt = common["mgmt"]
        dhcp = mgmt["dhcp-server"]
        http = mgmt["http"]
        ztp = mgmt["ztp"]
        switch_system = common["switch"]["system"]
    except (KeyError, TypeError) as exc:
        raise LoadError(
            f"global 缺少 common.mgmt.dhcp-server/http/ztp "
            f"或 common.switch.system：{exc}"
        ) from exc

    dhcp_enabled = _enabled(dhcp.get("status"), "common.mgmt.dhcp-server.status")
    dhcp_package = str(dhcp.get("package") or "").strip()
    if not dhcp_package:
        raise LoadError("common.mgmt.dhcp-server.package 不能为空")
    http_enabled = _enabled(http.get("status"), "common.mgmt.http.status")
    http_package = str(http.get("package") or "").strip()
    if not http_package:
        raise LoadError("common.mgmt.http.package 不能为空")
    http_root_text = str(http.get("http_root") or "").strip()
    if not http_root_text or not Path(http_root_text).is_absolute():
        raise LoadError("common.mgmt.http.http_root 必须是绝对路径")
    ztp_enabled = _enabled(ztp.get("status"), "common.mgmt.ztp.status")
    prefix = _validate_ztp_prefix(ztp.get("ztp_url_prefix"))
    # service_ip is intentionally not part of global.yaml. It is derived from
    # the declarative endpoint fields in 02-dhcp-subnet_config.csv.
    ztp_ips: dict[str, tuple[str, ...]] = {}
    for label in ("dns", "ntp", "date-time"):
        if label not in switch_system:
            raise LoadError(f"global 缺少 common.switch.system.{label}")

    versions: dict[str, str] = {}
    switches = data.get("switches")
    if not isinstance(switches, list):
        raise LoadError("global.switches 必须是 list")
    for entry in switches:
        if not isinstance(entry, dict) or len(entry) != 1:
            raise LoadError("global.switches 每项必须只包含一种设备类型")
        kind, config = next(iter(entry.items()))
        if kind not in {"eth", "ib", "nvl"}:
            raise LoadError(f"global.switches 包含未知设备类型：{kind}")
        if not isinstance(config, dict):
            raise LoadError(f"switches.{kind} 必须是 mapping")
        version = str(config.get("version") or "").strip()
        if version:
            _version_key(version)
            versions[kind] = version
    if schema_version == 2:
        eth_config = next(
            (entry["eth"] for entry in switches if isinstance(entry, dict) and "eth" in entry),
            None,
        )
        try:
            normalize_v2_mlag_policy(eth_config)
            normalize_v2_vrr_policy(eth_config)
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
    return GlobalSettings(
        dhcp_enabled=dhcp_enabled,
        dhcp_package=dhcp_package,
        http_enabled=http_enabled,
        http_package=http_package,
        http_root=Path(http_root_text),
        ztp_enabled=ztp_enabled,
        ztp_prefix=prefix,
        ztp_ips=ztp_ips,
        versions=versions,
        schema_version=schema_version,
    )


def derive_service_ips_from_subnet(
    path: Path, ztp_prefix: str,
) -> dict[str, tuple[str, ...]]:
    """Derive Cumulus bootstrap service addresses from profile declarations."""
    _nonempty_file(path, "02-dhcp-subnet_config.csv")
    _validate_ztp_prefix(ztp_prefix)
    found: dict[str, set[str]] = {profile: set() for profile in BOOTSTRAP_BY_PROFILE}
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for lineno, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            address, profile, _nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            if profile == "none":
                continue
            found[profile].add(address)

    result: dict[str, tuple[str, ...]] = {}
    for profile, addresses in found.items():
        bootstrap = BOOTSTRAP_BY_PROFILE[profile]
        if len(addresses) > 1:
            raise LoadError(
                f"cumulus_profile={profile}（{bootstrap}）只能写入一个 ZTP_SERVER，"
                "但 DHCP subnet CSV "
                f"配置了多个地址：{','.join(sorted(addresses))}"
            )
        values = tuple(sorted(addresses, key=ipaddress.IPv4Address))
        for role in ROLES_BY_BOOTSTRAP[bootstrap]:
            result[role] = values
    return result


def derive_boot_ips_from_subnet(
    path: Path, ztp_prefix: str,
) -> tuple[str, ...]:
    """Derive the single NVOS ztp.json service address from yes/no declarations."""
    _validate_ztp_prefix(ztp_prefix)
    found = set()
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for lineno, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            address, _profile, nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            if nvos_ztp == "yes":
                found.add(address)
    if len(found) > 1:
        raise LoadError(
            "ztp.json 只能使用一个服务地址，但 DHCP subnet CSV 配置了："
            + ",".join(sorted(found, key=ipaddress.IPv4Address))
        )
    return tuple(sorted(found, key=ipaddress.IPv4Address))


def apply_subnet_service_ips(
    settings: GlobalSettings, subnet_file: Path,
) -> GlobalSettings:
    """Populate service addresses from the authoritative DHCP subnet CSV."""
    derived = derive_service_ips_from_subnet(subnet_file, settings.ztp_prefix)
    boot_ips = derive_boot_ips_from_subnet(subnet_file, settings.ztp_prefix)
    updated = replace(settings, ztp_ips=derived, boot_ips=boot_ips)
    if settings.ztp_enabled and not updated.service_ips:
        raise LoadError(
            "ZTP enabled 但 DHCP subnet CSV 没有启用任何 Cumulus/NVOS endpoint"
        )
    return updated


def load_device_types(
    path: Path, schema_version: int = GLOBAL_SCHEMA_VERSION,
) -> frozenset[str]:
    _nonempty_file(path, "devices_config.csv")
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.reader(stream)
            raw_header = next(reader, [])
            fields = [str(field or "").strip().casefold() for field in raw_header]
            if schema_version == 2:
                try:
                    parse_device_csv_layout(fields, schema_version)
                except ValueError as exc:
                    raise LoadError(str(exc)) from exc
            if tuple(fields[:len(DEVICE_HEADER_PREFIX)]) != DEVICE_HEADER_PREFIX:
                raise LoadError(
                    "devices_config.csv 前 11 列顺序必须为："
                    + ",".join(DEVICE_HEADER_PREFIX)
                )
            for required in ("hostname", "type", "template", "eth0_ip"):
                if required not in fields:
                    raise LoadError(f"devices_config.csv 缺少列：{required}")
            types: set[str] = set()
            seen_hostnames: set[str] = set()
            rows = 0
            for lineno, raw_row in enumerate(reader, start=2):
                if not any(str(value or "").strip() for value in raw_row):
                    continue
                try:
                    require_device_csv_row_width(
                        raw_row, len(fields), schema_version, lineno=lineno,
                    )
                except ValueError as exc:
                    raise LoadError(str(exc)) from exc
                row = list(raw_row)
                rows += 1
                hostname = str(row[fields.index("hostname")] or "").strip()
                kind = str(row[fields.index("type")] or "").strip().casefold()
                template = str(row[fields.index("template")] or "").strip()
                address = str(row[fields.index("eth0_ip")] or "").strip().split("/", 1)[0]
                if not hostname:
                    raise LoadError(f"devices_config.csv 第 {lineno} 行 hostname 为空")
                if not SAFE_HOSTNAME.fullmatch(hostname):
                    raise LoadError(
                        f"devices_config.csv 第 {lineno} 行 hostname 含不安全字符："
                        f"{hostname!r}"
                    )
                hostname_key = hostname.casefold()
                if hostname_key in seen_hostnames:
                    raise LoadError(f"devices_config.csv hostname 重复：{hostname}")
                seen_hostnames.add(hostname_key)
                if kind not in VALID_TYPES:
                    raise LoadError(f"devices_config.csv 第 {lineno} 行 type={kind!r} 无效")
                if kind in {"eth", "eth_spx", "spx"} and (
                    not template or template.casefold() in {"na", "none", "null"}
                ):
                    raise LoadError(
                        f"devices_config.csv 第 {lineno} 行 {hostname} type={kind} "
                        "必须显式指定 template，不允许 NA/空值或按 hostname 自动猜测"
                    )
                try:
                    ipaddress.IPv4Address(address)
                except ValueError as exc:
                    raise LoadError(
                        f"devices_config.csv 第 {lineno} 行 eth0_ip={address!r} 无效"
                    ) from exc
                types.add(kind)
    except UnicodeDecodeError as exc:
        raise LoadError(f"devices_config.csv 不是有效 UTF-8：{exc}") from exc
    if rows == 0:
        raise LoadError("devices_config.csv 没有设备记录")
    return frozenset(types)


def select_p2p(project: Path, explicit: str | None = None) -> Path:
    if explicit:
        path = (project / explicit).resolve()
        if not _inside(path, project) or path.parent not in {project, project / "p2p"}:
            raise LoadError("--p2p-file 必须位于项目根目录或 p2p/ 目录")
    else:
        canonical = project / "p2p.xlsx"
        if canonical.is_file() and canonical.stat().st_size > 0:
            path = canonical
        else:
            version_dir = project / "p2p"
            version_candidates = [
                item for item in version_dir.iterdir()
                if item.is_file()
                and not item.name.startswith(("~$", "._"))
                and item.name.casefold().endswith(".xlsx")
                and "p2p" in item.name.casefold()
                and item.stat().st_size > 0
            ] if version_dir.is_dir() else []
            if version_candidates:
                path = max(
                    version_candidates,
                    key=lambda item: (item.stat().st_mtime_ns, item.name.casefold()),
                )
            else:
                candidates = [
                    item for item in sorted(project.iterdir())
                    if item.is_file()
                    and not item.name.startswith(("~$", "._"))
                    and item.name.casefold().endswith(".xlsx")
                    and "p2p" in item.name.casefold()
                    and item.stat().st_size > 0
                ]
                if len(candidates) != 1:
                    names = ", ".join(item.name for item in candidates) or "none"
                    raise LoadError(
                        f"需要唯一文件名含 P2P 的非空 XLSX；当前候选：{names}。"
                        "可用 --p2p-file 明确指定"
                    )
                path = candidates[0]
    _nonempty_file(path, "p2p.xlsx")
    if path.suffix.casefold() != ".xlsx" or not zipfile.is_zipfile(path):
        raise LoadError(f"P2P 文件不是合法 XLSX：{path.name}")
    with zipfile.ZipFile(path) as archive:
        if "xl/workbook.xml" not in archive.namelist():
            raise LoadError(f"P2P XLSX 缺少 xl/workbook.xml：{path.name}")
    return path


def validate_subnet_file(path: Path, settings: GlobalSettings) -> None:
    _nonempty_file(path, "02-dhcp-subnet_config.csv")
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        count = 0
        for lineno, row in enumerate(reader, start=2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            count += 1
            service_ip, _profile, _nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            try:
                network = ipaddress.IPv4Network(
                    f"{row['subnet'].strip()}/{row['netmask'].strip()}", strict=False
                )
                start = ipaddress.IPv4Address(row["range_start"].strip())
                end = ipaddress.IPv4Address(row["range_end"].strip())
                router = ipaddress.IPv4Address(row["routers"].strip())
            except (ValueError, AttributeError) as exc:
                raise LoadError(f"DHCP subnet CSV 第 {lineno} 行网络字段无效：{exc}") from exc
            if start not in network or end not in network or router not in network or start > end:
                raise LoadError(f"DHCP subnet CSV 第 {lineno} 行 range/router 不属于 {network}")
            if start <= router <= end:
                raise LoadError(
                    f"DHCP subnet CSV 第 {lineno} 行 routers={router} "
                    f"落入动态 range {start}-{end}"
                )
            if service_ip:
                service_address = ipaddress.IPv4Address(service_ip)
                if service_address in network:
                    if service_address in (
                        network.network_address, network.broadcast_address,
                    ):
                        raise LoadError(
                            f"DHCP subnet CSV 第 {lineno} 行 "
                            f"ztp_service_ip={service_address} 不是 {network} 的可用主机地址"
                        )
                    if start <= service_address <= end:
                        raise LoadError(
                            f"DHCP subnet CSV 第 {lineno} 行 "
                            f"ztp_service_ip={service_address} 落入动态 range {start}-{end}"
                        )
            for service_ip in settings.service_ips:
                try:
                    service_address = ipaddress.IPv4Address(service_ip)
                except ipaddress.AddressValueError as exc:
                    raise LoadError(f"推导出的 service_ip={service_ip!r} 无效") from exc
                if service_address in network and start <= service_address <= end:
                    raise LoadError(
                        f"DHCP subnet CSV 第 {lineno} 行 service_ip={service_address} "
                        f"落入动态 range {start}-{end}"
                    )
    if count == 0:
        raise LoadError("02-dhcp-subnet_config.csv 没有 subnet 记录")


def validate_pubkey(path: Path) -> None:
    _nonempty_file(path, "SSH 公钥")
    first = path.read_text(encoding="utf-8").splitlines()[0].strip()
    if not re.match(
        r"^(ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
        r"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+\S+",
        first,
    ):
        raise LoadError(f"SSH 公钥格式无效：{path.name}")
    keygen = shutil.which("ssh-keygen")
    if keygen:
        result = subprocess.run([keygen, "-l", "-f", str(path)], capture_output=True, text=True)
        if result.returncode != 0:
            raise LoadError(f"ssh-keygen 校验失败 {path.name}：{result.stderr.strip()}")


def _default_ssh_dir() -> Path:
    return Path.home() / ".ssh"


MANAGEMENT_PUBKEY_MARKER = ".management-pubkeys"
LAPTOP_PUBKEY_NAME = "laptop.pub"
MANAGEMENT_PUBKEY_NAME = "mgmt-server.pub"


def _pubkey_sort_key(path: Path) -> tuple[int, str]:
    """Keep the two canonical project key roles in a stable order."""
    priority = {LAPTOP_PUBKEY_NAME: 0, MANAGEMENT_PUBKEY_NAME: 1}
    return priority.get(path.name, 2), path.name


def deployable_pubkeys(pubkeys: tuple[Path, ...]) -> tuple[Path, ...]:
    """Return only non-empty keys that may be published or downloaded."""
    return tuple(
        item for item in pubkeys
        if item.is_file() and item.stat().st_size > 0
    )


def _public_key_identity(path: Path) -> str:
    """Return the key type/blob pair, excluding the non-identity comment."""
    fields = path.read_text(encoding="utf-8").splitlines()[0].split()
    return " ".join(fields[:2])


def ensure_management_key(ssh_dir: Path, *, dry_run: bool = False) -> Path:
    """Create or validate a distinct management-host Ed25519 key pair."""
    private_key = ssh_dir / "id_ed25519"
    public_key = ssh_dir / "id_ed25519.pub"
    private_exists = private_key.is_file() and private_key.stat().st_size > 0
    public_exists = public_key.is_file() and public_key.stat().st_size > 0
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        raise LoadError("未找到 ssh-keygen，无法准备管理服务器 SSH key")

    if not private_exists and not public_exists:
        if dry_run:
            raise LoadError(
                f"管理服务器密钥对不存在：{private_key}；dry-run 不会自动生成，"
                "请先正式执行一次 load 或手工运行 ssh-keygen"
            )
        ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        ssh_dir.chmod(0o700)
        result = subprocess.run(
            [
                keygen, "-q", "-t", "ed25519", "-N", "", "-f",
                str(private_key), "-C", f"{getpass.getuser()}@management-server",
            ],
            capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise LoadError(f"自动生成管理服务器 SSH key 失败：{result.stderr.strip()}")
        private_key.chmod(0o600)
        public_key.chmod(0o644)
        print(f"[KEY] 已生成管理服务器专用 SSH key：{public_key}")
        private_exists = public_exists = True

    if private_exists and not public_exists:
        if dry_run:
            raise LoadError(
                f"管理服务器私钥存在但公钥缺失：{public_key}；dry-run 不会修复"
            )
        result = subprocess.run(
            [keygen, "-y", "-P", "", "-f", str(private_key)],
            capture_output=True, text=True,
        )
        if result.returncode != 0 or not result.stdout.strip():
            raise LoadError(
                f"无法从管理服务器私钥恢复公钥：{result.stderr.strip()}"
            )
        public_key.write_text(
            result.stdout.strip() + f" {getpass.getuser()}@management-server\n",
            encoding="utf-8",
        )
        public_key.chmod(0o644)
        print(f"[KEY] 已从现有管理服务器私钥恢复公钥：{public_key}")
        public_exists = True

    if public_exists and not private_exists:
        raise LoadError(
            f"管理服务器公钥存在但私钥缺失：{private_key}；"
            "为避免生成不匹配的密钥对，未覆盖现有公钥"
        )

    validate_pubkey(public_key)
    derived = subprocess.run(
        [keygen, "-y", "-P", "", "-f", str(private_key)],
        capture_output=True, text=True,
    )
    if derived.returncode != 0 or len(derived.stdout.split()) < 2:
        raise LoadError(
            f"无法校验管理服务器私钥：{private_key}：{derived.stderr.strip()}"
        )
    public_fields = public_key.read_text(encoding="utf-8").split()
    derived_fields = derived.stdout.split()
    if public_fields[:2] != derived_fields[:2]:
        raise LoadError(
            f"管理服务器公私钥不匹配：{private_key} / {public_key}；"
            "为避免失去交换机访问权限，未覆盖任何文件"
        )
    return public_key


def prepare_pubkeys(
    project: Path, *, ssh_dir: Path, dry_run: bool = False,
    inject_management_key: bool = True,
) -> tuple[Path, ...]:
    pubs = sorted(project.glob("*.pub"))
    marker = project / MANAGEMENT_PUBKEY_MARKER
    managed_names = {
        line.strip() for line in marker.read_text(encoding="utf-8").splitlines()
        if line.strip().endswith(".pub")
    } if marker.is_file() else set()
    canonical_management = project / MANAGEMENT_PUBKEY_NAME
    legacy_managed = {
        name for name in managed_names if name != MANAGEMENT_PUBKEY_NAME
    }
    if canonical_management.exists() and legacy_managed:
        populated_legacy = [
            project / name for name in legacy_managed
            if (project / name).is_file() and (project / name).stat().st_size > 0
        ]
        if populated_legacy:
            warn(
                "检测到已有内容的旧管理公钥，未自动改名："
                + ", ".join(item.name for item in populated_legacy)
                + f"；请确认后手工迁移到 {MANAGEMENT_PUBKEY_NAME}"
            )
        else:
            managed_names = {MANAGEMENT_PUBKEY_NAME}
            if dry_run:
                print(
                    f"[DRY] 将管理公钥 marker 从 {','.join(sorted(legacy_managed))} "
                    f"迁移到 {MANAGEMENT_PUBKEY_NAME}"
                )
            else:
                marker.write_text(MANAGEMENT_PUBKEY_NAME + "\n", encoding="utf-8")
                marker.chmod(0o644)
                print(
                    f"[KEY] 已把空的旧管理公钥 marker 迁移到 {MANAGEMENT_PUBKEY_NAME}"
                )
    # A downloaded package deliberately omits the management-server key but
    # retains this marker, so recreate its placeholder before resolving keys.
    for name in managed_names:
        candidate = project / name
        if not candidate.exists() and not dry_run:
            candidate.touch()
            pubs.append(candidate)
    pubs = sorted(set(pubs))
    empty = [item for item in pubs if not item.is_file() or item.stat().st_size == 0]
    static = [item for item in pubs if item not in empty and item.name not in managed_names]
    if not static:
        raise LoadError(
            "项目必须至少包含一个非空 *.pub（例如模板中的电脑公钥）"
        )
    for item in static:
        validate_pubkey(item)

    if not inject_management_key:
        planned_management = sorted(
            project / name for name in managed_names
            if (project / name).is_file()
        )
        if not planned_management:
            planned_management = sorted(empty)
        preserved = sorted(
            item for item in planned_management if item.stat().st_size > 0
        )
        for item in preserved:
            validate_pubkey(item)
        static_identities = {_public_key_identity(item) for item in static}
        if any(_public_key_identity(item) in static_identities for item in preserved):
            raise LoadError("项目中的管理服务器公钥与项目电脑公钥相同")
        if preserved:
            print(
                "[SKIP] 当前平台仅准备配置，保留项目中已标记的管理服务器公钥："
                + ", ".join(item.name for item in preserved)
            )
        else:
            warn(
                "当前平台仅准备配置，项目中的管理服务器公钥尚未注入；"
                "保留计划公钥路径但不发布空文件。请在 Linux 管理服务器正式 load 时注入管理 key"
            )
        valid = static + planned_management
        if len(valid) < 2:
            raise LoadError(
                "ZTP 需要一个电脑公钥和一个管理服务器公钥占位路径；"
                f"请在项目中增加空的 {MANAGEMENT_PUBKEY_NAME}"
            )
        return tuple(sorted(valid, key=_pubkey_sort_key))

    managed_placeholders = sorted(
        {project / name for name in managed_names} if managed_names else set(empty)
    )
    if not managed_placeholders:
        raise LoadError(
            "项目必须包含一个空 *.pub 占位文件，用于注入管理服务器公钥"
        )
    static_identities = {_public_key_identity(item) for item in static}
    empty_managed = [
        item for item in managed_placeholders
        if not item.is_file() or item.stat().st_size == 0
    ]
    management_key = None
    if empty_managed:
        management_key = ensure_management_key(ssh_dir, dry_run=dry_run)
        if _public_key_identity(management_key) in static_identities:
            raise LoadError("管理服务器公钥与项目电脑公钥相同，无法保证两个独立 key")
    for placeholder in managed_placeholders:
        if placeholder.is_file() and placeholder.stat().st_size > 0:
            validate_pubkey(placeholder)
            if _public_key_identity(placeholder) in static_identities:
                raise LoadError("管理服务器公钥与项目电脑公钥相同，无法保证两个独立 key")
            print(f"[SKIP] 管理服务器公钥已存在，不覆盖：{placeholder.name}")
            continue
        assert management_key is not None
        if dry_run:
            print(f"[DRY] 将注入管理服务器公钥：{management_key} → {placeholder}")
            continue
        shutil.copy2(management_key, placeholder)
        placeholder.chmod(0o644)
        print(f"[KEY] 已注入管理服务器公钥：{placeholder.name}")
    if not dry_run:
        marker.write_text(
            "".join(f"{item.name}\n" for item in managed_placeholders), encoding="utf-8"
        )
        marker.chmod(0o644)
    valid = static + managed_placeholders
    for item in valid:
        if not dry_run:
            validate_pubkey(item)
    if not valid:
        raise LoadError("项目没有合法 SSH 公钥")
    preferred = sorted(valid, key=_pubkey_sort_key)
    return tuple(preferred)


def expected_images(settings: GlobalSettings, device_types: frozenset[str]) -> dict[str, str]:
    expected: dict[str, str] = {}
    if device_types & {"eth", "eth_spx", "spx"}:
        version = settings.versions.get("eth")
        if not version:
            raise LoadError("devices CSV 有 eth/eth_spx/spx，但 global 缺少 switches.eth.version")
        expected["eth"] = f"cumulus-linux-{version}-mlx-amd64.bin"
    for kind in ("ib", "nvl"):
        if kind not in device_types:
            continue
        version = settings.versions.get(kind)
        if not version:
            raise LoadError(f"devices CSV 有 {kind}，但 global 缺少 switches.{kind}.version")
        normalized = _version_filename(version)
        expected[kind] = f"nvosv{normalized}amd64.bin"
    return expected


def validate_image(path: Path, expected_name: str) -> None:
    if path.name != expected_name:
        raise LoadError(f"镜像 {path.name} 与 global 期望 {expected_name} 不一致")
    if path.stat().st_size < 1024 * 1024:
        raise LoadError(f"镜像过小或为空：{path}（{path.stat().st_size} 字节）")
    with path.open("rb") as stream:
        if stream.read(9) != b"#!/bin/sh":
            raise LoadError(f"镜像头无效（预期 self-extracting shell）：{path}")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def prepare_images(
    project: Path, expected: dict[str, str], *, dry_run: bool = False, quiet: bool = False,
) -> dict[str, Path]:
    if not dry_run:
        IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    expected_names = set(expected.values())
    project_bins = sorted(project.glob("*.bin"))
    # The complete project template intentionally carries zero-byte .bin files
    # for every supported image as preparation reminders.  They are metadata,
    # not candidate payloads, so only a non-empty unexpected image is a version
    # conflict.  Exact expected placeholders are resolved from the shared store.
    unexpected = [
        item.name for item in project_bins
        if item.name not in expected_names and item.stat().st_size > 0
    ]
    errors = []
    if unexpected:
        errors.append(
            "项目镜像不符合当前 global/device type："
            + ", ".join(unexpected)
            + f"；期望：{', '.join(sorted(expected_names)) or 'none'}"
        )
    resolved: dict[str, Path] = {}
    copy_pairs: list[tuple[Path, Path]] = []
    for kind, filename in expected.items():
        project_image = project / filename
        shared_image = IMAGE_DIR / filename
        try:
            if project_image.is_file() and project_image.stat().st_size > 0:
                validate_image(project_image, filename)
                if shared_image.exists() and shared_image.stat().st_size > 0:
                    validate_image(shared_image, filename)
                    if project_image.stat().st_size != shared_image.stat().st_size or _sha256(
                        project_image
                    ) != _sha256(shared_image):
                        raise LoadError(f"项目和共享目录中的同名镜像内容不同：{filename}")
                else:
                    copy_pairs.append((project_image, shared_image))
                resolved[kind] = shared_image
            elif shared_image.is_file() and shared_image.stat().st_size > 0:
                validate_image(shared_image, filename)
                resolved[kind] = shared_image
            else:
                raise LoadError(
                    f"缺少 {kind} {filename}：项目占位文件为空，且 {IMAGE_DIR} 中没有合法镜像"
                )
        except LoadError as exc:
            errors.append(str(exc))
    if errors:
        raise LoadError("镜像检查失败：\n  - " + "\n  - ".join(errors))
    for project_image, shared_image in copy_pairs:
        if not quiet:
            print(f"[IMAGE] {project_image} → {shared_image}")
        if not dry_run:
            shutil.copy2(project_image, shared_image)
    for kind, filename in expected.items():
        if not (project / filename).is_file() or (project / filename).stat().st_size == 0:
            if not quiet:
                info(f"项目镜像为空/缺失，复用共享镜像：image/{filename}")
    return resolved


def active_project() -> Path | None:
    if not MANIFEST.is_file():
        return None
    first = MANIFEST.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
    if not first or "proj:" not in first[0]:
        return None
    project = Path(first[0].split("proj:", 1)[1].strip())
    return project.resolve() if project.is_dir() else None


def sync_marker_present(path: Path) -> bool:
    """Fail closed for regular, special, symlink, and broken-symlink markers."""
    return os.path.lexists(path)


def activate_project(
    project: Path, p2p_file: Path, *, strict: bool = True, dry_run: bool = False,
    deployment_lock_descriptor: int | None = None,
) -> None:
    current = active_project()
    if current == project:
        mode = "严格" if strict else "配置准备/no-upgrade（跳过部署门禁）"
        info(f"当前活动项目就是目标项目；重新执行{mode} setup 以检查并修复全部链接")
    elif current:
        info(f"活动项目将从 {current.name} 切换到 {project.name}")
    else:
        info(f"当前没有有效活动项目；将激活 {project.name}")
    command = [sys.executable, str(SETUP_SCRIPT), "-y"]
    if strict:
        command.append("--strict")
    try:
        p2p_argument = p2p_file.relative_to(project).as_posix()
    except ValueError as exc:
        raise LoadError(f"P2P 文件不在项目目录内：{p2p_file}") from exc
    command.extend([f"--p2p-file={p2p_argument}", str(project)])
    run(
        command, cwd=HERE, dry_run=dry_run,
        inherited_lock_descriptor=deployment_lock_descriptor,
    )
    if not dry_run and active_project() != project:
        raise LoadError("01-a-setup.py 返回成功，但活动项目清单未指向目标项目")


def active_managed_services() -> tuple[str, ...]:
    """Return the managed units that are currently active, without mutation."""
    if not supports_local_ztp_services():
        return ()
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return ()
    active = []
    for service in ("isc-dhcp-server", "apache2"):
        result = subprocess.run(
            [systemctl, "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            active.append(service)
    return tuple(active)


def require_artifact_builder_services_inactive(dry_run: bool = False) -> None:
    """Never stop unrelated live services for a configuration-only Linux run."""
    if dry_run:
        return
    active = active_managed_services()
    if active:
        raise LoadError(
            "本机不具备当前项目 service_ip，且以下服务正在运行："
            + ", ".join(active)
            + "；为避免中断现有服务或在运行中切换项目链接，配置准备已在修改前拒绝。"
            "请改在独立工作目录/主机生成，或由操作员先明确停止这些服务"
        )
    ok("本机不具备当前项目 service_ip，且 Apache/DHCP 均未运行；可以只生成制品")


def quiesce_services(dry_run: bool = False) -> None:
    """Stop services before changing project links; failed loads remain safely stopped."""
    if not supports_local_ztp_services():
        info(f"{runtime_os()} 不管理 Apache/ISC DHCP，跳过旧服务状态检查")
        return
    if not shutil.which("systemctl"):
        info("未找到 systemctl，跳过旧服务状态检查")
        return
    active = list(active_managed_services())
    if not active:
        ok("Apache/DHCP 当前均未运行，可以安全切换项目")
        return
    warn(
        "切换/重建期间将停止正在运行的服务：" + ", ".join(active)
        + "；流程失败时保持停止，避免发布半成品"
    )
    for service in active:
        run(sudo_command("systemctl", "stop", service), dry_run=dry_run)


def _atomic_replace(path: Path, transform: object, dry_run: bool = False) -> None:
    original = path.read_text(encoding="utf-8")
    updated = transform(original)
    if updated == original:
        return
    if dry_run:
        print(f"[DRY] 将更新运行时参数：{path.relative_to(HTTP_ROOT)}")
        return
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(updated)
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    print(f"[UPDATE] {path.relative_to(HTTP_ROOT)}")


def _ztp_prefix_publication_path(settings: GlobalSettings) -> Path:
    """Resolve a validated URL prefix below this deployment's HTTP root."""
    if settings.http_root.resolve() != HTTP_ROOT.resolve():
        raise LoadError(
            f"不能发布 ztp_url_prefix：global http_root={settings.http_root}，"
            f"当前代码根目录={HTTP_ROOT}"
        )
    prefix = _validate_ztp_prefix(settings.ztp_prefix)
    destination = HTTP_ROOT.joinpath(*prefix.lstrip("/").split("/"))
    try:
        destination.relative_to(HTTP_ROOT)
    except ValueError as exc:
        raise LoadError(f"ztp_url_prefix 逃逸 HTTP root：{prefix}") from exc
    try:
        inside_ztp_lexically = destination.relative_to(ZTP_DIR)
    except ValueError:
        inside_ztp_lexically = None
    if destination != ZTP_DIR and inside_ztp_lexically is not None:
        raise LoadError(
            f"ztp_url_prefix={prefix} 位于实际 ZTP 目录内部，会形成循环链接"
        )
    cursor = HTTP_ROOT
    for part in destination.relative_to(HTTP_ROOT).parts[:-1]:
        cursor = cursor / part
        if cursor.is_symlink():
            raise LoadError(
                f"ztp_url_prefix 父路径不能是符号链接：{cursor.relative_to(HTTP_ROOT)}"
            )
        if cursor.exists() and not cursor.is_dir():
            raise LoadError(
                f"ztp_url_prefix 父路径不是目录：{cursor.relative_to(HTTP_ROOT)}"
            )
    return destination


def _managed_ztp_prefix_path() -> Path | None:
    """Return the prior custom publication link recorded by this loader."""
    if not os.path.lexists(ZTP_PREFIX_MARKER):
        return None
    if ZTP_PREFIX_MARKER.is_symlink() or not ZTP_PREFIX_MARKER.is_file():
        raise LoadError(f"ZTP prefix marker 不是普通文件：{ZTP_PREFIX_MARKER}")
    try:
        marker = json.loads(ZTP_PREFIX_MARKER.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(f"ZTP prefix marker 无效：{exc}") from exc
    schema_version = marker.get("schema_version") if isinstance(marker, dict) else None
    if isinstance(schema_version, bool) or schema_version != 1:
        raise LoadError("ZTP prefix marker schema_version 必须为 1")
    prefix = _validate_ztp_prefix(marker.get("prefix"))
    if prefix == "/ztp":
        raise LoadError("ZTP prefix marker 不应记录内置 /ztp")
    settings = GlobalSettings(
        dhcp_enabled=False, dhcp_package="", http_enabled=False,
        http_package="", http_root=HTTP_ROOT, ztp_enabled=False,
        ztp_prefix=prefix, ztp_ips={}, versions={},
    )
    path = _ztp_prefix_publication_path(settings)
    recorded = str(marker.get("path") or "")
    if not recorded or Path(recorded) != path:
        raise LoadError("ZTP prefix marker 的 prefix/path 不一致")
    target = str(marker.get("target") or "")
    if not target or Path(target) != ZTP_DIR:
        raise LoadError("ZTP prefix marker 的 target 与当前 ZTP_DIR 不一致")
    if os.path.lexists(path):
        if not path.is_symlink() or path.resolve() != ZTP_DIR.resolve():
            raise LoadError(f"已管理 ZTP prefix 路径发生冲突：{path}")
    return path


def _write_ztp_prefix_marker(prefix: str, path: Path) -> None:
    payload = {
        "schema_version": 1,
        "prefix": prefix,
        "path": str(path),
        "target": str(ZTP_DIR),
    }
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{ZTP_PREFIX_MARKER.name}.", suffix=".tmp",
        dir=ZTP_PREFIX_MARKER.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
        os.replace(temporary, ZTP_PREFIX_MARKER)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def snapshot_ztp_prefix_publication(
    settings: GlobalSettings,
) -> ZtpPrefixPublicationSnapshot:
    """Capture every path configure_ztp_prefix_publication may mutate."""
    destination = _ztp_prefix_publication_path(settings)
    previous = _managed_ztp_prefix_path()
    links: dict[Path, tuple[str, str | None]] = {}
    for path in {destination, previous} - {None, ZTP_DIR}:
        assert path is not None
        if path.is_symlink():
            links[path] = ("link", os.readlink(path))
        elif os.path.lexists(path):
            links[path] = ("other", None)
        else:
            links[path] = ("missing", None)
    marker = ZTP_PREFIX_MARKER.read_bytes() if ZTP_PREFIX_MARKER.is_file() else None
    return ZtpPrefixPublicationSnapshot(marker=marker, links=links)


def restore_ztp_prefix_publication(
    snapshot: ZtpPrefixPublicationSnapshot,
) -> None:
    """Restore the prefix link/marker snapshot after a pre-commit failure."""
    errors = []
    for path, (kind, target) in snapshot.links.items():
        try:
            if kind == "other":
                # configure rejects an existing real object before mutation.
                continue
            if kind == "missing":
                if path.is_symlink():
                    if path.resolve() != ZTP_DIR.resolve():
                        raise LoadError(
                            f"拒绝删除已被外部改写的 prefix 链接：{path}"
                        )
                    path.unlink()
                elif os.path.lexists(path):
                    raise LoadError(f"prefix 回滚目标已变成实际文件/目录：{path}")
                continue
            if kind != "link" or target is None:
                raise LoadError(f"未知 prefix snapshot 状态：{kind}")
            if os.path.lexists(path) and not path.is_symlink():
                raise LoadError(f"prefix 回滚目标已变成实际文件/目录：{path}")
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.parent / f".{path.name}.rollback.{os.getpid()}"
            try:
                temporary.unlink(missing_ok=True)
                temporary.symlink_to(target)
                os.replace(temporary, path)
            finally:
                temporary.unlink(missing_ok=True)
        except (LoadError, OSError) as exc:
            errors.append(f"{path}: {exc}")
    try:
        if snapshot.marker is None:
            if ZTP_PREFIX_MARKER.is_symlink():
                raise LoadError("prefix marker 已变成符号链接")
            if os.path.lexists(ZTP_PREFIX_MARKER):
                if not ZTP_PREFIX_MARKER.is_file():
                    raise LoadError("prefix marker 已变成非普通文件")
                ZTP_PREFIX_MARKER.unlink()
        else:
            if ZTP_PREFIX_MARKER.is_symlink():
                raise LoadError("prefix marker 已变成符号链接")
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{ZTP_PREFIX_MARKER.name}.rollback.",
                dir=ZTP_PREFIX_MARKER.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(snapshot.marker)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.chmod(temporary, 0o644)
                os.replace(temporary, ZTP_PREFIX_MARKER)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
    except (LoadError, OSError) as exc:
        errors.append(f"{ZTP_PREFIX_MARKER}: {exc}")
    if errors:
        raise LoadError("ZTP prefix publication 回滚失败：" + "；".join(errors))
    warn("统一 release 未提交；已恢复本次 load 前的 ZTP URL prefix 链接")


def configure_ztp_prefix_publication(
    settings: GlobalSettings, dry_run: bool = False,
) -> Path:
    """Atomically expose ZTP_DIR at the URL prefix declared in global.yaml.

    Only a link previously recorded by this loader may be removed. Existing
    real files/directories and unrelated links fail closed. An internal error
    restores both the old link and marker before returning control to load.
    """
    destination = _ztp_prefix_publication_path(settings)
    previous = _managed_ztp_prefix_path()
    builtin = destination == ZTP_DIR
    if not builtin and os.path.lexists(destination):
        if previous != destination:
            raise LoadError(
                f"ztp_url_prefix 发布路径已被占用且没有有效 ownership marker："
                f"{destination}；不会收编或删除用户链接"
            )
        if not destination.is_symlink() or destination.resolve() != ZTP_DIR.resolve():
            raise LoadError(f"ztp_url_prefix 发布路径已被占用：{destination}")
    if dry_run:
        if builtin:
            info("dry-run：ztp_url_prefix=/ztp 使用现有 ZTP 目录")
        else:
            info(f"dry-run：将发布 URL path {settings.ztp_prefix} -> {ZTP_DIR}")
        if previous is not None and previous != destination:
            info(f"dry-run：将清理旧 ZTP prefix 链接 {previous}")
        return destination

    marker_before = (
        ZTP_PREFIX_MARKER.read_bytes() if ZTP_PREFIX_MARKER.is_file() else None
    )
    previous_target = os.readlink(previous) if previous is not None and previous.is_symlink() else None
    destination_existed = os.path.lexists(destination)
    created_destination = False
    removed_previous = False
    try:
        if not builtin and not destination_existed:
            destination.parent.mkdir(parents=True, exist_ok=True)
            temporary = destination.parent / f".{destination.name}.tmp.{os.getpid()}"
            try:
                temporary.unlink(missing_ok=True)
                temporary.symlink_to(os.path.relpath(ZTP_DIR, destination.parent))
                os.replace(temporary, destination)
                created_destination = True
            finally:
                temporary.unlink(missing_ok=True)
        if previous is not None and previous != destination and previous.is_symlink():
            previous.unlink()
            removed_previous = True
        if builtin:
            ZTP_PREFIX_MARKER.unlink(missing_ok=True)
            ok("ztp_url_prefix=/ztp 使用现有 ZTP 目录")
        else:
            _write_ztp_prefix_marker(settings.ztp_prefix, destination)
            ok(f"ZTP URL path 已发布：{settings.ztp_prefix} -> {ZTP_DIR}")
        return destination
    except BaseException:
        if created_destination and destination.is_symlink():
            destination.unlink()
        if removed_previous and previous is not None and previous_target is not None:
            previous.parent.mkdir(parents=True, exist_ok=True)
            previous.symlink_to(previous_target)
        if marker_before is None:
            ZTP_PREFIX_MARKER.unlink(missing_ok=True)
        else:
            descriptor, temporary = tempfile.mkstemp(
                prefix=f".{ZTP_PREFIX_MARKER.name}.rollback.",
                dir=ZTP_PREFIX_MARKER.parent,
            )
            try:
                with os.fdopen(descriptor, "wb") as stream:
                    stream.write(marker_before)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.replace(temporary, ZTP_PREFIX_MARKER)
            finally:
                if os.path.exists(temporary):
                    os.unlink(temporary)
        raise


def render_ztp_runtime(
    settings: GlobalSettings, pubkeys: tuple[Path, ...], device_types: frozenset[str],
    *, upgrade_enabled: bool = True, dry_run: bool = False,
) -> None:
    prod_oob_ips = settings.boot_ips or settings.ztp_ips.get("prod_oob", ())
    if settings.ztp_enabled and device_types & {"ib", "nvl"} and not prod_oob_ips:
        raise LoadError("ZTP enabled 但缺少 prod_oob 地址（NVOS ztp.json 需要）")
    eth_version = settings.versions.get("eth")
    scripts = []
    for roles, filename in (
        (("air_oob", "prod_oob"), "ztp-bootstrap_oob.sh"),
        (("air_oobofoob", "prod_oobofoob"), "ztp-bootstrap_oobofoob.sh"),
    ):
        configured = {
            addresses[0]
            for role in roles
            if (addresses := settings.ztp_ips.get(role, ()))
        }
        if len(configured) > 1:
            raise LoadError(
                f"{filename} 只能写入一个 ZTP_SERVER，但 "
                f"{'/'.join(roles)} 配置了不同地址：{','.join(sorted(configured))}"
            )
        if configured:
            scripts.append((filename, next(iter(configured))))
    deployable_keys = deployable_pubkeys(pubkeys)
    if not deployable_keys:
        raise LoadError("ZTP 至少需要一个非空 SSH 公钥")
    # Keep the management-key URL in every rendered bootstrap, including a
    # macOS preparation artifact where mgmt-server.pub is intentionally still
    # an empty placeholder.  Linux load publishes the non-empty key at this
    # fixed URL.  Omitting the path on macOS can otherwise leave a subsequently
    # synced bootstrap unable to install the key used by the root monitor.
    key_names = list(dict.fromkeys([
        *(item.name for item in pubkeys), MANAGEMENT_PUBKEY_NAME,
    ]))
    template = ZTP_DIR / "templates" / "ztp-bootstrap.sh"
    if not template.is_file():
        raise LoadError(f"缺少不可变 bootstrap 模板：{template}")
    template_text = template.read_text(encoding="utf-8")
    manual_urls = {
        filename: f"http://{address}{settings.ztp_prefix}/{filename}"
        for filename, address in scripts
    }
    for filename, address in scripts:
        script = ZTP_DIR / filename

        def transform(
            text: str, address: str = address, filename: str = filename,
        ) -> str:
            text, server_count = re.subn(
                r'^ZTP_SERVER="[^"]*"$', f'ZTP_SERVER="http://{address}"',
                text, count=1, flags=re.MULTILINE,
            )
            text, prefix_count = re.subn(
                r'^ZTP_URL_PREFIX="[^"]*"$',
                f'ZTP_URL_PREFIX="{settings.ztp_prefix}"', text, count=1,
                flags=re.MULTILINE,
            )
            text, manual_oob_count = re.subn(
                r'^MANUAL_ZTP_OOB_URL="[^"]*"$',
                f'MANUAL_ZTP_OOB_URL="{manual_urls.get("ztp-bootstrap_oob.sh", "")}"',
                text, count=1,
                flags=re.MULTILINE,
            )
            text, manual_oobofoob_count = re.subn(
                r'^MANUAL_ZTP_OOBOFOOB_URL="[^"]*"$',
                f'MANUAL_ZTP_OOBOFOOB_URL="{manual_urls.get("ztp-bootstrap_oobofoob.sh", "")}"',
                text, count=1,
                flags=re.MULTILINE,
            )
            text, upgrade_count = re.subn(
                r'^ZTP_UPGRADE_ENABLED="(?:true|false)"$',
                f'ZTP_UPGRADE_ENABLED="{str(upgrade_enabled).lower()}"',
                text, count=1, flags=re.MULTILINE,
            )
            key_block = "PUBKEY_PATHS=(\n" + "".join(
                f'    "${{ZTP_URL_PREFIX}}/config/publickey/{name}"\n'
                for name in key_names
            ) + ")"
            text, key_count = re.subn(
                r'^PUBKEY_PATHS=\(\n.*?^\)$', key_block, text, count=1,
                flags=re.MULTILINE | re.DOTALL,
            )
            if (
                server_count != 1 or prefix_count != 1
                or manual_oob_count != 1 or manual_oobofoob_count != 1
                or upgrade_count != 1 or key_count != 1
            ):
                raise LoadError(
                    f"无法安全更新 {script.name} 的服务器、手工 ZTP URL、升级开关或公钥参数"
                )
            if eth_version:
                text, version_count = re.subn(
                    r'^TARGET_CL_VER="[^"]*"$',
                    f'TARGET_CL_VER="{eth_version}"', text, count=1,
                    flags=re.MULTILINE,
                )
                if version_count != 1:
                    raise LoadError(f"无法安全更新 {script.name} 的 TARGET_CL_VER")
            return text

        rendered = transform(template_text)
        try:
            display_script = script.relative_to(HTTP_ROOT)
        except ValueError:
            display_script = script
        if dry_run:
            print(f"[DRY] 将从模板生成 {display_script}")
            continue
        descriptor, temporary = tempfile.mkstemp(prefix=f".{script.name}.", dir=script.parent)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(rendered)
                stream.flush()
                os.fsync(stream.fileno())
            os.chmod(temporary, 0o755)
            os.replace(temporary, script)
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)
        print(f"[UPDATE] {display_script}（来自 templates/ztp-bootstrap.sh）")

    if prod_oob_ips:
        json_template = ZTP_DIR / "templates" / "ztp.json"
        json_path = ZTP_DIR / "ztp.json"
        if not json_template.is_file():
            raise LoadError(f"缺少不可变 NVOS ZTP 模板：{json_template}")
        try:
            data = json.loads(json_template.read_text(encoding="utf-8"))
            ztp = data["ztp"]
            ping_hosts = ztp["01-connectivity-check"]["ping-hosts"]
            if not isinstance(ping_hosts, list) or not ping_hosts:
                raise TypeError("01-connectivity-check.ping-hosts 必须是非空列表")
            ping_hosts[0] = prod_oob_ips[0]
            ztp["02-commands-list"]["url"] = (
                f"http://{prod_oob_ips[0]}{settings.ztp_prefix}/config/nvos/disable-password-hardening.nv"
            )
            ztp["03-provisioning-script"]["url"] = (
                f"http://{prod_oob_ips[0]}{settings.ztp_prefix}/ztp-bootstrap_oob.sh"
            )
        except (OSError, UnicodeError, KeyError, TypeError, json.JSONDecodeError) as exc:
            raise LoadError(f"NVOS ZTP 模板结构无效：{exc}") from exc
        rendered = json.dumps(data, indent=4, ensure_ascii=False) + "\n"
        try:
            display_json = json_path.relative_to(HTTP_ROOT)
        except ValueError:
            display_json = json_path
        if dry_run:
            print(f"[DRY] 将从模板生成 {display_json}")
        else:
            current = None
            if json_path.is_file() and not json_path.is_symlink():
                try:
                    current = json_path.read_text(encoding="utf-8")
                except (OSError, UnicodeError):
                    current = None
            if current != rendered:
                descriptor, temporary = tempfile.mkstemp(
                    prefix=f".{json_path.name}.", dir=json_path.parent,
                )
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                        stream.write(rendered)
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.chmod(temporary, 0o644)
                    os.replace(temporary, json_path)
                finally:
                    if os.path.exists(temporary):
                        os.unlink(temporary)
                print(f"[UPDATE] {display_json}（来自 templates/ztp.json）")


def select_http_ip(settings: GlobalSettings) -> str:
    local = local_ipv4_addresses()
    for address in settings.service_ips:
        if address in local:
            return address
    if settings.service_ips:
        return settings.service_ips[0]
    raise LoadError("DHCP subnet CSV 没有可用于 HTTP Server 的 service_ip")


def management_has_mellanox_nic() -> bool:
    """Detect a Mellanox/NVIDIA PCI NIC without requiring lspci."""
    pci_root = Path("/sys/bus/pci/devices")
    if pci_root.is_dir():
        for vendor_file in pci_root.glob("*/vendor"):
            try:
                if vendor_file.read_text(encoding="ascii").strip().lower() == "0x15b3":
                    return True
            except OSError:
                continue
    lspci = shutil.which("lspci")
    if not lspci:
        return False
    result = subprocess.run(
        [lspci], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False,
    )
    return "mellanox" in result.stdout.casefold()


def prepare_infra(
    inputs: ProjectInputs,
    dry_run: bool = False,
    skip_doca: bool = False,
    download_doca: bool = False,
) -> None:
    http_ip = select_http_ip(inputs.settings)
    run(
        [
            sys.executable, str(INFRA_DIR / "deploy_infra.py"), "--prepare-only",
            "--http-server-ip", http_ip,
            "--global-file", str(inputs.global_file),
            "--devices-file", str(inputs.devices_file),
        ],
        cwd=INFRA_DIR,
        dry_run=dry_run,
    )
    setup_command = sudo_command(
        "bash", str(INFRA_DIR / "infra-setup.sh"), "--mgmt", "--defer-services"
    )
    if skip_doca:
        setup_command.append("--skip-doca")
    elif download_doca:
        setup_command.append("--download-doca")
    elif not management_has_mellanox_nic():
        warn(
            "管理服务器未检测到 Mellanox/NVIDIA PCI 网卡；默认不下载或缓存 "
            "DOCA。若需要为其他离线客户端准备 DOCA，请重新执行并加 "
            "--download-doca。"
        )
        setup_command.append("--skip-doca")
    if inputs.settings.http_enabled:
        if inputs.settings.http_package != "apache2":
            raise LoadError(
                f"infra 当前仅支持 HTTP package=apache2，实际为 {inputs.settings.http_package}"
            )
        setup_command.append("--install-apache")
    if inputs.settings.dhcp_enabled:
        if inputs.settings.dhcp_package != "isc-dhcp-server":
            raise LoadError(
                "infra 当前仅支持 DHCP package=isc-dhcp-server，"
                f"实际为 {inputs.settings.dhcp_package}"
            )
        setup_command.append("--install-dhcp")
    run(
        setup_command,
        cwd=INFRA_DIR,
        dry_run=dry_run,
    )


def newest_directory(parent: Path, pattern: re.Pattern[str]) -> Path | None:
    candidates = [item for item in parent.iterdir() if item.is_dir() and pattern.fullmatch(item.name)]
    return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None


def dhcp_file_mappings() -> dict[Path, Path]:
    dhcp_dir = ZTP_DIR / "config/isc-dhcp-server"
    return {
        dhcp_dir / "dhcpd.conf": Path("/etc/dhcp/dhcpd.conf"),
        dhcp_dir / "dhcpd_eth.hosts": Path("/etc/dhcp/dhcpd_eth.hosts"),
        dhcp_dir / "dhcpd_ib.hosts": Path("/etc/dhcp/dhcpd_ib.hosts"),
        dhcp_dir / "dhcpd_nvl.hosts": Path("/etc/dhcp/dhcpd_nvl.hosts"),
    }


def _rewrite_dhcp_staging_includes(text: str, staged_dir: Path) -> str:
    """Bind exactly the three canonical live includes to an unpublished set."""
    for hosts_name in (
        "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
    ):
        live_include = f'include "/etc/dhcp/{hosts_name}";'
        if text.count(live_include) != 1:
            raise LoadError(
                f"dhcpd.conf 必须且只能包含一次标准 include：{live_include}"
            )
        text = text.replace(
            live_include, f'include "{staged_dir / hosts_name}";', 1,
        )
    return text


def mount_and_test_dhcp(
    dry_run: bool = False,
    *,
    parent_candidate: PreparedParentRelease | None = None,
) -> None:
    """Validate a staged DHCP set, then install all four files transactionally.

    ``dhcpd.conf`` uses absolute ``/etc/dhcp`` include paths, so the staging
    copy rewrites only those three include statements for the first syntax
    check.  If an install or the final syntax check fails, every previous
    destination (including a symlink) is restored before the error is raised.
    """
    mappings = dhcp_file_mappings()
    for source in mappings:
        _nonempty_file(source, f"DHCP 输出 {source.name}")
    if dry_run:
        info("dry-run：将先在 staging 检查四个 DHCP 文件，再事务式安装并复检")
        for source, destination in mappings.items():
            run(
                sudo_command(
                    "install", "-m", "0644", str(source.resolve()), str(destination)
                ),
                dry_run=True,
            )
        run(
            sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"),
            dry_run=True,
        )
        return

    destination_parents = {destination.parent for destination in mappings.values()}
    if len(destination_parents) != 1:
        raise LoadError("四个 DHCP 运行文件必须位于同一目录，无法建立事务 staging")
    dhcp_runtime_dir = next(iter(destination_parents))
    transaction_dir = dhcp_runtime_dir / (
        f".load-dhcp-transaction-{os.getpid()}-{secrets.token_hex(8)}"
    )
    staged_dir = transaction_dir / "staged"
    backup_dir = transaction_dir / "backup"
    if transaction_dir.parent != dhcp_runtime_dir or not transaction_dir.name.startswith(
        ".load-dhcp-transaction-"
    ):
        raise LoadError(f"拒绝使用不安全的 DHCP 事务目录：{transaction_dir}")
    if os.path.lexists(transaction_dir):
        raise LoadError(f"DHCP 事务目录已存在：{transaction_dir}")

    transaction_created = False
    try:
        # Ubuntu's dhcpd AppArmor profile permits configuration reads below
        # /etc/dhcp but rejects arbitrary /tmp paths.  Create the unpublished
        # candidate beside the live files, with traverse/read permissions for
        # a dhcpd process that may drop privileges while parsing.  The backup
        # remains root-only.
        run(sudo_command(
            "install", "-d", "-m", "0755", "--", str(transaction_dir),
        ))
        transaction_created = True
        run(sudo_command(
            "install", "-d", "-m", "0755", "--", str(staged_dir),
        ))
        run(sudo_command(
            "install", "-d", "-m", "0700", "--", str(backup_dir),
        ))

        with tempfile.TemporaryDirectory(prefix="load-dhcp-build-") as temporary:
            build_dir = Path(temporary)
            for source in mappings:
                shutil.copy2(source.resolve(), build_dir / source.name)
            build_conf = build_dir / "dhcpd.conf"
            staged_text = _rewrite_dhcp_staging_includes(
                build_conf.read_text(encoding="utf-8"), staged_dir,
            )
            build_conf.write_text(staged_text, encoding="utf-8")
            for source in mappings:
                run(sudo_command(
                    "install", "-m", "0644", "--",
                    str(build_dir / source.name), str(staged_dir / source.name),
                ))

        staged_conf = staged_dir / "dhcpd.conf"
        run(sudo_command("dhcpd", "-t", "-cf", str(staged_conf)))

        existed: dict[Path, bool] = {}
        for destination in mappings.values():
            existed[destination] = os.path.lexists(destination)
            if existed[destination]:
                run(
                    sudo_command(
                        "cp", "-a", "--", str(destination),
                        str(backup_dir / destination.name),
                    )
                )

        try:
            for source, destination in mappings.items():
                # AppArmor resolves symlink targets and can deny HTTP-root
                # paths.  The installed runtime artifact must be a regular
                # file below /etc/dhcp.
                run(
                    sudo_command(
                        "install", "-m", "0644", str(source.resolve()),
                        str(destination),
                    )
                )
            run(sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"))
            if parent_candidate is not None:
                # Keep the old DHCP files available until the only externally
                # visible commit marker has been atomically replaced.  If the
                # parent commit fails, this exception path restores all four
                # installed files before load releases its deployment lock.
                commit_prepared_release(parent_candidate)
        except BaseException:
            if parent_candidate is not None and parent_candidate.committed:
                # Nothing runs after the atomic replace inside the try block;
                # this branch is defensive against future refactors.  Rolling
                # DHCP back after advertising the new parent would create the
                # inverse split-brain and is therefore forbidden.
                raise
            warn("DHCP 安装或最终语法检查失败；正在恢复本次操作前的四个文件")
            restore_errors = []
            for destination in mappings.values():
                result = subprocess.run(
                    sudo_command("rm", "-f", "--", str(destination)), check=False,
                )
                if result.returncode != 0:
                    restore_errors.append(str(destination))
                    continue
                if existed[destination]:
                    result = subprocess.run(
                        sudo_command(
                            "cp", "-a", "--", str(backup_dir / destination.name),
                            str(destination),
                        ),
                        check=False,
                    )
                    if result.returncode != 0:
                        restore_errors.append(str(destination))
            if restore_errors:
                raise LoadError(
                    "DHCP 安装失败，且以下旧文件未能自动恢复："
                    + ", ".join(restore_errors)
                )
            raise
    finally:
        if transaction_created:
            cleanup_failed = False
            for directory in (staged_dir, backup_dir):
                for name in mappings:
                    result = subprocess.run(
                        sudo_command("rm", "-f", "--", str(directory / name.name)),
                        check=False,
                    )
                    cleanup_failed = cleanup_failed or result.returncode != 0
            for directory in (backup_dir, staged_dir, transaction_dir):
                result = subprocess.run(
                    sudo_command("rmdir", "--", str(directory)), check=False,
                )
                cleanup_failed = cleanup_failed or result.returncode != 0
            if cleanup_failed:
                warn(f"DHCP 事务目录清理失败，请手工删除：{transaction_dir}")
    ok("四个 DHCP 文件已事务式复制到 /etc/dhcp，dhcpd -t 检查通过；服务尚未启动")


def _device_types_after_dhcp(
    device_types: frozenset[str], *, dry_run: bool,
    schema_version: int = GLOBAL_SCHEMA_VERSION,
) -> frozenset[str]:
    # A clean project may intentionally contain no type=air rows. The DHCP
    # generator creates those rows from p2p-air.json, so do not keep using the
    # device-type snapshot captured before generation. In dry-run mode no CSV
    # is written; the linked AIR JSON still tells us to include the AIR publish
    # steps in the displayed execution plan.
    effective_types = set(device_types)
    devices_csv = ZTP_DIR / "config/isc-dhcp-server/02-devices_config.csv"
    p2p_air_json = ZTP_DIR / "config/isc-dhcp-server/p2p-air.json"
    if not dry_run:
        effective_types = set(load_device_types(devices_csv, schema_version))
    # AIR-only nodes intentionally stay out of the unified CSV, but they still
    # require baseline Cumulus YAML and MAC-link publication.  Inspect the
    # actual topology nodes in both normal and dry-run paths rather than using
    # a non-empty JSON file as a proxy.
    if p2p_air_json.is_file() and any(
        item.get("type") == "air"
        for item in _augment_air_json_inventory([], p2p_air_json)
    ):
        effective_types.add("air")
    return frozenset(effective_types)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _normalized_mac(value: object) -> str:
    text = re.sub(r"[^0-9a-f]", "", str(value or "").casefold())
    if len(text) != 12:
        return ""
    return ":".join(text[index:index + 2] for index in range(0, 12, 2))


def _release_inventory(path: Path) -> list[dict[str, object]]:
    """Read the identity fields exactly as the DHCP/publishers consume them."""
    records: list[dict[str, object]] = []
    with path.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.reader(stream)
        header = [str(item or "").strip().casefold() for item in next(reader, [])]
        try:
            hostname_col = header.index("hostname")
            type_col = header.index("type")
            eth0_mac_col = header.index("eth0_mac")
            eth1_mac_col = header.index("eth1_mac")
        except ValueError as exc:
            raise LoadError(f"统一 release 无法读取设备身份列：{exc}") from exc
        seen = set()
        for lineno, row in enumerate(reader, 2):
            row = [str(item or "").strip() for item in row]
            if not any(row):
                continue
            if max(hostname_col, type_col, eth0_mac_col, eth1_mac_col) >= len(row):
                raise LoadError(f"统一 release：devices_config.csv 第 {lineno} 行列数不足")
            hostname = row[hostname_col]
            device_type = row[type_col].casefold()
            if device_type == "server":
                continue
            key = hostname.casefold()
            if not hostname or key in seen:
                raise LoadError(f"统一 release：hostname 为空或重复：{hostname!r}")
            if not SAFE_HOSTNAME.fullmatch(hostname):
                raise LoadError(
                    f"统一 release：hostname 含不安全字符：{hostname!r}"
                )
            seen.add(key)
            eth0_mac = _normalized_mac(row[eth0_mac_col])
            eth1_mac = _normalized_mac(row[eth1_mac_col])
            records.append({
                "hostname": hostname,
                "hostname_key": key,
                "type": device_type,
                "eth0_mac": eth0_mac,
                "eth1_mac": eth1_mac,
                "identity_state": "managed" if eth0_mac else "identity_pending",
                "identity_source": "devices_config",
            })
    return records


def _augment_air_json_inventory(
    records: list[dict[str, object]], air_json_path: Path,
) -> list[dict[str, object]]:
    """Add AIR-only Cumulus identities that intentionally are not CSV rows.

    AIR simulation exposes every switch MAC in the generated AIR JSON.  A node
    with a matching static ``type=air`` row is verified against that row; a
    Cumulus/OOB switch present only in AIR is a managed baseline identity and
    must participate in the same DHCP/YAML parent release.  Treating the CSV
    as the sole inventory would incorrectly reject those baseline devices as
    extra output even though both child generators derived them from the
    current P2P input.
    """
    if not air_json_path.is_file():
        return records
    try:
        document = json.loads(air_json_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(f"统一 release 无法读取 AIR JSON：{exc}") from exc
    content = document.get("content", document) if isinstance(document, dict) else None
    nodes = content.get("nodes") if isinstance(content, dict) else None
    if not isinstance(nodes, dict):
        raise LoadError("统一 release：AIR JSON 缺少 object 类型 content.nodes")

    result = list(records)
    by_hostname = {str(item["hostname_key"]): item for item in result}
    mac_owner = {
        str(mac): str(item["hostname"])
        for item in result
        for mac in (item.get("eth0_mac"), item.get("eth1_mac"))
        if mac
    }
    for raw_hostname, node in nodes.items():
        if not isinstance(node, dict):
            continue
        os_name = str(node.get("os") or "").strip().casefold()
        if not (os_name.startswith("cumulus") or os_name == "oob-mgmt-switch"):
            continue
        hostname = str(raw_hostname or "").strip()
        if not hostname or not SAFE_HOSTNAME.fullmatch(hostname):
            raise LoadError(
                f"统一 release：AIR JSON hostname 为空或含不安全字符：{hostname!r}"
            )
        interfaces = node.get("management_interfaces")
        eth0 = interfaces.get("eth0", {}) if isinstance(interfaces, dict) else {}
        mac = _normalized_mac(
            eth0.get("mac_address") or eth0.get("mac")
            if isinstance(eth0, dict) else ""
        )
        if not mac:
            raise LoadError(f"统一 release：AIR JSON {hostname} 缺少有效 eth0 MAC")
        key = hostname.casefold()
        existing = by_hostname.get(key)
        if existing is not None:
            if existing.get("type") != "air":
                raise LoadError(
                    f"统一 release：AIR JSON hostname {hostname} 与非 AIR CSV 设备冲突"
                )
            if existing.get("eth0_mac") != mac:
                raise LoadError(
                    f"统一 release：AIR JSON {hostname} MAC={mac} 与 CSV "
                    f"MAC={existing.get('eth0_mac') or 'missing'} 不一致"
                )
            continue
        owner = mac_owner.get(mac)
        if owner is not None:
            raise LoadError(
                f"统一 release：AIR JSON {hostname} MAC={mac} 与 {owner} 冲突"
            )
        item = {
            "hostname": hostname,
            "hostname_key": key,
            "type": "air",
            "eth0_mac": mac,
            "eth1_mac": "",
            "identity_state": "managed",
            "identity_source": "air_json",
        }
        result.append(item)
        by_hostname[key] = item
        mac_owner[mac] = hostname
    return result


def _load_release_json(path: Path, label: str) -> dict[str, object]:
    _nonempty_file(path, label)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise LoadError(f"{label} 不是有效 JSON：{exc}") from exc
    if not isinstance(data, dict) or data.get("schema_version") != 1:
        raise LoadError(f"{label} schema_version 必须为 1")
    if not str(data.get("release_id") or "").strip():
        raise LoadError(f"{label} 缺少 release_id")
    return data


def _validate_manifest_devices(
    *, label: str, manifest: dict[str, object], expected: list[dict[str, object]],
) -> None:
    rows = manifest.get("devices")
    if not isinstance(rows, list):
        raise LoadError(f"{label}.devices 必须是 list")
    actual: dict[str, dict[str, object]] = {}
    for item in rows:
        if not isinstance(item, dict):
            raise LoadError(f"{label}.devices 包含非 object 元素")
        hostname = str(item.get("hostname") or "").strip()
        key = hostname.casefold()
        if not hostname or key in actual:
            raise LoadError(f"{label} hostname 为空或重复：{hostname!r}")
        actual[key] = item
    expected_by_host = {str(item["hostname_key"]): item for item in expected}
    if set(actual) != set(expected_by_host):
        missing = sorted(set(expected_by_host) - set(actual))
        extra = sorted(set(actual) - set(expected_by_host))
        raise LoadError(
            f"{label} 与当前设备清单漂移：missing={missing or 'none'}，"
            f"extra={extra or 'none'}"
        )
    for key, inventory in expected_by_host.items():
        item = actual[key]
        manifest_macs = {
            normalized for normalized in (
                _normalized_mac(value) for value in (item.get("macs") or [])
            ) if normalized
        }
        expected_macs = {
            str(value) for value in (
                inventory.get("eth0_mac"), inventory.get("eth1_mac")
            ) if value
        }
        if manifest_macs != expected_macs:
            raise LoadError(
                f"{label} {inventory['hostname']} MAC 漂移："
                f"manifest={sorted(manifest_macs)} current={sorted(expected_macs)}"
            )
        expected_state = str(inventory["identity_state"])
        actual_state = str(item.get("identity_state") or "")
        if actual_state != expected_state:
            raise LoadError(
                f"{label} {inventory['hostname']} identity_state={actual_state!r}，"
                f"当前应为 {expected_state!r}"
            )


def _validate_child_artifacts(
    *, label: str, release_dir: Path, manifest: dict[str, object],
) -> None:
    """Bind every child manifest row to its real YAML and MAC links.

    Identity-only validation is insufficient for an automatic ZTP release: a
    stale or edited YAML, a missing MAC link, or an extra link left from an old
    device can otherwise be published under a fresh parent release.  All paths
    are therefore constrained to one release directory and all MAC links must
    match the manifest exactly.
    """
    rows = manifest.get("devices")
    if not isinstance(rows, list):
        raise LoadError(f"{label}.devices 必须是 list")
    expected_links: dict[str, str] = {}
    for item in rows:
        if not isinstance(item, dict):
            raise LoadError(f"{label}.devices 包含非 object 元素")
        hostname = str(item.get("hostname") or "").strip()
        config_name = str(item.get("config") or "").strip()
        expected_config = f"{hostname}.yaml"
        if (
            not hostname
            or config_name != expected_config
            or Path(config_name).name != config_name
        ):
            raise LoadError(
                f"{label} {hostname or '<empty>'} config 必须为安全的 "
                f"{expected_config!r}，实际为 {config_name!r}"
            )
        config_path = release_dir / config_name
        if config_path.is_symlink() or not config_path.is_file():
            raise LoadError(f"{label} 专属 YAML 缺失或不是普通文件：{config_path}")
        expected_hash = str(item.get("config_sha256") or "").strip().casefold()
        if not expected_hash or _sha256_path(config_path) != expected_hash:
            raise LoadError(f"{label} 专属 YAML hash 漂移：{config_path}")
        for value in item.get("macs") or []:
            mac = _normalized_mac(value)
            if not mac:
                raise LoadError(f"{label} {hostname} manifest 包含无效 MAC：{value!r}")
            link_name = mac.replace(":", "") + ".yaml"
            owner = expected_links.get(link_name)
            if owner is not None and owner != config_name:
                raise LoadError(
                    f"{label} MAC 链接 {link_name} 同时属于 {owner} 和 {config_name}"
                )
            expected_links[link_name] = config_name

    for link_name, config_name in expected_links.items():
        link_path = release_dir / link_name
        if not link_path.is_symlink():
            raise LoadError(f"{label} MAC YAML 链接缺失：{link_path}")
        target = os.readlink(link_path)
        if Path(target).is_absolute() or Path(target).name != target or target != config_name:
            raise LoadError(
                f"{label} MAC YAML 链接目标错误：{link_path} -> {target!r}，"
                f"应为 {config_name!r}"
            )
        try:
            resolved = link_path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LoadError(f"{label} MAC YAML 链接不可解析：{link_path}: {exc}") from exc
        if resolved != (release_dir / config_name).resolve(strict=True):
            raise LoadError(f"{label} MAC YAML 链接逃逸发布目录：{link_path}")

    actual_links: set[str] = set()
    for path in release_dir.iterdir():
        if not re.fullmatch(r"[0-9A-Fa-f]{12}\.yaml", path.name):
            continue
        if not path.is_symlink():
            raise LoadError(f"{label} MAC YAML 入口不是软链接：{path}")
        actual_links.add(path.name)
    if actual_links != set(expected_links):
        missing = sorted(set(expected_links) - actual_links)
        extra = sorted(actual_links - set(expected_links))
        raise LoadError(
            f"{label} MAC YAML 链接集合漂移：missing={missing or 'none'}，"
            f"extra={extra or 'none'}"
        )

    if label == "cumulus":
        default_name = str(manifest.get("effective_default") or "").strip()
        if not default_name or Path(default_name).name != default_name:
            raise LoadError("cumulus release manifest 缺少安全的 effective_default")
        default_path = release_dir / default_name
        if default_path.is_symlink() or not default_path.is_file():
            raise LoadError(f"cumulus effective default 缺失或不是普通文件：{default_path}")
        default_hash = str(
            manifest.get("effective_default_sha256") or ""
        ).strip().casefold()
        if not default_hash or _sha256_path(default_path) != default_hash:
            raise LoadError(f"cumulus effective default hash 漂移：{default_path}")


def validate_and_publish_release(
    project: Path, inputs: ProjectInputs, *, dry_run: bool = False,
    publish: bool = True,
) -> dict[str, object] | None:
    """Bind DHCP, Cumulus and NVOS child releases to one validated release.

    Child generators intentionally use independent release IDs.  The parent
    manifest records their exact IDs and file hashes after proving that every
    child contains the same current hostname/MAC/pending identity contract.
    """
    if dry_run:
        info(
            "dry-run：生成结束后将验证 DHCP/Cumulus/NVOS 子 release 的设备、"
            "MAC、identity_pending 和文件 hash，再写 current-release.json"
        )
        return None

    inventory = _augment_air_json_inventory(
        _release_inventory(inputs.devices_file),
        ZTP_DIR / "config/isc-dhcp-server/p2p-air.json",
    )
    dhcp_path = ZTP_DIR / "config/isc-dhcp-server/dhcp-release-manifest.json"
    dhcp = _load_release_json(dhcp_path, "DHCP release manifest")
    dhcp_rows = dhcp.get("devices")
    if not isinstance(dhcp_rows, list):
        raise LoadError("DHCP release manifest.devices 必须是 list")
    expected_dhcp: dict[tuple[str, str], dict[str, object]] = {}
    for item in inventory:
        expected_dhcp[(str(item["hostname_key"]), "eth0")] = {
            **item, "mac": item["eth0_mac"],
        }
        if item.get("eth1_mac"):
            expected_dhcp[(str(item["hostname_key"]), "eth1")] = {
                **item, "mac": item["eth1_mac"],
            }
    actual_dhcp: dict[tuple[str, str], dict[str, object]] = {}
    for row in dhcp_rows:
        if not isinstance(row, dict):
            raise LoadError("DHCP release manifest.devices 包含非 object 元素")
        key = (
            str(row.get("hostname") or "").strip().casefold(),
            str(row.get("interface") or "").strip().casefold(),
        )
        if not all(key) or key in actual_dhcp:
            raise LoadError(f"DHCP release manifest 设备接口为空或重复：{key}")
        actual_dhcp[key] = row
    if set(actual_dhcp) != set(expected_dhcp):
        missing = sorted(set(expected_dhcp) - set(actual_dhcp))
        extra = sorted(set(actual_dhcp) - set(expected_dhcp))
        raise LoadError(
            f"DHCP release 与当前设备接口清单漂移：missing={missing or 'none'}，"
            f"extra={extra or 'none'}"
        )
    for key, expected in expected_dhcp.items():
        row = actual_dhcp[key]
        if str(row.get("type") or "").casefold() != expected["type"]:
            raise LoadError(f"DHCP release {key} type 与当前 CSV 不一致")
        actual_mac = _normalized_mac(row.get("mac"))
        if actual_mac != expected["mac"]:
            raise LoadError(f"DHCP release {key} MAC 与当前 CSV 不一致")
        expected_state = "identified" if expected["mac"] else "identity_pending"
        if row.get("identity_state") != expected_state:
            raise LoadError(
                f"DHCP release {key} identity_state={row.get('identity_state')!r}，"
                f"当前应为 {expected_state!r}"
            )
    output_hashes = dhcp.get("outputs")
    if not isinstance(output_hashes, dict):
        raise LoadError("DHCP release manifest 缺少 outputs hash")
    for source in dhcp_file_mappings():
        item = output_hashes.get(source.name)
        expected_hash = item.get("sha256") if isinstance(item, dict) else None
        if expected_hash != _sha256_path(source):
            raise LoadError(f"DHCP release 输出 hash 漂移：{source.name}")

    components: dict[str, dict[str, str]] = {
        "dhcp": {
            "release_id": str(dhcp["release_id"]),
            "manifest_sha256": _sha256_path(dhcp_path),
        },
    }
    platform_specs = (
        ("cumulus", {"eth", "eth_spx", "spx", "air"},
         ZTP_DIR / "config/cumulus/latest_yaml"),
        ("nvos", {"ib", "nvl"}, ZTP_DIR / "config/nvos/latest_yaml"),
    )
    for label, kinds, latest in platform_specs:
        expected = [item for item in inventory if item["type"] in kinds]
        if not expected:
            continue
        try:
            release_dir = latest.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LoadError(f"{label} latest_yaml 不可用：{latest}: {exc}") from exc
        marker = release_dir / ".published-complete"
        _nonempty_release_file(marker, f"{label} published marker")
        manifest_path = release_dir / "release-manifest.json"
        _nonempty_release_file(manifest_path, f"{label} release manifest")
        manifest = _load_release_json(manifest_path, f"{label} release manifest")
        _validate_manifest_devices(label=label, manifest=manifest, expected=expected)
        _validate_child_artifacts(
            label=label, release_dir=release_dir, manifest=manifest,
        )
        components[label] = {
            "release_id": str(manifest["release_id"]),
            "manifest_sha256": _sha256_path(manifest_path),
            "published_marker_sha256": _sha256_path(marker),
            "release_dir": str(release_dir.relative_to(project.resolve())),
        }

    input_files = {
        "global": inputs.global_file,
        "devices": inputs.devices_file,
        "subnet": inputs.subnet_file,
        "p2p": inputs.p2p_file,
    }
    input_hashes = {name: _sha256_path(path) for name, path in input_files.items()}
    release_basis = {
        "project": project.name,
        "inputs": input_hashes,
        "components": components,
        "inventory": [{
            "hostname": item["hostname"],
            "type": item["type"],
            "eth0_mac": item["eth0_mac"] or None,
            "eth1_mac": item["eth1_mac"] or None,
            "identity_state": item["identity_state"],
            "identity_source": item.get("identity_source", "devices_config"),
        } for item in inventory],
    }
    release_id = hashlib.sha256(
        json.dumps(
            release_basis, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:20]
    parent = {
        "schema_version": 1,
        "release_id": release_id,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "validation": "passed",
        **release_basis,
    }
    if publish:
        publish_current_release(project, parent)
    else:
        pending = sum(item["identity_state"] == "identity_pending" for item in inventory)
        ok(
            f"统一 release {release_id} 已验证：{len(inventory)} 台设备，"
            f"identity_pending={pending}；等待 DHCP 事务安装后提交"
        )
    return parent


def prepare_current_release(
    project: Path, parent: dict[str, object],
) -> PreparedParentRelease:
    """Write and fsync a parent candidate without making it visible yet."""
    destination = project / "99-output-ztp/current-release.json"
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".current-release.", suffix=".tmp", dir=destination.parent,
    )
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(parent, stream, ensure_ascii=False, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o644)
    except BaseException:
        if os.path.exists(temporary):
            os.unlink(temporary)
        raise
    return PreparedParentRelease(
        destination=destination,
        temporary=Path(temporary),
        release_id=str(parent.get("release_id") or ""),
    )


def commit_prepared_release(candidate: PreparedParentRelease) -> Path:
    """Commit an already-fsynced parent candidate with one atomic replace."""
    if candidate.committed:
        return candidate.destination
    os.replace(candidate.temporary, candidate.destination)
    candidate.committed = True
    # fsync the containing directory so the rename itself survives a crash.
    try:
        descriptor = os.open(candidate.destination.parent, os.O_RDONLY)
    except OSError:
        descriptor = None
    if descriptor is not None:
        try:
            try:
                os.fsync(descriptor)
            except OSError as exc:
                # The atomic replace is already externally visible.  Report
                # the durability warning without pretending the commit failed
                # and rolling another component back behind its marker.
                warn(f"current-release 目录 fsync 失败（原子提交已完成）：{exc}")
        finally:
            os.close(descriptor)
    try:
        ok(
            f"统一 release {candidate.release_id} 已提交：{candidate.destination}"
        )
    except BrokenPipeError:
        pass
    return candidate.destination


def discard_prepared_release(candidate: PreparedParentRelease | None) -> None:
    """Remove an uncommitted candidate after any earlier transaction failure."""
    if candidate is not None and not candidate.committed:
        candidate.temporary.unlink(missing_ok=True)


def publish_current_release(project: Path, parent: dict[str, object]) -> Path:
    """Compatibility wrapper for callers that do not install local DHCP."""
    candidate = prepare_current_release(project, parent)
    try:
        return commit_prepared_release(candidate)
    finally:
        discard_prepared_release(candidate)


def snapshot_release_links(project: Path) -> dict[Path, Optional[str]]:
    """Capture logical YAML release links before generators publish a candidate."""
    snapshot: dict[Path, Optional[str]] = {}
    for path in (
        project / "99-output-eth/latest",
        project / "99-output-ib_nvl/latest",
    ):
        try:
            snapshot[path] = os.readlink(path) if path.is_symlink() else None
        except OSError as exc:
            raise LoadError(f"无法读取现有 release 链接 {path}: {exc}") from exc
    return snapshot


def restore_release_links(snapshot: dict[Path, Optional[str]]) -> None:
    """Restore logical latest links after a pre-commit generation/install failure."""
    errors = []
    for path, target in snapshot.items():
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.parent / f".{path.name}.rollback.{os.getpid()}"
            temporary.unlink(missing_ok=True)
            if target is None:
                path.unlink(missing_ok=True)
                continue
            temporary.symlink_to(target)
            os.replace(temporary, path)
        except OSError as exc:
            errors.append(f"{path}: {exc}")
    if errors:
        raise LoadError("YAML release 回滚失败：" + "; ".join(errors))
    if snapshot:
        warn("统一 release 未提交；已恢复本次 load 前的 YAML latest 链接")


def generate_configs(
    device_types: frozenset[str], *, install_dhcp: bool, dry_run: bool = False,
    schema_version: int = GLOBAL_SCHEMA_VERSION,
) -> None:
    p2p_dir = ZTP_DIR / "config/cumulus/template/P2P"
    run([sys.executable, "b-xlsx_to_dot.py", "-y"], cwd=p2p_dir, dry_run=dry_run)

    # AIR node identity/MAC comes from p2p-air.json. c1-generate_dhcp.py copies
    # template/IP/netmask/gateway from the matching production CSV row. It must
    # run before hostname2mac validates each pair and points both MACs at the
    # same production full-config YAML.
    run(
        [sys.executable, "c1-generate_dhcp.py", "-y"],
        cwd=ZTP_DIR / "config/isc-dhcp-server",
        dry_run=dry_run,
    )
    device_types = _device_types_after_dhcp(
        device_types, dry_run=dry_run, schema_version=schema_version,
    )

    if device_types & {"eth", "eth_spx", "spx", "air"}:
        template_dir = ZTP_DIR / "config/cumulus/template"
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "eth", "-y"],
            cwd=template_dir, dry_run=dry_run,
        )
        if not dry_run:
            output_root = template_dir / "99-output"
            generated = newest_directory(output_root, re.compile(r"\d{8}_\d{6}"))
            if not generated:
                raise LoadError("Cumulus 生成器执行成功但没有找到输出目录")
            with_desc = output_root / (generated.name + "_with_desc")
            publish = with_desc if with_desc.is_dir() else generated
            run(
                [sys.executable, "d-hostname2mac.py", "-y", str(publish)],
                cwd=ZTP_DIR / "config/cumulus",
            )

    if device_types & {"ib", "nvl"}:
        template_dir = ZTP_DIR / "config/nvos/template"
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "ib", "-y"],
            cwd=template_dir, dry_run=dry_run,
        )
        if not dry_run:
            output_root = template_dir / "99-output-ib_nvl"
            kinds = []
            for kind in ("ib", "nvl"):
                if kind not in device_types:
                    continue
                directory = newest_directory(
                    output_root, re.compile(rf"\d{{8}}_\d{{6}}-{kind}")
                )
                if not directory:
                    raise LoadError(f"NVOS 生成器执行成功但没有找到 {kind} 输出目录")
                kinds.append(directory)
            run(
                [sys.executable, "d-hostname2mac.py", "-y", *map(str, kinds)],
                cwd=ZTP_DIR / "config/nvos",
            )

    if install_dhcp:
        info("DHCP 安装已延后到统一 release 验证通过之后")
    else:
        warn("本机没有可用 service_ip：已生成 DHCP 文件，但不复制到 /etc/dhcp，也不执行 dhcpd -t")


def confirm_service_start() -> bool:
    if not sys.stdin.isatty():
        warn("非交互终端默认不启动 Apache/DHCP；使用 --start-services 明确启用")
        return False
    print(
        "是否启动 Apache 和 DHCP？直接回车或 "
        f"{PROMPT_TIMEOUT} 秒无输入默认启动 [yes]：",
        end="", flush=True,
    )
    ready, _, _ = select.select([sys.stdin], [], [], PROMPT_TIMEOUT)
    if not ready:
        print("yes")
        return True
    try:
        answer = sys.stdin.readline().strip().casefold()
    except EOFError:
        return False
    return answer in {"", "y", "yes"}


def confirm_ztp_monitor_start() -> bool:
    if not sys.stdin.isatty():
        warn(
            "非交互终端默认不启动 ZTP 后台监控；"
            "使用 --start-ztp-monitor 明确启用"
        )
        return False
    print(
        "是否在后台启动 ZTP 状态监控并实时刷新 monitor.html？直接回车或 "
        f"{PROMPT_TIMEOUT} 秒无输入默认启动 [yes]：",
        end="", flush=True,
    )
    ready, _, _ = select.select([sys.stdin], [], [], PROMPT_TIMEOUT)
    if not ready:
        print("yes")
        return True
    try:
        answer = sys.stdin.readline().strip().casefold()
    except EOFError:
        return False
    return answer in {"", "y", "yes"}


def _ztp_monitor_paths() -> tuple[Path, Path, Path]:
    status_dir = ZTP_DIR / "status"
    return (
        status_dir,
        status_dir / "ztp-monitor.pid",
        status_dir / "ztp-monitor-background.log",
    )


def ztp_monitor_running(pid_file: Path, project: Path) -> tuple[bool, int | None]:
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        if pid <= 0:
            return False, None
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False, None

    # On Linux, protect against a stale PID file whose PID has been reused by an
    # unrelated process. If /proc is unavailable, the PID file + kill(0) check is
    # the best portable evidence available.
    cmdline_path = Path("/proc") / str(pid) / "cmdline"
    try:
        cmdline = cmdline_path.read_bytes().replace(b"\0", b" ").decode(
            "utf-8", errors="replace"
        )
    except OSError:
        return True, pid
    expected = (ZTP_MONITOR_SCRIPT.name, project.name)
    return all(item in cmdline for item in expected), pid


def stop_other_ztp_monitors(project: Path) -> list[int]:
    """Stop detached monitors for another project before starting the active one."""
    stopped: list[int] = []
    proc_root = Path("/proc")
    if not proc_root.is_dir():
        return stopped
    current_pid = os.getpid()
    for entry in proc_root.iterdir():
        if not entry.name.isdigit():
            continue
        pid = int(entry.name)
        if pid == current_pid:
            continue
        try:
            cmdline = [token.decode("utf-8", errors="replace") for token in
                       (entry / "cmdline").read_bytes().split(b"\0") if token]
        except OSError:
            continue
        if (str(ZTP_MONITOR_SCRIPT) not in cmdline or "--watch" not in cmdline
                or str(project) in cmdline):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            continue
        stopped.append(pid)
    return stopped


def resolve_ztp_monitor_scope(
    project: Path, requested: str, *, prompt_fn=None,
) -> str:
    """Resolve the environment reachable from this management server.

    AIR and Production intentionally reuse management IP addresses, while one
    management server normally reaches only one environment.  Do not guess an
    environment for collection or completion handling.
    """
    if requested != "auto":
        return requested
    if prompt_fn is None:
        if not sys.stdin.isatty():
            raise LoadError(
                "非交互启动 ZTP 监控时必须指定 "
                "--ztp-monitor-scope air 或 --ztp-monitor-scope prod"
            )
        prompt_fn = input
    while True:
        answer = prompt_fn(
            "当前管理服务器可达哪个 ZTP 环境？请输入 air 或 prod："
        ).strip().casefold()
        aliases = {"a": "air", "air": "air", "p": "prod",
                   "prod": "prod", "production": "prod"}
        if answer in aliases:
            scope = aliases[answer]
            info(f"ZTP 监控采集范围：{scope}")
            return scope
        warn("无效环境；请输入 air 或 prod（此选择没有默认值）")


def print_ztp_monitor_access(service_ips: tuple[str, ...]) -> None:
    """Show operators where the live ZTP status can be inspected."""
    status_csv = ZTP_DIR / "status" / "latest" / "devices.csv"
    info(f"ZTP 状态 CSV：{status_csv}")
    for address in dict.fromkeys(service_ips):
        info(f"ZTP 状态页面：http://{address}/monitor/monitor.html")


def start_switch_collection_worker(scope: str, *, dry_run: bool = False) -> None:
    """Start the Switch Status collector with resources separate from ZTP control."""
    status_dir = HTTP_ROOT / "monitor/status"
    request_file = status_dir / "switch-collection.request"
    pid_file = status_dir / "switch-collection.pid"
    log_file = status_dir / "switch-collection.log"
    command = [
        sys.executable, "-u", str(SWITCH_COLLECTION_WORKER), "--scope", scope,
    ]
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(
            f"[DRY] 安装 Switch 收集控制端点：{SWITCH_COLLECTION_CONTROL_SOURCE} -> "
            f"{SWITCH_COLLECTION_CONTROL_DEST}"
        )
        print(f"[DRY] 后台启动独立 Switch 收集 worker：{display}")
        print(f"[DRY] PID: {pid_file}；日志: {log_file}；请求: {request_file}")
        return
    for source, label in (
        (SWITCH_COLLECTION_WORKER, "Switch 收集 worker"),
        (SWITCH_COLLECTION_CONTROL_SOURCE, "Switch 收集控制脚本"),
    ):
        if not source.is_file():
            raise LoadError(f"{label}不存在：{source}")
    status_dir.mkdir(parents=True, exist_ok=True)
    run(sudo_command("install", "-d", "-m", "0755", str(SWITCH_COLLECTION_CONTROL_DEST.parent)))
    run(sudo_command(
        "install", "-m", "0755", str(SWITCH_COLLECTION_CONTROL_SOURCE),
        str(SWITCH_COLLECTION_CONTROL_DEST),
    ))
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as request_source:
        request_source.write("idle\n")
        request_source.flush()
        run(sudo_command(
            "install", "-m", "0664", "-o", "root", "-g", "www-data",
            request_source.name, str(request_file),
        ))
    if subprocess.run(
        ["systemctl", "is-active", "--quiet", "apache2"], check=False,
    ).returncode == 0:
        run(sudo_command("apache2ctl", "configtest"))
        run(sudo_command("systemctl", "reload", "apache2"))

    old_pid = None
    try:
        old_pid = int(pid_file.read_text(encoding="utf-8").strip())
        cmdline = (Path("/proc") / str(old_pid) / "cmdline").read_bytes().replace(b"\0", b" ")
        if SWITCH_COLLECTION_WORKER.name.encode() not in cmdline:
            old_pid = None
    except (OSError, ValueError):
        old_pid = None
    if old_pid:
        try:
            os.kill(old_pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(old_pid, 0)
            except (OSError, ProcessLookupError):
                break
            time.sleep(0.1)
        else:
            raise LoadError(f"旧 Switch 收集 worker PID={old_pid} 在 5 秒内未退出")
    pid_file.unlink(missing_ok=True)
    with log_file.open("a", encoding="utf-8") as output:
        output.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] load.py starting: {display}\n")
        output.flush()
        process = subprocess.Popen(
            command, cwd=HTTP_ROOT, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if process.poll() is not None:
        pid_file.unlink(missing_ok=True)
        raise LoadError(f"Switch 收集 worker 启动后立即退出；请检查 {log_file}")
    ok(f"独立 Switch 收集 worker 已启动：PID={process.pid}，scope={scope}，日志={log_file}")


def start_manual_ztp_worker(scope: str, *, dry_run: bool = False) -> None:
    """Start the restricted per-device manual ZTP GUI worker."""
    if scope not in {"air", "prod"}:
        raise LoadError("手工 ZTP worker 必须使用 air 或 prod scope")
    status_dir = HTTP_ROOT / "monitor/status"
    request_file = status_dir / "manual-ztp.request.json"
    pid_file = status_dir / "manual-ztp.pid"
    log_file = status_dir / "manual-ztp.log"
    command = [sys.executable, "-u", str(MANUAL_ZTP_WORKER), "--scope", scope]
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(
            f"[DRY] 安装手工 ZTP 控制端点：{MANUAL_ZTP_CONTROL_SOURCE} -> "
            f"{MANUAL_ZTP_CONTROL_DEST}"
        )
        print(f"[DRY] 后台启动手工 ZTP worker：{display}")
        print(f"[DRY] PID: {pid_file}；日志: {log_file}；请求: {request_file}")
        return
    for source, label in (
        (MANUAL_ZTP_WORKER, "手工 ZTP worker"),
        (MANUAL_ZTP_CONTROL_SOURCE, "手工 ZTP 控制脚本"),
        (HTTP_ROOT / "ztp/manual-ztp.py", "手工 ZTP 执行脚本"),
        (HTTP_ROOT / "ztp/manual-reset.py", "手工重置执行脚本"),
    ):
        if not source.is_file():
            raise LoadError(f"{label}不存在：{source}")
    status_dir.mkdir(parents=True, exist_ok=True)
    run(sudo_command("install", "-d", "-m", "0755", str(MANUAL_ZTP_CONTROL_DEST.parent)))
    run(sudo_command(
        "install", "-m", "0755", str(MANUAL_ZTP_CONTROL_SOURCE),
        str(MANUAL_ZTP_CONTROL_DEST),
    ))
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as request_source:
        request_source.write('{"requests":[]}\n')
        request_source.flush()
        run(sudo_command(
            "install", "-m", "0664", "-o", "root", "-g", "www-data",
            request_source.name, str(request_file),
        ))
    if subprocess.run(
        ["systemctl", "is-active", "--quiet", "apache2"], check=False,
    ).returncode == 0:
        run(sudo_command("apache2ctl", "configtest"))
        run(sudo_command("systemctl", "reload", "apache2"))

    old_pid = None
    try:
        old_pid = int(pid_file.read_text(encoding="utf-8").strip())
        cmdline = (Path("/proc") / str(old_pid) / "cmdline").read_bytes().replace(b"\0", b" ")
        if MANUAL_ZTP_WORKER.name.encode() not in cmdline:
            old_pid = None
    except (OSError, ValueError):
        old_pid = None
    if old_pid:
        try:
            os.kill(old_pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            try:
                os.kill(old_pid, 0)
            except (OSError, ProcessLookupError):
                break
            time.sleep(0.1)
        else:
            raise LoadError(f"旧手工 ZTP worker PID={old_pid} 在 5 秒内未退出")
    pid_file.unlink(missing_ok=True)
    with log_file.open("a", encoding="utf-8") as output:
        output.write(f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] load.py starting: {display}\n")
        output.flush()
        process = subprocess.Popen(
            command, cwd=HTTP_ROOT, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if process.poll() is not None:
        pid_file.unlink(missing_ok=True)
        raise LoadError(f"手工 ZTP worker 启动后立即退出；请检查 {log_file}")
    ok(f"手工 ZTP worker 已启动：PID={process.pid}，scope={scope}，日志={log_file}")


def start_ztp_monitor(
    project: Path, *, interval: int = DEFAULT_ZTP_MONITOR_INTERVAL,
    scope: str = "all",
    service_ips: tuple[str, ...] = (),
    dry_run: bool = False,
) -> None:
    if interval < 5:
        raise LoadError("ZTP 监控间隔不能小于 5 秒")
    if not ZTP_MONITOR_SCRIPT.is_file():
        raise LoadError(f"ZTP 监控脚本不存在：{ZTP_MONITOR_SCRIPT}")
    if not ZTP_MONITOR_HTML_SCRIPT.is_file():
        raise LoadError(f"监控 HTML 生成脚本不存在：{ZTP_MONITOR_HTML_SCRIPT}")
    status_dir, pid_file, log_file = _ztp_monitor_paths()
    control_file = status_dir / "ztp-monitor.control"
    known_hosts = status_dir / "ztp-known-hosts"
    command = [
        sys.executable, "-u", str(ZTP_MONITOR_SCRIPT), str(project),
        "--watch", str(interval), "--generate-html",
        "--exit-on-complete",
        "--known-hosts", str(known_hosts),
        "--scope", scope,
    ]
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(
            f"[DRY] 安装 ZTP 页面控制端点：{ZTP_MONITOR_CONTROL_SOURCE} -> "
            f"{ZTP_MONITOR_CONTROL_DEST}"
        )
        print(f"[DRY] 后台启动：{display}")
        print(f"[DRY] PID: {pid_file}；日志: {log_file}")
        print_ztp_monitor_access(service_ips)
        return

    status_dir.mkdir(parents=True, exist_ok=True)
    if not ZTP_MONITOR_CONTROL_SOURCE.is_file():
        raise LoadError(f"ZTP 页面控制脚本不存在：{ZTP_MONITOR_CONTROL_SOURCE}")
    run(sudo_command("install", "-d", "-m", "0755", str(ZTP_MONITOR_CONTROL_DEST.parent)))
    run(sudo_command(
        "install", "-m", "0755", str(ZTP_MONITOR_CONTROL_SOURCE),
        str(ZTP_MONITOR_CONTROL_DEST),
    ))
    run(sudo_command("a2enmod", "cgid"))
    run(sudo_command("a2enconf", "serve-cgi-bin"))
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as control_source:
        control_source.write("running\n")
        control_source.flush()
        run(sudo_command(
            "install", "-m", "0664", "-o", "root", "-g", "www-data",
            control_source.name, str(control_file),
        ))
    apache_active = subprocess.run(
        ["systemctl", "is-active", "--quiet", "apache2"], check=False,
    ).returncode == 0
    if apache_active:
        run(sudo_command("apache2ctl", "configtest"))
        run(sudo_command("systemctl", "reload", "apache2"))
    stopped = stop_other_ztp_monitors(project)
    if stopped:
        warn("已停止其他项目的旧 ZTP 监控进程：" + ", ".join(map(str, stopped)))
    running, pid = ztp_monitor_running(pid_file, project)
    if running:
        try:
            os.kill(pid, signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
        else:
            warn(f"已停止同项目旧 ZTP 监控进程 PID={pid}，将使用本次代码和 scope 重启")
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                try:
                    os.kill(pid, 0)
                except (OSError, ProcessLookupError):
                    break
                time.sleep(0.1)
            else:
                raise LoadError(
                    f"同项目旧 ZTP 监控进程 PID={pid} 在 5 秒内未退出；"
                    "为避免重复采集，本次不启动新进程"
                )
    if pid_file.exists():
        pid_file.unlink()

    with log_file.open("a", encoding="utf-8") as output:
        output.write(
            f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"load.py starting: {display}\n"
        )
        output.flush()
        process = subprocess.Popen(
            command,
            cwd=HTTP_ROOT,
            stdin=subprocess.DEVNULL,
            stdout=output,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if process.poll() is not None:
        pid_file.unlink(missing_ok=True)
        raise LoadError(f"ZTP 后台监控启动后立即退出；请检查 {log_file}")
    ok(
        f"ZTP 后台监控已启动：PID={process.pid}，间隔={interval}s，"
        f"scope={scope}，日志={log_file}；停止命令：kill $(cat {pid_file})"
    )
    print_ztp_monitor_access(service_ips)


def local_ipv4_addresses() -> set[str]:
    addresses: set[str] = set()
    if shutil.which("ip"):
        result = subprocess.run(
            ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True
        )
        if result.returncode == 0:
            addresses.update(re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", result.stdout))
    if not addresses and shutil.which("ifconfig"):
        result = subprocess.run(["ifconfig"], capture_output=True, text=True)
        if result.returncode == 0:
            addresses.update(re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", result.stdout))
    return {address for address in addresses if not address.startswith("127.")}


def service_ip_bindings(inputs: ProjectInputs) -> tuple[str, ...]:
    """Return service IP/prefix pairs sourced from enabled endpoint rows."""
    allowed = set(inputs.settings.service_ips)
    bindings: dict[str, int] = {}
    with inputs.subnet_file.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for lineno, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            try:
                network = ipaddress.IPv4Network(
                    f"{str(row.get('subnet') or '').strip()}/"
                    f"{str(row.get('netmask') or '').strip()}",
                    strict=False,
                )
            except ValueError as exc:
                raise LoadError(
                    f"DHCP subnet CSV 第 {lineno} 行无法推导 service_ip 前缀：{exc}"
                ) from exc
            address_text, profile, nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            if profile == "none" and nvos_ztp == "no":
                continue
            if address_text not in allowed:
                raise LoadError(
                    f"DHCP subnet CSV 第 {lineno} 行 ztp_service_ip={address_text} "
                    "不在已推导的启用 endpoint"
                )
            address = ipaddress.IPv4Address(address_text)
            # An endpoint may legitimately be routed from this subnet. Only
            # its on-link row can define the management-server interface prefix.
            if address not in network:
                continue
            previous = bindings.get(address_text)
            if previous is not None and previous != network.prefixlen:
                raise LoadError(
                    f"DHCP subnet CSV 为 service_ip {address_text} 定义了不同掩码："
                    f"/{previous} 和 /{network.prefixlen}"
                )
            bindings[address_text] = network.prefixlen
    ordered = []
    for role in SERVICE_IP_PRIORITY:
        for address_text in inputs.settings.ztp_ips.get(role, ()):
            if address_text not in bindings:
                continue
            binding = f"{address_text}/{bindings[address_text]}"
            if binding not in ordered:
                ordered.append(binding)
    for address_text in inputs.settings.boot_ips:
        if address_text not in bindings:
            # A routed endpoint can be outside every served DHCP subnet. Its
            # interface prefix cannot be inferred here; the per-address local
            # gate below still requires that exact IP to exist on this host.
            continue
        binding = f"{address_text}/{bindings[address_text]}"
        if binding not in ordered:
            ordered.append(binding)
    return tuple(ordered)


def _local_ipv4_assignments() -> dict[str, set[tuple[str, int]]]:
    """Return every IPv4 -> {(interface, prefix length), ...} assignment."""
    if not shutil.which("ip"):
        raise LoadError("本机没有 ip 命令，无法配置 service_ip")
    result = subprocess.run(
        ["ip", "-4", "-o", "address", "show"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise LoadError("无法读取本机 IPv4 接口配置")
    assignments: dict[str, set[tuple[str, int]]] = {}
    for line in result.stdout.splitlines():
        match = re.match(
            r"^\d+:\s+([^\s:@]+)(?:@[^\s:]+)?\s+inet\s+"
            r"(\d+\.\d+\.\d+\.\d+)/(\d+)\b",
            line,
        )
        if match:
            interface, address, prefix = match.groups()
            assignments.setdefault(address, set()).add((interface, int(prefix)))
    return assignments


def configure_service_ips(
    requested: tuple[tuple[str, str], ...], dry_run: bool = False,
) -> tuple[tuple[str, str], ...]:
    """Apply individually selected (CIDR, interface) service IP mappings."""
    if not requested:
        raise LoadError("DHCP subnet CSV 没有可配置的 service_ip")
    normalized = []
    seen_bindings = set()
    for binding, raw_interface in requested:
        try:
            interface = ipaddress.IPv4Interface(binding)
        except ValueError as exc:
            raise LoadError(f"service_ip CIDR 无效：{binding}") from exc
        address_text = str(interface.ip)
        interface_name = raw_interface.strip()
        if (not interface_name or
                not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", interface_name)):
            raise LoadError(f"接口名无效：{raw_interface!r}")
        requested_binding = (address_text, interface_name)
        if requested_binding in seen_bindings:
            raise LoadError(
                f"service_ip 接口重复配置：{address_text} dev {interface_name}"
            )
        seen_bindings.add(requested_binding)
        normalized.append((str(interface), interface_name))

    if not dry_run:
        if not shutil.which("ip"):
            raise LoadError("本机没有 ip 命令，无法配置 service_ip")
        for interface_name in sorted({item[1] for item in normalized}):
            check = subprocess.run(
                ["ip", "link", "show", "dev", interface_name],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            if check.returncode != 0:
                raise LoadError(f"本机接口不存在：{interface_name}")

    assignments = {} if dry_run else _local_ipv4_assignments()

    pending = []
    for binding, interface_name in normalized:
        address_text, prefix_text = binding.split("/", 1)
        existing = assignments.get(address_text, set())
        # Compatibility for callers/tests written before multiple-interface
        # assignments were supported.
        if isinstance(existing, tuple):
            existing = {existing}
        expected = (interface_name, int(prefix_text))
        if expected in existing:
            ok(f"service_ip 已配置：{binding} dev {interface_name}")
            continue
        conflicting_prefix = [
            prefix for name, prefix in existing if name == interface_name
        ]
        if conflicting_prefix:
            raise LoadError(
                f"service_ip {address_text} 已配置在 {interface_name}/"
                f"{conflicting_prefix[0]}，与请求前缀 /{prefix_text} 不同；不会自动修改，"
                "以免中断管理连接"
            )
        pending.append((binding, interface_name))

    if not pending:
        return tuple(normalized)
    for interface_name in sorted({item[1] for item in pending}):
        run(
            sudo_command("ip", "link", "set", "dev", interface_name, "up"),
            dry_run=dry_run,
        )
    added = []
    configured_per_address = {
        address: len(values) for address, values in assignments.items()
    }
    try:
        for binding, interface_name in pending:
            address_text = binding.split("/", 1)[0]
            command = ["ip", "address", "add", binding, "dev", interface_name]
            if configured_per_address.get(address_text, 0) > 0:
                # The first assignment owns the connected prefix route.  Every
                # additional interface carries the same local address without
                # trying to install the same route again.
                command.append("noprefixroute")
            run(
                sudo_command(*command),
                dry_run=dry_run,
            )
            added.append((binding, interface_name))
            configured_per_address[address_text] = (
                configured_per_address.get(address_text, 0) + 1
            )
            ok(f"已配置 service_ip：{binding} dev {interface_name}")
    except LoadError:
        if not dry_run:
            for binding, interface_name in reversed(added):
                subprocess.run(
                    sudo_command(
                        "ip", "address", "del", binding, "dev", interface_name
                    ),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
        raise
    return tuple(normalized)


def _service_ip_interface_names(raw_value: str) -> tuple[str, ...]:
    """Split one prompt value into ordered comma/space-separated interfaces."""
    values = [
        value for value in re.split(r"[,\s]+", raw_value.strip()) if value
    ]
    ordered = []
    for value in values:
        if value not in ordered:
            ordered.append(value)
    return tuple(ordered)


def configure_static_routes(
    requested: tuple[tuple[str, str], ...], dry_run: bool = False,
) -> tuple[tuple[str, str], ...]:
    """Add non-conflicting IPv4 static routes as (destination, gateway)."""
    normalized = []
    seen_destinations = set()
    for raw_destination, raw_gateway in requested:
        destination_text = raw_destination.strip().casefold()
        if destination_text == "default":
            destination_text = "0.0.0.0/0"
        try:
            destination = ipaddress.IPv4Network(destination_text, strict=False)
            gateway = ipaddress.IPv4Address(raw_gateway.strip())
        except ValueError as exc:
            raise LoadError(
                f"静态路由无效：{raw_destination} via {raw_gateway}"
            ) from exc
        if gateway.is_unspecified or gateway.is_multicast:
            raise LoadError(f"静态路由下一跳不可用：{gateway}")
        destination_text = str(destination)
        if destination_text in seen_destinations:
            raise LoadError(f"静态路由目标重复：{destination_text}")
        seen_destinations.add(destination_text)
        normalized.append((destination_text, str(gateway)))

    if not normalized:
        return ()
    if not dry_run and not shutil.which("ip"):
        raise LoadError("本机没有 ip 命令，无法配置静态路由")

    pending = []
    for destination, gateway in normalized:
        if not dry_run:
            current = subprocess.run(
                ["ip", "-4", "route", "show", "exact", destination],
                capture_output=True, text=True,
            )
            if current.returncode != 0:
                raise LoadError(f"无法检查现有静态路由：{destination}")
            routes = [line.strip() for line in current.stdout.splitlines() if line.strip()]
            if routes:
                exact = any(
                    re.search(rf"(?:^|\s)via\s+{re.escape(gateway)}(?:\s|$)", line)
                    for line in routes
                )
                if exact:
                    ok(f"静态路由已存在：{destination} via {gateway}")
                    continue
                raise LoadError(
                    f"静态路由 {destination} 已存在其他配置："
                    + " | ".join(routes)
                    + "；不会自动覆盖"
                )
        pending.append((destination, gateway))

    added = []
    try:
        for destination, gateway in pending:
            run(
                sudo_command(
                    "ip", "route", "add", destination, "via", gateway,
                ),
                dry_run=dry_run,
            )
            added.append((destination, gateway))
            ok(f"已配置静态路由：{destination} via {gateway}")
    except LoadError:
        if not dry_run:
            for destination, gateway in reversed(added):
                subprocess.run(
                    sudo_command(
                        "ip", "route", "del", destination, "via", gateway,
                    ),
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                )
        raise
    return tuple(normalized)


def validate_management_host(settings: GlobalSettings, dry_run: bool = False) -> bool:
    problems: list[str] = []
    if settings.http_root.resolve() != HTTP_ROOT.resolve():
        problems.append(
            f"global http_root={settings.http_root}，当前代码根目录={HTTP_ROOT}"
        )
    configured_ips = set(settings.service_ips)
    local_ips = local_ipv4_addresses()
    matching_local = sorted(configured_ips & local_ips)
    missing_local = sorted(configured_ips - local_ips, key=ipaddress.IPv4Address)
    if not matching_local:
        problems.append(
            "DHCP subnet CSV 的 service_ip 中没有任何地址配置在本机接口"
            f"（service_ip={','.join(sorted(configured_ips)) or 'none'}；"
            f"local={','.join(sorted(local_ips)) or 'none'}）"
        )
    elif missing_local:
        warn(
            "以下启用 service_ip 尚未配置在本机接口，将在 DHCP 重启前逐一门禁并"
            "提供重试提示：" + ", ".join(missing_local)
        )
    disabled = []
    if not settings.http_enabled:
        disabled.append("http")
    if not settings.dhcp_enabled:
        disabled.append("dhcp-server")
    if not settings.ztp_enabled:
        disabled.append("ztp")
    if disabled:
        problems.append("以下服务在 global 中未启用：" + ", ".join(disabled))
    if not problems:
        ok("管理服务器 HTTP 根目录和本机 service_ip 基础检查通过：" + ", ".join(matching_local))
        return True
    message = "；".join(problems)
    warn("服务不可用，不能在本机部署/启动 Apache 与 DHCP：" + message)
    info("load 将继续完成项目 setup、bootstrap 渲染和配置文件生成")
    return False


def verify_http_publication(inputs: ProjectInputs, images: dict[str, Path], dry_run: bool) -> None:
    urls = []
    for role, addresses in inputs.settings.ztp_ips.items():
        for address in addresses:
            for pubkey in deployable_pubkeys(inputs.pubkeys):
                urls.append(
                    f"http://{address}{inputs.settings.ztp_prefix}/config/publickey/"
                    f"{pubkey.name}"
                )
            script = BOOTSTRAP_BY_ROLE[role]
            urls.append(f"http://{address}{inputs.settings.ztp_prefix}/{script}")
    for address in inputs.settings.boot_ips:
        urls.append(
            f"http://{address}{inputs.settings.ztp_prefix}/ztp.json"
        )
    for kind, image in images.items():
        platform = "cumulus" if kind == "eth" else "nvos"
        all_addresses = {
            address for address in inputs.settings.service_ips
        }
        for address in sorted(all_addresses):
            urls.append(
                f"http://{address}{inputs.settings.ztp_prefix}/image/{platform}/{image.name}"
            )
    for url in dict.fromkeys(urls):
        run(["curl", "-fsSI", "--max-time", "5", url], dry_run=dry_run)


def verify_published_files(
    inputs: ProjectInputs, images: dict[str, Path], *, dry_run: bool = False,
) -> None:
    runtime_keys = []
    for pubkey in deployable_pubkeys(inputs.pubkeys):
        runtime = pubkey if dry_run else ZTP_DIR / "config/publickey" / pubkey.name
        _nonempty_file(runtime, f"已发布 SSH 公钥 {pubkey.name}")
        validate_pubkey(runtime)
        runtime_keys.append(runtime.name)
    if not runtime_keys:
        raise LoadError("没有可发布的非空 SSH 公钥")
    for role, addresses in inputs.settings.ztp_ips.items():
        if addresses:
            _nonempty_file(ZTP_DIR / BOOTSTRAP_BY_ROLE[role], f"{role} bootstrap")
    for kind, image in images.items():
        platform = "cumulus" if kind == "eth" else "nvos"
        published = image if dry_run else ZTP_DIR / "image" / platform / image.name
        _nonempty_file(published, f"HTTP 镜像发布文件 {published.name}")
    ok("公钥与 HTTP 发布文件检查通过：" + ", ".join(runtime_keys))


def verify_apache_publication_boundary(*, dry_run: bool = False) -> None:
    """Require the exact infra-managed static publication policy before start."""
    if dry_run:
        print(
            f"[DRY] 校验 Apache 静态发布边界：{APACHE_PUBLIC_BOUNDARY_CONF} "
            f"sha256={APACHE_PUBLIC_BOUNDARY_SHA256}"
        )
        return
    try:
        payload = APACHE_PUBLIC_BOUNDARY_CONF.read_bytes()
    except OSError as exc:
        raise LoadError(
            "缺少 Apache 静态发布边界；请先运行当前 infra-setup.sh："
            f"{APACHE_PUBLIC_BOUNDARY_CONF}: {exc}"
        ) from exc
    actual = hashlib.sha256(payload).hexdigest()
    if actual != APACHE_PUBLIC_BOUNDARY_SHA256:
        raise LoadError(
            "Apache 静态发布边界与当前 load 版本不一致："
            f"{APACHE_PUBLIC_BOUNDARY_CONF} sha256={actual}，"
            f"期望={APACHE_PUBLIC_BOUNDARY_SHA256}；请重新运行当前 infra-setup.sh"
        )
    ok(f"Apache 静态发布边界已验证：{APACHE_PUBLIC_BOUNDARY_CONF}")


def preflight_services(
    inputs: ProjectInputs, images: dict[str, Path], dry_run: bool = False,
) -> None:
    if not inputs.settings.ztp_enabled:
        info("global 中 ZTP status=disabled，不启动服务")
        return
    if not validate_management_host(inputs.settings, dry_run):
        raise LoadError("本机服务启动条件不满足")
    verify_published_files(inputs, images, dry_run=dry_run)
    verify_apache_publication_boundary(dry_run=dry_run)
    for source in dhcp_file_mappings():
        _nonempty_file(source, f"DHCP 输出 {source.name}")
    run(sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"), dry_run=dry_run)
    run(sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
    ok("启动前检查通过：公钥、DHCP、Apache 配置和 HTTP 发布文件均有效")


def ztp_url_network_requirements(
    inputs: ProjectInputs,
) -> tuple[tuple[str, ...], dict[str, list[tuple[str, str, str]]]]:
    """Return URL service CIDRs and the DHCP networks which reference each IP."""
    bindings = service_ip_bindings(inputs)
    references: dict[str, list[tuple[str, str, str]]] = {}
    with inputs.subnet_file.open(newline="", encoding="utf-8-sig") as stream:
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for lineno, row in enumerate(reader, 2):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            try:
                network = ipaddress.IPv4Network(
                    f"{str(row.get('subnet') or '').strip()}/"
                    f"{str(row.get('netmask') or '').strip()}", strict=False,
                )
            except ValueError:
                continue  # validate_subnet_file already reports the precise input error.
            address, profile, nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            if profile == "none" and nvos_ztp == "no":
                continue
            item = (
                str(row.get("shared_network") or "").strip() or "unnamed",
                str(network), str(row.get("routers") or "").strip(),
            )
            if item not in references.setdefault(address, []):
                references[address].append(item)
    return bindings, references


def missing_ztp_url_bindings(
    bindings: tuple[str, ...], assignments: dict[str, set[tuple[str, int]]],
) -> list[str]:
    missing = []
    for binding in bindings:
        interface = ipaddress.IPv4Interface(binding)
        address = str(interface.ip)
        existing = assignments.get(address, set())
        if isinstance(existing, tuple):
            existing = {existing}
        if not any(prefix == interface.network.prefixlen for _name, prefix in existing):
            missing.append(binding)
    return missing


def missing_service_ip_addresses(
    service_ips: tuple[str, ...],
    assignments: dict[str, set[tuple[str, int]]],
) -> list[str]:
    """Return every enabled endpoint IP absent from all local interfaces."""
    return [address for address in service_ips if not assignments.get(address)]


def print_ztp_url_network_guidance(
    missing: list[str], references: dict[str, list[tuple[str, str, str]]],
) -> None:
    warn("管理服务器本地接口缺少 DHCP subnet ZTP URL 使用的服务地址：")
    for binding in missing:
        address = binding.split("/", 1)[0]
        print(f"  - {binding}")
        print(f"    接口配置：sudo ip address add {binding} dev <interface>")
        for shared, network, client_router in references.get(address, []):
            print(
                f"    {shared}: 客户端网段 {network}，DHCP routers={client_router or '未设置'}"
            )
            if ipaddress.IPv4Address(address) in ipaddress.IPv4Network(network):
                print("      该接口地址配置后会自动建立此网段的 connected route")
            else:
                print(f"      检查路由：ip route get {network.split('/', 1)[0]}")
                print(
                    f"      如需静态路由：sudo ip route add {network} "
                    "via <reachable-next-hop> dev <interface>"
                )
    warn(
        "DHCP CSV 的 routers 是客户端默认网关，不一定是管理服务器可用的下一跳；"
        "load 不会自动猜测路由。"
    )


def ensure_ztp_url_network_ready(
    inputs: ProjectInputs, *, dry_run: bool = False,
) -> None:
    """Gate the DHCP restart on every URL IP being configured locally."""
    bindings, references = ztp_url_network_requirements(inputs)
    if dry_run:
        info(
            "dry-run：重启 DHCP 前将逐一检查本地 endpoint："
            + ", ".join(inputs.settings.service_ips)
        )
        if bindings:
            info("dry-run：其中 on-link endpoint 还将校验前缀：" + ", ".join(bindings))
        return
    while True:
        assignments = _local_ipv4_assignments()
        missing_addresses = missing_service_ip_addresses(
            inputs.settings.service_ips, assignments,
        )
        missing_bindings = missing_ztp_url_bindings(bindings, assignments)
        if not missing_addresses and not missing_bindings:
            details = []
            expected = {binding.split("/", 1)[0]: binding for binding in bindings}
            for address in inputs.settings.service_ips:
                names = ",".join(
                    sorted(
                        f"{name}/{prefix}"
                        for name, prefix in assignments.get(address, set())
                    )
                )
                label = expected.get(address, address)
                details.append(f"{label} dev {names}")
            ok(
                "DHCP 重启门禁：全部 ZTP endpoint 均已配置在本地接口（"
                + "；".join(details) + "）"
            )
            return
        if missing_addresses:
            warn(
                "以下启用 endpoint IP 未配置在本机任何接口："
                + ", ".join(missing_addresses)
            )
            onlink_addresses = {
                binding.split("/", 1)[0] for binding in bindings
            }
            for address in missing_addresses:
                if address not in onlink_addresses:
                    print(
                        f"  - {address}（routed/off-link；请按管理网络规划配置正确 CIDR）"
                    )
        if missing_bindings:
            print_ztp_url_network_guidance(missing_bindings, references)
        if not sys.stdin.isatty():
            raise LoadError(
                "非交互模式无法确认接口/路由配置；为避免启动不可用的 DHCP，已停止服务启动"
            )
        print(
            "请在另一终端完成接口地址和路由配置；完成后输入 r 重新检查，"
            f"输入 q 取消（{PROMPT_TIMEOUT} 秒无输入默认 q）[r/q]：",
            end="", flush=True,
        )
        ready, _, _ = select.select([sys.stdin], [], [], PROMPT_TIMEOUT)
        if not ready:
            print("q")
            raise LoadError("ZTP URL 地址尚未配置，未重启 DHCP")
        answer = sys.stdin.readline().strip().casefold()
        if answer not in {"r", "retry"}:
            raise LoadError("ZTP URL 地址尚未配置，未重启 DHCP")


def snapshot_service_states(
    services: tuple[str, ...],
) -> dict[str, ServiceRuntimeState]:
    """Capture service state after all read-only gates and before first mutation."""
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise LoadError("服务启动门禁失败：未找到 systemctl")
    states: dict[str, ServiceRuntimeState] = {}
    for service in services:
        active = subprocess.run(
            [systemctl, "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        enabled = subprocess.run(
            [systemctl, "is-enabled", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        states[service] = ServiceRuntimeState(enabled=enabled, active=active)
    return states


def restore_service_states(states: dict[str, ServiceRuntimeState]) -> None:
    """Best-effort restoration after a partial service activation failure."""
    commands: list[list[str]] = []
    # Stop both units first so an enable/disable rollback cannot leave a
    # half-started Apache/DHCP pair serving different releases.
    commands.extend(
        sudo_command("systemctl", "stop", service) for service in states
    )
    commands.extend(
        sudo_command(
            "systemctl", "enable" if state.enabled else "disable", service,
        )
        for service, state in states.items()
    )
    commands.extend(
        sudo_command("systemctl", "start", service)
        for service, state in states.items() if state.active
    )
    errors = []
    for command in commands:
        try:
            run(command)
        except (LoadError, OSError, subprocess.SubprocessError) as exc:
            errors.append(str(exc))
    if errors:
        raise LoadError("服务状态回滚失败：" + "；".join(errors))
    warn("服务启动未完成；已恢复进入启动阶段前的 enabled/active 状态")


def start_services(inputs: ProjectInputs, images: dict[str, Path], dry_run: bool = False) -> None:
    services = ("apache2", "isc-dhcp-server")
    # This network/interface check can prompt the operator, so it must finish
    # before the first enable/start/restart action.
    ensure_ztp_url_network_ready(inputs, dry_run=dry_run)
    if dry_run:
        run(sudo_command("systemctl", "enable", "--now", "apache2"), dry_run=True)
        run(sudo_command("systemctl", "enable", "isc-dhcp-server"), dry_run=True)
        run(sudo_command("systemctl", "restart", "isc-dhcp-server"), dry_run=True)
        verify_http_publication(inputs, images, True)
    else:
        states = snapshot_service_states(services)
        try:
            run(sudo_command("systemctl", "enable", "--now", "apache2"))
            run(sudo_command("systemctl", "enable", "isc-dhcp-server"))
            run(sudo_command("systemctl", "restart", "isc-dhcp-server"))
            # Live URL checks are post-start health verification; every check
            # which can run while quiesced has already passed above/in preflight.
            verify_http_publication(inputs, images, False)
        except BaseException as exc:
            rollback_error = ""
            try:
                restore_service_states(states)
            except (LoadError, OSError, subprocess.SubprocessError) as rollback_exc:
                rollback_error = str(rollback_exc)
            if rollback_error:
                print(f"[ERROR] {rollback_error}", file=sys.stderr)
                if isinstance(exc, Exception):
                    raise LoadError(
                        f"服务启动失败且状态回滚不完整：{exc}；{rollback_error}"
                    ) from exc
            # In particular, never turn KeyboardInterrupt into a normal return.
            raise
    ok(
        "ZTP 服务已启动；HTTP URL 回读检查通过。"
        f"使用镜像：{', '.join(path.name for path in images.values()) or 'none'}"
    )


def validate_inputs(
    project: Path, args: argparse.Namespace,
) -> tuple[ProjectInputs, dict[str, Path]]:
    global_file = project / "01-global.yaml"
    devices_file = project / "02-devices_config.csv"
    subnet_file = project / "02-dhcp-subnet_config.csv"
    settings = load_global(global_file)
    validation_errors = []
    device_types: frozenset[str] = frozenset()
    p2p_file = project / (args.p2p_file or "p2p.xlsx")
    try:
        settings = apply_subnet_service_ips(settings, subnet_file)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        device_types = load_device_types(devices_file, settings.schema_version)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        p2p_file = select_p2p(project, args.p2p_file)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        validate_subnet_file(subnet_file, settings)
    except LoadError as exc:
        validation_errors.append(str(exc))
    if device_types and not args.no_upgrade:
        try:
            # First pass is read-only so all customer-input errors are reported
            # together before a project image is copied into the shared store.
            prepare_images(
                project, expected_images(settings, device_types), dry_run=True, quiet=True
            )
        except LoadError as exc:
            validation_errors.append(str(exc))
    if validation_errors:
        raise LoadError("项目输入检查失败：\n  - " + "\n  - ".join(validation_errors))
    pubkeys = prepare_pubkeys(
        project,
        ssh_dir=args.ssh_dir,
        dry_run=args.dry_run,
        inject_management_key=supports_local_ztp_services(),
    )
    if args.no_upgrade:
        images: dict[str, Path] = {}
        info("--no-upgrade：跳过项目及共享 image 目录中的全部 .bin 检查")
    else:
        images = prepare_images(
            project, expected_images(settings, device_types), dry_run=args.dry_run
        )
    ok(
        f"输入检查通过：types={','.join(sorted(device_types))}，"
        f"P2P={p2p_file.name}，keys={','.join(item.name for item in pubkeys[:2])}"
    )
    return (
        ProjectInputs(
            global_file=global_file,
            devices_file=devices_file,
            subnet_file=subnet_file,
            p2p_file=p2p_file,
            device_types=device_types,
            pubkeys=pubkeys,
            settings=settings,
        ),
        images,
    )


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("project", help="DAY0-Prepare 下的部署项目目录或其绝对路径")
    parser.add_argument("--p2p-file", help="明确选择项目根目录或 p2p/ 下的 P2P XLSX")
    parser.add_argument("--dry-run", action="store_true", help="仅显示动作，不安装、生成或启动")
    parser.add_argument(
        "--no-upgrade", action="store_true",
        help="所有设备保留当前系统版本；跳过 .bin 检查并禁止 bootstrap 执行镜像升级",
    )
    parser.add_argument("--skip-infra", action="store_true", help="跳过本机 infra 安装（调试用）")
    parser.add_argument(
        "--skip-doca", action="store_true",
        help="执行 infra 时跳过全部 DOCA 下载、缓存和安装",
    )
    parser.add_argument(
        "--download-doca", action="store_true",
        help="即使管理服务器没有 Mellanox 网卡，也下载并缓存 DOCA",
    )
    parser.add_argument("--skip-generate", action="store_true", help="跳过配置生成（调试用）")
    parser.add_argument(
        "--start-services", action="store_true",
        help="验证通过后明确启动 Apache/DHCP；不指定时最终交互确认，默认启动",
    )
    parser.add_argument(
        "--start-ztp-monitor", action="store_true",
        help=("load 完成后明确在后台启动 ZTP 状态监控并持续刷新 monitor.html；"
              "不指定时交互确认，默认启动"),
    )
    parser.add_argument(
        "--ztp-monitor-interval", type=int, default=DEFAULT_ZTP_MONITOR_INTERVAL,
        metavar="SECONDS", help="后台 ZTP 监控间隔（默认 30 秒，最小 5 秒）",
    )
    environment = parser.add_mutually_exclusive_group()
    environment.add_argument(
        "--ztp-monitor-scope", choices=("auto", "prod", "air"),
        dest="ztp_monitor_scope",
        help=("本管理服务器可达的 ZTP 环境：auto 在交互终端询问；"
              "prod/air 仅采集指定环境"),
    )
    environment.add_argument(
        "--type", choices=("auto", "prod", "air"), dest="ztp_monitor_scope",
        help="ZTP 监控环境；等价于 --ztp-monitor-scope",
    )
    environment.add_argument(
        "--air", action="store_const", const="air", dest="ztp_monitor_scope",
        help="本管理服务器监控 AIR；等价于 --type air",
    )
    environment.add_argument(
        "--prod", action="store_const", const="prod", dest="ztp_monitor_scope",
        help="本管理服务器监控 Production；等价于 --type prod",
    )
    parser.set_defaults(ztp_monitor_scope="auto")
    parser.add_argument(
        "--ssh-dir", type=Path, default=_default_ssh_dir(), help=argparse.SUPPRESS,
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    release_link_snapshot: dict[Path, Optional[str]] = {}
    release_committed = False
    deployment_lock_descriptor: int | None = None
    parent_candidate: PreparedParentRelease | None = None
    prefix_publication_snapshot: ZtpPrefixPublicationSnapshot | None = None
    services_must_remain_stopped = False
    try:
        if args.skip_doca and args.download_doca:
            raise LoadError("--skip-doca 和 --download-doca 不能同时使用")
        if args.skip_generate and not args.dry_run:
            raise LoadError(
                "--skip-generate 已禁止用于实际 load：现有子 release 不包含 "
                "global/devices/subnet/p2p 来源证明，不能把旧制品重新签名为当前输入；"
                "请执行完整配置生成"
            )
        if not args.dry_run:
            deployment_lock_descriptor = acquire_deployment_lock(exclusive=True)
        host_os = runtime_os()
        local_services_supported = supports_local_ztp_services(host_os)
        info(f"运行平台：{host_os}")
        if not local_services_supported:
            warn(
                f"{host_os} 配置准备模式：继续 setup 和配置生成；跳过 infra、"
                "Apache/ISC DHCP 文件安装、语法检查及服务启停"
            )
        project = resolve_project(args.project)
        sync_marker = HERE.parent / ".sync-code-in-progress"
        if sync_marker_present(sync_marker):
            raise LoadError(
                f"检测到代码/项目同步尚未完成：{sync_marker}\n"
                "请等待 sync-code.py 打印 [OK] 同步完成后再执行 load；"
                "若同步进程已异常退出，请先重新完成一次 sync-code.py"
            )
        if not project.exists() or not _meaningful_entries(project):
            section("初始化空项目")
            initialize_from_template(project, args.dry_run)
            required_images = "" if args.no_upgrade else " 和 global 指定版本的 *.bin"
            result_text = (
                "dry-run：实际执行时将创建项目模板"
                if args.dry_run else "项目模板已创建"
            )
            print(
                f"\n{result_text}。请准备 01-global.yaml、02-devices_config.csv、"
                f"02-dhcp-subnet_config.csv、p2p.xlsx、*.pub{required_images}，"
                "然后再次执行 11-load.py。"
            )
            return 2
        if not project.is_dir():
            raise LoadError(f"参数不是目录：{project}")

        section("补齐项目模板合同")
        initialize_from_template(project, args.dry_run)

        section("项目输入合法性与制品检查")
        inputs, images = validate_inputs(project, args)

        section("活动项目 setup 检查/切换")
        service_available = (
            validate_management_host(inputs.settings, args.dry_run)
            if local_services_supported else False
        )
        # Set the cleanup obligation before the first stop: an interrupt in the
        # middle of quiescing must retry the stop rather than leave one old
        # service active against links which may already be changing.
        services_must_remain_stopped = (
            local_services_supported and service_available and not args.dry_run
        )
        if service_available:
            quiesce_services(args.dry_run)
        elif local_services_supported:
            require_artifact_builder_services_inactive(args.dry_run)
        activate_project(
            project, inputs.p2p_file,
            # Configuration-only platforms cannot inject the management-host
            # key and therefore cannot satisfy the Linux deployment gate.
            strict=local_services_supported and not args.no_upgrade,
            dry_run=args.dry_run,
            deployment_lock_descriptor=deployment_lock_descriptor,
        )

        section("同步 ZTP 运行时参数")
        if service_available:
            if not args.dry_run:
                prefix_publication_snapshot = snapshot_ztp_prefix_publication(
                    inputs.settings
                )
            configure_ztp_prefix_publication(inputs.settings, args.dry_run)
        elif not local_services_supported:
            # A workstation preparation run renders artifacts for the remote
            # Linux management server.  Its declared http_root (normally
            # /var/www/html) is not this checkout and must never be published
            # as a local runtime symlink or ownership marker.  The Linux load
            # path above retains the strict root, ownership and rollback gates.
            info(
                f"{host_os} 配置准备模式：保留远端 ZTP URL path "
                f"{inputs.settings.ztp_prefix}，不发布本机 prefix 运行态"
            )
        else:
            # Linux can also be used only to prepare artifacts when none of the
            # declared service endpoints belongs to this host (or another
            # management-host gate failed).  Publishing a local URL alias in
            # that state would contradict validate_management_host(), and may
            # target a checkout whose path is not the declared remote root.
            warn(
                "本机不具备 ZTP 服务发布条件：保留配置中的 URL path "
                f"{inputs.settings.ztp_prefix}，跳过 prefix 运行态"
            )
        render_ztp_runtime(
            inputs.settings, inputs.pubkeys, inputs.device_types,
            upgrade_enabled=not args.no_upgrade,
            dry_run=args.dry_run,
        )
        if args.no_upgrade:
            if args.dry_run:
                info("dry-run：实际执行时会把全部 bootstrap 写为 no-upgrade 模式")
            else:
                ok("no-upgrade 模式已写入全部 bootstrap：仅配置设备，不安装系统镜像")

        if not local_services_supported:
            warn(f"{host_os} 跳过 infra 安装；不会安装 Apache/ISC DHCP")
        elif service_available and not args.skip_infra:
            section("安装/检查 ZTP 管理服务器")
            prepare_infra(
                inputs,
                args.dry_run,
                skip_doca=args.skip_doca,
                download_doca=args.download_doca,
            )
        elif not service_available:
            warn("本机不具备服务地址，跳过 infra 部署；load 继续")
        else:
            warn("已按参数跳过 infra 安装")

        if not args.skip_generate:
            section("生成 P2P、YAML 和 DHCP 配置")
            if not args.dry_run:
                release_link_snapshot = snapshot_release_links(project)
            generate_configs(
                inputs.device_types,
                install_dhcp=service_available,
                dry_run=args.dry_run,
                schema_version=inputs.settings.schema_version,
            )
        else:
            warn(
                "dry-run：仅展示跳过生成的调试路径；实际 load 会安全拒绝 "
                "--skip-generate"
            )

        section("统一 release 一致性与 DHCP 事务安装")
        parent_release = validate_and_publish_release(
            project, inputs, dry_run=args.dry_run, publish=False,
        )
        if parent_release is not None:
            # Materialize and fsync the parent before touching /etc/dhcp.  The
            # remaining commit is one os.replace performed while DHCP backups
            # and the global deployment lock are still held.
            parent_candidate = prepare_current_release(project, parent_release)
        if local_services_supported and service_available:
            mount_and_test_dhcp(
                args.dry_run, parent_candidate=parent_candidate,
            )
            release_committed = bool(
                parent_candidate is not None and parent_candidate.committed
            )
        elif not local_services_supported:
            info(f"{host_os} 不安装 /etc/dhcp；统一 release 仍已完成一致性验证")
        else:
            warn("本机没有可用 service_ip：统一 release 已验证，但不安装 /etc/dhcp")
        if parent_candidate is not None and not parent_candidate.committed:
            # Hosts without a local DHCP install still use the same prepared
            # single-replace parent commit.
            commit_prepared_release(parent_candidate)
            release_committed = True

        section("服务启动门禁")
        if not local_services_supported:
            if args.start_services:
                warn(f"{host_os} 不支持本流程的 --start-services，已忽略")
            info(f"{host_os} 配置准备完成；未检查或启动 Apache/ISC DHCP")
        elif not service_available:
            warn("service_ip 与本机不匹配：本次仅完成 load，不能部署或启动服务")
        else:
            preflight_services(inputs, images, args.dry_run)
            should_start = args.start_services or (
                not args.dry_run and confirm_service_start()
            )
            if should_start:
                start_services(inputs, images, args.dry_run)
            else:
                info("Apache/DHCP 未启动。确认输出后可重新执行并加 --start-services。")

        if local_services_supported:
            section("ZTP 状态后台监控")
            if not service_available:
                warn("本机不具备 service_ip，不启动 ZTP 后台监控")
            else:
                should_monitor = args.start_ztp_monitor or (
                    not args.dry_run and confirm_ztp_monitor_start()
                )
                if should_monitor:
                    monitor_scope = resolve_ztp_monitor_scope(
                        project, args.ztp_monitor_scope
                    )
                    start_ztp_monitor(
                        project, interval=args.ztp_monitor_interval,
                        scope=monitor_scope,
                        service_ips=inputs.settings.service_ips,
                        dry_run=args.dry_run,
                    )
                    start_switch_collection_worker(
                        monitor_scope, dry_run=args.dry_run,
                    )
                    start_manual_ztp_worker(
                        monitor_scope, dry_run=args.dry_run,
                    )
                else:
                    info(
                        "ZTP 后台监控未启动。可重新执行并加 --start-ztp-monitor，"
                        f"或手工运行 {ZTP_MONITOR_SCRIPT.name}。"
                    )
        elif args.start_ztp_monitor:
            warn(f"{host_os} 不运行 ZTP 后台监控，已忽略 --start-ztp-monitor")
        ok(f"load 流程完成：{project}")
        return 0
    except BaseException as exc:
        cleanup_errors = []
        release_committed = release_committed or bool(
            parent_candidate is not None and parent_candidate.committed
        )
        if services_must_remain_stopped:
            try:
                quiesce_services(False)
            except (LoadError, OSError, subprocess.SubprocessError) as cleanup_exc:
                cleanup_errors.append(f"服务停止清理失败：{cleanup_exc}")
        if release_link_snapshot and not release_committed:
            try:
                restore_release_links(release_link_snapshot)
            except (LoadError, OSError) as rollback_exc:
                cleanup_errors.append(str(rollback_exc))
        if prefix_publication_snapshot is not None and not release_committed:
            try:
                restore_ztp_prefix_publication(prefix_publication_snapshot)
            except (LoadError, OSError) as rollback_exc:
                cleanup_errors.append(str(rollback_exc))
        if isinstance(exc, KeyboardInterrupt):
            print("[CANCEL] load 被用户中断；已执行事务清理", file=sys.stderr)
        elif isinstance(exc, Exception):
            print(f"[ERROR] {exc}", file=sys.stderr)
        for cleanup_error in cleanup_errors:
            print(f"[ERROR] {cleanup_error}", file=sys.stderr)
        if isinstance(exc, KeyboardInterrupt):
            # Preserve shell semantics (normally exit 130) after cleanup.
            raise
        if isinstance(exc, Exception):
            # Input/library ValueError and similar recoverable failures now
            # follow the same rollback path as LoadError.
            return 1
        raise
    finally:
        discard_prepared_release(parent_candidate)
        release_deployment_lock(deployment_lock_descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
