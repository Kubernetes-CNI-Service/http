#!/usr/bin/env python3
"""Read-only acceptance checks for an Ubuntu ZTP management VM.

This helper never runs load, changes passwords, restarts services, or edits the
project.  It writes one JSON evidence report (under /tmp by default) and exits
non-zero when a required acceptance check fails.
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import http.client
import importlib.util
import ipaddress
import json
import getpass
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
from typing import Any, Iterable


sys.dont_write_bytecode = True


SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
MAC_RE = re.compile(r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$", re.IGNORECASE)
GLOBAL_BASELINE = Path("99-output-ztp/.sync-code-global.sha256")
PARENT_RELEASE = Path("99-output-ztp/current-release.json")
INPUT_PATHS = {
    "global": Path("01-global.yaml"),
    "devices": Path("02-devices_config.csv"),
    "subnet": Path("02-dhcp-subnet_config.csv"),
    "air_topology_policy": Path("03-air-topology-policy.json"),
    "mini_air_devices": Path("04-air-mini-devices.txt"),
}
REQUIRED_INPUTS = frozenset({"global", "devices", "subnet", "p2p"})
DHCP_OUTPUTS = (
    "dhcpd.conf",
    "dhcpd_eth.hosts",
    "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts",
)
REQUIRED_COMMANDS = (
    "bash", "curl", "dhcpd", "flock", "ip", "rsync", "ssh", "systemctl",
    "tar",
)
REQUIRED_PYTHON_MODULES = ("yaml", "jinja2", "openpyxl", "xlsxwriter")
FULL_SOURCE_ROOTS = (
    "DAY0-Prepare", "ethernet", "infiniband", "infra", "monitor", "nvlink",
    "tools", "ztp",
)
FULL_SOURCE_SKIP_DIRS = frozenset({
    ".git", ".venv", "__pycache__", "apps", "backup", "docker", "firmware",
    "image", "node_modules", "status", "test_cases",
})
INTERFACE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:@-]{0,14}$")
BOOTSTRAP_BY_PROFILE = {
    "oob": "ztp-bootstrap_oob.sh",
    "oobofoob": "ztp-bootstrap_oobofoob.sh",
}
SAFE_ZTP_PREFIX_RE = re.compile(r"/[A-Za-z0-9._~-]+(?:/[A-Za-z0-9._~-]+)*")
ZTP_PREFIX_RESERVED_SEGMENTS = frozenset({
    "day0-prepare", "status", "backup", "optimize",
})
ZTP_PREFIX_RESERVED_SEQUENCES = (
    ("monitor", "ztp-status"),
    ("config", "isc-dhcp-server"),
    ("config", "cumulus", "template"),
    ("config", "nvos", "template"),
)
CONTROL_CGI_NAMES = (
    "ztp-monitor-control",
    "switch-collection-control",
    "manual-ztp-control",
)
CONTROL_AUTH_USERS = ("nvis", "cumulus")
CONTROL_AUTH_REALM = "HTTP ZTP Monitor Control"
CONTROL_CGI_ROUTES = {
    "ztp-monitor-control": (
        "/monitor/control/ztp-monitor",
        "/cgi-bin/ztp-monitor-control",
    ),
    "switch-collection-control": (
        "/monitor/control/switch-collection",
        "/cgi-bin/switch-collection-control",
    ),
    "manual-ztp-control": (
        "/monitor/control/manual-ztp",
        "/cgi-bin/manual-ztp-control",
    ),
}


@dataclass(frozen=True)
class DhcpSubnet:
    name: str
    network: ipaddress.IPv4Network
    service_ip: ipaddress.IPv4Address | None
    configured_service_ip: ipaddress.IPv4Address | None = None
    cumulus_profile: str = "none"
    nvos_ztp: bool = False


@dataclass(frozen=True)
class HttpAsset:
    address: str
    url_path: str
    source: Path


@dataclass(frozen=True)
class Finding:
    level: str
    check: str
    detail: str


class Recorder:
    def __init__(self) -> None:
        self.findings: list[Finding] = []

    def add(self, level: str, check: str, detail: str) -> None:
        finding = Finding(level, check, detail)
        self.findings.append(finding)
        print(f"[{level}] {check}: {detail}")

    def passed(self, check: str, detail: str) -> None:
        self.add("PASS", check, detail)

    def warn(self, check: str, detail: str) -> None:
        self.add("WARN", check, detail)

    def fail(self, check: str, detail: str) -> None:
        self.add("FAIL", check, detail)

    def guarded(self, check: str, callback) -> Any:
        try:
            return callback()
        except Exception as exc:  # keep later checks and the evidence report
            self.fail(check, f"{type(exc).__name__}: {exc}")
            return None


def sha256_file(path: Path, *, allow_empty: bool = False) -> str:
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(f"不是 single-link regular file: {path}")
    if not allow_empty and before.st_size <= 0:
        raise ValueError(f"文件为空: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError(f"打开期间文件发生变化: {path}")
        while True:
            block = os.read(descriptor, 1024 * 1024)
            if not block:
                break
            digest.update(block)
    finally:
        os.close(descriptor)
    after = path.lstat()
    if (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    ):
        raise ValueError(f"读取期间文件发生变化: {path}")
    return digest.hexdigest()


def read_regular_bytes(
    path: Path, *, max_bytes: int = 32 * 1024 * 1024,
    allow_empty: bool = False,
) -> bytes:
    """Read one bounded, stable, single-link regular file without following links."""
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(f"不是 single-link regular file: {path}")
    if before.st_size > max_bytes:
        raise ValueError(f"文件超过 {max_bytes} bytes 上限: {path}")
    if not allow_empty and before.st_size <= 0:
        raise ValueError(f"文件为空: {path}")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    chunks: list[bytes] = []
    remaining = max_bytes + 1
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError(f"打开期间文件发生变化: {path}")
        while remaining:
            block = os.read(descriptor, min(1024 * 1024, remaining))
            if not block:
                break
            chunks.append(block)
            remaining -= len(block)
    finally:
        os.close(descriptor)
    payload = b"".join(chunks)
    if len(payload) > max_bytes:
        raise ValueError(f"文件超过 {max_bytes} bytes 上限: {path}")
    after = path.lstat()
    if (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    ):
        raise ValueError(f"读取期间文件发生变化: {path}")
    return payload


def load_json(path: Path) -> dict[str, Any]:
    sha256_file(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"JSON 顶层不是 object: {path}")
    return value


def project_path(root: Path, value: str) -> Path:
    root = root.resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / "DAY0-Prepare" / candidate
    candidate = candidate.resolve()
    candidate.relative_to((root / "DAY0-Prepare").resolve())
    metadata = candidate.lstat()
    if not stat.S_ISDIR(metadata.st_mode):
        raise ValueError(f"项目不是实际目录: {candidate}")
    return candidate


def p2p_input_path(project: Path) -> Path:
    alias = project / "p2p.xlsx"
    if os.path.lexists(alias):
        resolved = alias.resolve(strict=True)
        resolved.relative_to(project.resolve())
        sha256_file(resolved)
        return resolved
    candidates = sorted(
        item for item in project.glob("*.xlsx")
        if not item.name.startswith(("~$", "._")) and item.is_file()
    )
    if len(candidates) != 1:
        raise ValueError(
            f"无法唯一选择 P2P xlsx（candidates={len(candidates)}）"
        )
    sha256_file(candidates[0])
    return candidates[0]


def release_input_errors(
    project: Path, parent: dict[str, Any],
) -> list[str]:
    expected = parent.get("inputs")
    if not isinstance(expected, dict):
        return ["parent release inputs 不是 object"]
    errors: list[str] = []
    keys = set(expected)
    missing = sorted(REQUIRED_INPUTS - keys)
    if missing:
        errors.append("parent release 缺少输入 hash: " + ", ".join(missing))
    unknown = sorted(keys - set(INPUT_PATHS) - {"p2p"})
    if unknown:
        errors.append("parent release 含未知输入键: " + ", ".join(unknown))

    for optional in ("air_topology_policy", "mini_air_devices"):
        exists = os.path.lexists(project / INPUT_PATHS[optional])
        if exists and optional not in expected:
            errors.append(f"{optional} 文件存在但未绑定到 parent release")

    for label, wanted in expected.items():
        if not isinstance(wanted, str) or not SHA256_RE.fullmatch(wanted):
            errors.append(f"{label} 的 parent SHA-256 非法")
            continue
        try:
            path = p2p_input_path(project) if label == "p2p" else (
                project / INPUT_PATHS[label]
            )
            actual = sha256_file(path)
        except (KeyError, OSError, ValueError) as exc:
            errors.append(f"{label} 无法安全读取: {exc}")
            continue
        if actual != wanted:
            errors.append(
                f"{label} SHA-256 与 parent release 不一致: "
                f"current={actual}, release={wanted}"
            )
    return errors


def parent_release_errors(
    parent: dict[str, Any], expected_project: str,
) -> list[str]:
    errors: list[str] = []
    if parent.get("schema_version") != 1:
        errors.append("parent release schema_version 必须为 1")
    if parent.get("project") != expected_project:
        errors.append(
            f"parent project={parent.get('project')!r}，预期 {expected_project!r}"
        )
    if parent.get("validation") != "passed":
        errors.append(f"parent validation={parent.get('validation')!r}")
    basis_keys = ("project", "inputs", "components", "inventory")
    if all(key in parent for key in basis_keys):
        basis = {key: parent[key] for key in basis_keys}
        expected_id = hashlib.sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()[:20]
        if parent.get("release_id") != expected_id:
            errors.append(
                "parent release_id 与 canonical basis 不一致: "
                f"expected={expected_id}, actual={parent.get('release_id')}"
            )
    else:
        errors.append("parent release 缺少 canonical basis 字段")
    return errors


def parse_dhcp_subnets(path: Path) -> tuple[DhcpSubnet, ...]:
    sha256_file(path)
    rows: list[DhcpSubnet] = []
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        required = {"shared_network", "subnet", "netmask", "ztp_service_ip"}
        if not reader.fieldnames or not required <= set(reader.fieldnames):
            raise ValueError("DHCP subnet CSV 缺少必需列")
        for lineno, row in enumerate(reader, 2):
            name = str(row.get("shared_network") or "").strip()
            if not name:
                raise ValueError(f"第 {lineno} 行 shared_network 为空")
            network = ipaddress.ip_network(
                (str(row["subnet"]).strip(), str(row["netmask"]).strip()),
                strict=True,
            )
            if not isinstance(network, ipaddress.IPv4Network):
                raise ValueError(f"第 {lineno} 行不是 IPv4 subnet")
            raw_service = str(row.get("ztp_service_ip") or "").strip()
            service = ipaddress.ip_address(raw_service) if raw_service else None
            if service is not None and not isinstance(service, ipaddress.IPv4Address):
                raise ValueError(f"第 {lineno} 行 ztp_service_ip 不是 IPv4")
            profile = str(row.get("cumulus_profile") or "none").strip().casefold()
            if profile not in {"none", *BOOTSTRAP_BY_PROFILE}:
                raise ValueError(
                    f"第 {lineno} 行 cumulus_profile 非法: {profile!r}"
                )
            nvos_text = str(row.get("nvos_ztp") or "no").strip().casefold()
            if nvos_text not in {"yes", "no"}:
                raise ValueError(f"第 {lineno} 行 nvos_ztp 非法: {nvos_text!r}")
            # The same service may be a relay target for another subnet.  Only
            # its on-link subnet makes this management host listen directly.
            direct_service = service if service and service in network else None
            rows.append(DhcpSubnet(
                name, network, direct_service,
                configured_service_ip=service,
                cumulus_profile=profile,
                nvos_ztp=nvos_text == "yes",
            ))
    if not rows:
        raise ValueError("DHCP subnet CSV 没有数据行")
    return tuple(rows)


def bootstrap_http_assets(
    root: Path, subnets: Iterable[DhcpSubnet], prefix: str,
) -> tuple[HttpAsset, ...]:
    """Return unique runtime bootstrap/ztp.json HTTP assets declared by CSV."""
    if not prefix.startswith("/") or prefix == "/" or prefix.endswith("/"):
        raise ValueError(f"ztp_url_prefix 非法: {prefix!r}")
    if "//" in prefix or any(part in {"", ".", ".."} for part in prefix[1:].split("/")):
        raise ValueError(f"ztp_url_prefix 非法: {prefix!r}")
    result: dict[tuple[str, str], HttpAsset] = {}
    for row in subnets:
        address = row.configured_service_ip
        if address is None:
            continue
        address_text = str(address)
        script = BOOTSTRAP_BY_PROFILE.get(row.cumulus_profile)
        if script:
            item = HttpAsset(
                address_text, f"{prefix}/{script}", root / "ztp" / script,
            )
            result[(item.address, item.url_path)] = item
        if row.nvos_ztp:
            item = HttpAsset(
                address_text, f"{prefix}/ztp.json", root / "ztp/ztp.json",
            )
            result[(item.address, item.url_path)] = item
    return tuple(result[key] for key in sorted(result))


def read_ztp_prefix(global_yaml: Path) -> str:
    try:
        import yaml
    except ImportError as exc:  # already reported by the dependency check
        raise ValueError("缺少 PyYAML，无法读取 ztp_url_prefix") from exc
    payload = read_regular_bytes(global_yaml, max_bytes=4 * 1024 * 1024)
    try:
        document = yaml.safe_load(payload)
        value = document["common"]["mgmt"]["ztp"]["ztp_url_prefix"]
    except (KeyError, TypeError, yaml.YAMLError) as exc:
        raise ValueError(f"无法读取 schema 2 ztp_url_prefix: {exc}") from exc
    prefix = str(value or "").strip().rstrip("/")
    if (
        not SAFE_ZTP_PREFIX_RE.fullmatch(prefix)
        or any(part in {".", ".."} for part in prefix.split("/"))
    ):
        raise ValueError(f"ztp_url_prefix 不是安全绝对 URL path: {value!r}")
    parts = tuple(part.casefold() for part in prefix.lstrip("/").split("/"))
    if any(part in ZTP_PREFIX_RESERVED_SEGMENTS for part in parts):
        raise ValueError(f"ztp_url_prefix 使用 Apache 保留路径: {value!r}")
    for reserved in ZTP_PREFIX_RESERVED_SEQUENCES:
        width = len(reserved)
        if any(
            parts[index:index + width] == reserved
            for index in range(len(parts) - width + 1)
        ):
            raise ValueError(f"ztp_url_prefix 使用 Apache 保留路径: {value!r}")
    return prefix


def _sample_indices(length: int, samples: int) -> tuple[int, ...]:
    if length <= 0 or samples <= 0:
        return ()
    if length <= samples:
        return tuple(range(length))
    if samples == 1:
        return (0,)
    return tuple(sorted({
        round(index * (length - 1) / (samples - 1))
        for index in range(samples)
    }))


def release_http_assets(
    root: Path, project: Path, parent: dict[str, Any],
    service_ips: Iterable[str], prefix: str, *, samples: int = 3,
) -> tuple[HttpAsset, ...]:
    """Choose deterministic MAC-addressed YAML samples bound by the parent."""
    components = parent.get("components")
    if not isinstance(components, dict):
        raise ValueError("parent components 不是 object")
    addresses = tuple(sorted(set(service_ips)))
    result: dict[tuple[str, str], HttpAsset] = {}
    for label in ("cumulus", "nvos"):
        record = components.get(label)
        if record is None:
            continue
        if not isinstance(record, dict):
            raise ValueError(f"parent {label} component 不是 object")
        relative = record.get("release_dir")
        if not isinstance(relative, str) or not relative:
            raise ValueError(f"parent {label} release_dir 非法")
        release = (project / relative).resolve(strict=True)
        release.relative_to(project.resolve())
        manifest = load_json(release / "release-manifest.json")
        devices = manifest.get("devices")
        if not isinstance(devices, list) or not devices:
            raise ValueError(f"{label} release manifest devices 为空")
        ordered = sorted(
            devices,
            key=lambda item: str(item.get("hostname") or "").casefold()
            if isinstance(item, dict) else "",
        )
        for index in _sample_indices(len(ordered), samples):
            item = ordered[index]
            if not isinstance(item, dict):
                raise ValueError(f"{label} devices 包含非 object")
            config_name = str(item.get("config") or "")
            if not config_name or Path(config_name).name != config_name:
                raise ValueError(f"{label} config 名称非法: {config_name!r}")
            source = release / config_name
            sha256_file(source)
            macs = [
                str(value).casefold() for value in (item.get("macs") or [])
                if MAC_RE.fullmatch(str(value))
            ]
            url_name = (
                sorted(macs)[0].replace(":", "") + ".yaml"
                if macs else config_name
            )
            if macs:
                link = release / url_name
                if not link.is_symlink() or link.resolve(strict=True) != source.resolve():
                    raise ValueError(f"{label} MAC YAML 链接错误: {link}")
            for address in addresses:
                path = f"{prefix}/config/{label}/latest_yaml/{url_name}"
                result[(address, path)] = HttpAsset(address, path, source)
    return tuple(result[key] for key in sorted(result))


def local_interface_addresses() -> dict[str, set[ipaddress.IPv4Address]]:
    completed = subprocess.run(
        ["ip", "-j", "-4", "address", "show"],
        check=False, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "ip address show 失败")
    payload = json.loads(completed.stdout)
    result: dict[str, set[ipaddress.IPv4Address]] = {}
    for item in payload:
        name = item.get("ifname")
        if not isinstance(name, str) or not name:
            continue
        values: set[ipaddress.IPv4Address] = set()
        for address in item.get("addr_info", []):
            if address.get("family") != "inet":
                continue
            try:
                parsed = ipaddress.ip_address(address.get("local"))
            except ValueError:
                continue
            if isinstance(parsed, ipaddress.IPv4Address):
                values.add(parsed)
        result[name] = values
    return result


def shared_network_conflicts(
    subnets: Iterable[DhcpSubnet],
    interfaces: dict[str, set[ipaddress.IPv4Address]],
) -> dict[str, tuple[str, ...]]:
    rows = tuple(subnets)
    conflicts: dict[str, tuple[str, ...]] = {}
    for interface, addresses in interfaces.items():
        names = sorted({
            row.name for row in rows for address in addresses
            if address in row.network
        })
        if len(names) > 1:
            conflicts[interface] = tuple(names)
    return conflicts


def service_ip_assignments(
    subnets: Iterable[DhcpSubnet],
    interfaces: dict[str, set[ipaddress.IPv4Address]],
) -> dict[str, tuple[str, ...]]:
    services = sorted({row.service_ip for row in subnets if row.service_ip})
    return {
        str(service): tuple(sorted(
            name for name, addresses in interfaces.items() if service in addresses
        ))
        for service in services
    }


def devices_csv_errors(path: Path) -> tuple[list[str], dict[str, int], int]:
    sha256_file(path)
    errors: list[str] = []
    counts: dict[str, int] = {}
    hostnames: set[str] = set()
    macs: set[str] = set()
    fake_macs = 0
    with path.open("r", encoding="utf-8-sig", newline="") as stream:
        rows = list(csv.reader(stream))
    if not rows:
        return ["devices CSV 为空"], counts, fake_macs
    header = rows[0]
    if "terminal_l2_ports" in header:
        errors.append("devices CSV 仍含已废弃 terminal_l2_ports")
    required = {"hostname", "type", "eth0_mac", "eth1_mac"}
    invalid_identity = sorted(
        name for name in required if header.count(name) != 1
    )
    if invalid_identity:
        errors.append(
            "devices CSV 身份列必须且只能出现一次: "
            + ", ".join(invalid_identity)
        )
        return errors, counts, fake_macs
    width = len(header)
    indices = {name: header.index(name) for name in required}
    for lineno, row in enumerate(rows[1:], 2):
        if len(row) != width:
            errors.append(f"第 {lineno} 行宽度 {len(row)} != {width}")
            continue
        hostname = row[indices["hostname"]].strip()
        kind = row[indices["type"]].strip()
        if not hostname or hostname in hostnames:
            errors.append(f"第 {lineno} 行 hostname 为空或重复: {hostname!r}")
        hostnames.add(hostname)
        counts[kind] = counts.get(kind, 0) + 1
        for field in ("eth0_mac", "eth1_mac"):
            value = row[indices[field]].strip().casefold()
            if not value:
                continue
            if not MAC_RE.fullmatch(value):
                errors.append(f"第 {lineno} 行 {field} 非法")
                continue
            if value in macs:
                errors.append(f"第 {lineno} 行身份 MAC 重复: {value}")
            macs.add(value)
            if value.startswith(("02:10:", "02:11:", "02:20:", "02:21:", "02:30:")):
                fake_macs += 1
    return errors, counts, fake_macs


def component_artifact_errors(
    project: Path, parent: dict[str, Any],
) -> tuple[list[str], int]:
    errors: list[str] = []
    checked_configs = 0
    components = parent.get("components")
    if not isinstance(components, dict):
        return ["parent components 不是 object"], checked_configs
    for label, record in components.items():
        if not isinstance(record, dict):
            errors.append(f"component {label} 不是 object")
            continue
        if label == "dhcp":
            manifest_path = project / "99-output-dhcp/dhcp-release-manifest.json"
            release_dir = project / "99-output-dhcp"
        else:
            relative = record.get("release_dir")
            if not isinstance(relative, str):
                errors.append(f"component {label} 缺少 release_dir")
                continue
            release_dir = (project / relative).resolve()
            try:
                release_dir.relative_to(project.resolve())
            except ValueError:
                errors.append(f"component {label} release_dir 越界")
                continue
            manifest_path = release_dir / "release-manifest.json"
        try:
            manifest_hash = sha256_file(manifest_path)
            manifest = load_json(manifest_path)
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            errors.append(f"component {label} manifest 无法读取: {exc}")
            continue
        if manifest_hash != record.get("manifest_sha256"):
            errors.append(f"component {label} manifest SHA-256 漂移")
        if manifest.get("release_id") != record.get("release_id"):
            errors.append(f"component {label} release_id 漂移")
        marker_hash = record.get("published_marker_sha256")
        if marker_hash is not None:
            try:
                actual_marker = sha256_file(release_dir / ".published-complete")
            except (OSError, ValueError) as exc:
                errors.append(f"component {label} marker 无法读取: {exc}")
            else:
                if actual_marker != marker_hash:
                    errors.append(f"component {label} marker SHA-256 漂移")

        if label == "dhcp":
            outputs = manifest.get("outputs", {})
            for name in DHCP_OUTPUTS:
                expected = outputs.get(name, {}).get("sha256") if isinstance(
                    outputs.get(name), dict
                ) else None
                try:
                    actual = sha256_file(release_dir / name)
                except (OSError, ValueError) as exc:
                    errors.append(f"DHCP output {name} 无法读取: {exc}")
                    continue
                if actual != expected:
                    errors.append(f"DHCP output {name} SHA-256 漂移")
            continue

        devices = manifest.get("devices")
        if not isinstance(devices, list):
            errors.append(f"component {label} devices 不是 list")
            continue
        for item in devices:
            if not isinstance(item, dict):
                errors.append(f"component {label} device entry 非 object")
                continue
            config = item.get("config")
            expected = item.get("config_sha256")
            if not isinstance(config, str) or Path(config).name != config:
                errors.append(f"component {label} config 名称非法")
                continue
            try:
                actual = sha256_file(release_dir / config)
            except (OSError, ValueError) as exc:
                errors.append(f"component {label} {config} 无法读取: {exc}")
                continue
            checked_configs += 1
            if actual != expected:
                errors.append(f"component {label} {config} SHA-256 漂移")
    return errors, checked_configs


def runtime_pointer_errors(
    root: Path, project: Path, parent: dict[str, Any],
) -> list[str]:
    """Require runtime/latest links to resolve to the parent-bound release."""
    errors: list[str] = []
    components = parent.get("components")
    if not isinstance(components, dict):
        return ["parent components 不是 object"]

    def check(pointer: Path, target: Path, label: str) -> None:
        if not pointer.is_symlink():
            errors.append(f"{label} 不是 symlink: {pointer}")
            return
        try:
            actual = pointer.resolve(strict=True)
            expected = target.resolve(strict=True)
        except OSError as exc:
            errors.append(f"{label} 无法解析: {exc}")
            return
        if actual != expected:
            errors.append(
                f"{label} 指向错误: actual={actual}, expected={expected}"
            )

    layouts = {
        "cumulus": (
            project / "99-output-eth/latest",
            root / "ztp/config/cumulus/latest_yaml",
        ),
        "nvos": (
            project / "99-output-ib_nvl/latest",
            root / "ztp/config/nvos/latest_yaml",
        ),
    }
    for label, pointers in layouts.items():
        record = components.get(label)
        if not isinstance(record, dict):
            errors.append(f"parent 缺少 {label} component")
            continue
        relative = record.get("release_dir")
        if not isinstance(relative, str) or not relative:
            errors.append(f"parent {label} release_dir 非法")
            continue
        target = (project / relative).resolve()
        try:
            target.relative_to(project.resolve())
        except ValueError:
            errors.append(f"parent {label} release_dir 越界")
            continue
        check(pointers[0], target, f"{label} project latest")
        check(pointers[1], target, f"{label} runtime latest_yaml")

    if "dhcp" not in components:
        errors.append("parent 缺少 dhcp component")
    else:
        check(
            root / "ztp/config/isc-dhcp-server/dhcp-release-manifest.json",
            project / "99-output-dhcp/dhcp-release-manifest.json",
            "dhcp runtime manifest",
        )
    return errors


def command_result(argv: list[str], *, timeout: int = 30) -> tuple[bool, str]:
    completed = subprocess.run(
        argv, check=False, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=timeout,
    )
    return completed.returncode == 0, completed.stdout.strip()


def expected_apache_boundary(source: Path) -> bytes:
    """Extract the exact infra-managed Apache boundary heredoc."""
    payload = read_regular_bytes(source, max_bytes=2 * 1024 * 1024)
    marker = b"cat <<'APACHE_PUBLIC_BOUNDARY_EOF'"
    start = payload.find(marker)
    if start < 0:
        raise ValueError("infra-setup.sh 缺少 Apache publication boundary heredoc")
    start = payload.find(b"\n", start)
    if start < 0:
        raise ValueError("Apache publication boundary heredoc 起始行不完整")
    start += 1
    end_marker = b"\nAPACHE_PUBLIC_BOUNDARY_EOF\n"
    end = payload.find(end_marker, start)
    if end < 0:
        raise ValueError("Apache publication boundary heredoc 结束标记缺失")
    result = payload[start:end] + b"\n"
    if b"HTTP-ZTP-PUBLIC-BOUNDARY-V1" not in result:
        raise ValueError("Apache publication boundary 缺少版本标记")
    return result


def installed_cgi_errors(root: Path, cgi_root: Path) -> list[str]:
    errors: list[str] = []
    for name in CONTROL_CGI_NAMES:
        source = root / "monitor" / f"{name}.cgi"
        destination = cgi_root / name
        try:
            source_hash = sha256_file(source)
            destination_hash = sha256_file(destination)
            metadata = destination.lstat()
        except (OSError, ValueError) as exc:
            errors.append(f"{name}: {exc}")
            continue
        if source_hash != destination_hash:
            errors.append(f"{name}: installed CGI hash 漂移")
        if not metadata.st_mode & 0o111:
            errors.append(f"{name}: installed CGI 不是 executable")
    return errors


def parse_interfacesv4(payload: str) -> tuple[str, ...]:
    """Parse INTERFACESv4 as data; never source or evaluate the defaults file."""
    assignments: list[str] = []
    for raw in payload.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r"INTERFACESv4\s*=\s*(.*)", line)
        if match:
            assignments.append(match.group(1))
    if len(assignments) != 1:
        raise ValueError(
            f"/etc/default/isc-dhcp-server 必须恰有一个 INTERFACESv4，"
            f"实际 {len(assignments)} 个"
        )
    try:
        pieces = shlex.split(assignments[0], posix=True)
    except ValueError as exc:
        raise ValueError(f"INTERFACESv4 引号非法: {exc}") from exc
    names = tuple(name for piece in pieces for name in piece.split() if name)
    for name in names:
        if not INTERFACE_NAME_RE.fullmatch(name):
            raise ValueError(f"INTERFACESv4 接口名非法: {name!r}")
    if len(names) != len(set(names)):
        raise ValueError("INTERFACESv4 包含重复接口")
    return names


def dhcp_runtime_interface_errors(
    configured: Iterable[str],
    assignments: dict[str, tuple[str, ...]],
    process_command: str,
    local_interfaces: set[str],
) -> list[str]:
    configured_names = tuple(configured)
    errors: list[str] = []
    if not configured_names:
        # Native systemd deployments intentionally support Ubuntu's empty
        # INTERFACESv4 setting: dhcpd discovers eligible host interfaces from
        # their addresses and the subnet declarations.  Interface names are
        # installation-specific, so only an explicitly configured allowlist is
        # required to match the live process argv.
        return []
    missing_local = sorted(set(configured_names) - local_interfaces)
    if missing_local:
        errors.append("INTERFACESv4 引用了不存在接口: " + ", ".join(missing_local))
    direct_names = {
        name for names in assignments.values() for name in names
    }
    missing_direct = sorted(direct_names - set(configured_names))
    if missing_direct:
        errors.append(
            "service_ip 所在接口未包含在 INTERFACESv4: "
            + ", ".join(missing_direct)
        )
    try:
        tokens = shlex.split(process_command)
    except ValueError as exc:
        errors.append(f"dhcpd cmdline 无法解析: {exc}")
        return errors
    missing_process = sorted(set(configured_names) - set(tokens))
    if missing_process:
        errors.append(
            "dhcpd cmdline 缺少显式接口: " + ", ".join(missing_process)
        )
    return errors


def _source_directory_skipped(name: str) -> bool:
    return name in FULL_SOURCE_SKIP_DIRS or name.startswith("99-output")


def source_syntax_errors(root: Path) -> tuple[dict[str, int], list[str]]:
    """Compile deployed Python/CGI and parse Shell sources without writing files."""
    counts = {"python": 0, "shell": 0}
    errors: list[str] = []
    for relative in FULL_SOURCE_ROOTS:
        base = root / relative
        try:
            metadata = base.lstat()
        except FileNotFoundError:
            continue
        if not stat.S_ISDIR(metadata.st_mode):
            errors.append(f"source root 不是实际目录: {base}")
            continue
        for current, directories, filenames in os.walk(base, followlinks=False):
            current_path = Path(current)
            kept: list[str] = []
            for name in directories:
                candidate = current_path / name
                try:
                    candidate_metadata = candidate.lstat()
                except OSError as exc:
                    errors.append(f"无法 lstat source directory {candidate}: {exc}")
                    continue
                if _source_directory_skipped(name) or stat.S_ISLNK(
                    candidate_metadata.st_mode
                ):
                    continue
                kept.append(name)
            directories[:] = kept
            for name in sorted(filenames):
                path = current_path / name
                if path.suffix not in {".py", ".cgi", ".sh"}:
                    continue
                try:
                    metadata = path.lstat()
                except OSError as exc:
                    errors.append(f"无法 lstat source {path}: {exc}")
                    continue
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                    # Runtime publication aliases are checked elsewhere.  The
                    # syntax scanner deliberately never follows them.
                    continue
                if path.suffix in {".py", ".cgi"}:
                    counts["python"] += 1
                    try:
                        source = read_regular_bytes(
                            path, max_bytes=16 * 1024 * 1024, allow_empty=True,
                        )
                        compile(source, str(path), "exec", dont_inherit=True)
                    except (OSError, UnicodeError, ValueError, SyntaxError) as exc:
                        errors.append(f"{path}: {type(exc).__name__}: {exc}")
                else:
                    counts["shell"] += 1
                    try:
                        ok, detail = command_result(
                            ["bash", "-n", str(path)], timeout=15,
                        )
                    except (OSError, subprocess.SubprocessError) as exc:
                        errors.append(f"{path}: {type(exc).__name__}: {exc}")
                    else:
                        if not ok:
                            errors.append(f"{path}: {detail or 'bash -n failed'}")
    return counts, errors


def _option_values(tokens: list[str], name: str) -> list[str]:
    values: list[str] = []
    for index, token in enumerate(tokens):
        if token == name and index + 1 < len(tokens):
            values.append(tokens[index + 1])
        elif token.startswith(name + "="):
            values.append(token.split("=", 1)[1])
    return values


def worker_command_errors(
    label: str, command: str, *, root: Path, project: Path,
    expected_scope: str = "auto",
) -> list[str]:
    """Bind a PID cmdline to the exact managed worker, project and scope."""
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        return [f"cmdline 无法解析: {exc}"]
    expected_scripts = {
        "ztp-monitor": root / "DAY0-Prepare/12-ztp-monitor.py",
        "switch-collection": root / "monitor/switch-collection-worker.py",
        "manual-ztp": root / "monitor/manual-ztp-worker.py",
    }
    expected_script = expected_scripts.get(label)
    if expected_script is None:
        return [f"未知 worker label: {label}"]
    errors: list[str] = []
    if str(expected_script) not in tokens:
        errors.append(f"worker script 不匹配: expected={expected_script}")
    scopes = _option_values(tokens, "--scope")
    if len(scopes) != 1 or scopes[0] not in {"prod", "air"}:
        errors.append(f"worker scope 缺失或非法: {scopes}")
    elif expected_scope != "auto" and scopes[0] != expected_scope:
        errors.append(
            f"worker scope 不匹配: expected={expected_scope}, actual={scopes[0]}"
        )
    if label == "ztp-monitor" and str(project) not in tokens:
        errors.append(f"worker project 不匹配: expected={project}")
    return errors


def http_request(
    address: str, url_path: str, *, timeout: float, method: str = "GET",
    max_body_bytes: int = 32 * 1024 * 1024,
    authorization: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    parsed = ipaddress.ip_address(address)
    if not isinstance(parsed, ipaddress.IPv4Address):
        raise ValueError(f"HTTP 地址不是 IPv4: {address!r}")
    if (
        not url_path.startswith("/") or "\r" in url_path or "\n" in url_path
        or " " in url_path
    ):
        raise ValueError(f"HTTP path 非法: {url_path!r}")
    if timeout <= 0 or timeout > 60:
        raise ValueError(f"HTTP timeout 超出 0..60 秒: {timeout}")
    headers = {
        "Accept-Encoding": "identity",
        "Connection": "close",
        "Host": address,
        "User-Agent": "http-ztp-systemd-vm-validator/1",
    }
    if authorization is not None:
        if not re.fullmatch(r"Basic [A-Za-z0-9+/]+={0,2}", authorization):
            raise ValueError("HTTP Basic authorization 格式非法")
        headers["Authorization"] = authorization
    connection = http.client.HTTPConnection(address, 80, timeout=timeout)
    try:
        connection.request(method, url_path, headers=headers)
        response = connection.getresponse()
        body = response.read(max_body_bytes + 1)
        if len(body) > max_body_bytes:
            raise ValueError(
                f"HTTP body 超过 {max_body_bytes} bytes: {address}{url_path}"
            )
        headers = {name.casefold(): value for name, value in response.getheaders()}
        return int(response.status), headers, body
    finally:
        connection.close()


def verify_http_asset(
    asset: HttpAsset, *, timeout: float, authorization: str | None = None,
) -> str:
    expected = read_regular_bytes(asset.source)
    expected_sha = hashlib.sha256(expected).hexdigest()
    status_code, _headers, actual = http_request(
        asset.address, asset.url_path, timeout=timeout,
        max_body_bytes=max(len(expected), 1),
        authorization=authorization,
    )
    if status_code != 200:
        raise ValueError(
            f"HTTP status expected=200 actual={status_code}: "
            f"{asset.address}{asset.url_path}"
        )
    actual_sha = hashlib.sha256(actual).hexdigest()
    if actual_sha != expected_sha or len(actual) != len(expected):
        raise ValueError(
            f"HTTP 内容 hash/size 不匹配: {asset.address}{asset.url_path}; "
            f"expected={expected_sha}/{len(expected)}, "
            f"actual={actual_sha}/{len(actual)}"
        )
    if read_regular_bytes(asset.source) != expected:
        raise ValueError(f"HTTP 校验期间源文件变化: {asset.source}")
    return (
        f"http://{asset.address}{asset.url_path} bytes={len(actual)} "
        f"sha256={actual_sha}"
    )


def verify_http_status(
    address: str, url_path: str, *, expected: int, timeout: float,
) -> str:
    status_code, _headers, _body = http_request(
        address, url_path, timeout=timeout, max_body_bytes=64 * 1024,
    )
    if status_code != expected:
        raise ValueError(
            f"HTTP status 不匹配: expected={expected}, actual={status_code}, "
            f"url=http://{address}{url_path}"
        )
    return f"http://{address}{url_path} -> HTTP {status_code}"


def verify_http_head(
    address: str, url_path: str, source: Path, *, timeout: float,
) -> str:
    before = source.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
    ):
        raise ValueError(f"HTTP HEAD 源不是非空 single-link regular file: {source}")
    status_code, headers, body = http_request(
        address, url_path, timeout=timeout, method="HEAD", max_body_bytes=0,
    )
    if status_code != 200:
        raise ValueError(
            f"HTTP HEAD status expected=200 actual={status_code}: "
            f"{address}{url_path}"
        )
    if body:
        raise ValueError(f"HTTP HEAD 意外返回 body: {address}{url_path}")
    raw_length = headers.get("content-length")
    try:
        content_length = int(raw_length or "")
    except ValueError as exc:
        raise ValueError(
            f"HTTP HEAD 缺少合法 Content-Length: {address}{url_path}"
        ) from exc
    if content_length != before.st_size:
        raise ValueError(
            f"HTTP HEAD Content-Length 不匹配: expected={before.st_size}, "
            f"actual={content_length}, url=http://{address}{url_path}"
        )
    after = source.lstat()
    if (
        after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns
    ) != (
        before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns
    ):
        raise ValueError(f"HTTP HEAD 期间源文件变化: {source}")
    return f"http://{address}{url_path} bytes={content_length}"


def read_control_authorization(
    user: str, *, password_reader=getpass.getpass,
) -> str:
    """Prompt once and return an in-memory Basic header for this run only."""
    if user not in CONTROL_AUTH_USERS:
        raise ValueError("control auth user 必须是 nvis 或 cumulus")
    password = password_reader(f"Monitor control password for {user}: ")
    if not isinstance(password, str):
        raise ValueError("Monitor control password 必须是文本")
    try:
        password_bytes = password.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Monitor control password 必须是可打印 ASCII") from exc
    if not 1 <= len(password_bytes) <= 72:
        raise ValueError("Monitor control password 长度必须是 1..72 bytes")
    if any(value < 0x20 or value > 0x7E for value in password_bytes):
        raise ValueError("Monitor control password 必须是可打印 ASCII")
    token = base64.b64encode(user.encode("ascii") + b":" + password_bytes)
    return "Basic " + token.decode("ascii")


def verify_control_auth_challenge(address: str, *, timeout: float) -> str:
    url_path = "/monitor/monitor.html"
    status_code, headers, _body = http_request(
        address, url_path, timeout=timeout, max_body_bytes=64 * 1024,
    )
    if status_code != 401:
        raise ValueError(
            f"Monitor auth status expected=401 actual={status_code}: "
            f"{address}{url_path}"
        )
    expected = f'Basic realm="{CONTROL_AUTH_REALM}"'
    actual = headers.get("www-authenticate", "")
    if actual != expected:
        raise ValueError(
            "Monitor auth realm 不匹配: "
            f"expected={expected!r}, actual={actual!r}"
        )
    return f"http://{address}{url_path} -> HTTP 401, realm={CONTROL_AUTH_REALM}"


def verify_control_cgi(
    address: str, name: str, *, url_path: str, authorization: str,
    timeout: float,
) -> str:
    if name not in CONTROL_CGI_NAMES:
        raise ValueError(f"未知 control CGI: {name!r}")
    if url_path not in CONTROL_CGI_ROUTES[name]:
        raise ValueError(f"control CGI URL 非 canonical/legacy exact route: {url_path!r}")
    status_code, headers, body = http_request(
        address, url_path, timeout=timeout, max_body_bytes=1024 * 1024,
        authorization=authorization,
    )
    if status_code != 200:
        raise ValueError(
            f"control CGI status expected=200 actual={status_code}: "
            f"{address}{url_path}"
        )
    content_type = headers.get("content-type", "").casefold()
    if not content_type.startswith("application/json"):
        raise ValueError(f"control CGI Content-Type 非 JSON: {content_type!r}")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"control CGI JSON 非法: {exc}") from exc
    if not isinstance(payload, dict) or payload.get("process_alive") is not True:
        raise ValueError(
            f"control CGI 未确认 process_alive=true: {payload!r}"
        )
    state = str(payload.get("state") or "n/a")
    return (
        f"http://{address}{url_path} -> HTTP 200, "
        f"process_alive=true, state={state}"
    )


def confined_regular_target(
    path: Path, root: Path, *, hash_content: bool = True,
) -> Path:
    try:
        target = path.resolve(strict=True)
        target.relative_to(root.resolve())
    except (OSError, RuntimeError, ValueError) as exc:
        raise ValueError(f"发布文件越界或不可解析: {path}: {exc}") from exc
    metadata = target.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        raise ValueError(f"发布目标不是非空 single-link regular file: {target}")
    if hash_content:
        sha256_file(target)
    return target


def check_password_backend(root: Path) -> str:
    tools = root / "tools"
    sys.path.insert(0, str(tools))
    try:
        path = tools / "password-update.py"
        sha256_file(path)
        spec = importlib.util.spec_from_file_location(
            "vm_password_backend_probe", path,
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("无法载入 password-update.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        try:
            spec.loader.exec_module(module)
            return str(module.validate_hash_backend(("eth", "ib", "nvl")))
        finally:
            sys.modules.pop(spec.name, None)
    finally:
        try:
            sys.path.remove(str(tools))
        except ValueError:
            pass


def process_command(pid: int) -> str:
    if pid <= 1:
        raise ValueError("PID 必须大于 1")
    path = Path("/proc") / str(pid) / "cmdline"
    payload = path.read_bytes()
    if not payload or len(payload) > 1024 * 1024:
        raise ValueError(f"进程 cmdline 为空或过大: PID={pid}")
    return payload.replace(b"\0", b" ").decode("utf-8", "replace").strip()


def systemd_main_process(service: str) -> tuple[int, str]:
    ok, output = command_result([
        "systemctl", "show", "--property=MainPID", "--value", service,
    ])
    if not ok:
        raise RuntimeError(output or f"无法读取 {service} MainPID")
    try:
        pid = int(output.strip())
    except ValueError as exc:
        raise ValueError(f"{service} MainPID 非法: {output!r}") from exc
    return pid, process_command(pid)


def check_worker(path: Path) -> tuple[bool, str]:
    try:
        raw = read_regular_bytes(path, max_bytes=64).decode("ascii").strip()
        pid = int(raw)
        return True, process_command(pid)
    except (OSError, UnicodeError, ValueError) as exc:
        return False, str(exc)


def monitor_runtime_evidence(
    root: Path, project: Path, expected_scope: str, *, max_age_seconds: int = 1800,
) -> str:
    latest = root / "ztp/status/latest"
    if not latest.is_symlink():
        raise ValueError(f"ZTP latest 不是 symlink: {latest}")
    directory = latest.resolve(strict=True)
    directory.relative_to((root / "ztp/status").resolve())
    report_path = directory / "report.json"
    report = load_json(report_path)
    if report.get("project") != project.name:
        raise ValueError(
            f"ZTP report project 不匹配: {report.get('project')!r}"
        )
    scope = str(report.get("scope") or "")
    if expected_scope != "auto" and scope != expected_scope:
        raise ValueError(
            f"ZTP report scope 不匹配: expected={expected_scope}, actual={scope}"
        )
    devices = report.get("devices")
    if not isinstance(devices, list) or not devices:
        raise ValueError("ZTP report devices 为空")
    generated = str(report.get("generated_at") or "")
    try:
        generated_at = datetime.fromisoformat(generated)
        age = (datetime.now().astimezone() - generated_at).total_seconds()
    except (TypeError, ValueError) as exc:
        raise ValueError(f"ZTP report generated_at 非法: {generated!r}") from exc
    if age < -300 or age > max_age_seconds:
        raise ValueError(f"ZTP report 不新鲜: age_seconds={round(age)}")
    return (
        f"project={project.name}, scope={scope}, devices={len(devices)}, "
        f"age_seconds={max(0, round(age))}"
    )


def mini_air_summary(project: Path) -> tuple[int, int]:
    canonical = project / "04-air-mini-devices.txt"
    sha256_file(canonical)
    minimum = customer = 0
    section = None
    for raw in canonical.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.casefold() == "[minimum-required]":
            section = "minimum"
        elif line.casefold() == "[customer-provided]":
            section = "customer"
        elif section == "minimum":
            minimum += 1
        elif section == "customer":
            customer += 1
        else:
            raise ValueError("mini 清单设备必须位于两个 section 中")
    if minimum == 0:
        raise ValueError("mini 最低必需集合为空")
    candidates = sorted((project / "99-output-p2p").glob("*-air.json"))
    if len(candidates) != 1:
        raise ValueError(f"AIR JSON 数量不是 1: {len(candidates)}")
    air = load_json(candidates[0])
    nodes = air.get("content", {}).get("nodes")
    if not isinstance(nodes, dict) or not nodes:
        raise ValueError("AIR JSON nodes 为空或格式错误")
    return minimum + customer, len(nodes)


def atomic_report(path: Path, payload: dict[str, Any]) -> None:
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    if os.path.lexists(path):
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError(f"报告目标不是 single-link regular file: {path}")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "只读验证 Ubuntu ZTP 管理 VM；不运行 load、不改密码、不重启服务"
        ),
    )
    parser.add_argument("project")
    parser.add_argument("--root", type=Path, default=Path("/var/www/html"))
    parser.add_argument("--expect-services", action="store_true")
    parser.add_argument("--expect-workers", action="store_true")
    parser.add_argument("--expect-air-workers", action="store_true")
    parser.add_argument("--expect-mini", action="store_true")
    parser.add_argument(
        "--full-systemd", action="store_true",
        help=(
            "执行原生 systemd 全量验收：服务/worker、部署源码语法、"
            "DHCP 监听、Apache 发布边界及主动 HTTP 内容校验"
        ),
    )
    parser.add_argument(
        "--worker-scope", choices=("auto", "prod", "air"), default="auto",
        help="要求三个 worker 使用指定 scope；auto 仅要求三者一致",
    )
    parser.add_argument(
        "--check-http-content", action="store_true",
        help="主动 GET 公共文件并核对内容，同时验证内部路径拒绝策略",
    )
    parser.add_argument(
        "--check-source-syntax", action="store_true",
        help="只读编译部署树 Python/CGI，并对 Shell 执行 bash -n",
    )
    parser.add_argument(
        "--http-timeout", type=float, default=5.0,
        help="单次 HTTP 请求超时秒数（默认 5）",
    )
    parser.add_argument(
        "--control-auth-user", choices=CONTROL_AUTH_USERS,
        help="主动 HTTP 验收使用的 Monitor 用户；密码仅通过一次 getpass 输入",
    )
    parser.add_argument("--strict-warnings", action="store_true")
    parser.add_argument("--output", type=Path)
    return parser.parse_args(argv)


def apply_validation_profile(args: argparse.Namespace) -> None:
    if args.http_timeout <= 0 or args.http_timeout > 60:
        raise ValueError("--http-timeout 必须大于 0 且不超过 60 秒")
    if args.expect_air_workers:
        if args.worker_scope not in {"auto", "air"}:
            raise ValueError(
                "--expect-air-workers 与 --worker-scope prod 冲突"
            )
        args.worker_scope = "air"
    if args.full_systemd:
        args.expect_services = True
        args.expect_workers = True
        args.check_http_content = True
        args.check_source_syntax = True
    if args.check_http_content and args.control_auth_user is None:
        raise ValueError(
            "--check-http-content/--full-systemd 必须指定 "
            "--control-auth-user {nvis,cumulus}"
        )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    recorder = Recorder()
    try:
        apply_validation_profile(args)
    except ValueError as exc:
        recorder.fail("arguments", str(exc))
    started = datetime.now().astimezone()
    output = args.output or Path(
        f"/tmp/http-vm-validation-{started.strftime('%Y%m%d-%H%M%S')}-"
        f"{os.getpid()}.json"
    )
    root = args.root.resolve()
    project: Path | None = None
    parent: dict[str, Any] | None = None
    subnets: tuple[DhcpSubnet, ...] | None = None
    interfaces: dict[str, set[ipaddress.IPv4Address]] | None = None
    assignments: dict[str, tuple[str, ...]] = {}
    service_processes: dict[str, tuple[int, str]] = {}
    ztp_prefix: str | None = None

    system = platform.system()
    os_release: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                os_release[key] = value.strip().strip('"')
    except OSError as exc:
        recorder.fail("operating-system", str(exc))
    else:
        if system == "Linux" and os_release.get("ID") == "ubuntu" and os_release.get(
            "VERSION_ID"
        ) == "24.04":
            recorder.passed("operating-system", "Ubuntu 24.04 / Linux")
        else:
            recorder.fail(
                "operating-system",
                f"system={system}, ID={os_release.get('ID')}, "
                f"VERSION_ID={os_release.get('VERSION_ID')}",
            )

    missing_commands = [name for name in REQUIRED_COMMANDS if not shutil.which(name)]
    if missing_commands:
        recorder.fail("commands", "缺少: " + ", ".join(missing_commands))
    else:
        recorder.passed("commands", ", ".join(REQUIRED_COMMANDS))
    missing_modules = [
        name for name in REQUIRED_PYTHON_MODULES
        if importlib.util.find_spec(name) is None
    ]
    if missing_modules:
        recorder.fail("python-modules", "缺少: " + ", ".join(missing_modules))
    else:
        recorder.passed("python-modules", ", ".join(REQUIRED_PYTHON_MODULES))

    if args.full_systemd and os.geteuid() != 0:
        recorder.fail("privilege", "--full-systemd 必须由 root 执行")

    if args.check_source_syntax:
        syntax_result = recorder.guarded(
            "source-syntax", lambda: source_syntax_errors(root),
        )
        if syntax_result is not None:
            counts, errors = syntax_result
            if errors:
                for error in errors:
                    recorder.fail("source-syntax", error)
            elif not any(counts.values()):
                recorder.fail("source-syntax", "部署树中没有发现 Python/CGI/Shell 源码")
            else:
                recorder.passed(
                    "source-syntax",
                    f"python/cgi={counts['python']}, shell={counts['shell']}",
                )

    project = recorder.guarded(
        "project-path", lambda: project_path(root, args.project),
    )
    if project is not None:
        recorder.passed("project-path", str(project))
        marker = root / ".sync-code-in-progress"
        if os.path.lexists(marker):
            recorder.fail("sync-marker", f"同步门禁仍存在: {marker}")
        else:
            recorder.passed("sync-marker", "不存在半同步门禁")

        if args.check_http_content:
            ztp_prefix = recorder.guarded(
                "ztp-url-prefix",
                lambda: read_ztp_prefix(project / "01-global.yaml"),
            )
            if ztp_prefix is not None:
                recorder.passed("ztp-url-prefix", ztp_prefix)

        backend = recorder.guarded(
            "password-backend", lambda: check_password_backend(root),
        )
        if backend is not None:
            recorder.passed("password-backend", backend)

        parent = recorder.guarded(
            "parent-release", lambda: load_json(project / PARENT_RELEASE),
        )
        if parent is not None:
            errors = parent_release_errors(parent, project.name)
            if errors:
                for error in errors:
                    recorder.fail("parent-release", error)
            else:
                recorder.passed(
                    "parent-release", f"release_id={parent['release_id']}",
                )
            input_errors = release_input_errors(project, parent)
            if input_errors:
                for error in input_errors:
                    recorder.fail("release-inputs", error)
            else:
                recorder.passed(
                    "release-inputs",
                    f"{len(parent.get('inputs', {}))} 个输入 SHA-256 全匹配",
                )
            artifact_errors, checked = component_artifact_errors(project, parent)
            if artifact_errors:
                for error in artifact_errors:
                    recorder.fail("release-artifacts", error)
            else:
                recorder.passed(
                    "release-artifacts",
                    f"3 个组件与 {checked} 份设备配置 hash 匹配",
                )
            pointer_errors = runtime_pointer_errors(root, project, parent)
            if pointer_errors:
                for error in pointer_errors:
                    recorder.fail("runtime-pointers", error)
            else:
                recorder.passed(
                    "runtime-pointers",
                    "Cumulus/NVOS latest 与 DHCP runtime manifest 均绑定 parent",
                )
            inventory = parent.get("inventory")
            if isinstance(inventory, list):
                pending = sum(
                    item.get("identity_state") == "identity_pending"
                    for item in inventory if isinstance(item, dict)
                )
                if pending:
                    recorder.warn(
                        "identity", f"inventory={len(inventory)}, pending={pending}",
                    )
                else:
                    recorder.passed(
                        "identity", f"inventory={len(inventory)}, pending=0",
                    )

        csv_result = recorder.guarded(
            "devices-csv", lambda: devices_csv_errors(
                project / "02-devices_config.csv"
            ),
        )
        if csv_result is not None:
            errors, counts, fake_macs = csv_result
            if errors:
                for error in errors:
                    recorder.fail("devices-csv", error)
            else:
                recorder.passed(
                    "devices-csv",
                    "types=" + ",".join(
                        f"{key}:{value}" for key, value in sorted(counts.items())
                    ),
                )
            if fake_macs:
                recorder.warn(
                    "temporary-macs",
                    f"识别到 {fake_macs} 个临时 LAA；不能用于真实硬件身份验收",
                )

        subnets = recorder.guarded(
            "dhcp-subnets", lambda: parse_dhcp_subnets(
                project / "02-dhcp-subnet_config.csv"
            ),
        )
        if subnets is not None:
            direct = sorted({str(row.service_ip) for row in subnets if row.service_ip})
            recorder.passed(
                "dhcp-subnets",
                f"rows={len(subnets)}, on-link service_ip={','.join(direct)}",
            )
        interfaces = recorder.guarded(
            "interface-addresses", local_interface_addresses,
        )
        if interfaces is not None:
            recorder.passed(
                "interface-addresses",
                "; ".join(
                    f"{name}={','.join(map(str, sorted(values)))}"
                    for name, values in sorted(interfaces.items()) if values
                ) or "没有 IPv4 地址",
            )
        if subnets is not None and interfaces is not None:
            conflicts = shared_network_conflicts(subnets, interfaces)
            if conflicts:
                for name, networks in conflicts.items():
                    recorder.fail(
                        "dhcp-interface-isolation",
                        f"{name} 同时命中 shared-network: {','.join(networks)}",
                    )
            else:
                recorder.passed(
                    "dhcp-interface-isolation",
                    "每个接口最多命中一个 shared-network",
                )
            assignments = service_ip_assignments(subnets, interfaces)
            wrong = {
                address: names for address, names in assignments.items()
                if len(names) != 1
            }
            detail = "; ".join(
                f"{address}={','.join(names) or '<missing>'}"
                for address, names in assignments.items()
            )
            if args.expect_services and wrong:
                recorder.fail("service-ip-bindings", detail)
            elif wrong:
                recorder.warn("service-ip-bindings", detail)
            else:
                recorder.passed("service-ip-bindings", detail)

        baseline = project / GLOBAL_BASELINE
        recorder.passed(
            "global-sync-policy",
            "Mac 掌管普通输入，VM 只掌管 eth/ib/nvl 密码哈希；"
            + (
                "旧 .sync-code-global.sha256 存在但已忽略"
                if os.path.lexists(baseline)
                else "无旧版 global 基线"
            ),
        )

        if args.expect_mini:
            summary = recorder.guarded(
                "mini-air", lambda: mini_air_summary(project),
            )
            if summary is not None:
                listed, nodes = summary
                if parent is not None and "mini_air_devices" not in parent.get(
                    "inputs", {}
                ):
                    recorder.fail(
                        "mini-air", "parent release 未绑定 mini_air_devices hash",
                    )
                else:
                    recorder.passed(
                        "mini-air",
                        f"清单条目={listed}（允许重复），AIR nodes={nodes}",
                    )

    if args.expect_services:
        if os.geteuid() != 0 and not args.full_systemd:
            recorder.warn("privilege", "建议 root 执行，以完整读取 DHCP 服务证据")
        for service in ("apache2", "isc-dhcp-server"):
            ok, output_text = command_result(["systemctl", "is-active", service])
            if ok and output_text == "active":
                recorder.passed(f"service:{service}", "active")
            else:
                recorder.fail(f"service:{service}", output_text or "inactive")
            if args.full_systemd:
                ok, enabled = command_result(["systemctl", "is-enabled", service])
                if ok and enabled == "enabled":
                    recorder.passed(f"service-enabled:{service}", enabled)
                else:
                    recorder.fail(
                        f"service-enabled:{service}", enabled or "not enabled",
                    )
                process = recorder.guarded(
                    f"service-process:{service}",
                    lambda service=service: systemd_main_process(service),
                )
                if process is not None:
                    pid, command = process
                    expected_name = "apache2" if service == "apache2" else "dhcpd"
                    if expected_name not in command:
                        recorder.fail(
                            f"service-process:{service}",
                            f"MainPID={pid} cmdline 身份错误: {command}",
                        )
                    else:
                        service_processes[service] = process
                        recorder.passed(
                            f"service-process:{service}",
                            f"MainPID={pid} {command}",
                        )
        ok, output_text = command_result([
            "dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf",
        ])
        (recorder.passed if ok else recorder.fail)(
            "dhcpd-syntax", output_text or ("valid" if ok else "failed"),
        )
        apache = shutil.which("apache2ctl") or shutil.which("apachectl")
        if apache:
            ok, output_text = command_result([apache, "configtest"])
            (recorder.passed if ok else recorder.fail)(
                "apache-config", output_text or ("valid" if ok else "failed"),
            )
        else:
            recorder.fail("apache-config", "缺少 apache2ctl/apachectl")
        if args.full_systemd:
            boundary = recorder.guarded(
                "apache-public-boundary",
                lambda: (
                    expected_apache_boundary(root / "infra/infra-setup.sh"),
                    read_regular_bytes(Path(
                        "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
                    ), max_bytes=2 * 1024 * 1024),
                ),
            )
            if boundary is not None:
                expected_boundary, installed_boundary = boundary
                if expected_boundary == installed_boundary:
                    recorder.passed(
                        "apache-public-boundary",
                        "安装配置与当前 infra-setup.sh 逐字匹配",
                    )
                else:
                    recorder.fail(
                        "apache-public-boundary",
                        "安装配置与当前 infra-setup.sh 不匹配",
                    )
            cgi_errors = recorder.guarded(
                "installed-control-cgi",
                lambda: installed_cgi_errors(root, Path("/usr/lib/cgi-bin")),
            )
            if cgi_errors is not None:
                if cgi_errors:
                    for error in cgi_errors:
                        recorder.fail("installed-control-cgi", error)
                else:
                    recorder.passed(
                        "installed-control-cgi",
                        "三个控制 CGI hash 与 executable mode 匹配",
                    )
        if project is not None:
            for name in DHCP_OUTPUTS:
                generated = project / "99-output-dhcp" / name
                installed = Path("/etc/dhcp") / name
                try:
                    left = sha256_file(generated)
                    right = sha256_file(installed)
                except (OSError, ValueError) as exc:
                    recorder.fail("installed-dhcp", f"{name}: {exc}")
                else:
                    if left == right:
                        recorder.passed("installed-dhcp", f"{name} hash 匹配")
                    else:
                        recorder.fail("installed-dhcp", f"{name} hash 漂移")
        if subnets is not None:
            for address in sorted({row.service_ip for row in subnets if row.service_ip}):
                try:
                    with socket.create_connection((str(address), 80), timeout=3):
                        pass
                except OSError as exc:
                    recorder.fail("http-listener", f"{address}:80: {exc}")
                else:
                    recorder.passed("http-listener", f"{address}:80 可连接")
        if args.full_systemd and interfaces is not None and assignments:
            runtime_result = recorder.guarded(
                "dhcp-runtime-interfaces",
                lambda: parse_interfacesv4(
                    read_regular_bytes(
                        Path("/etc/default/isc-dhcp-server"), max_bytes=64 * 1024,
                    ).decode("utf-8")
                ),
            )
            if runtime_result is not None:
                dhcp_process = service_processes.get("isc-dhcp-server")
                if dhcp_process is None:
                    recorder.fail(
                        "dhcp-runtime-interfaces",
                        "无法取得 isc-dhcp-server MainPID cmdline",
                    )
                else:
                    errors = dhcp_runtime_interface_errors(
                        runtime_result, assignments, dhcp_process[1],
                        set(interfaces),
                    )
                    if errors:
                        for error in errors:
                            recorder.fail("dhcp-runtime-interfaces", error)
                    else:
                        runtime_label = (
                            "auto-discovery (INTERFACESv4 empty)"
                            if not runtime_result else
                            "explicit=" + ",".join(runtime_result)
                        )
                        recorder.passed(
                            "dhcp-runtime-interfaces",
                            runtime_label,
                        )

    if args.expect_workers:
        worker_paths = (
            (root / "ztp/status/ztp-monitor.pid", "ztp-monitor"),
            (root / "monitor/status/switch-collection.pid", "switch-collection"),
            (root / "monitor/status/manual-ztp.pid", "manual-ztp"),
        )
        observed_scopes: list[str] = []
        for path, label in worker_paths:
            ok, detail = check_worker(path)
            if not ok:
                recorder.fail(f"worker:{label}", detail)
                continue
            if project is None:
                recorder.fail(f"worker:{label}", "项目路径验证失败，无法绑定 worker")
                continue
            errors = worker_command_errors(
                label, detail, root=root, project=project,
                expected_scope=args.worker_scope,
            )
            if errors:
                for error in errors:
                    recorder.fail(f"worker:{label}", f"{error}; cmdline={detail}")
                continue
            scopes = _option_values(shlex.split(detail), "--scope")
            observed_scopes.extend(scopes)
            recorder.passed(f"worker:{label}", detail)
        if len(observed_scopes) == 3 and len(set(observed_scopes)) == 1:
            recorder.passed("worker-scope", observed_scopes[0])
        elif observed_scopes:
            recorder.fail("worker-scope", f"三个 worker scope 不一致: {observed_scopes}")

        if args.full_systemd and project is not None:
            for label, path in (
                ("switch-collection", root / "monitor/status/switch-collection.status.json"),
                ("manual-ztp", root / "monitor/status/manual-ztp.status.json"),
            ):
                status_payload = recorder.guarded(
                    f"worker-status:{label}", lambda path=path: load_json(path),
                )
                if status_payload is None:
                    continue
                actual_scope = str(status_payload.get("scope") or "")
                if (
                    actual_scope not in {"prod", "air"}
                    or (args.worker_scope != "auto" and actual_scope != args.worker_scope)
                ):
                    recorder.fail(
                        f"worker-status:{label}",
                        f"scope={actual_scope!r}, expected={args.worker_scope}",
                    )
                    continue
                state = str(status_payload.get("state") or "")
                if label == "switch-collection" and state == "failed":
                    recorder.fail(
                        f"worker-status:{label}",
                        f"state=failed: {status_payload.get('reason') or ''}",
                    )
                else:
                    recorder.passed(
                        f"worker-status:{label}",
                        f"scope={actual_scope}, state={state or 'n/a'}",
                    )
            monitor = recorder.guarded(
                "ztp-monitor-report",
                lambda: monitor_runtime_evidence(
                    root, project, args.worker_scope, max_age_seconds=1800,
                ),
            )
            if monitor is not None:
                recorder.passed("ztp-monitor-report", monitor)

    if args.check_http_content:
        if project is None or parent is None or subnets is None or ztp_prefix is None:
            recorder.fail(
                "http-content",
                "项目、parent release、DHCP subnet 或 ztp_url_prefix 验证失败",
            )
        else:
            service_addresses = tuple(sorted({
                str(row.service_ip) for row in subnets if row.service_ip is not None
            }))
            if not service_addresses:
                recorder.fail("http-content", "没有本机 on-link HTTP service_ip")
            else:
                control_authorization: str | None = None
                if args.control_auth_user is not None:
                    try:
                        control_authorization = read_control_authorization(
                            args.control_auth_user,
                        )
                    except (EOFError, KeyboardInterrupt, ValueError) as exc:
                        recorder.fail(
                            "http-control-auth",
                            f"无法取得一次性 Monitor 验收凭据: {type(exc).__name__}",
                        )
                planned: dict[tuple[str, str], HttpAsset] = {}
                monitor_html = root / "monitor/monitor.html"
                try:
                    assets = list(bootstrap_http_assets(root, subnets, ztp_prefix))
                    assets.extend(release_http_assets(
                        root, project, parent, service_addresses, ztp_prefix,
                        samples=3,
                    ))
                    sha256_file(monitor_html)
                    public_keys = root / "ztp/config/publickey"
                    key_count = 0
                    for publication in sorted(public_keys.iterdir()):
                        if publication.name.startswith("."):
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9._~-]+", publication.name):
                            raise ValueError(
                                f"published publickey URL 名称非法: {publication.name!r}"
                            )
                        source = confined_regular_target(publication, root)
                        key_count += 1
                        for address in service_addresses:
                            assets.append(HttpAsset(
                                address,
                                f"{ztp_prefix}/config/publickey/{publication.name}",
                                source,
                            ))
                    if key_count == 0:
                        raise ValueError("没有已发布 SSH public key")
                    for asset in assets:
                        planned[(asset.address, asset.url_path)] = asset
                except (OSError, RuntimeError, ValueError) as exc:
                    recorder.fail("http-content-plan", f"{type(exc).__name__}: {exc}")
                else:
                    recorder.passed(
                        "http-content-plan", f"GET assets={len(planned)}",
                    )
                    for asset in planned.values():
                        try:
                            detail = verify_http_asset(
                                asset, timeout=args.http_timeout,
                            )
                        except (OSError, ValueError, http.client.HTTPException) as exc:
                            recorder.fail(
                                "http-content", f"{type(exc).__name__}: {exc}",
                            )
                        else:
                            recorder.passed("http-content", detail)

                for address in service_addresses:
                    try:
                        detail = verify_control_auth_challenge(
                            address, timeout=args.http_timeout,
                        )
                    except (
                        OSError, ValueError, http.client.HTTPException,
                    ) as exc:
                        recorder.fail(
                            "http-control-auth", f"{type(exc).__name__}: {exc}",
                        )
                    else:
                        recorder.passed("http-control-auth", detail)
                    if control_authorization is None:
                        recorder.fail(
                            "http-monitor-authenticated",
                            "没有可用的 Monitor 验收凭据",
                        )
                        continue
                    try:
                        detail = verify_http_asset(
                            HttpAsset(
                                address, "/monitor/monitor.html", monitor_html,
                            ),
                            timeout=args.http_timeout,
                            authorization=control_authorization,
                        )
                    except (
                        OSError, ValueError, http.client.HTTPException,
                    ) as exc:
                        recorder.fail(
                            "http-monitor-authenticated",
                            f"{type(exc).__name__}: {exc}",
                        )
                    else:
                        recorder.passed("http-monitor-authenticated", detail)

                image_count = 0
                components = parent.get("components")
                for platform_name in ("cumulus", "nvos"):
                    if not isinstance(components, dict) or platform_name not in components:
                        continue
                    image_dir = root / "ztp/image" / platform_name
                    try:
                        publications = sorted(image_dir.iterdir())
                    except OSError as exc:
                        recorder.fail("http-image", f"{platform_name}: {exc}")
                        continue
                    platform_count = 0
                    for publication in publications:
                        if publication.name.startswith(".") or not publication.is_file():
                            continue
                        if not re.fullmatch(r"[A-Za-z0-9._~-]+", publication.name):
                            recorder.fail(
                                "http-image",
                                f"URL 名称非法: {platform_name}/{publication.name!r}",
                            )
                            continue
                        try:
                            source = confined_regular_target(
                                publication, root, hash_content=False,
                            )
                        except (OSError, ValueError) as exc:
                            recorder.fail("http-image", f"{publication}: {exc}")
                            continue
                        platform_count += 1
                        image_count += 1
                        for address in service_addresses:
                            url_path = (
                                f"{ztp_prefix}/image/{platform_name}/{publication.name}"
                            )
                            try:
                                detail = verify_http_head(
                                    address, url_path, source,
                                    timeout=args.http_timeout,
                                )
                            except (
                                OSError, ValueError, http.client.HTTPException,
                            ) as exc:
                                recorder.fail(
                                    "http-image", f"{type(exc).__name__}: {exc}",
                                )
                            else:
                                recorder.passed("http-image", detail)
                    if platform_count == 0:
                        recorder.fail(
                            "http-image", f"{platform_name} 没有已发布镜像",
                        )
                if image_count:
                    recorder.passed("http-image-plan", f"published images={image_count}")

                for address in service_addresses:
                    denied_paths = (
                        f"/DAY0-Prepare/{project.name}/01-global.yaml",
                        f"{ztp_prefix}/config/isc-dhcp-server/"
                        "dhcp-release-manifest.json",
                        "/monitor/generate-monitor-html.py",
                    )
                    for url_path in denied_paths:
                        try:
                            detail = verify_http_status(
                                address, url_path, expected=403,
                                timeout=args.http_timeout,
                            )
                        except (
                            OSError, ValueError, http.client.HTTPException,
                        ) as exc:
                            recorder.fail(
                                "http-deny-boundary", f"{type(exc).__name__}: {exc}",
                            )
                        else:
                            recorder.passed("http-deny-boundary", detail)
                    if control_authorization is None:
                        continue
                    for cgi_name in CONTROL_CGI_NAMES:
                        for control_path in CONTROL_CGI_ROUTES[cgi_name]:
                            try:
                                detail = verify_control_cgi(
                                    address,
                                    cgi_name,
                                    url_path=control_path,
                                    authorization=control_authorization,
                                    timeout=args.http_timeout,
                                )
                            except (
                                OSError, ValueError, http.client.HTTPException,
                            ) as exc:
                                recorder.fail(
                                    "http-control-cgi",
                                    f"{type(exc).__name__}: {exc}",
                                )
                            else:
                                recorder.passed("http-control-cgi", detail)

    levels = {level: 0 for level in ("PASS", "WARN", "FAIL")}
    for finding in recorder.findings:
        levels[finding.level] += 1
    payload = {
        "schema_version": 1,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "read_only": True,
        "validation_profile": "full-systemd" if args.full_systemd else "standard",
        "active_http_requests": bool(args.check_http_content),
        "side_effects": (
            ["Apache access log receives validation GET/HEAD requests"]
            if args.check_http_content else []
        ),
        "root": str(root),
        "project": str(project) if project else args.project,
        "summary": levels,
        "findings": [asdict(item) for item in recorder.findings],
    }
    try:
        atomic_report(output, payload)
    except Exception as exc:
        print(f"[FAIL] report: {exc}", file=sys.stderr)
        return 1
    print(f"[REPORT] {output.resolve()}")
    print(
        f"[SUMMARY] PASS={levels['PASS']} WARN={levels['WARN']} "
        f"FAIL={levels['FAIL']}"
    )
    return 1 if levels["FAIL"] or (args.strict_warnings and levels["WARN"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
