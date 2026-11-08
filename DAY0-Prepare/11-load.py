#!/usr/bin/env python3
"""Validate, activate and prepare one DAY0 deployment project end to end.

The script deliberately separates reversible preparation from the final service
start. Apache and DHCP start with ``--start-services`` or unless the operator
declines the default-yes service prompt. A second default-yes bounded prompt
starts the detached ZTP status monitor after the load flow succeeds.

P2P headers are strict by default. ``--p2p-legacy-columns`` explicitly opts this
run into the producer's historical column layout; an AIR policy never implies
that opt-in. It does not bypass topology or splitter-profile validation.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import csv
import ctypes
from collections.abc import Callable
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import datetime
import fcntl
import getpass
import gzip
import hashlib
import hmac
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import secrets
import select
import selectors
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import zipfile
import uuid


def _preflight_macos_generation_imports() -> None:
    """Give a clean install hint before shared modules import third-party code."""
    if (platform.system() or "").casefold() != "darwin":
        return
    required = (("PyYAML", "yaml"), ("Jinja2", "jinja2"), ("openpyxl", "openpyxl"))
    missing = []
    for label, module in required:
        try:
            available = importlib.util.find_spec(module) is not None
        except (AttributeError, ImportError, ValueError):
            available = False
        if not available:
            missing.append(label)
    if not missing:
        return
    print(
        "[ERROR] macOS 配置生成缺少必需依赖："
        f"{', '.join(missing)}",
        file=sys.stderr,
    )
    print(
        "[INSTALL] python3 -m pip install -r requirements-dev.txt "
        "Jinja2==3.1.6",
        file=sys.stderr,
    )
    raise SystemExit(1)


_preflight_macos_generation_imports()

try:
    import yaml
except ModuleNotFoundError as exc:
    if (platform.system() or "").casefold() == "linux":
        if exc.name != "yaml":
            raise
        print(
            "[ERROR] Linux LOAD 启动缺少必需模块：PyYAML (yaml)",
            file=sys.stderr,
        )
        print(
            "[DEPENDENCY] 本次未安装任何软件；需由已审核的启动环境提供 PyYAML。",
            file=sys.stderr,
        )
        raise SystemExit(1) from None
    yaml = None


HERE = Path(__file__).resolve().parent
HTTP_ROOT = HERE.parent
TOOLS_DIR = HTTP_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import generation_report
from infra_components import encode_load_components, select_load_components
import ssh_key_preparation as ssh_keys
from project_contract import (
    GLOBAL_SCHEMA_VERSION,
    ActiveProjectPointerError,
    PublicationPlan,
    ServiceEndpoint,
    SWITCH_CREDENTIAL_FAMILY_ORDER,
    SWITCH_CREDENTIAL_PATHS,
    SWITCH_SCHEMA_FAMILIES,
    active_project_dir,
    detect_global_schema_version,
    device_visible_urls,
    normalize_issue_tracker_policy,
    normalize_v2_mlag_policy,
    normalize_v2_vrr_policy,
    parse_device_csv_layout,
    require_device_csv_row_width,
    require_project_eligible,
    safe_load_global_yaml,
    service_url,
    validate_cumulus_dns_domain,
    validate_dhcp_subnet_placements,
    validate_device_config_method,
    resolve_device_config_method,
    validate_service_endpoint,
    validate_ztp_url_prefix,
)
from _package_common import (
    P2PSelectionError,
    assert_p2p_source_snapshot,
    p2p_source_snapshot,
    p2p_source_relative,
    project_p2p_candidates,
    project_p2p_user_link,
    read_p2p_receipt,
    read_project_input_links,
    select_project_p2p_source,
    select_upload_p2p,
)
from deployment_lock import (
    DeploymentLockError,
    _require_darwin_witnessed_current_exclusive,
    acquire_lock_path_descriptor,
    deployment_lock,
    inherited_lock_subprocess_kwargs,
    release_lock_descriptor,
)

_strict_yaml_document = safe_load_global_yaml
from ztp_service_runtime import (
    DhcpRuntimePlan,
    RuntimeContractError,
    ServiceRuntimeBackend,
    SystemdRuntimeBackend,
    monitor_pid_lock,
    plan_dhcp_runtime,
    runtime_backend_from_environment,
    snapshot_subnet_csv_text,
    subnet_csv_record_start_lines,
    stop_native_ztp_monitors,
    write_monitor_pid_record_locked,
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
PASSWORD_UPDATE_SCRIPT = TOOLS_DIR / "password-update.py"
CONTROL_AUTH_SOURCE = TOOLS_DIR / "control-auth.py"
CONTROL_AUTH_NATIVE_HELPER = Path("/usr/local/lib/http-ztp/control-auth.py")
CONTROL_AUTH_CONTAINER_HELPER = Path("/opt/http-ztp/control-auth.py")
CONTROL_AUTH_SOURCE_SHA256 = (
    "f5cea5266ab808250b718250a8a73d7d6f6452a199b97fa500643d7ed9e988db"
)
CONTROL_AUTH_HELPER_MAX_BYTES = 256 * 1024
CONTROL_AUTH_STATUS_MAX_BYTES = 4096
APACHE_PUBLIC_BOUNDARY_CONF = Path(
    "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf"
)
NATIVE_APACHE_LISTENER_CONF = Path(
    "/etc/apache2/conf-enabled/http-ztp-listeners.conf"
)
APACHE_PUBLIC_BOUNDARY_SHA256 = (
    "616629333ac16e4bc0c076a499d98864959372b5a24bee3c0d4257c1aa9d15fb"
)
MANIFEST = ZTP_DIR / ".setup_manifest"
DEPLOYMENT_LOCK = HTTP_ROOT / ".deployment.lock"
LOCAL_TEST_RUNNER = HTTP_ROOT / "test_cases/run_related_tests.py"
ZTP_PREFIX_MARKER = HTTP_ROOT / ".ztp-prefix-publication.json"
PROMPT_TIMEOUT = 15
DEFAULT_ZTP_MONITOR_INTERVAL = 30
AIR_TOPOLOGY_POLICY_NAME = "03-air-topology-policy.json"
MINI_AIR_DEVICES_NAME = "04-air-mini-devices.txt"
SHARED_ARTIFACT_RECEIPT_DIR = ".shared-artifact-receipts"
SHARED_ARTIFACT_RECEIPT_MAX_BYTES = 64 * 1024 * 1024
SHARED_ARTIFACT_RECEIPT_MAX_ENTRIES = 10_000
SHARED_ARTIFACT_MAX_BYTES = 16 * 1024 * 1024 * 1024
VALID_TYPES = {
    "eth", "eth_spx", "spx", "ib", "nvl", "server", "air", "eth_jump",
    "server_mgmt", "server_ufm",
}
# Server rows are never switches (owner 2026-10-19..22): server_mgmt is the new
# spelling of server (deployed by infra/); server_ufm is a UFM appliance that
# fills only the first seven columns and is handled by
# infiniband/bringup/ufm-setup-upgrade and the monitor, never by this load.
SERVER_TYPES = frozenset({"server", "server_mgmt", "server_ufm"})
BOOTSTRAP_BY_ROLE = {
    "air_oobofoob": "ztp-bootstrap_oobofoob.sh",
    "air_oob": "ztp-bootstrap_oob.sh",
    "prod_oobofoob": "ztp-bootstrap_oobofoob.sh",
    "prod_oob": "ztp-bootstrap_oob.sh",
}
SERVICE_IP_PRIORITY = (
    "air_oob", "air_oobofoob", "prod_oob", "prod_oobofoob",
)
MACOS_MIN_PYTHON = (3, 9)
MACOS_GENERATION_MODULES = (
    ("PyYAML", "yaml"),
    ("Jinja2", "jinja2"),
    ("openpyxl", "openpyxl"),
)
MACOS_VALIDATION_MODULES = (
    ("pandas", "pandas"),
    ("XlsxWriter", "xlsxwriter"),
)
MACOS_TRANSFER_COMMANDS = ("git", "ssh", "scp", "ssh-keygen", "rsync")
MACOS_HOMEBREW_CANDIDATES = (
    Path("/opt/homebrew/bin/brew"),
    Path("/usr/local/bin/brew"),
)
MACOS_LIBXCRYPT_CANDIDATES = (
    Path("/opt/homebrew/opt/libxcrypt/lib/libcrypt.2.dylib"),
    Path("/usr/local/opt/libxcrypt/lib/libcrypt.2.dylib"),
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
ETH_JUMP_CONFIG_ONLY_FIELDS = frozenset({
    "lo_ip", "vrf_default", "vlan_id", "svi_ip", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan",
})
DHCP_INTERFACE_ALLOWLIST_ENV = "HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST"
DHCP_RELAY_INGRESS_ENV = "HTTP_ZTP_DHCP_RELAY_INGRESS"
SUPERVISOR_QUIESCE_SERVICES = (
    "ztp-monitor", "switch-collection", "manual-ztp",
    "isc-dhcp-server", "apache2",
)
_DEPLOYMENT_LOCK_CONTEXTS: dict[int, object] = {}
_MINI_GENERATION_AUTHORITIES: dict[
    tuple[str, str], tuple[str, str, str | None]
] = {}


class LoadError(RuntimeError):
    pass


@dataclass
class ImportConfigSelection:
    """An fd-bound external configuration set, not a pathname to reopen."""

    name: str
    root_fd: int
    directory_fd: int
    root_path: Path
    root_alias_identity: tuple[int, int, str | None]
    root_identity: tuple[int, int]
    directory_identity: tuple[int, int]
    eligible_names: tuple[str, ...]
    automatic: bool

    def close(self) -> None:
        for fd_name in ("directory_fd", "root_fd"):
            descriptor = getattr(self, fd_name)
            if descriptor >= 0:
                os.close(descriptor)
                setattr(self, fd_name, -1)

    def __enter__(self) -> ImportConfigSelection:
        return self

    def __exit__(self, _type, _value, _traceback) -> None:
        self.close()


@dataclass(frozen=True)
class ImportedConfigSnapshot:
    source_name: str
    files: tuple[tuple[str, bytes], ...]
    digest: str
    member_identities: tuple[tuple[str, int, int, int, int, int], ...]


def _import_set_name(name: str) -> bool:
    # fullmatch is intentional: `$` would accept a trailing newline.
    return re.fullmatch(r"\d{8}_\d{6}", name, flags=re.ASCII) is not None


def _import_root_alias_identity(root: Path) -> tuple[int, int, str | None]:
    metadata = root.lstat()
    if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode)):
        raise LoadError("import-configs must be a directory or owned directory alias")
    return (
        metadata.st_dev, metadata.st_ino,
        os.readlink(root) if stat.S_ISLNK(metadata.st_mode) else None,
    )


def select_import_config_set(project: Path, selector: str) -> ImportConfigSelection:
    """Freeze the newest named set, or one explicitly named set, by dirfd."""
    if selector and not _import_set_name(selector):
        raise LoadError("--import-configs accepts one YYYYMMDD_HHMMSS name only")
    root = project / "import-configs"
    root_fd = -1
    directory_fd = -1
    try:
        alias_identity = _import_root_alias_identity(root)
        root_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        root_stat = os.fstat(root_fd)
        if not stat.S_ISDIR(root_stat.st_mode):
            raise LoadError("import-configs target is not a directory")
        eligible = tuple(sorted(name for name in os.listdir(root_fd)
                                if _import_set_name(name)))
        if not eligible:
            raise LoadError("import-configs has no YYYYMMDD_HHMMSS configuration set")
        selected = selector or eligible[-1]
        if selected not in eligible:
            raise LoadError(f"import-configs configuration set is missing: {selected}")
        entry = os.stat(selected, dir_fd=root_fd, follow_symlinks=False)
        if not stat.S_ISDIR(entry.st_mode):
            raise LoadError("selected import-configs set must be a real directory")
        directory_fd = os.open(
            selected, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=root_fd,
        )
        opened = os.fstat(directory_fd)
        if (entry.st_dev, entry.st_ino) != (opened.st_dev, opened.st_ino):
            raise LoadError("selected import-configs set changed during opening")
        if alias_identity != _import_root_alias_identity(root):
            raise LoadError("import-configs alias changed during selection")
        return ImportConfigSelection(
            name=selected, root_fd=root_fd, directory_fd=directory_fd,
            root_path=root, root_alias_identity=alias_identity,
            root_identity=(root_stat.st_dev, root_stat.st_ino),
            directory_identity=(opened.st_dev, opened.st_ino),
            eligible_names=eligible, automatic=not bool(selector),
        )
    except (OSError, LoadError) as exc:
        if directory_fd >= 0:
            os.close(directory_fd)
        if root_fd >= 0:
            os.close(root_fd)
        if isinstance(exc, LoadError):
            raise
        raise LoadError(f"cannot select import-configs source: {exc}") from exc


def _import_publisher_module():
    """Use the actual Cumulus parser/checker at the import preflight gate."""
    name = "_http_import_cumulus_publisher"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    path = HTTP_ROOT / "ztp/config/cumulus/d-hostname2mac.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise LoadError("cannot load Cumulus publication validator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def _reject_import_yaml_nulls(value: object, *, location: str = "$") -> None:
    if value is None:
        raise LoadError(f"imported Cumulus YAML contains null: {location}")
    if isinstance(value, dict):
        for key, child in value.items():
            key_text = str(key)
            if key is None or key_text.casefold() in {"none", "null", "vlannone"}:
                raise LoadError(f"imported Cumulus YAML has forbidden key: {location}.{key_text}")
            _reject_import_yaml_nulls(child, location=f"{location}.{key_text}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_import_yaml_nulls(child, location=f"{location}[{index}]")


def _require_import_selection_binding(selected: ImportConfigSelection) -> None:
    """Qualify both held input directories and their current logical names."""
    if selected.directory_fd < 0 or selected.root_fd < 0:
        raise LoadError("import-configs source descriptor is already closed")
    try:
        if _import_root_alias_identity(selected.root_path) != selected.root_alias_identity:
            raise LoadError("import-configs root alias changed during load")
        root = os.fstat(selected.root_fd)
        named_root = selected.root_path.stat()
        if (not stat.S_ISDIR(named_root.st_mode)
                or (root.st_dev, root.st_ino) != selected.root_identity
                or (named_root.st_dev, named_root.st_ino) != selected.root_identity):
            raise LoadError("import-configs root target changed during load")
        child = os.stat(selected.name, dir_fd=selected.root_fd, follow_symlinks=False)
        held = os.fstat(selected.directory_fd)
        if (not stat.S_ISDIR(child.st_mode)
                or (child.st_dev, child.st_ino) != selected.directory_identity
                or (held.st_dev, held.st_ino) != selected.directory_identity):
            raise LoadError("selected import-configs directory changed during load")
        if selected.automatic:
            names = tuple(sorted(name for name in os.listdir(selected.root_fd)
                                 if _import_set_name(name)))
            if names != selected.eligible_names:
                raise LoadError(
                    "import-configs latest selection changed during load；"
                    "请重新运行 load 以使用最新配置目录"
                )
    except OSError as exc:
        raise LoadError(f"cannot recheck import-configs source binding: {exc}") from exc


def _import_member_owner(metadata: os.stat_result) -> tuple[int, ...]:
    # Atime is intentionally excluded: the qualified read itself can change it.
    return (metadata.st_dev, metadata.st_ino, metadata.st_mode, metadata.st_uid,
            metadata.st_gid, metadata.st_nlink, metadata.st_size,
            metadata.st_mtime_ns, metadata.st_ctime_ns)


def preflight_import_configs(
    selected: ImportConfigSelection, devices_file: Path,
) -> ImportedConfigSnapshot:
    """Read only fd-bound input bytes and reject an incomplete foreign set."""
    publisher = _import_publisher_module()
    try:
        _require_import_selection_binding(selected)
        devices = publisher.load_csv(str(devices_file), switch_scope="eth")
        names = tuple(sorted(os.listdir(selected.directory_fd)))
        if not names or len(names) > 10000:
            raise LoadError("import-configs set is empty or exceeds the member limit")
        expected = {
            key for key, device in devices.items()
            if device["dev_type"] in {"eth", "eth_spx", "spx"}
        }
        if not expected:
            raise LoadError("import-configs has no Cumulus devices in the CSV")
        copied: list[tuple[str, bytes]] = []
        identities: list[tuple[str, int, int, int, int, int]] = []
        original_owners: dict[str, tuple[int, ...]] = {}
        seen: set[str] = set()
        total = 0
        for name in names:
            if name == "default.yaml":
                raise LoadError("default.yaml is publisher output, not an import source")
            if not name.endswith(".yaml") or "/" in name or "\\" in name:
                raise LoadError(f"import-configs contains an unsupported member: {name!r}")
            host = name[:-5].casefold()
            device = devices.get(host)
            if host in seen or host not in expected or device is None:
                raise LoadError(f"import-configs contains an unknown/duplicate Cumulus host: {name!r}")
            if name != f"{device['hostname']}.yaml":
                raise LoadError(f"import-configs member has noncanonical hostname case: {name!r}")
            metadata = os.stat(name, dir_fd=selected.directory_fd, follow_symlinks=False)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                    or metadata.st_size <= 0 or metadata.st_size > 8 * 1024 * 1024):
                raise LoadError(f"import-configs member is not a bounded single-link file: {name!r}")
            fd = os.open(
                name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=selected.directory_fd,
            )
            try:
                opened = os.fstat(fd)
                if _import_member_owner(opened) != _import_member_owner(metadata):
                    raise LoadError(f"import-configs member changed while opening: {name!r}")
                with os.fdopen(os.dup(fd), "rb") as stream:
                    data = stream.read(8 * 1024 * 1024 + 1)
                after = os.fstat(fd)
            finally:
                os.close(fd)
            if len(data) != metadata.st_size or len(data) > 8 * 1024 * 1024:
                raise LoadError(f"import-configs member size changed: {name!r}")
            identity = (
                name, metadata.st_dev, metadata.st_ino, metadata.st_size,
                metadata.st_mtime_ns, metadata.st_ctime_ns,
            )
            after_identity = (
                name, after.st_dev, after.st_ino, after.st_size,
                after.st_mtime_ns, after.st_ctime_ns,
            )
            if (identity != after_identity
                    or _import_member_owner(metadata) != _import_member_owner(after)):
                raise LoadError(f"import-configs member changed while reading: {name!r}")
            try:
                document = publisher._strict_yaml_load(io.StringIO(data.decode("utf-8")))
            except (UnicodeError, yaml.YAMLError) as exc:
                raise LoadError(f"invalid imported Cumulus YAML {name!r}: {exc}") from exc
            _reject_import_yaml_nulls(document)
            checks = [("eth0", device["eth0_ip_cidr"], device["eth0_gw"])]
            if device["eth1_mac"]:
                checks.append(("eth1", device["eth1_ip_cidr"], device["eth1_gw"]))
            for iface, cidr, gateway in checks:
                if not publisher._check_iface(document, name, iface, cidr, gateway):
                    raise LoadError(f"imported Cumulus YAML address differs from CSV: {name!r} {iface}")
            copied.append((name, data))
            identities.append(identity)
            original_owners[name] = _import_member_owner(metadata)
            seen.add(host)
            total += len(data)
            if total > 256 * 1024 * 1024:
                raise LoadError("import-configs set exceeds the total byte limit")
        missing = expected - seen
        if missing:
            raise LoadError("import-configs is missing Cumulus hosts: "
                            + ", ".join(sorted(missing)[:10]))
        # Parsing is an input read boundary, not authority to keep using an
        # earlier list or a detached directory. Qualify the complete original
        # set again after the last parser/checker has returned.
        _require_import_selection_binding(selected)
        if tuple(sorted(os.listdir(selected.directory_fd))) != names:
            raise LoadError("import-configs member inventory changed while reading")
        for name in names:
            current = os.stat(name, dir_fd=selected.directory_fd, follow_symlinks=False)
            if _import_member_owner(current) != original_owners[name]:
                raise LoadError(f"import-configs member owner changed while reading: {name!r}")
        _require_import_selection_binding(selected)
        basis = {
            "source_name": selected.name,
            "root_alias": selected.root_alias_identity,
            "root_identity": selected.root_identity,
            "directory_identity": selected.directory_identity,
            "members": [(name, hashlib.sha256(data).hexdigest()) for name, data in copied],
        }
        digest = hashlib.sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8")).hexdigest()
        return ImportedConfigSnapshot(selected.name, tuple(copied), digest, tuple(identities))
    except (OSError, ValueError) as exc:
        if isinstance(exc, LoadError):
            raise
        raise LoadError(f"import-configs preflight failed: {exc}") from exc


def assert_import_source_unchanged(
    selected: ImportConfigSelection, snapshot: ImportedConfigSnapshot,
    devices_file: Path,
) -> None:
    """Recheck alias, chosen dir, set inventory and bytes before publication."""
    try:
        again = preflight_import_configs(selected, devices_file)
        if again != snapshot:
            raise LoadError("import-configs member identity or bytes changed during load")
    except OSError as exc:
        raise LoadError(f"cannot recheck import-configs source: {exc}") from exc


def publish_imported_output(
    snapshot: ImportedConfigSnapshot, output_root: Path, timestamp: str,
) -> Path:
    """Commit one entirely new, fsynced Cumulus source directory."""
    if not _import_set_name(timestamp):
        raise LoadError("imported output timestamp is invalid")
    try:
        alias_before = _import_root_alias_identity(output_root)
        root_fd = os.open(output_root, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    except OSError as exc:
        raise LoadError(f"Cumulus output root is absent: {exc}") from exc
    output = output_root / timestamp
    stage_name = f".{timestamp}.import.{secrets.token_hex(16)}"
    stage_fd = -1
    created = False
    committed = False
    try:
        try:
            os.stat(timestamp, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise LoadError("Cumulus output timestamp already exists; refuse replacement")
        os.mkdir(stage_name, mode=0o700, dir_fd=root_fd)
        created = True
        stage_fd = os.open(
            stage_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
            dir_fd=root_fd,
        )
        if stat.S_IMODE(os.fstat(stage_fd).st_mode) != 0o700:
            raise LoadError("imported configuration stage is not private")
        for name, data in snapshot.files:
            if not name.endswith(".yaml") or name == "default.yaml" or "/" in name:
                raise LoadError("imported configuration snapshot contains an unsafe member")
            fd = os.open(name,
                         os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                         0o600, dir_fd=stage_fd)
            try:
                with os.fdopen(os.dup(fd), "wb") as stream:
                    stream.write(data)
                    stream.flush()
                os.fsync(fd)
                os.fchmod(fd, 0o644)
                os.fsync(fd)
            finally:
                os.close(fd)
            check_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=stage_fd)
            with os.fdopen(check_fd, "rb") as stream:
                staged = stream.read(len(data) + 1)
            if staged != data:
                raise LoadError(f"imported configuration stage changed: {name!r}")
        os.fchmod(stage_fd, 0o755)
        os.fsync(stage_fd)
        try:
            os.stat(timestamp, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise LoadError("Cumulus output timestamp was claimed during staging")
        if _import_root_alias_identity(output_root) != alias_before:
            raise LoadError("Cumulus output root alias changed before publication")
        os.rename(stage_name, timestamp, src_dir_fd=root_fd, dst_dir_fd=root_fd)
        committed = True
        os.fsync(root_fd)
        if _import_root_alias_identity(output_root) != alias_before:
            raise LoadError("Cumulus output root alias changed after publication")
        return output
    finally:
        if not committed and created:
            if stage_fd >= 0:
                for name, _ in snapshot.files:
                    try:
                        os.unlink(name, dir_fd=stage_fd)
                    except FileNotFoundError:
                        pass
            os.rmdir(stage_name, dir_fd=root_fd)
        if stage_fd >= 0:
            os.close(stage_fd)
        os.close(root_fd)


def _device_csv_na(value: object) -> bool:
    return str(value or "").strip().casefold() in {"", "na", "n/a", "none", "null", "-"}


def _eth_jump_inventory_errors(fields, row, is_na, *, skip_indices=(), schema_version=None):
    """Check supplied inventory cells without deriving configuration or doing IO.

    ``None`` is the standalone initial reader's schema-independent metadata
    mode: recognize only existing v1/v2 lexical spellings, not either dialect's
    configuration completeness. Setup/load pass their declared schema version.
    """
    errors = []
    totals = {field: fields.count(field) for field in fields}
    occurrences = {}

    def numeric_selector(value, maximum, *, native=False):
        if value.casefold().endswith("/native"):
            if not native or not re.fullmatch(r"[0-9]+", value[:-7]):
                return False
            value = value[:-7]
        for token in re.split(r"[/,]", value):
            match = re.fullmatch(r"([0-9]+)(?:-([0-9]+))?", token.strip())
            if match is None:
                return False
            start = int(match.group(1))
            end = int(match.group(2) or start)
            if not 1 <= start <= end <= maximum:
                return False
        return True

    def port_selector(value, *, bond=False, peerlink=False):
        for group in value.split("|" if bond else "/"):
            if not group.strip():
                return False
            for token in group.split("/"):
                token = token.strip()
                if not peerlink and (
                    token == "peerlink.4094"
                    or re.fullmatch(r"(?:bond[0-9]+)+", token)
                    or (schema_version in (None, 2)
                        and re.fullmatch(r"bond[0-9]+(?:b[0-9]+)+", token))
                ):
                    continue
                prefix = "bond" if bond else "swp"
                pattern = (
                    r"([1-9][0-9]*)(?:-([1-9][0-9]*))?" if peerlink else
                    r"([0-9]+)(?:-([0-9]+))?(?:s([0-9]+)(?:-([0-9]+))?)?"
                )
                match = re.fullmatch(prefix + pattern, token)
                if match is None:
                    return False
                if int(match.group(2) or match.group(1)) < int(match.group(1)):
                    return False
                if not peerlink and match.group(3) is not None:
                    if int(match.group(4) or match.group(3)) < int(match.group(3)):
                        return False
        return True

    for index, field in enumerate(fields):
        occurrence = occurrences.get(field, 0) + 1
        occurrences[field] = occurrence
        if index in skip_indices:
            continue
        value = str(row[index] or "").strip() if index < len(row) else ""
        if is_na(value):
            continue
        label = field if totals[field] == 1 else f"{field}[{occurrence}]"
        valid = True
        try:
            if field in {"eth0_ip", "eth1_ip", "eth0_gw", "eth1_gw"}:
                ipaddress.IPv4Address(value)
            elif field in {"lo_ip", "svi_ip", "vrr_ip"}:
                ipaddress.ip_interface(value)
            elif field == "netmask":
                if value.isdigit():
                    valid = 1 <= int(value) <= 32
                else:
                    valid = str(ipaddress.IPv4Network("0.0.0.0/" + value).netmask) == value
            elif field == "bond_mac":
                valid = all(
                    is_na(token.strip()) or bool(re.fullmatch(
                        r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|"
                        r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", token.strip(),
                    ))
                    for token in value.split("|")
                )
            elif field in {"eth0_mac", "eth1_mac", "vrr_mac"}:
                valid = bool(re.fullmatch(
                    r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}|"
                    r"(?:[0-9a-fA-F]{2}-){5}[0-9a-fA-F]{2}", value,
                ))
            elif field in {"vlan_id", "evpn_l3vlan", "evpn_l2vlan"}:
                valid = numeric_selector(
                    value, 4094,
                    native=(schema_version in (None, 2)
                            and field in {"vlan_id", "evpn_l2vlan"}),
                )
            elif field in {"evpn_l3vni", "evpn_l2vni"}:
                valid = numeric_selector(value, 16777215)
            elif field == "bgp_asn":
                valid = 1 <= int(value) <= 4294967295
            elif field in {"bgp_ports", "vlan_ports", "peerlink_ports", "bond_ports"}:
                valid = port_selector(
                    value, bond=(field == "bond_ports"),
                    peerlink=(field == "peerlink_ports"),
                )
            elif field == "bond_type":
                allowed = {"localbond", "mlag", "mlagbond", "evpn_multihoming"}
                if schema_version in (None, 2):
                    allowed |= {"local", "evpn"}
                valid = all(token.strip().casefold() in allowed for token in value.split("|"))
            elif field == "vrl":
                valid = value.casefold() in {"false", "0", "no", "n", "true", "1", "yes", "y"}
            # template, VRF labels and relay server-group selectors remain
            # inventory text: no template/global lookup or companion inference.
        except (ValueError, TypeError, OverflowError):
            valid = False
        if not valid:
            errors.append(f"{label}={value!r} 无效")
    return tuple(errors)


@dataclass(frozen=True)
class MacOSClientRequirementStatus:
    """Detected client-side prerequisites shown before a macOS load mutates state."""

    python_version: str
    python_supported: bool
    missing_generation_modules: tuple[str, ...]
    missing_commands: tuple[str, ...]
    missing_validation_modules: tuple[str, ...]
    password_backend: str | None
    homebrew: str | None


@dataclass
class PreparedParentRelease:
    """A fully written parent manifest waiting for its single atomic commit."""

    destination: Path
    temporary: Path
    release_id: str
    committed: bool = False
    splitter_provenance: dict[str, object] | None = None
    generated_inventory: dict[str, object] | None = None
    source_inventory_sha256: str | None = None
    source_authorities: dict[str, tuple[str, str]] | None = None
    dhcp_manifest_sha256: str | None = None
    dhcp_source_dir: Path | None = None
    precommit_check: Callable[[], None] | None = None
    directory_synced: bool = False


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
    http_port: int = 80
    http_address: str | None = None

    @property
    def service_ips(self) -> tuple[str, ...]:
        """ZTP addresses derived from declarative subnet rows only."""
        values = [
            address
            for role in SERVICE_IP_PRIORITY
            for address in self.ztp_ips.get(role, ())
        ]
        values.extend(self.boot_ips)
        return tuple(dict.fromkeys(values))

    @property
    def http_listener_ips(self) -> tuple[str, ...]:
        """Apache binds only the explicitly declared HTTP authority."""
        if not self.http_enabled:
            return ()
        if not self.http_address:
            raise LoadError("common.mgmt.http.address 必须显式指定独立的 HTTP 服务 IPv4")
        return (self.http_address,)


def publication_plan_for(
    settings: GlobalSettings, *, pubkey_names: tuple[str, ...],
    image_names: tuple[tuple[str, str], ...],
) -> PublicationPlan:
    """Bind declarative project URLs to the same endpoints Apache will listen on."""
    http_addresses = settings.http_listener_ips
    active_roles = tuple(
        role for role in SERVICE_IP_PRIORITY if settings.ztp_ips.get(role)
    )
    if (active_roles or settings.boot_ips) and not http_addresses:
        raise LoadError(
            "ZTP publication requires enabled common.mgmt.http.address"
        )
    http_endpoint = (
        validate_service_endpoint(
            http_addresses[0], settings.http_port,
            field="common.mgmt.http.address",
        ) if http_addresses else None
    )
    return PublicationPlan(
        endpoints_by_role=tuple(
            (role, (http_endpoint,)) for role in active_roles
        ),
        boot_endpoints=(http_endpoint,) if settings.boot_ips else (),
        ztp_prefix=settings.ztp_prefix,
        pubkey_names=pubkey_names,
        image_names=image_names,
        apt_endpoint=None,
    )


@dataclass(frozen=True)
class ProjectInputs:
    global_file: Path
    devices_file: Path
    subnet_file: Path
    p2p_file: Path
    device_types: frozenset[str]
    pubkeys: tuple[Path, ...]
    settings: GlobalSettings
    air_topology_policy: Path | None = None
    mini_devices_file: Path | None = None
    mini_source_file: Path | None = None
    deployment_scope: str = "all"
    switch_scope: str = "all"
    source_identities: dict[str, str] | None = None
    device_methods: dict[str, str] | None = None
    effective_devices_file: Path | None = None
    effective_devices_sha256: str | None = None


@dataclass(frozen=True)
class DerivedInventory:
    path: Path
    sha256: str


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(2, 58 - len(title)))


def ok(message: str) -> None:
    print(f"[OK] {message}")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def _run_local_test_runner(
    arguments: list[str], label: str, *,
    accepted_returncodes: frozenset[int] = frozenset({0}),
) -> int:
    try:
        runner_info = LOCAL_TEST_RUNNER.lstat()
    except FileNotFoundError as exc:
        raise LoadError(f"本机 load 测试门禁不存在：{LOCAL_TEST_RUNNER}") from exc
    if (
        not stat.S_ISREG(runner_info.st_mode)
        or runner_info.st_nlink != 1
        or LOCAL_TEST_RUNNER.is_symlink()
    ):
        raise LoadError(
            f"本机 load 测试门禁必须是单链接普通文件：{LOCAL_TEST_RUNNER}"
        )
    command = [sys.executable, "-B", str(LOCAL_TEST_RUNNER), *arguments]
    info(f"{label}：" + " ".join(shlex_quote(item) for item in command))
    completed = _run_subprocess(
        command, cwd=HTTP_ROOT, shell=False, check=False,
    )
    if completed.returncode not in accepted_returncodes:
        raise LoadError(f"{label}失败（exit={completed.returncode}）")
    return completed.returncode


def run_local_full_test_gate(*, validation_only: bool = False) -> None:
    """Reuse an exact proof, or create one only for stale/missing proof state."""
    intent = ["--validation-only"] if validation_only else []
    status = _run_local_test_runner(
        ["--check", "--require-full", *intent],
        "本机正式 load 前全量测试证明检查",
        accepted_returncodes=frozenset({0, 4, 5}),
    )
    if status == 0:
        info("已复用精确全量测试证明；本次不重复执行全量套件")
        return
    if status not in {4, 5}:
        # _run_local_test_runner already rejects every other return code.  Keep
        # this branch as a defensive contract if its implementation changes.
        raise LoadError(f"本机正式 load 前测试门禁失败（exit={status}）")
    reason = "受管字节未批准" if status == 4 else "全量证明缺失、过期或环境不匹配"
    info(f"{reason}；开始执行一次全量测试")
    _run_local_test_runner(["--all", *intent], "本机正式 load 前全量测试")
    verify_local_full_test_attestation(validation_only=validation_only)


def verify_local_full_test_attestation(*, validation_only: bool = False) -> None:
    """Require the exact full-suite attestation without running tests."""
    intent = ["--validation-only"] if validation_only else []
    _run_local_test_runner(
        ["--check", "--require-full", *intent], "本机 load 全量测试证明复核",
    )


def acquire_deployment_lock(*, exclusive: bool = True) -> int:
    """Acquire the process-wide deployment gate without waiting.

    Child generators publish their own ``latest`` links before the parent
    ``current-release.json`` commit.  Holding this lock across the whole load
    keeps every cooperating manual/GUI operation outside that short window.
    """
    lock_context = None
    lock_entered = False
    try:
        if not exclusive:
            return acquire_lock_path_descriptor(
                DEPLOYMENT_LOCK, exclusive=False, create=True,
            )
        # A container management wrapper may already hold this exact lock and
        # pass its open descriptor through HTTP_DEPLOYMENT_LOCK_FD.  Reuse the
        # shared contract so the descriptor is validated against the lock path
        # and the child closes its copy without unlocking the parent's open
        # file description.  Opening the path again here would self-deadlock.
        lock_context = deployment_lock(DEPLOYMENT_LOCK.parent)
        descriptor = lock_context.__enter__()
        lock_entered = True
        if descriptor is None:  # actual load never requests a dry-run lock
            raise DeploymentLockError("deployment lock descriptor is absent")
        _DEPLOYMENT_LOCK_CONTEXTS[descriptor] = lock_context
        return descriptor
    except DeploymentLockError as exc:
        if lock_context is not None and lock_entered:
            lock_context.__exit__(type(exc), exc, exc.__traceback__)
        raise LoadError(
            "另一个 load 或人工 ZTP/重置操作正在使用部署 release；"
            "请等待其完成后重试"
        ) from exc


def release_deployment_lock(descriptor: int | None) -> None:
    if descriptor is None:
        return
    lock_context = _DEPLOYMENT_LOCK_CONTEXTS.pop(descriptor, None)
    if lock_context is not None:
        lock_context.__exit__(None, None, None)
        return
    release_lock_descriptor(descriptor)


def runtime_os() -> str:
    """Return the host OS name used to gate Linux-only service operations."""
    return platform.system() or "Unknown"


def _default_regular_file(path: Path) -> bool:
    try:
        metadata = path.stat()
    except OSError:
        return False
    return stat.S_ISREG(metadata.st_mode)


def macos_client_requirement_status(
    *,
    command_resolver=None,
    module_resolver=None,
    regular_file=None,
    python_version=None,
) -> MacOSClientRequirementStatus:
    """Inspect every supported macOS client dependency without changing state."""
    command_resolver = command_resolver or shutil.which
    module_resolver = module_resolver or importlib.util.find_spec
    regular_file = regular_file or _default_regular_file
    version = tuple(python_version or sys.version_info[:3])

    def module_present(name: str) -> bool:
        try:
            return module_resolver(name) is not None
        except (AttributeError, ImportError, ValueError):
            return False

    missing_generation = tuple(
        label for label, module in MACOS_GENERATION_MODULES
        if not module_present(module)
    )
    missing_validation = tuple(
        label for label, module in MACOS_VALIDATION_MODULES
        if not module_present(module)
    )
    missing_commands = tuple(
        command for command in MACOS_TRANSFER_COMMANDS
        if not command_resolver(command)
    )

    brew_path = command_resolver("brew")
    if not brew_path:
        brew_path = next(
            (str(path) for path in MACOS_HOMEBREW_CANDIDATES if regular_file(path)),
            None,
        )
    mkpasswd = command_resolver("mkpasswd")
    libxcrypt = next(
        (str(path) for path in MACOS_LIBXCRYPT_CANDIDATES if regular_file(path)),
        None,
    )
    backend = (
        f"mkpasswd ({mkpasswd})" if mkpasswd
        else f"Homebrew libxcrypt ({libxcrypt})" if libxcrypt
        else None
    )
    normalized_version = tuple(int(item) for item in version[:3])
    return MacOSClientRequirementStatus(
        python_version=".".join(str(item) for item in normalized_version),
        python_supported=normalized_version[:2] >= MACOS_MIN_PYTHON,
        missing_generation_modules=missing_generation,
        missing_commands=missing_commands,
        missing_validation_modules=missing_validation,
        password_backend=backend,
        homebrew=str(brew_path) if brew_path else None,
    )


def print_macos_client_requirements(
    *, update_passwords: bool, printer=print, **probe_overrides,
) -> MacOSClientRequirementStatus:
    """Print tiered macOS client status and hints only for missing tools."""
    status = macos_client_requirement_status(**probe_overrides)
    printer("")
    printer("── macOS 客户端依赖检查（load / tar-for-upload / sync-code）")
    python_mark = "[OK]" if status.python_supported else "[MISSING]"
    printer(
        f"{python_mark} Python 3.9+：当前 {status.python_version}"
    )

    generation_all = ", ".join(label for label, _ in MACOS_GENERATION_MODULES)
    if status.missing_generation_modules:
        printer(
            "[MISSING] 配置生成模块："
            f"{', '.join(status.missing_generation_modules)}"
            f"（完整要求：{generation_all}）"
        )
    else:
        printer(f"[OK] 配置生成模块：{generation_all}")

    command_all = "Git/git, OpenSSH/ssh/scp/ssh-keygen, rsync"
    if status.missing_commands:
        printer(
            "[MISSING] 上传/同步命令："
            f"{', '.join(status.missing_commands)}"
            f"（完整要求：{command_all}）"
        )
    else:
        printer(f"[OK] 上传/同步命令：{command_all}")

    validation_all = ", ".join(label for label, _ in MACOS_VALIDATION_MODULES)
    if status.missing_validation_modules:
        printer(
            "[MISSING] 全量测试/报表模块："
            f"{', '.join(status.missing_validation_modules)}"
            f"（完整要求：{validation_all}）"
        )
    else:
        printer(f"[OK] 全量测试/报表模块：{validation_all}")

    if status.password_backend:
        printer(
            "[OK] 密码更新后端（仅 --update-passwords）："
            f"{status.password_backend}"
        )
    else:
        password_mark = "[MISSING]" if update_passwords else "[OPTIONAL]"
        printer(
            f"{password_mark} 密码更新后端（仅 --update-passwords）："
            "whois/mkpasswd 或 Homebrew libxcrypt"
        )
    if status.homebrew:
        printer(f"[OK] Homebrew：{status.homebrew}")
    else:
        printer("[OPTIONAL] Homebrew：仅安装 libxcrypt 等可选工具时需要")

    if not status.python_supported:
        printer("[INSTALL] brew install python@3.12")
    developer_commands = {"git", "ssh", "scp", "ssh-keygen"}
    if developer_commands.intersection(status.missing_commands):
        printer("[INSTALL] xcode-select --install")
    if "rsync" in status.missing_commands:
        printer("[INSTALL] brew install rsync")
    if status.missing_generation_modules or status.missing_validation_modules:
        printer(
            "[INSTALL] python3 -m pip install -r requirements-dev.txt "
            "Jinja2==3.1.6"
        )
    if status.password_backend is None:
        printer("[INSTALL] brew install libxcrypt  # 仅 --update-passwords")
    printer(
        "[INFO] Apache、ISC DHCP、systemd、iproute2 只安装在 Ubuntu 管理服务器；"
        "VirtualBox/Docker/Excel 不是代码必需依赖。"
    )
    return status


def validate_macos_client_requirements(
    status: MacOSClientRequirementStatus,
) -> None:
    """Fail before mutation only when local configuration generation is unsafe."""
    missing = []
    if not status.python_supported:
        missing.append("Python 3.9+")
    missing.extend(status.missing_generation_modules)
    if missing:
        raise LoadError(
            "macOS 配置生成缺少必需依赖："
            f"{', '.join(missing)}；请先安装上方 [INSTALL] 项后重试"
        )


def supports_local_ztp_services(os_name: str | None = None) -> bool:
    """Apache/ISC DHCP/infra service management is intentionally Linux-only."""
    return (os_name or runtime_os()).casefold() == "linux"


def resolve_host_role(declared: str | None, os_name: str | None = None) -> str:
    """Resolve an operator declaration, never a service/IP/HOME heuristic."""
    host_os = (os_name or runtime_os()).casefold()
    if declared not in (None, "workstation", "management-server"):
        raise LoadError("invalid --host-role; expected workstation or management-server")
    if host_os == "darwin":
        if declared not in (None, "workstation"):
            raise LoadError("Darwin host role must be workstation")
        return "workstation"
    if host_os == "linux":
        if declared is None:
            raise LoadError("Linux requires explicit --host-role=workstation|management-server before any write")
        return declared
    raise LoadError(f"unsupported host OS for --host-role: {host_os}")


def _flush_operator_output() -> None:
    """Commit buffered narration before a direct child can emit output."""
    sys.stdout.flush()
    sys.stderr.flush()


def _run_subprocess(*args, **kwargs):
    """Run one direct child after preserving transcript causal order."""
    _flush_operator_output()
    return subprocess.run(*args, **kwargs)


def _popen_subprocess(*args, **kwargs):
    """Start one direct child after preserving transcript causal order."""
    _flush_operator_output()
    return subprocess.Popen(*args, **kwargs)


def run(
    command: list[str], *, cwd: Path | None = None, dry_run: bool = False,
    inherited_lock_descriptor: int | None = None,
    setup_key_context: bool | None = None,
    expected_global_sha256: str | None = None,
) -> None:
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(f"[DRY] ({cwd or Path.cwd()}) {display}")
        return
    print(f"[RUN] ({cwd or Path.cwd()}) {display}")
    child_kwargs = inherited_lock_subprocess_kwargs(inherited_lock_descriptor)
    if expected_global_sha256 is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_global_sha256):
            raise LoadError("invalid global source authority")
        child_env = dict(child_kwargs.get("env") or os.environ)
        child_env["HTTP_EXPECTED_GLOBAL_SHA256"] = expected_global_sha256
        child_kwargs["env"] = child_env
    if setup_key_context is not None:
        # This private mode is scoped to the setup child.  Never let an
        # unrelated parent environment silently decide the child's key role.
        child_env = dict(child_kwargs.get("env") or os.environ)
        child_env.pop("HTTP_SETUP_KEY_MODE", None)
        if setup_key_context:
            if inherited_lock_descriptor is None:
                raise LoadError("server-delegated setup requires the deployment lock FD")
            child_env["HTTP_SETUP_KEY_MODE"] = "server-delegated"
        child_kwargs["env"] = child_env
    result = _run_subprocess(command, cwd=cwd, **child_kwargs)
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
    # A local dry-run may intentionally name a not-yet-created project; the
    # template planner reports that future creation.  An existing directory
    # must pass the restore gate before any subsequent project operation.
    if os.path.lexists(project):
        try:
            require_project_eligible(project)
        except ValueError as exc:
            raise LoadError(f"部署目录恢复提交未完成：{project}: {exc}") from exc
    return project


def _meaningful_entries(directory: Path) -> list[Path]:
    if not directory.exists():
        return []
    return [item for item in directory.iterdir() if item.name not in {".DS_Store"}]


def _setup_module():
    """Load 01-a-setup.py once (its name has hyphens), as _import_publisher_module does.

    Its module level only extends sys.path and imports the same tools/ modules load already uses: no
    write, no lock (v3.1.1 WP-2 checked every top-level statement).
    """
    name = f"_http_load_setup_{abs(hash(os.fspath(SETUP_SCRIPT)))}"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, SETUP_SCRIPT)
    if spec is None or spec.loader is None:
        raise LoadError(f"cannot load the setup template completion: {SETUP_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def initialize_from_template(project: Path, dry_run: bool = False) -> None:
    """Complete the project from the template with setup's one implementation (v3.1.1 WP-2).

    setup's rules hold here too: only missing items, conflicts are errors, laptop.pub is never copied,
    .bin placeholders are, nothing is written through a link out of the project, dry-run only prints.
    Afterwards load alone adds an empty laptop.pub placeholder where nothing is (review S1).
    """
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
    setup = _setup_module()
    # setup's globals are this process's now: set what the completion reads, and hand its error count back.
    setup.TEMPLATE_DIR = os.fspath(TEMPLATE_DIR)
    setup._DRY_RUN = dry_run
    setup._LINK_ERRORS = 0
    setup._initialize_project_from_template(os.fspath(project))
    errors, setup._LINK_ERRORS = setup._LINK_ERRORS, 0
    if errors:
        raise LoadError(f"项目与模板有 {errors} 处冲突（见上方 [ERROR]）；请处理后再次执行 load")
    # The configuration-only key preflight runs before setup and accepts only an empty regular laptop.pub
    # placeholder (_prepare_pubkeys_without_management_injection); setup's completion never copies that
    # file.  So, as the v3.1.0 load did, add it where nothing is; a link, directory or file stays untouched
    # (review S1, http dev 2026-11-08 改法 (a)).  The setup child then prepares the real key.
    laptop = project / LAPTOP_PUBKEY_NAME
    if not os.path.lexists(laptop):
        if dry_run:
            print(f"  [DRY] 创建空占位 {LAPTOP_PUBKEY_NAME}")
        else:
            laptop.open("x").close()   # exclusive create: never through a link
            print(f"  [INIT] {LAPTOP_PUBKEY_NAME} ← 空占位（setup 随后准备本机公钥）")


def _nonempty_file(path: Path, label: str) -> None:
    if not path.is_file():
        raise LoadError(f"缺少 {label}：{path.name}")
    if path.stat().st_size == 0:
        raise LoadError(f"{label} 大小为 0：{path.name}；请准备真实内容后再次执行 load")


def _require_subnet_input_file(path: Path) -> os.stat_result:
    """Reject missing, linked, non-regular and zero-byte subnet authorities."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LoadError(f"缺少 02-dhcp-subnet_config.csv：{exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LoadError("02-dhcp-subnet_config.csv 必须是非软链接 single-link 普通文件")
    if metadata.st_size == 0:
        raise LoadError("02-dhcp-subnet_config.csv 为零字节；必须提供规范表头")
    return metadata


def _open_subnet_input_file(path: Path):
    """Read the validated final CSV through the same regular nofollow inode."""
    initial = _require_subnet_input_file(path)
    if any(not hasattr(os, name) for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")):
        raise LoadError("02-dhcp-subnet_config.csv 安全打开要求 O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC")
    descriptor = -1
    try:
        descriptor = os.open(
            path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)):
            raise LoadError("DHCP subnet CSV 来源身份在读取前变化")
        if opened.st_size == 0:
            raise LoadError("02-dhcp-subnet_config.csv 为零字节；必须提供规范表头")
        stream = os.fdopen(descriptor, "r", newline="", encoding="utf-8-sig")
        descriptor = -1
        return stream
    except OSError as exc:
        raise LoadError(f"无法安全读取 02-dhcp-subnet_config.csv：{exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _subnet_source_token(path: Path) -> tuple[object, ...]:
    """Bind the current CSV bytes and inode across LOAD validation phases."""
    with _open_subnet_input_file(path) as stream:
        before = os.fstat(stream.fileno())
        digest = hashlib.sha256()
        for block in iter(lambda: stream.buffer.read(1024 * 1024), b""):
            digest.update(block)
        after = os.fstat(stream.fileno())
        try:
            current = path.lstat()
        except OSError as exc:
            raise LoadError(f"DHCP subnet CSV 来源在读取中消失：{exc}") from exc
    fields = lambda value: (
        value.st_dev, value.st_ino, value.st_size,
        value.st_mtime_ns, value.st_ctime_ns,
    )
    if (
        not stat.S_ISREG(after.st_mode) or after.st_nlink != 1
        or not stat.S_ISREG(current.st_mode) or current.st_nlink != 1
        or fields(before) != fields(after) or fields(before) != fields(current)
    ):
        raise LoadError("DHCP subnet CSV 来源身份在哈希期间变化")
    return (*fields(before), digest.hexdigest())


def project_air_topology_policy(project: Path) -> Path | None:
    """Return the fixed optional AIR topology policy for one project."""
    path = project / AIR_TOPOLOGY_POLICY_NAME
    if not os.path.lexists(path):
        return None
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LoadError(f"无法检查 AIR 拓扑策略：{path.name}: {exc}") from exc
    if stat.S_ISLNK(metadata.st_mode):
        raise LoadError(f"AIR 拓扑策略不得为 symlink：{path.name}")
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LoadError(
            f"AIR 拓扑策略必须是 single-link regular file：{path.name}"
        )
    if metadata.st_size == 0:
        raise LoadError(f"AIR 拓扑策略大小为 0：{path.name}")
    if metadata.st_size > 1024 * 1024:
        raise LoadError(f"AIR 拓扑策略超过 1 MiB：{path.name}")
    return path


def project_mini_air_devices(
    project: Path, value: str | None,
) -> tuple[Path | None, Path | None]:
    """Resolve the optional customer mini list and its canonical output."""
    if value is None:
        return None, None
    project_root = project.resolve()
    source = Path(value)
    if not source.is_absolute():
        source = project_root / source
    if source.parent.resolve() != project_root or source.suffix.casefold() != ".txt":
        raise LoadError("--mini 设备清单必须是项目根目录下的 .txt 文件")
    canonical = project_root / MINI_AIR_DEVICES_NAME
    if source != canonical and not os.path.lexists(source):
        raise LoadError(f"--mini 设备清单不存在：{source.name}")
    if os.path.lexists(source):
        try:
            metadata = source.lstat()
        except OSError as exc:
            raise LoadError(f"无法检查 --mini 设备清单：{source.name}: {exc}") from exc
        if stat.S_ISLNK(metadata.st_mode):
            target = os.readlink(source)
            if source == canonical or Path(target).is_absolute() or target != canonical.name:
                raise LoadError(
                    f"--mini 设备清单链接必须相对指向 {canonical.name}"
                )
        elif not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LoadError("--mini 设备清单必须是 single-link regular file")
    return source, canonical


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
    text = str(value or "").strip()
    match = re.fullmatch(
        r"[0-9]+(?P<separator>[.-])[0-9]+(?P=separator)[0-9]+",
        text,
    )
    if match is None:
        raise LoadError(f"无法识别版本号：{value!r}")
    return text.replace(".", "-")


_NVOS_LEGACY_IMAGE_RE = re.compile(
    r"^nvosv(?P<version>[0-9]+-[0-9]+-[0-9]+)amd64\.bin$"
)
_NVOS_MODERN_IMAGE_RE = re.compile(
    r"^nvos-amd64-(?P<version>[0-9]+\.[0-9]+\.[0-9]+)\.bin$"
)


def _image_filename_candidates(expected_name: str) -> tuple[str, ...]:
    """Return exact accepted aliases, ordered by deterministic preference."""
    legacy = _NVOS_LEGACY_IMAGE_RE.fullmatch(expected_name)
    if legacy is not None:
        version = legacy.group("version")
        modern = f"nvos-amd64-{version.replace('-', '.')}.bin"
        return modern, expected_name
    modern = _NVOS_MODERN_IMAGE_RE.fullmatch(expected_name)
    if modern is not None:
        version = modern.group("version")
        legacy_name = f"nvosv{version.replace('.', '-')}amd64.bin"
        return expected_name, legacy_name
    return (expected_name,)


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


def _subnet_record_lines(stream) -> tuple[int, ...]:
    try:
        return subnet_csv_record_start_lines(stream)
    except RuntimeContractError as exc:
        # The shared runtime keeps its English diagnostic; LOAD reports DEV's (2848e52) wording.
        empty_record = re.fullmatch(
            r"DHCP subnet CSV line (\d+) \(行\1\) contains an empty delimiter/quote record",
            str(exc),
        )
        if empty_record:
            raise LoadError(
                f"DHCP subnet CSV 第 {empty_record.group(1)} 行是仅含分隔符或引号的空字段记录；"
                "若该行无意义请整行删除"
            ) from exc
        raise LoadError(str(exc)) from exc


def _snapshot_subnet_input_stream(stream):
    try:
        return snapshot_subnet_csv_text(stream)
    except RuntimeContractError as exc:
        raise LoadError(str(exc)) from exc


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
            endpoint = validate_service_endpoint(
                raw_ip, field=f"DHCP subnet CSV 第 {lineno} 行 ztp_service_ip"
            )
        except ValueError as exc:
            raise LoadError(
                f"DHCP subnet CSV 第 {lineno} 行 ztp_service_ip={raw_ip!r} "
                "不是可用单播地址"
            ) from exc
        service_ip = endpoint.host
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


def _load_global_document(path: Path) -> dict[str, object]:
    _nonempty_file(path, "global.yaml")
    try:
        data = safe_load_global_yaml(path.read_text(encoding="utf-8"))
    except (yaml.YAMLError, ValueError) as exc:
        raise LoadError(f"global YAML 语法错误：{exc}") from exc
    if not isinstance(data, dict):
        raise LoadError("global.yaml 顶层必须是 mapping")
    return data


def load_global(
    path: Path, *, global_data: dict[str, object] | None = None,
    switch_scope: str = "all",
) -> GlobalSettings:
    data = _load_global_document(path) if global_data is None else global_data
    selected_switch = str(switch_scope or "all").strip().casefold()
    if selected_switch not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    try:
        schema_version = detect_global_schema_version(data)
        normalize_issue_tracker_policy(data)
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    if "schema_version" not in data:
        print("[WARN] 01-global.yaml 缺少 schema_version；按旧版 schema 1 兼容读取")
    try:
        common = data["common"]
        mgmt = common["mgmt"]
        dhcp = mgmt["dhcp-server"]
        # Projects predating the HTTP section retain their port-80 listener.
        # A section that is present must still pass every explicit field gate.
        http = mgmt.get("http", {
            "status": "enabled", "package": "apache2",
            "http_root": "/var/www/html", "port": 80,
        })
        ztp = mgmt["ztp"]
        switch_system = common["switch"]["system"]
    except (KeyError, TypeError) as exc:
        raise LoadError(
            f"global 缺少 common.mgmt.dhcp-server/http/ztp "
            f"或 common.switch.system：{exc}"
        ) from exc
    if not isinstance(http, dict):
        raise LoadError("common.mgmt.http 必须是 mapping")

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
    try:
        http_port = validate_service_endpoint(
            "192.0.2.1", http.get("port", 80), field="common.mgmt.http.port"
        ).port
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    http_address = None
    if http_enabled and "address" not in http:
        raise LoadError(
            "common.mgmt.http.address 必须显式指定独立的 HTTP 服务 IPv4"
        )
    if "address" in http:
        try:
            http_address = validate_service_endpoint(
                http["address"], field="common.mgmt.http.address"
            ).host
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
    ztp_enabled = _enabled(ztp.get("status"), "common.mgmt.ztp.status")
    if not dhcp_enabled and ztp_enabled:
        raise LoadError("DHCP disabled + ZTP enabled 是非法组合")
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
        if kind not in SWITCH_SCHEMA_FAMILIES:
            raise LoadError(f"global.switches 包含未知设备类型：{kind}")
        if not isinstance(config, dict):
            raise LoadError(f"switches.{kind} 必须是 mapping")
        version = str(config.get("version") or "").strip()
        if version:
            _version_key(version)
            versions[kind] = version
    if schema_version == 2 and selected_switch in {"all", "eth"}:
        eth_config = next(
            (entry["eth"] for entry in switches if isinstance(entry, dict) and "eth" in entry),
            None,
        )
        try:
            normalize_v2_mlag_policy(eth_config)
            normalize_v2_vrr_policy(eth_config)
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
    else:
        eth_config = next(
            (entry["eth"] for entry in switches if isinstance(entry, dict) and "eth" in entry),
            None,
        )
    if selected_switch in {"all", "eth"}:
        try:
            validate_cumulus_dns_domain(eth_config)
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
        http_port=http_port,
        http_address=http_address,
    )


def find_placeholder_password_sections(
    global_data: object, *, switch_scope: str = "all",
) -> tuple[str, ...]:
    """Return selected switch families whose managed credential is exactly ``*``."""
    if set(SWITCH_CREDENTIAL_PATHS) != set(SWITCH_SCHEMA_FAMILIES):
        raise LoadError("switch credential contract does not cover every schema family")
    selected_scope = str(switch_scope or "all").strip().casefold()
    if selected_scope not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    selected_families = (
        set(SWITCH_SCHEMA_FAMILIES)
        if selected_scope == "all"
        else {selected_scope}
    )
    if not isinstance(global_data, dict):
        raise LoadError("global.yaml 顶层必须是 mapping")
    switches = global_data.get("switches")
    if not isinstance(switches, list):
        raise LoadError("global.switches 必须是 list")

    values: dict[str, object] = {}
    for index, item in enumerate(switches, 1):
        if not isinstance(item, dict) or len(item) != 1:
            raise LoadError(f"global.switches[{index}] 必须只包含一种设备类型")
        family, config = next(iter(item.items()))
        if family not in SWITCH_SCHEMA_FAMILIES:
            raise LoadError(
                f"switch credential contract does not cover schema family: {family}"
            )
        if family in values:
            raise LoadError(f"global.switches 包含重复设备类型：{family}")
        if family not in selected_families:
            values[family] = None
            continue
        node: object = config
        traversed = f"switches.{family}"
        for key in SWITCH_CREDENTIAL_PATHS[family]:
            if not isinstance(node, dict) or key not in node:
                raise LoadError(f"switch credential path missing: {traversed}.{key}")
            node = node[key]
            traversed += f".{key}"
        values[family] = node

    placeholders: list[str] = []
    for family in SWITCH_CREDENTIAL_FAMILY_ORDER:
        value = values.get(family)
        if not isinstance(value, str):
            continue
        normalized = value.strip()
        if (
            len(normalized) >= 2
            and normalized[0] == normalized[-1]
            and normalized[0] in {"'", '"'}
        ):
            normalized = normalized[1:-1]
        if normalized == "*":
            placeholders.append(family)
    return tuple(placeholders)


def _placeholder_password_error(
    project: Path, sections: tuple[str, ...], *, host_role: str,
) -> LoadError:
    platforms = {"eth": "cumulus", "ib": "ib", "nvl": "nvl"}
    commands = [
        f"DAY0-Prepare/11-load.py {project} --update-passwords "
        f"--host-role={host_role}"
    ]
    if sections == SWITCH_CREDENTIAL_FAMILY_ORDER:
        commands.append(
            f"python3 tools/password-update.py {project} --platform all"
        )
    commands.extend(
        f"python3 tools/password-update.py {project} --platform {platforms[section]}"
        for section in sections
    )
    return LoadError(
        "global.yaml 仍含占位密码，受影响平台："
        + ", ".join(sections)
        + "。请先执行以下任一对应修复命令：\n  - "
        + "\n  - ".join(commands)
    )


def derive_service_ips_from_subnet(
    path: Path, ztp_prefix: str,
) -> dict[str, tuple[str, ...]]:
    """Derive Cumulus bootstrap service addresses from profile declarations."""
    _require_subnet_input_file(path)
    _validate_ztp_prefix(ztp_prefix)
    found: dict[str, set[str]] = {profile: set() for profile in BOOTSTRAP_BY_PROFILE}
    with _snapshot_subnet_input_stream(_open_subnet_input_file(path)) as stream:
        line_starts = _subnet_record_lines(stream)
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for index, row in enumerate(reader):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            lineno = line_starts[index]
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
    _require_subnet_input_file(path)
    _validate_ztp_prefix(ztp_prefix)
    found = set()
    with _snapshot_subnet_input_stream(_open_subnet_input_file(path)) as stream:
        line_starts = _subnet_record_lines(stream)
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for index, row in enumerate(reader):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            lineno = line_starts[index]
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
    _require_subnet_input_file(subnet_file)
    derived = derive_service_ips_from_subnet(subnet_file, settings.ztp_prefix)
    boot_ips = derive_boot_ips_from_subnet(subnet_file, settings.ztp_prefix)
    if (not settings.dhcp_enabled and not settings.ztp_enabled
            and not any(derived.values()) and not boot_ips):
        return replace(settings, ztp_ips={}, boot_ips=())
    updated = replace(settings, ztp_ips=derived, boot_ips=boot_ips)
    if settings.ztp_enabled and not updated.service_ips:
        raise LoadError(
            "ZTP enabled 但 DHCP subnet CSV 没有启用任何 Cumulus/NVOS endpoint"
        )
    return updated


def load_device_types(
    path: Path, schema_version: int = GLOBAL_SCHEMA_VERSION,
    switch_scope: str = "all",
    methods_out: dict[str, str] | None = None,
) -> frozenset[str]:
    selected_scope = str(switch_scope or "").strip().casefold()
    if selected_scope not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
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
            if fields.count("config_method") > 1:
                raise LoadError("devices_config.csv config_method 列重复")
            method_index = fields.index("config_method") if "config_method" in fields else None
            types: set[str] = set()
            methods: dict[str, str] = {}
            seen_hostnames: set[str] = set()
            seen_eth0_addr: dict[str, tuple[int, str]] = {}
            seen_eth0_mac: dict[str, tuple[int, str]] = {}
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
                raw_address = str(row[fields.index("eth0_ip")] or "").strip()
                address = raw_address.split("/", 1)[0]
                raw_mac = str(row[fields.index("eth0_mac")] or "").strip()
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
                # server_ufm leaves every column after eth0_mac empty and has no
                # executor in this repo, so (like eth_jump) it declares no method.
                if kind == "server_ufm":
                    pass
                elif method_index is not None:
                    if len(row) <= method_index:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 {hostname} config_method 列缺失"
                        )
                    try:
                        method = validate_device_config_method(kind, row[method_index])
                    except ValueError as exc:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 {hostname} {exc}"
                        ) from exc
                elif kind != "eth_jump":
                    try:
                        method = resolve_device_config_method(kind)
                    except ValueError as exc:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 {hostname} {exc}"
                        ) from exc
                if kind not in {"eth_jump", "server_ufm"}:
                    methods[hostname_key] = method
                selected_kind = (
                    selected_scope == "all"
                    or kind in SWITCH_SCOPE_TYPES[selected_scope]
                )
                try:
                    parsed_address = ipaddress.IPv4Interface(raw_address).ip
                except ValueError:
                    parsed_address = None
                if parsed_address is not None:
                    address_key = str(parsed_address)
                    previous = seen_eth0_addr.get(address_key)
                    if previous is not None and (
                        kind == "eth_jump" or previous[1] == "eth_jump"
                    ):
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 eth0_ip 重复"
                            f"（{address_key}，首次行{previous[0]}）"
                        )
                    seen_eth0_addr.setdefault(address_key, (lineno, kind))
                valid_mac = bool(re.fullmatch(
                    r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}|"
                    r"(?:[0-9a-f]{2}-){5}[0-9a-f]{2}",
                    raw_mac.casefold(),
                ))
                if kind == "eth_jump" and not _device_csv_na(raw_mac) and not valid_mac:
                    raise LoadError(
                        f"devices_config.csv 第 {lineno} 行 eth_jump "
                        f"eth0_mac={raw_mac!r} 无效"
                    )
                if valid_mac:
                    mac_key = raw_mac.casefold().replace("-", ":")
                    previous = seen_eth0_mac.get(mac_key)
                    if previous is not None and (
                        kind == "eth_jump" or previous[1] == "eth_jump"
                    ):
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 eth0_mac 重复"
                            f"（首次行{previous[0]}）"
                        )
                    seen_eth0_mac.setdefault(mac_key, (lineno, kind))
                if kind == "eth_jump":
                    inventory_errors = _eth_jump_inventory_errors(
                        fields, row, _device_csv_na,
                        skip_indices=(fields.index("eth0_mac"),),
                        schema_version=schema_version,
                    )
                    if inventory_errors:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 {hostname} type=eth_jump "
                            + "; ".join(inventory_errors)
                        )
                    if selected_kind:
                        types.add(kind)
                    continue
                if not selected_kind:
                    continue
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
    if methods_out is not None:
        methods_out.clear()
        methods_out.update(methods)
    return frozenset(types)


def select_p2p(
    project: Path, explicit: str | None = None, *,
    migrate_legacy_canonical: bool = False,
    management_server: bool = False,
) -> Path:
    project = project.resolve()
    canonical = project / "p2p.xlsx"
    try:
        receipt = read_p2p_receipt(project) if management_server else None
        if receipt is not None:
            if explicit is not None and explicit != receipt["basename"]:
                raise P2PSelectionError("--p2p-file 与本次传输的 P2P 收据选择不一致")
            explicit = receipt["basename"]
        elif management_server and explicit is None and len(project_p2p_candidates(project)) > 1:
            raise P2PSelectionError("管理服务器存在多个 P2P 候选且缺少本次传输收据；请明确 --p2p-file")
        # A pre-link real canonical workbook is the sole migration exception:
        # setup rescues it using an atomic no-replace move before reconciliation.
        if (
            migrate_legacy_canonical and explicit is None and os.path.lexists(canonical)
            and stat.S_ISREG(canonical.lstat().st_mode)
            and canonical.stat().st_size > 0
        ):
            path = canonical
        else:
            path = select_project_p2p_source(project, explicit)
    except (OSError, P2PSelectionError) as exc:
        raise LoadError(f"P2P 选择失败：{exc}") from exc
    _nonempty_file(path, "p2p.xlsx")
    before = p2p_source_snapshot(project, path)
    if path.suffix.casefold() != ".xlsx" or not zipfile.is_zipfile(path):
        raise LoadError(f"P2P 文件不是合法 XLSX：{path.name}")
    with zipfile.ZipFile(path) as archive:
        if "xl/workbook.xml" not in archive.namelist():
            raise LoadError(f"P2P XLSX 缺少 xl/workbook.xml：{path.name}")
    try:
        assert_p2p_source_snapshot(project, path, before)
    except P2PSelectionError as exc:
        raise LoadError(str(exc)) from exc
    return path


def validate_subnet_file(path: Path, settings: GlobalSettings) -> None:
    if type(settings.dhcp_enabled) is not bool or type(settings.ztp_enabled) is not bool:
        raise LoadError("DHCP/ZTP 状态必须是显式布尔值")
    if settings.ztp_enabled and not settings.dhcp_enabled:
        raise LoadError("DHCP disabled 且 ZTP enabled 的全局组合非法")
    _require_subnet_input_file(path)
    with _snapshot_subnet_input_stream(_open_subnet_input_file(path)) as stream:
        line_starts = _subnet_record_lines(stream)
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        rows = []
        active_ztp_rows = 0
        for index, row in enumerate(reader):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            lineno = line_starts[index]
            _service_ip, profile, nvos_ztp = _parse_subnet_ztp_fields(row, lineno)
            if profile in BOOTSTRAP_BY_PROFILE or nvos_ztp == "yes":
                active_ztp_rows += 1
                if not settings.ztp_enabled:
                    raise LoadError(
                        f"DHCP subnet CSV 第 {lineno} 行启用了平台 ZTP，"
                        "但 global ZTP disabled"
                    )
            rows.append((lineno, row))
    try:
        validate_dhcp_subnet_placements(rows, service_ips=settings.service_ips)
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    if not rows and settings.dhcp_enabled:
        raise LoadError("02-dhcp-subnet_config.csv 没有 subnet 记录")
    # DEV 2848e52 (agreed 2026-10-25): with DHCP disabled, fully validated rows may still
    # describe an external DHCP service; plan_local_dhcp_runtime authorizes no listener.
    if settings.ztp_enabled and rows and not active_ztp_rows:
        raise LoadError("全局 ZTP enabled 但没有启用 ZTP 的 endpoint 行")


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
        result = _run_subprocess([keygen, "-l", "-f", str(path)], capture_output=True, text=True)
        if result.returncode != 0:
            raise LoadError(f"ssh-keygen 校验失败 {path.name}：{result.stderr.strip()}")


def _default_ssh_dir() -> Path:
    return Path.home() / ".ssh"


MANAGEMENT_PUBKEY_MARKER = ".management-pubkeys"
LAPTOP_PUBKEY_NAME = "laptop.pub"
MANAGEMENT_PUBKEY_NAME = "mgmt-server.pub"
MANAGEMENT_PRIVATE_KEY_NAME = "id_ed25519"
MANAGEMENT_PUBLIC_KEY_NAME = "id_ed25519.pub"
MANAGEMENT_KEY_MAX_BYTES = 64 * 1024
MANAGEMENT_KEYGEN = Path("/usr/bin/ssh-keygen")


@dataclass
class _HeldManagementDirectory:
    path: Path
    descriptor: int
    identity: tuple[int, ...]
    uid: int
    gid: int
    allowed_modes: tuple[int, ...]
    label: str

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _HeldManagementLeaf:
    directory: _HeldManagementDirectory
    name: str
    descriptor: int
    identity: tuple[int, ...]
    payload: bytes
    mode: int
    label: str

    def close(self) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)
            self.descriptor = -1


@dataclass
class _HeldManagementPair:
    directory: _HeldManagementDirectory
    private: _HeldManagementLeaf
    public: _HeldManagementLeaf
    identity: tuple[bytes, bytes]

    def close(self) -> None:
        self.private.close()
        self.public.close()
        self.directory.close()


@dataclass(frozen=True)
class _ManagementCommandResult:
    returncode: int
    stdout: bytes
    stderr: bytes


def _management_key_checkpoint(_stage: str) -> None:
    """Deterministic direct-test checkpoint; production performs no action."""


def _terminate_management_command(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as exc:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired as final:
            raise LoadError("management ssh-keygen process could not be reaped") from final


def _run_bounded_management_command(
    argv: list[str], *, pass_fds: tuple[int, ...] = (), timeout: float = 10,
) -> _ManagementCommandResult:
    if not argv or not argv[0] or any(type(item) is not str for item in argv):
        raise LoadError("management ssh-keygen argv 不安全")
    validation_shape = (
        len(argv) == 6
        and argv[:5] == [os.fspath(MANAGEMENT_KEYGEN), "-y", "-P", "", "-f"]
        and argv[5] in {f"/proc/self/fd/{fd}" for fd in pass_fds}
        | {f"/dev/fd/{fd}" for fd in pass_fds}
        and len(pass_fds) == 1
    )
    generation_shape = (
        len(argv) == 10
        and argv[:7] == [
            os.fspath(MANAGEMENT_KEYGEN), "-q", "-t", "ed25519", "-N", "", "-f",
        ]
        and argv[8:] == ["-C", "root@management-server"]
        and pass_fds == ()
    )
    if not (validation_shape or generation_shape):
        raise LoadError("management ssh-keygen argv 不符合固定 validate/generate schema")
    process: subprocess.Popen[bytes] | None = None
    selector: selectors.BaseSelector | None = None
    owned_streams: list[object] = []
    streams: dict[int, tuple[object, bytearray]] = {}
    completed = False
    try:
        process = _popen_subprocess(
            argv,
            env={
                "HOME": "/root", "LANG": "C", "LC_ALL": "C",
                "PATH": "/usr/bin:/bin", "PYTHONNOUSERSITE": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            close_fds=True,
            pass_fds=pass_fds,
            start_new_session=True,
            bufsize=0,
        )
        if process.stdout is None or process.stderr is None:
            raise LoadError("management ssh-keygen pipe unavailable")
        owned_streams = [process.stdout, process.stderr]
        selector = selectors.DefaultSelector()
        stdout_descriptor = process.stdout.fileno()
        stderr_descriptor = process.stderr.fileno()
        os.set_blocking(stdout_descriptor, False)
        os.set_blocking(stderr_descriptor, False)
        streams = {
            stdout_descriptor: (process.stdout, bytearray()),
            stderr_descriptor: (process.stderr, bytearray()),
        }
        for descriptor in streams:
            selector.register(descriptor, selectors.EVENT_READ)
        deadline = time.monotonic() + float(timeout)
        failure = ""
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                failure = "management ssh-keygen timeout"
                break
            for key, _mask in selector.select(min(remaining, 0.1)):
                stream, payload = streams[key.fd]
                try:
                    chunk = os.read(
                        key.fd,
                        min(16384, MANAGEMENT_KEY_MAX_BYTES + 1 - len(payload)),
                    )
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fd)
                    stream.close()
                    continue
                payload.extend(chunk)
                if len(payload) > MANAGEMENT_KEY_MAX_BYTES:
                    failure = "management ssh-keygen bounded output exceeded limit"
                    break
            if failure:
                break
        if failure:
            raise LoadError(failure)
        try:
            returncode = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        except subprocess.TimeoutExpired as exc:
            raise LoadError("management ssh-keygen timeout") from exc
        result = _ManagementCommandResult(
            returncode=int(returncode),
            stdout=bytes(streams[stdout_descriptor][1]),
            stderr=bytes(streams[stderr_descriptor][1]),
        )
        completed = True
        return result
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        raise LoadError(f"management ssh-keygen bounded capture failed：{exc}") from exc
    finally:
        try:
            if process is not None and not completed:
                _terminate_management_command(process)
        finally:
            try:
                if selector is not None:
                    selector.close()
            finally:
                for stream in owned_streams:
                    try:
                        stream.close()
                    except (OSError, ValueError):
                        pass


def _management_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _management_directory_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        getattr(metadata, "st_mtime_ns", int(metadata.st_mtime * 1_000_000_000)),
        getattr(metadata, "st_ctime_ns", int(metadata.st_ctime * 1_000_000_000)),
    )


def _management_directory_flags() -> int:
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required):
        raise LoadError("当前平台缺少安全打开管理 SSH 目录所需的能力")
    return os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def _open_management_directory(
    path: Path, *, label: str, allowed_modes: tuple[int, ...],
) -> _HeldManagementDirectory:
    descriptor = -1
    try:
        direct = os.lstat(path)
        if stat.S_ISLNK(direct.st_mode) or not stat.S_ISDIR(direct.st_mode):
            raise LoadError(f"{label} 必须是非 symlink 的安全 directory")
        if direct.st_uid != os.geteuid() or direct.st_gid != os.getegid():
            raise LoadError(f"{label} owner uid/gid 不安全")
        if stat.S_IMODE(direct.st_mode) not in allowed_modes:
            expected = "/".join(f"{mode:04o}" for mode in allowed_modes)
            raise LoadError(f"{label} mode 必须是 {expected}")
        descriptor = os.open(os.fspath(path), _management_directory_flags())
        held = os.fstat(descriptor)
        if _management_directory_identity(direct) != _management_directory_identity(held):
            raise LoadError(f"{label} identity changed while opening")
        return _HeldManagementDirectory(
            path=path,
            descriptor=descriptor,
            identity=_management_directory_identity(held),
            uid=held.st_uid,
            gid=held.st_gid,
            allowed_modes=allowed_modes,
            label=label,
        )
    except LoadError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise LoadError(f"无法安全打开 {label}：{exc}") from exc


def _revalidate_management_directory(directory: _HeldManagementDirectory) -> None:
    try:
        held = os.fstat(directory.descriptor)
        rebound = os.lstat(directory.path)
    except OSError as exc:
        raise LoadError(f"{directory.label} canonical binding disappeared：{exc}") from exc
    if (
        _management_directory_identity(held) != directory.identity
        or _management_directory_identity(rebound) != directory.identity
    ):
        raise LoadError(f"{directory.label} directory identity changed or rebound")


def _management_read_bounded(descriptor: int, limit: int, label: str) -> bytes:
    payload = bytearray()
    offset = 0
    while True:
        try:
            chunk = os.pread(descriptor, min(8192, limit + 1 - len(payload)), offset)
        except OSError as exc:
            raise LoadError(f"无法读取 {label}：{exc}") from exc
        if not chunk:
            return bytes(payload)
        payload.extend(chunk)
        offset += len(chunk)
        if len(payload) > limit:
            raise LoadError(f"{label} exceeds bounded size limit")


def _validate_management_leaf_metadata(
    metadata: os.stat_result, *, label: str, mode: int,
    uid: int, gid: int,
) -> None:
    if not stat.S_ISREG(metadata.st_mode):
        raise LoadError(f"{label} 必须是 regular file，不能是 symlink/FIFO/special")
    if metadata.st_nlink != 1:
        raise LoadError(f"{label} 必须是 single-link file")
    if metadata.st_uid != uid or metadata.st_gid != gid:
        raise LoadError(f"{label} owner uid/gid 不安全")
    if stat.S_IMODE(metadata.st_mode) != mode:
        raise LoadError(f"{label} mode 必须是 {mode:04o}")


def _open_management_leaf(
    directory: _HeldManagementDirectory,
    name: str,
    *,
    label: str,
    mode: int,
    writable: bool = False,
) -> _HeldManagementLeaf:
    descriptor = -1
    required = ("O_NOFOLLOW", "O_NONBLOCK", "O_CLOEXEC")
    if any(not hasattr(os, item) for item in required):
        raise LoadError("当前平台缺少安全打开管理 SSH 文件所需的能力")
    flags = (os.O_RDWR if writable else os.O_RDONLY)
    flags |= os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        direct = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
        _validate_management_leaf_metadata(
            direct,
            label=label,
            mode=mode,
            uid=directory.uid,
            gid=directory.gid,
        )
        descriptor = os.open(name, flags, dir_fd=directory.descriptor)
        held = os.fstat(descriptor)
        _validate_management_leaf_metadata(
            held,
            label=label,
            mode=mode,
            uid=directory.uid,
            gid=directory.gid,
        )
        if _management_metadata_identity(direct) != _management_metadata_identity(held):
            raise LoadError(f"{label} identity changed while opening")
        payload = _management_read_bounded(descriptor, MANAGEMENT_KEY_MAX_BYTES, label)
        after = os.fstat(descriptor)
        rebound = os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
        identity = _management_metadata_identity(held)
        if (
            _management_metadata_identity(after) != identity
            or _management_metadata_identity(rebound) != identity
        ):
            raise LoadError(f"{label} changed or rebound while held")
        return _HeldManagementLeaf(
            directory=directory,
            name=name,
            descriptor=descriptor,
            identity=identity,
            payload=payload,
            mode=mode,
            label=label,
        )
    except LoadError:
        if descriptor >= 0:
            os.close(descriptor)
        raise
    except OSError as exc:
        if descriptor >= 0:
            os.close(descriptor)
        raise LoadError(f"无法安全打开 {label}：{exc}") from exc


def _revalidate_management_leaf(leaf: _HeldManagementLeaf) -> None:
    try:
        held = os.fstat(leaf.descriptor)
        rebound = os.stat(
            leaf.name,
            dir_fd=leaf.directory.descriptor,
            follow_symlinks=False,
        )
    except OSError as exc:
        raise LoadError(f"{leaf.label} canonical binding disappeared：{exc}") from exc
    if (
        _management_metadata_identity(held) != leaf.identity
        or _management_metadata_identity(rebound) != leaf.identity
        or _management_read_bounded(
            leaf.descriptor, MANAGEMENT_KEY_MAX_BYTES, leaf.label,
        ) != leaf.payload
    ):
        raise LoadError(f"{leaf.label} changed, drifted, or rebound")


def _parse_management_ed25519(payload: bytes, label: str) -> tuple[bytes, bytes]:
    try:
        identity = ssh_keys.public_key_identity_bytes(payload)
    except ssh_keys.SshKeyPreparationError as exc:
        raise LoadError(f"{label} Ed25519 public key 无效：{exc}") from exc
    if identity[0] != b"ssh-ed25519":
        raise LoadError(f"{label} 必须是 ssh-ed25519 public key")
    return identity[0], base64.b64encode(identity[1])


def _parse_held_project_public_identity(
    payload: bytes, label: str,
) -> tuple[bytes, bytes]:
    try:
        identity = ssh_keys.public_key_identity_bytes(payload)
    except ssh_keys.SshKeyPreparationError as exc:
        raise LoadError(f"{label} SSH public key 无效：{exc}") from exc
    return identity[0], base64.b64encode(identity[1])


def _management_fd_path(descriptor: int) -> str:
    for root in ("/proc/self/fd", "/dev/fd"):
        if os.path.isdir(root):
            return f"{root}/{descriptor}"
    raise LoadError("当前平台无法把 held management private key 交给 ssh-keygen")


def _open_management_pair(ssh_dir: Path) -> _HeldManagementPair:
    directory = _open_management_directory(
        ssh_dir, label="管理服务器 SSH 目录", allowed_modes=(0o700,),
    )
    private: _HeldManagementLeaf | None = None
    public: _HeldManagementLeaf | None = None
    try:
        present = []
        for name in (MANAGEMENT_PRIVATE_KEY_NAME, MANAGEMENT_PUBLIC_KEY_NAME):
            try:
                os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                present.append(False)
            except OSError as exc:
                raise LoadError(f"无法检查管理服务器密钥对：{exc}") from exc
            else:
                present.append(True)
        if present == [False, False]:
            raise LoadError("管理服务器 SSH key 尚未由 host helper prepared")
        if present[0] != present[1]:
            raise LoadError("管理服务器 SSH key pair 不完整，未进行自动修复")
        private = _open_management_leaf(
            directory,
            MANAGEMENT_PRIVATE_KEY_NAME,
            label="管理服务器 private key",
            mode=0o600,
        )
        public = _open_management_leaf(
            directory,
            MANAGEMENT_PUBLIC_KEY_NAME,
            label="管理服务器 public key",
            mode=0o644,
        )
        public_identity = _parse_management_ed25519(public.payload, public.label)
        if not MANAGEMENT_KEYGEN.is_file():
            raise LoadError("固定 /usr/bin/ssh-keygen 不存在，无法校验管理服务器 key")
        result = _run_bounded_management_command(
            [
                os.fspath(MANAGEMENT_KEYGEN), "-y", "-P", "", "-f",
                _management_fd_path(private.descriptor),
            ],
            pass_fds=(private.descriptor,),
        )
        if result.returncode != 0:
            raise LoadError("管理服务器 private key 无法用空口令校验或已加密")
        stdout = bytes(result.stdout)
        stderr = bytes(result.stderr)
        if stderr or len(stdout) > MANAGEMENT_KEY_MAX_BYTES:
            raise LoadError("管理服务器 private key 校验输出不符合 bounded canonical contract")
        derived_payload = stdout
        if not derived_payload.endswith(b"\n"):
            derived_payload += b"\n"
        derived_identity = _parse_management_ed25519(
            derived_payload, "管理服务器 derived public key",
        )
        if derived_identity != public_identity:
            raise LoadError("管理服务器公私钥不匹配 mismatch，未覆盖任何文件")
        _revalidate_management_leaf(private)
        _revalidate_management_leaf(public)
        _revalidate_management_directory(directory)
        return _HeldManagementPair(
            directory=directory,
            private=private,
            public=public,
            identity=public_identity,
        )
    except BaseException:
        if private is not None:
            private.close()
        if public is not None:
            public.close()
        directory.close()
        raise


def _attest_management_project_objects(project: Path) -> None:
    directory = _open_management_directory(
        project, label="项目 SSH key directory", allowed_modes=(0o700, 0o755),
    )
    marker: _HeldManagementLeaf | None = None
    placeholder: _HeldManagementLeaf | None = None
    try:
        marker = _open_management_leaf(
            directory,
            MANAGEMENT_PUBKEY_MARKER,
            label="management marker",
            mode=0o644,
        )
        if marker.payload != b"mgmt-server.pub\n":
            raise LoadError("management marker 必须 exact 为 mgmt-server.pub\\n")
        placeholder = _open_management_leaf(
            directory,
            MANAGEMENT_PUBKEY_NAME,
            label="management placeholder",
            mode=0o644,
        )
        if placeholder.payload:
            _parse_management_ed25519(placeholder.payload, placeholder.label)
        _revalidate_management_leaf(marker)
        _revalidate_management_leaf(placeholder)
        _revalidate_management_directory(directory)
    finally:
        if marker is not None:
            marker.close()
        if placeholder is not None:
            placeholder.close()
        directory.close()


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


def _public_key_identity(path: Path) -> tuple[bytes, bytes]:
    """Return the key type/blob pair, excluding the non-identity comment."""
    try:
        return ssh_keys.public_key_identity(path)
    except ssh_keys.SshKeyPreparationError as exc:
        raise LoadError(f"项目公钥身份无效：{exc}") from exc


def _management_pair_presence(ssh_dir: Path) -> tuple[bool, bool]:
    try:
        directory = _open_management_directory(
            ssh_dir, label="管理服务器 SSH 目录", allowed_modes=(0o700,),
        )
    except FileNotFoundError:
        return False, False
    except LoadError:
        raise
    try:
        result = []
        for name in (MANAGEMENT_PRIVATE_KEY_NAME, MANAGEMENT_PUBLIC_KEY_NAME):
            try:
                os.stat(name, dir_fd=directory.descriptor, follow_symlinks=False)
            except FileNotFoundError:
                result.append(False)
            except OSError as exc:
                raise LoadError(f"无法检查管理服务器 key pair：{exc}") from exc
            else:
                result.append(True)
        _revalidate_management_directory(directory)
        return result[0], result[1]
    finally:
        directory.close()


def _server_rsa_public_fallback_present(ssh_dir: Path) -> bool:
    """Check a server RSA public leaf without consulting its private half.

    Native management-key generation must not silently supersede a present
    RSA public identity. RSA-only server operation remains unsupported until
    its separate no-private-read contract is resolved.
    """
    try:
        directory = _open_management_directory(
            ssh_dir, label="管理服务器 SSH 目录", allowed_modes=(0o700,),
        )
    except LoadError as exc:
        if "无法安全打开" in str(exc) and not ssh_dir.exists():
            return False
        raise
    rsa_public: _HeldManagementLeaf | None = None
    try:
        try:
            os.stat("id_rsa.pub", dir_fd=directory.descriptor, follow_symlinks=False)
        except FileNotFoundError:
            _revalidate_management_directory(directory)
            return False
        except OSError as exc:
            raise LoadError(f"无法检查管理服务器 RSA public key：{exc}") from exc
        rsa_public = _open_management_leaf(
            directory, "id_rsa.pub", label="管理服务器 RSA public key", mode=0o644,
        )
        try:
            identity = ssh_keys.public_key_identity_bytes(rsa_public.payload)
        except ssh_keys.SshKeyPreparationError as exc:
            raise LoadError(f"管理服务器 RSA public key 无效：{exc}") from exc
        if identity[0] != b"ssh-rsa":
            raise LoadError("id_rsa.pub 不是 RSA public key")
        _revalidate_management_leaf(rsa_public)
        _revalidate_management_directory(directory)
        return True
    finally:
        if rsa_public is not None:
            rsa_public.close()
        directory.close()


def _generate_native_management_key(ssh_dir: Path) -> None:
    try:
        ssh_keys.generate_ed25519_pair(ssh_dir, comment="root@management-server")
    except ssh_keys.SshKeyPreparationError as exc:
        raise LoadError(f"自动生成管理服务器 SSH key 失败：{exc}") from exc


def ensure_management_key(
    ssh_dir: Path, *, dry_run: bool = False, allow_generation: bool,
) -> Path:
    """Validate a held Ed25519 pair; only the native caller may generate it."""
    if type(allow_generation) is not bool:
        raise LoadError("allow_generation 必须是调用者提供的 literal bool")
    try:
        private_exists, public_exists = _management_pair_presence(ssh_dir)
    except LoadError as exc:
        if "无法安全打开" in str(exc) and not ssh_dir.exists():
            private_exists = public_exists = False
        else:
            raise
    if private_exists != public_exists:
        raise LoadError("管理服务器 SSH key pair 不完整，未自动修复")
    if not private_exists:
        if _server_rsa_public_fallback_present(ssh_dir):
            raise LoadError(
                "管理服务器存在 RSA public key；RSA-only server fallback 尚未获准，"
                "拒绝静默生成或发布另一把 Ed25519 key"
            )
        if not allow_generation:
            raise LoadError("管理服务器 SSH key 尚未由 host helper prepared；Supervisor 不会生成")
        if dry_run:
            raise LoadError("管理服务器 SSH key 不存在；dry-run 不会生成")
        _generate_native_management_key(ssh_dir)
        print(f"[KEY] 已生成管理服务器专用 SSH key：{ssh_dir / MANAGEMENT_PUBLIC_KEY_NAME}")
    pair = _open_management_pair(ssh_dir)
    try:
        return ssh_dir / MANAGEMENT_PUBLIC_KEY_NAME
    finally:
        pair.close()


def _prepare_pubkeys_without_management_injection(
    project: Path, *, dry_run: bool,
) -> tuple[Path, ...]:
    """Preserve the configuration-only behavior on platforms without services.

    R-014 第 3 条: a project key may be the operator's own link (laptop.pub -> their key).  The project's
    input links are resolved and read once here (read_project_input_links), and a linked key's identity
    comes from those bytes; the no-follow identity reader stays as it is for regular keys.
    """
    try:
        linked = {item.name: item.payload for item in read_project_input_links(project)}
    except ValueError as exc:
        raise LoadError(str(exc)) from exc

    def identity(item: Path) -> tuple[bytes, bytes]:
        if item.name not in linked:
            return _public_key_identity(item)
        try:
            return ssh_keys.public_key_identity_bytes(linked[item.name])
        except ssh_keys.SshKeyPreparationError as exc:
            raise LoadError(f"项目公钥身份无效：{item.name}：{exc}") from exc

    pubs = sorted(project.glob("*.pub"))
    marker = project / MANAGEMENT_PUBKEY_MARKER
    managed_names = {
        line.strip() for line in marker.read_text(encoding="utf-8").splitlines()
        if line.strip().endswith(".pub")
    } if marker.is_file() else set()
    empty = [item for item in pubs if not item.is_file() or item.stat().st_size == 0]
    static = [item for item in pubs if item not in empty and item.name not in managed_names]
    # setup, not this config-only preflight, prepares the laptop's HOME key.
    # Only its explicitly named empty regular placeholder may be planned as a
    # static key; no other empty *.pub can satisfy that role.
    laptop_placeholder = project / LAPTOP_PUBKEY_NAME
    planned_laptop = None
    if laptop_placeholder in empty and LAPTOP_PUBKEY_NAME not in managed_names:
        metadata = laptop_placeholder.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1 or metadata.st_size != 0:
            raise LoadError("laptop.pub 空占位在配置预检中发生变化或不是独立普通文件")
        planned_laptop = laptop_placeholder
    if not static and planned_laptop is None:
        raise LoadError("项目必须至少包含一个非空 *.pub（例如模板中的电脑公钥）")
    for item in static:
        validate_pubkey(item)
    planned_management = sorted(
        project / name for name in managed_names if (project / name).is_file()
    )
    if not planned_management:
        planned_management = sorted(item for item in empty if item != planned_laptop)
    preserved = sorted(item for item in planned_management if item.stat().st_size > 0)
    for item in preserved:
        validate_pubkey(item)
    static_identities = {identity(item) for item in static}
    if any(identity(item) in static_identities for item in preserved):
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
    valid = static + ([planned_laptop] if planned_laptop is not None else []) + planned_management
    if (planned_laptop is not None and not planned_management) or len(set(valid)) < 2:
        raise LoadError(
            "ZTP 需要一个电脑公钥和一个管理服务器公钥占位路径；"
            f"请在项目中增加空的 {MANAGEMENT_PUBKEY_NAME}"
        )
    return tuple(sorted(valid, key=_pubkey_sort_key))


def prepare_pubkeys(
    project: Path, *, ssh_dir: Path, dry_run: bool = False,
    inject_management_key: bool = True,
    allow_management_key_generation: bool,
) -> tuple[Path, ...]:
    if type(allow_management_key_generation) is not bool:
        raise LoadError("allow_management_key_generation 必须是 literal bool")
    if not inject_management_key:
        return _prepare_pubkeys_without_management_injection(project, dry_run=dry_run)

    project_directory = _open_management_directory(
        project, label="项目 SSH key directory", allowed_modes=(0o700, 0o755),
    )
    marker: _HeldManagementLeaf | None = None
    placeholder: _HeldManagementLeaf | None = None
    pair: _HeldManagementPair | None = None
    static_leaves: list[_HeldManagementLeaf] = []
    try:
        marker = _open_management_leaf(
            project_directory,
            MANAGEMENT_PUBKEY_MARKER,
            label="management marker",
            mode=0o644,
        )
        if marker.payload != b"mgmt-server.pub\n":
            raise LoadError("management marker 必须 exact 为 mgmt-server.pub\\n")
        placeholder = _open_management_leaf(
            project_directory,
            MANAGEMENT_PUBKEY_NAME,
            label="management placeholder",
            mode=0o644,
            writable=True,
        )
        placeholder_identity = None
        if placeholder.payload:
            placeholder_identity = _parse_management_ed25519(
                placeholder.payload, placeholder.label,
            )
        pub_names = sorted(
            name for name in os.listdir(project_directory.descriptor)
            if name.endswith(".pub") and name != MANAGEMENT_PUBKEY_NAME
        )
        if not pub_names:
            raise LoadError("项目必须至少包含一个非空 *.pub（例如模板中的电脑公钥）")
        for name in pub_names:
            static_leaves.append(_open_management_leaf(
                project_directory,
                name,
                label=f"项目公钥 {name}",
                mode=0o644,
            ))
        static = [project / leaf.name for leaf in static_leaves]
        static_identities = {
            _parse_held_project_public_identity(leaf.payload, leaf.label)
            for leaf in static_leaves
        }

        ensure_management_key(
            ssh_dir,
            dry_run=dry_run,
            allow_generation=allow_management_key_generation,
        )
        pair = _open_management_pair(ssh_dir)
        if pair.identity in static_identities:
            raise LoadError("管理服务器公钥与项目电脑公钥相同，无法保证两个独立 key")
        if placeholder_identity == pair.identity:
            _revalidate_management_leaf(marker)
            _revalidate_management_leaf(placeholder)
            for leaf in static_leaves:
                _revalidate_management_leaf(leaf)
            _revalidate_management_leaf(pair.private)
            _revalidate_management_leaf(pair.public)
            _revalidate_management_directory(pair.directory)
            _revalidate_management_directory(project_directory)
            print(f"[SKIP] 管理服务器公钥已存在且匹配，不覆盖：{placeholder.name}")
            return tuple(sorted(static + [project / MANAGEMENT_PUBKEY_NAME], key=_pubkey_sort_key))

        _management_key_checkpoint("service-public-held")
        _revalidate_management_leaf(pair.private)
        _revalidate_management_leaf(pair.public)
        _revalidate_management_directory(pair.directory)
        _management_key_checkpoint("project-placeholder-held")
        _revalidate_management_leaf(marker)
        _revalidate_management_leaf(placeholder)
        for leaf in static_leaves:
            _revalidate_management_leaf(leaf)
        _revalidate_management_directory(project_directory)
        _revalidate_management_leaf(pair.private)
        _revalidate_management_leaf(pair.public)
        _revalidate_management_directory(pair.directory)
        if placeholder_identity is not None:
            # Held management identities use canonical base64 as their second
            # field; OpenSSH fingerprints hash the decoded wire blob.
            old_wire = base64.b64decode(placeholder_identity[1], validate=True)
            new_wire = base64.b64decode(pair.identity[1], validate=True)
            mismatch = (
                f"management public key mismatch: {placeholder.name} "
                f"source={ssh_dir / MANAGEMENT_PUBLIC_KEY_NAME} "
                f"old={ssh_keys._fingerprint((placeholder_identity[0], old_wire))} "
                f"new={ssh_keys._fingerprint((pair.identity[0], new_wire))}; "
                "existing real key was not changed"
            )
            print(f"[BLOCK] {mismatch}")
            raise LoadError(mismatch)
        if dry_run:
            print(f"[DRY] 将注入 prepared service management public key → {placeholder.name}")
            return tuple(sorted(static + [project / MANAGEMENT_PUBKEY_NAME], key=_pubkey_sort_key))
        try:
            os.ftruncate(placeholder.descriptor, 0)
            written = 0
            while written < len(pair.public.payload):
                count = os.pwrite(
                    placeholder.descriptor, pair.public.payload[written:], written,
                )
                if count <= 0:
                    raise OSError("short management public-key write")
                written += count
            os.ftruncate(placeholder.descriptor, len(pair.public.payload))
            os.fsync(placeholder.descriptor)
        except OSError as exc:
            raise LoadError(f"写入 management placeholder 失败：{exc}") from exc
        _management_key_checkpoint("project-management-published")
        try:
            held = os.fstat(placeholder.descriptor)
            rebound = os.stat(
                placeholder.name,
                dir_fd=project_directory.descriptor,
                follow_symlinks=False,
            )
        except OSError as exc:
            raise LoadError(f"management placeholder post-write revalidation 失败：{exc}") from exc
        _validate_management_leaf_metadata(
            held,
            label=placeholder.label,
            mode=0o644,
            uid=project_directory.uid,
            gid=project_directory.gid,
        )
        if (
            (held.st_dev, held.st_ino) != (placeholder.identity[0], placeholder.identity[1])
            or _management_metadata_identity(held) != _management_metadata_identity(rebound)
            or _management_read_bounded(
                placeholder.descriptor, MANAGEMENT_KEY_MAX_BYTES, placeholder.label,
            ) != pair.public.payload
        ):
            raise LoadError("management placeholder changed or rebound after publication")
        _revalidate_management_leaf(marker)
        for leaf in static_leaves:
            _revalidate_management_leaf(leaf)
        _revalidate_management_leaf(pair.private)
        _revalidate_management_leaf(pair.public)
        _revalidate_management_directory(pair.directory)
        _revalidate_management_directory(project_directory)
        print(f"[KEY] 已注入 prepared service management public key：{placeholder.name}")
        return tuple(sorted(static + [project / MANAGEMENT_PUBKEY_NAME], key=_pubkey_sort_key))
    finally:
        if pair is not None:
            pair.close()
        if marker is not None:
            marker.close()
        if placeholder is not None:
            placeholder.close()
        for leaf in static_leaves:
            leaf.close()
        project_directory.close()


SWITCH_SCOPE_TYPES = {
    "all": frozenset({"eth", "eth_spx", "spx", "air", "ib", "nvl"}),
    "eth": frozenset({"eth", "eth_spx", "spx", "air"}),
    "ib": frozenset({"ib"}),
    "nvl": frozenset({"nvl"}),
}


def filter_device_types_for_switch_scope(
    device_types: frozenset[str] | set[str], switch_scope: str,
) -> frozenset[str]:
    """Return the exact platform family selected for this release."""
    selected = str(switch_scope or "").strip().casefold()
    allowed = SWITCH_SCOPE_TYPES.get(selected)
    if allowed is None:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    return frozenset(str(item).casefold() for item in device_types) & allowed


def expected_images(
    settings: GlobalSettings, device_types: frozenset[str], *,
    deployment_scope: str = "all", switch_scope: str = "all",
) -> dict[str, str]:
    if deployment_scope == "air":
        image_device_types = frozenset({"eth"})
    elif deployment_scope == "prod":
        image_device_types = device_types - {"air"}
    elif deployment_scope == "all":
        image_device_types = device_types | ({"eth"} if "air" in device_types else set())
    else:
        raise LoadError(f"无法识别 deployment scope：{deployment_scope!r}")
    image_device_types = filter_device_types_for_switch_scope(
        image_device_types, switch_scope,
    )
    expected: dict[str, str] = {}
    if image_device_types & {"eth", "eth_spx", "spx"}:
        version = settings.versions.get("eth")
        if not version:
            raise LoadError("devices CSV 有 eth/eth_spx/spx，但 global 缺少 switches.eth.version")
        expected["eth"] = f"cumulus-linux-{version}-mlx-amd64.bin"
    for kind in ("ib", "nvl"):
        if kind not in image_device_types:
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
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LoadError(f"无法读取镜像：{path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise LoadError(f"镜像必须是普通文件，不允许符号链接或其他文件类型：{path}")
    if metadata.st_size < 1024 * 1024:
        raise LoadError(f"镜像过小或为空：{path}（{metadata.st_size} 字节）")
    with path.open("rb") as stream:
        if stream.read(9) != b"#!/bin/sh":
            raise LoadError(f"镜像头无效（预期 self-extracting shell）：{path}")


def _image_has_payload(path: Path, expected_name: str) -> bool:
    """Return whether an exact candidate is populated; reject unsafe path types."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise LoadError(f"无法检查镜像候选：{path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise LoadError(f"镜像必须是普通文件，不允许符号链接或其他文件类型：{path}")
    if metadata.st_size == 0:
        return False
    validate_image(path, expected_name)
    return True


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(4 * 1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _stable_regular_bytes(
    path: Path, label: str, *, maximum_size: int,
    required_uid: int | None = None, exact_mode: int | None = None,
) -> tuple[bytes, os.stat_result]:
    """Read one trust anchor without following or racing its pathname."""
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        direct = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or before.st_size > maximum_size
            or before.st_mode & 0o022
            or (required_uid is not None and before.st_uid != required_uid)
            or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
            or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
        ):
            raise LoadError(f"{label} 必须是安全的 single-link 普通文件：{path}")
        remaining = before.st_size
        blocks: list[bytes] = []
        while remaining:
            block = os.read(descriptor, min(remaining, 4 * 1024 * 1024))
            if not block:
                raise LoadError(f"{label} 在读取时被截断：{path}")
            blocks.append(block)
            remaining -= len(block)
        if os.read(descriptor, 1):
            raise LoadError(f"{label} 在读取时增长：{path}")
        after = os.fstat(descriptor)
        current = os.lstat(path)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if any(
            getattr(before, field) != getattr(after, field)
            for field in identity_fields
        ) or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino):
            raise LoadError(f"{label} 在读取期间发生变化：{path}")
        return b"".join(blocks), before
    except OSError as exc:
        raise LoadError(f"无法安全读取{label}：{path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _stable_regular_identity(
    path: Path, label: str, *, maximum_size: int | None = None,
    required_uid: int | None = None, exact_mode: int | None = None,
    allow_writable: bool = False,
) -> dict[str, object]:
    """Hash a regular file through one stable descriptor."""
    descriptor = -1
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        direct = os.lstat(path)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_size <= 0
            or (not allow_writable and before.st_mode & 0o022)
            or (maximum_size is not None and before.st_size > maximum_size)
            or (required_uid is not None and before.st_uid != required_uid)
            or (exact_mode is not None and stat.S_IMODE(before.st_mode) != exact_mode)
            or (before.st_dev, before.st_ino) != (direct.st_dev, direct.st_ino)
        ):
            raise LoadError(f"{label} 必须是安全的 single-link 普通文件：{path}")
        digest = hashlib.sha256()
        total = 0
        while True:
            block = os.read(descriptor, 4 * 1024 * 1024)
            if not block:
                break
            digest.update(block)
            total += len(block)
        after = os.fstat(descriptor)
        current = os.lstat(path)
        identity_fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            total != before.st_size
            or any(
                getattr(before, field) != getattr(after, field)
                for field in identity_fields
            )
            or (current.st_dev, current.st_ino) != (before.st_dev, before.st_ino)
        ):
            raise LoadError(f"{label} 在读取期间发生变化：{path}")
        return {"sha256": digest.hexdigest(), "size": before.st_size}
    except OSError as exc:
        raise LoadError(f"无法安全读取{label}：{path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _reject_duplicate_receipt_keys(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise LoadError(f"共享制品 receipt 重复 JSON key：{key}")
        value[key] = item
    return value


def _shared_receipt_target(value: object) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise LoadError("共享制品 receipt target 非法")
    parts = PurePosixPath(value).parts
    if (
        PurePosixPath(value).is_absolute()
        or not parts
        or parts[0] not in {"image", "apps", "firmware"}
        or any(part in {"", ".", ".."} for part in parts)
        or "/".join(parts) != value
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        raise LoadError("共享制品 receipt target 非法")
    return value


def _parse_shared_artifact_receipt(payload: bytes) -> dict[str, object]:
    try:
        value = json.loads(
            payload.decode("ascii"), object_pairs_hook=_reject_duplicate_receipt_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"共享制品 receipt JSON 非法：{exc}") from exc
    expected = {
        "archive_sha256", "artifact_type", "artifacts", "metadata_sha256",
        "project", "schema_version", "selection",
    }
    digest_pattern = re.compile(r"^[0-9a-f]{64}$")
    if (
        not isinstance(value, dict)
        or set(value) != expected
        or value.get("artifact_type") != "http-ztp-shared-artifact-receipt"
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
        or not isinstance(value.get("project"), str)
        or not value["project"]
        or "/" in value["project"]
        or "\\" in value["project"]
        or any(
            ord(character) < 32 or ord(character) == 127
            for character in value["project"]
        )
        or not isinstance(value.get("archive_sha256"), str)
        or not digest_pattern.fullmatch(value["archive_sha256"])
        or not isinstance(value.get("metadata_sha256"), str)
        or not digest_pattern.fullmatch(value["metadata_sha256"])
        or not isinstance(value.get("selection"), dict)
        or not isinstance(value.get("artifacts"), list)
        or not value["artifacts"]
        or len(value["artifacts"]) > SHARED_ARTIFACT_RECEIPT_MAX_ENTRIES
    ):
        raise LoadError("共享制品 receipt schema 非法")
    selection = value["selection"]
    if (
        set(selection) != {
            "deployment_scope", "inputs", "mini", "mini_input",
            "switch_scope", "upgrade_policy",
        }
        or selection.get("deployment_scope") not in {"all", "prod", "air"}
        or selection.get("switch_scope") not in {"all", "eth", "ib", "nvl"}
        or selection.get("upgrade_policy") not in {"enabled", "disabled"}
        or not isinstance(selection.get("mini"), bool)
        or selection.get("mini_input") is not None
        and not isinstance(selection.get("mini_input"), str)
        or not isinstance(selection.get("inputs"), dict)
        or len(selection["inputs"]) not in {2, 3}
    ):
        raise LoadError("共享制品 receipt selection 非法")
    for name, identity in selection["inputs"].items():
        if (
            not isinstance(name, str) or not name
            or "/" in name or "\\" in name
            or any(
                ord(character) < 32 or ord(character) == 127
                for character in name
            )
            or not isinstance(identity, dict)
            or set(identity) != {"sha256", "size"}
            or not isinstance(identity.get("sha256"), str)
            or not digest_pattern.fullmatch(identity["sha256"])
            or type(identity.get("size")) is not int
            or identity["size"] <= 0
        ):
            raise LoadError("共享制品 receipt 输入身份非法")
    base_inputs = {"01-global.yaml", "02-devices_config.csv"}
    if selection["mini"]:
        mini_name = selection["mini_input"]
        if (
            selection["deployment_scope"] != "air"
            or selection["switch_scope"] != "eth"
            or not isinstance(mini_name, str)
            or not mini_name
            or "/" in mini_name or "\\" in mini_name
            or set(selection["inputs"]) != base_inputs | {mini_name}
        ):
            raise LoadError("共享制品 receipt mini selection 非法")
    elif (
        selection["mini_input"] is not None
        or set(selection["inputs"]) != base_inputs
    ):
        raise LoadError("共享制品 receipt 输入集合非法")
    if (
        selection["deployment_scope"] == "air"
        and selection["switch_scope"] != "eth"
    ):
        raise LoadError("共享制品 receipt AIR 范围必须选择 eth")
    seen_targets: set[str] = set()
    seen_families: set[str] = set()
    allowed_families = (
        {"eth", "ib", "nvl"}
        if selection["switch_scope"] == "all"
        else {selection["switch_scope"]}
    )
    apps_platforms = {
        "ubuntu-22.04/amd64", "ubuntu-22.04/arm64",
        "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
    }
    for artifact in value["artifacts"]:
        if (
            not isinstance(artifact, dict)
            or set(artifact) != {
                "consumers", "kind", "platform", "sha256", "size", "target",
            }
            or artifact.get("kind") not in {"switch-image", "apps", "firmware"}
            or not isinstance(artifact.get("consumers"), list)
            or not isinstance(artifact.get("sha256"), str)
            or not digest_pattern.fullmatch(artifact["sha256"])
            or type(artifact.get("size")) is not int
            or artifact["size"] <= 0
            or artifact["size"] > SHARED_ARTIFACT_MAX_BYTES
        ):
            raise LoadError("共享制品 receipt artifact 非法")
        target = _shared_receipt_target(artifact.get("target"))
        if target in seen_targets:
            raise LoadError("共享制品 receipt 包含重复 target")
        seen_targets.add(target)
        consumers = []
        for consumer in artifact["consumers"]:
            if (
                not isinstance(consumer, dict)
                or set(consumer) != {"family", "version"}
                or consumer.get("family") not in {"eth", "ib", "nvl"}
                or not isinstance(consumer.get("version"), str)
                or not re.fullmatch(
                    r"[0-9]+(?P<separator>[.-])[0-9]+(?P=separator)[0-9]+",
                    consumer["version"],
                )
            ):
                raise LoadError("共享制品 receipt consumer/版本非法")
            consumers.append((consumer["family"], consumer["version"]))
        if consumers != sorted(set(consumers)):
            raise LoadError("共享制品 receipt consumer 必须排序且不可重复")
        if artifact["kind"] == "switch-image" and (
            not consumers or not target.startswith("image/")
            or artifact.get("platform") is not None
        ):
            raise LoadError("共享制品 receipt switch-image 非法")
        target_parts = PurePosixPath(target).parts
        if artifact["kind"] == "switch-image":
            if len(target_parts) != 2:
                raise LoadError("共享制品 receipt switch-image target 非法")
            for family, version in consumers:
                normalized = version.replace(".", "-")
                accepted = (
                    {f"cumulus-linux-{version}-mlx-amd64.bin"}
                    if family == "eth" else {
                        f"nvosv{normalized}amd64.bin",
                        f"nvos-amd64-{normalized.replace('-', '.')}.bin",
                    }
                )
                if target_parts[1] not in accepted:
                    raise LoadError("共享制品 receipt 镜像文件名与 consumer/版本不一致")
                if family not in allowed_families or family in seen_families:
                    raise LoadError("共享制品 receipt consumer 与 switch scope 冲突")
                seen_families.add(family)
        elif consumers:
            raise LoadError("共享制品 receipt 非镜像 artifact 不得声明 consumer")
        elif artifact["kind"] == "apps":
            platform_name = artifact.get("platform")
            if (
                target_parts[0] != "apps"
                or len(target_parts) < 4
                or platform_name not in apps_platforms
                or "/".join(target_parts[1:3]) != platform_name
            ):
                raise LoadError("共享制品 receipt apps artifact 非法")
        elif (
            target_parts[0] != "firmware"
            or len(target_parts) < 2
            or artifact.get("platform") is not None
        ):
            raise LoadError("共享制品 receipt firmware artifact 非法")
    if selection["upgrade_policy"] == "disabled" and seen_families:
        raise LoadError("共享制品 receipt no-upgrade 不得包含交换机镜像")
    return value


def validate_shared_artifact_receipts(
    project: Path, inputs: ProjectInputs, images: dict[str, Path], *,
    upgrade_enabled: bool, root: Path = HTTP_ROOT,
) -> Path | None:
    """Bind receipt-managed switch images to this exact load selection.

    A deployment that predates shared bundles remains supported when the
    receipt namespace is absent.  Once a selected image is named by a receipt,
    however, at least one receipt must match the current project inputs,
    selection, family/version, and live payload bytes.
    """
    if not upgrade_enabled or not images:
        return None
    receipt_dir = root / SHARED_ARTIFACT_RECEIPT_DIR
    try:
        root_status = root.lstat()
        directory_status = receipt_dir.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise LoadError(f"无法检查共享制品 receipt 目录：{exc}") from exc
    if (
        not stat.S_ISDIR(root_status.st_mode)
        or stat.S_ISLNK(root_status.st_mode)
        or root.resolve(strict=True) != root.absolute()
        or root_status.st_uid != os.geteuid()
        or stat.S_IMODE(root_status.st_mode) != 0o755
    ):
        raise LoadError("共享制品 live root 不安全")
    if (
        not stat.S_ISDIR(directory_status.st_mode)
        or stat.S_ISLNK(directory_status.st_mode)
        or directory_status.st_uid != root_status.st_uid
        or stat.S_IMODE(directory_status.st_mode) != 0o755
    ):
        raise LoadError("共享制品 receipt 目录不安全")
    receipts: list[tuple[Path, dict[str, object]]] = []
    try:
        entries = sorted(receipt_dir.iterdir(), key=lambda item: item.name)
    except OSError as exc:
        raise LoadError(f"无法枚举共享制品 receipt：{exc}") from exc
    if not entries:
        raise LoadError("共享制品 receipt 目录为空")
    if len(entries) > SHARED_ARTIFACT_RECEIPT_MAX_ENTRIES:
        raise LoadError("共享制品 receipt 数量超过安全上限")
    for path in entries:
        if not re.fullmatch(r"[0-9a-f]{64}\.json", path.name):
            raise LoadError(f"共享制品 receipt 文件名非法：{path.name}")
        payload, _status = _stable_regular_bytes(
            path, "共享制品 receipt",
            maximum_size=SHARED_ARTIFACT_RECEIPT_MAX_BYTES,
            required_uid=root_status.st_uid, exact_mode=0o600,
        )
        receipt = _parse_shared_artifact_receipt(payload)
        if path.stem != receipt["archive_sha256"]:
            raise LoadError("共享制品 receipt 文件名与 archive SHA 不一致")
        receipts.append((path, receipt))

    expected_input_paths = {
        inputs.global_file.name: inputs.global_file,
        inputs.devices_file.name: inputs.devices_file,
    }
    mini_input = inputs.mini_source_file or inputs.mini_devices_file
    if mini_input is not None:
        try:
            if stat.S_ISLNK(mini_input.lstat().st_mode):
                mini_input = inputs.mini_devices_file
        except OSError as exc:
            raise LoadError(f"无法检查共享制品 mini 输入：{exc}") from exc
        if mini_input is None:
            raise LoadError("共享制品 mini 输入缺少 canonical 文件")
        expected_input_paths[mini_input.name] = mini_input
    expected_inputs = {
        name: _stable_regular_identity(
            path, f"共享制品绑定输入 {name}",
            maximum_size=64 * 1024 * 1024,
        )
        for name, path in expected_input_paths.items()
    }
    expected_selection = {
        "deployment_scope": inputs.deployment_scope,
        "inputs": expected_inputs,
        "mini": mini_input is not None,
        "mini_input": mini_input.name if mini_input is not None else None,
        "switch_scope": inputs.switch_scope,
        "upgrade_policy": "enabled",
    }
    selected_targets = {
        family: f"image/{path.name}" for family, path in images.items()
    }
    expected_versions = {
        family: str(inputs.settings.versions.get(family) or "").replace("-", ".")
        for family in images
    }
    relevant = []
    for path, receipt in receipts:
        artifacts = receipt["artifacts"]
        if any(
            artifact["target"] in selected_targets.values()
            or any(
                consumer["family"] in expected_versions
                and consumer["version"].replace("-", ".")
                == expected_versions[consumer["family"]]
                for consumer in artifact["consumers"]
            )
            for artifact in artifacts
        ):
            relevant.append((path, receipt))
    if not relevant:
        return None

    identity_cache: dict[str, dict[str, object]] = {}
    expected_artifacts: dict[str, dict[str, object]] = {}
    for family, target in selected_targets.items():
        identity = identity_cache.get(target)
        if identity is None:
            identity = _stable_regular_identity(
                root / target, f"共享制品镜像 {family}",
                required_uid=root_status.st_uid, exact_mode=0o644,
            )
            identity_cache[target] = identity
        record = expected_artifacts.setdefault(target, {
            "consumers": [],
            "kind": "switch-image",
            "platform": None,
            "sha256": identity["sha256"],
            "size": identity["size"],
            "target": target,
        })
        record["consumers"].append({
            "family": family,
            "version": expected_versions[family],
        })
    for record in expected_artifacts.values():
        record["consumers"].sort(key=lambda item: (item["family"], item["version"]))
    expected_switch_authority = sorted(
        expected_artifacts.values(), key=lambda item: item["target"],
    )
    matching_receipts: list[Path] = []
    for path, receipt in relevant:
        if (
            receipt["project"] != project.name
            or receipt["selection"] != expected_selection
        ):
            continue
        actual_switch_authority = []
        for artifact in receipt["artifacts"]:
            if artifact["kind"] != "switch-image":
                continue
            normalized = dict(artifact)
            normalized["consumers"] = sorted(
                [
                    {
                        "family": item["family"],
                        "version": item["version"].replace("-", "."),
                    }
                    for item in artifact["consumers"]
                ],
                key=lambda item: (item["family"], item["version"]),
            )
            actual_switch_authority.append(normalized)
        actual_switch_authority.sort(key=lambda item: item["target"])
        if actual_switch_authority == expected_switch_authority:
            matching_receipts.append(path)
    if not matching_receipts:
        raise LoadError(
            "共享制品 receipt 与当前项目、部署范围、输入、镜像 hash/大小或 consumer/版本不一致"
        )
    selected_receipt = sorted(matching_receipts)[0]
    ok(f"共享制品 receipt 与当前 load 输入及镜像身份一致：{selected_receipt.name}")
    return selected_receipt


def prepare_images(
    project: Path, expected: dict[str, str], *, dry_run: bool = False, quiet: bool = False,
) -> dict[str, Path]:
    expected_names = {
        candidate
        for filename in expected.values()
        for candidate in _image_filename_candidates(filename)
    }
    project_bins = sorted(project.glob("*.bin"))
    # Preserve zero-byte files in historical customer projects, but do not use
    # them as image payloads or create any new placeholders.
    errors = []
    unexpected = []
    for item in project_bins:
        try:
            metadata = item.lstat()
        except OSError as exc:
            errors.append(f"无法检查项目镜像：{item}: {exc}")
            continue
        if not stat.S_ISREG(metadata.st_mode):
            errors.append(f"镜像必须是普通文件，不允许符号链接或其他文件类型：{item}")
            continue
        if item.name not in expected_names and metadata.st_size > 0:
            unexpected.append(item.name)
    if unexpected:
        errors.append(
            "项目镜像不符合当前 global/device type："
            + ", ".join(unexpected)
            + f"；期望：{', '.join(sorted(expected_names)) or 'none'}"
        )
    resolved: dict[str, Path] = {}
    copy_pairs: dict[Path, Path] = {}
    resolution_cache: dict[str, tuple[Path, bool]] = {}
    for kind, filename in expected.items():
        cached = resolution_cache.get(filename)
        if cached is not None:
            resolved[kind] = cached[0]
            continue
        candidate_names = _image_filename_candidates(filename)
        try:
            payloads: list[tuple[str, str, Path]] = []
            for candidate in candidate_names:
                for origin, root in (("project", project), ("shared", IMAGE_DIR)):
                    path = root / candidate
                    if not _image_has_payload(path, candidate):
                        continue
                    payloads.append((candidate, origin, path))
            if not payloads:
                if len(candidate_names) == 1:
                    message = f"缺少 {kind} {candidate_names[0]}"
                else:
                    message = (
                        f"缺少 {kind} NVOS 镜像：接受 " + " 或 ".join(candidate_names)
                    )
                shared_candidates = " 或 ".join(
                    f"image/{candidate}" for candidate in candidate_names
                )
                raise LoadError(
                    message + f"；请将真实升级镜像放到共享 {IMAGE_DIR}/：{shared_candidates}"
                )
            if len(payloads) > 1:
                fingerprints: dict[tuple[int, str], list[tuple[str, str, Path]]] = {}
                for candidate, origin, path in payloads:
                    fingerprint = (path.stat().st_size, _sha256(path))
                    fingerprints.setdefault(fingerprint, []).append((candidate, origin, path))
                if len(fingerprints) > 1:
                    sources = ", ".join(
                        f"{origin}:{candidate}" for candidate, origin, _path in payloads
                    )
                    raise LoadError(
                        f"{kind} 同一版本存在内容不同的镜像别名：{sources}"
                    )

            selected: Path | None = None
            project_has_payload = any(origin == "project" for _name, origin, _path in payloads)
            for candidate in candidate_names:
                shared_image = IMAGE_DIR / candidate
                project_image = project / candidate
                if any(path == shared_image for _name, _origin, path in payloads):
                    selected = shared_image
                    break
                if any(path == project_image for _name, _origin, path in payloads):
                    copy_pairs[shared_image] = project_image
                    # A dry-run must validate the existing source.  The shared
                    # destination is only a projected path until the real copy.
                    selected = project_image if dry_run else shared_image
                    break
            assert selected is not None
            resolved[kind] = selected
            resolution_cache[filename] = (selected, project_has_payload)
        except LoadError as exc:
            errors.append(str(exc))
    if errors:
        raise LoadError("镜像检查失败：\n  - " + "\n  - ".join(errors))
    if copy_pairs and not dry_run:
        IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    for shared_image, project_image in copy_pairs.items():
        if not quiet:
            print(f"[IMAGE] {project_image} → {shared_image}")
        if not dry_run:
            shutil.copy2(project_image, shared_image)
    for kind, filename in expected.items():
        _selected, project_has_payload = resolution_cache[filename]
        if not project_has_payload:
            if not quiet:
                info(f"使用共享升级镜像：image/{resolved[kind].name}")
    return resolved


def active_project() -> Path | None:
    """The project DAY0-Prepare/activate-project selects (R-016 §5.1); None without a pointer."""
    try:
        return active_project_dir(HTTP_ROOT)
    except ActiveProjectPointerError as exc:
        raise LoadError(f"活动项目指针无效：{exc}") from exc


def sync_marker_present(path: Path) -> bool:
    """Fail closed for regular, special, symlink, and broken-symlink markers."""
    return os.path.lexists(path)


def activate_project(
    project: Path, p2p_file: Path, *, strict: bool = True, dry_run: bool = False,
    deployment_lock_descriptor: int | None = None,
    host_role: str | None = None,
    switch_scope: str = "all",
    no_upgrade: bool = False,
) -> None:
    host_role = resolve_host_role(host_role)
    try:
        current = active_project()
    except LoadError as exc:
        # setup re-points DAY0-Prepare/activate-project; an invalid one is repaired, not fatal here.
        # main already refused the non-link one setup cannot switch (review 5 A1).
        warn(f"{exc}；setup 将重建指针")
        current = None
    if current == project:
        mode = "严格" if strict else "配置准备/no-upgrade（跳过部署门禁）"
        info(f"当前活动项目就是目标项目；重新执行{mode} setup 以检查并修复全部链接")
    elif current:
        info(f"活动项目将从 {current.name} 切换到 {project.name}")
    else:
        info(f"当前没有有效活动项目；将激活 {project.name}")
    command = [
        sys.executable, str(SETUP_SCRIPT), "-y", "--confirm-project-switch",
    ]
    if strict:
        command.append("--strict")
    if no_upgrade:
        command.append("--no-upgrade")
    selected_switch = str(switch_scope or "all").strip().casefold()
    if selected_switch not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    if selected_switch != "all":
        command.append(f"--switch={selected_switch}")
    try:
        p2p_argument = p2p_file.relative_to(project).as_posix()
    except ValueError as exc:
        raise LoadError(f"P2P 文件不在项目目录内：{p2p_file}") from exc
    # A nonempty legacy canonical is migrated by setup's no-override path.
    # Passing it as an explicit pin would point at a name moved by the rescue.
    # The user's own p2p.xlsx -> p2p/<workbook> link (R-014 第 3 条) is followed
    # by setup itself; explicit pins stay root-local basenames (REQ-15).
    if (
        (p2p_argument != "p2p.xlsx" or p2p_file.is_symlink())
        and not p2p_argument.startswith("p2p/")
    ):
        command.append(f"--p2p-file={p2p_argument}")
    command.append(str(project))
    server_delegated_setup = host_role == "management-server"
    command.insert(-1, f"--host-role={host_role}")
    if server_delegated_setup and not dry_run and deployment_lock_descriptor is None:
        raise LoadError("server load invoking setup requires the inherited deployment lock FD")
    run(
        command, cwd=HERE, dry_run=dry_run,
        inherited_lock_descriptor=deployment_lock_descriptor,
        setup_key_context=server_delegated_setup,
    )
    if not dry_run and active_project() != project:
        raise LoadError("01-a-setup.py 返回成功，但 DAY0-Prepare/activate-project 未指向目标项目")
    if not dry_run:
        canonical = project / "p2p.xlsx"
        if not canonical.is_symlink():
            raise LoadError("setup 后 p2p.xlsx 不是项目根目录相对链接")
        try:
            selected = select_upload_p2p(project)
        except ValueError as exc:
            raise LoadError(f"setup 后 P2P 链接无效：{exc}") from exc
        if _sha256_path(selected) != _sha256_path(p2p_file):
            raise LoadError("setup 后 P2P 选定内容与预检内容不一致")


def _runtime_interface_names(raw_value: str) -> tuple[str, ...]:
    """Parse one operator-scoped interface setting without inventing NIC roles."""
    return tuple(dict.fromkeys(
        value for value in re.split(r"[,\s]+", str(raw_value or "").strip())
        if value
    ))


def service_runtime_backend(
    environment=None, *, command_runner=None,
) -> ServiceRuntimeBackend:
    """Resolve exactly one supported runtime; unknown values fail before mutation."""
    try:
        return runtime_backend_from_environment(
            os.environ if environment is None else environment,
            command_runner=command_runner,
        )
    except RuntimeContractError as exc:
        raise LoadError(f"服务运行后端无效：{exc}") from exc


def validate_runtime_options(
    args: argparse.Namespace, runtime_backend: ServiceRuntimeBackend,
) -> None:
    """Keep container execution out of the host-systemd infra lifecycle."""
    if runtime_backend.name == "supervisor" and not args.skip_infra:
        raise LoadError(
            "Supervisor/container backend 必须使用 --skip-infra；"
            "请由 infra/docker/deploy.sh 管理容器依赖，不能在容器内运行 host infra setup"
        )


def _local_ip_json_snapshots(*, command_runner=None) -> tuple[object, object]:
    """Capture the Linux link/address records consumed by the DHCP planner."""
    runner = command_runner or _run_subprocess
    snapshots = []
    for label, command in (
        ("link", ["ip", "-d", "-j", "link", "show"]),
        ("IPv4 address", ["ip", "-j", "-4", "address", "show"]),
    ):
        try:
            result = runner(
                command, capture_output=True, text=True, check=False,
            )
        except OSError as exc:
            raise LoadError(f"无法读取本机 {label} JSON：{exc}") from exc
        if result.returncode != 0:
            detail = str(result.stderr or "").strip()
            raise LoadError(
                f"无法读取本机 {label} JSON（exit={result.returncode}）"
                + (f"：{detail}" if detail else "")
            )
        snapshots.append(result.stdout)
    return snapshots[0], snapshots[1]


def plan_local_dhcp_runtime(
    inputs: ProjectInputs, *, environment=None,
    link_snapshot=None, address_snapshot=None, command_runner=None,
) -> DhcpRuntimePlan:
    """Derive the exact 0..N DHCP listeners from CSV plus live Linux state.

    The two optional interface environment variables are restrictions only;
    neither can create a listener which the project rows and live addresses do
    not justify.  No Global/CSV schema extension is involved.
    """
    if (link_snapshot is None) != (address_snapshot is None):
        raise LoadError("DHCP listener 规划必须同时提供 link/address 快照")
    if not inputs.settings.dhcp_enabled:
        # External DHCP may still use fully validated address data, but it
        # must not require or authorize this project's relay/listener plan.
        validate_subnet_file(inputs.subnet_file, inputs.settings)
        info("DHCP 已禁用；CSV 已校验，本地 listener 规划为 0")
        return DhcpRuntimePlan((), (), (), (), (), ())
    if link_snapshot is None:
        link_snapshot, address_snapshot = _local_ip_json_snapshots(
            command_runner=command_runner,
        )
    source = os.environ if environment is None else environment
    allowlist = _runtime_interface_names(
        source.get(DHCP_INTERFACE_ALLOWLIST_ENV, "")
    )
    relay_ingress = _runtime_interface_names(
        source.get(DHCP_RELAY_INGRESS_ENV, "")
    )
    try:
        plan = plan_dhcp_runtime(
            inputs.subnet_file,
            link_snapshot=link_snapshot,
            address_snapshot=address_snapshot,
            allowlist=allowlist,
            relay_ingress=relay_ingress,
            dhcp_enabled=inputs.settings.dhcp_enabled,
            ztp_enabled=inputs.settings.ztp_enabled,
        )
    except RuntimeContractError as exc:
        raise LoadError(f"DHCP listener 动态规划失败：{exc}") from exc
    if plan.listener_names:
        ok(
            "DHCP listener 动态规划通过："
            + ", ".join(
                f"{name}(ifindex={ifindex})" for name, ifindex in zip(
                    plan.listener_names, plan.listener_ifindexes,
                )
            )
        )
    else:
        info("DHCP listener 动态规划结果为 0；DHCP 必须保持停止")
    return plan


def _runtime_service_active(
    runtime_backend: ServiceRuntimeBackend, service: str,
) -> bool:
    try:
        return runtime_backend.is_active(service)
    except (RuntimeContractError, OSError) as exc:
        raise LoadError(f"无法检查服务 {service}：{exc}") from exc


def _runtime_service_action(
    runtime_backend: ServiceRuntimeBackend, action: str, service: str,
    *, dry_run: bool = False,
) -> None:
    if dry_run:
        print(f"[DRY] {runtime_backend.name} {action} {service}")
        return
    try:
        getattr(runtime_backend, action)(service)
    except RuntimeContractError as exc:
        raise LoadError(
            f"{runtime_backend.name} {action} {service} 失败：{exc}"
        ) from exc


def active_managed_services(
    runtime_backend: ServiceRuntimeBackend | None = None,
    *, host_role: str | None = None,
    _native_preinstall_absence: bool = False,
) -> tuple[str, ...]:
    """Return units not proven safely stopped; this is not a health predicate."""
    if type(_native_preinstall_absence) is not bool:
        raise LoadError("invalid native preinstall presence policy")
    host_role = resolve_host_role(host_role)
    if host_role != "management-server":
        if _native_preinstall_absence:
            raise LoadError("native preinstall presence policy requires management-server")
        return ()
    backend = runtime_backend or service_runtime_backend()
    if _native_preinstall_absence and type(backend) is not SystemdRuntimeBackend:
        raise LoadError("native preinstall presence policy requires systemd backend")
    services = (SUPERVISOR_QUIESCE_SERVICES if backend.name == "supervisor"
                else ("isc-dhcp-server", "apache2"))
    predicate = getattr(backend, "is_quiesced", None)
    if not callable(predicate):
        raise LoadError("无法检查服务：backend has no stopped-state authority")
    pending = []
    for service in services:
        try:
            if _native_preinstall_absence:
                unit_state = backend.read_unit_state(service)
                if unit_state.load_state == "not-found":
                    continue
                stopped = unit_state.loaded_quiescent()
            else:
                stopped = predicate(service)
        except (RuntimeContractError, OSError) as exc:
            raise LoadError(f"无法检查服务 {service}：{exc}") from exc
        if type(stopped) is not bool:
            raise LoadError(f"无法检查服务 {service}：invalid stopped-state authority")
        if not stopped:
            pending.append(service)
    return tuple(pending)


def require_artifact_builder_services_inactive(
    dry_run: bool = False, *,
    runtime_backend: ServiceRuntimeBackend | None = None,
    host_role: str | None = None,
) -> None:
    """Never stop unrelated live services for a configuration-only Linux run."""
    if dry_run:
        return
    active = active_managed_services(runtime_backend, host_role=host_role)
    if active:
        raise LoadError(
            "本机不具备当前项目 service_ip，且以下服务正在运行："
            + ", ".join(active)
            + "；为避免中断现有服务或在运行中切换项目链接，配置准备已在修改前拒绝。"
            "请改在独立工作目录/主机生成，或由操作员先明确停止这些服务"
        )
    ok("本机不具备当前项目 service_ip，且 Apache/DHCP 均未运行；可以只生成制品")


def quiesce_services(
    dry_run: bool = False, *, inputs: ProjectInputs | None = None,
    dhcp_runtime_plan: DhcpRuntimePlan | None = None,
    runtime_backend: ServiceRuntimeBackend | None = None,
    native_monitor_already_quiesced: bool = False,
    link_snapshot=None, address_snapshot=None,
    host_role: str | None = None,
    _native_preinstall_absence: bool = False,
    _native_http_only_inputs: ProjectInputs | None = None,
) -> DhcpRuntimePlan | None:
    """Stop services before changing project links; failed loads remain safely stopped."""
    if type(_native_preinstall_absence) is not bool:
        raise LoadError("invalid native preinstall presence policy")
    host_role = resolve_host_role(host_role)
    if _native_http_only_inputs is not None and (
            type(_native_http_only_inputs) is not ProjectInputs
            or host_role != "management-server" or dry_run
            or _native_preinstall_absence
            or not _explicit_http_only(_native_http_only_inputs.settings)):
        raise LoadError("invalid call-local native HTTP-only convergence target")
    if _native_preinstall_absence and (host_role != "management-server" or dry_run):
        raise LoadError("native preinstall presence policy requires real management-server")
    if host_role != "management-server":
        info("workstation 不管理 Apache/ISC DHCP，跳过旧服务状态检查")
        return None
    # This is deliberately the first executable gate in this function.  A
    # listener ambiguity must not stop even one currently healthy service.
    if inputs is not None and dhcp_runtime_plan is not None:
        raise LoadError(
            "quiesce_services 不能同时接收 inputs 和预生成 DHCP plan"
        )
    dhcp_plan = dhcp_runtime_plan
    if inputs is not None:
        dhcp_plan = plan_local_dhcp_runtime(
            inputs, link_snapshot=link_snapshot,
            address_snapshot=address_snapshot,
        )
    backend = runtime_backend or service_runtime_backend()
    if _native_preinstall_absence and type(backend) is not SystemdRuntimeBackend:
        raise LoadError("native preinstall presence policy requires systemd backend")
    if _native_http_only_inputs is not None and type(backend) is not SystemdRuntimeBackend:
        raise LoadError("optional ISC convergence requires systemd backend")
    presence_options = {"_native_preinstall_absence": True} if _native_preinstall_absence else {}
    if (
        backend.name == "systemd" and not dry_run
        and not native_monitor_already_quiesced
    ):
        stop_native_ztp_monitors(HTTP_ROOT)
    if backend.name == "systemd" and not shutil.which("systemctl"):
        if dry_run:
            info("未找到 systemctl，dry-run 不修改运行态")
            return dhcp_plan
        raise LoadError("未找到 systemctl，无法确认真实停服；HOLD")
    if _native_http_only_inputs is not None:
        _converge_native_http_only_services(
            _native_http_only_inputs, runtime_backend=backend,
        )
        return dhcp_plan
    active = list(active_managed_services(backend, host_role=host_role, **presence_options))
    if not active:
        ok("Apache/DHCP 当前均未运行，可以安全切换项目")
        return dhcp_plan
    warn(
        "切换/重建期间将停止正在运行的服务：" + ", ".join(active)
        + "；流程失败时保持停止，避免发布半成品"
    )
    for service in active:
        if backend.name == "systemd":
            run(sudo_command("systemctl", "stop", service), dry_run=dry_run)
        else:
            _runtime_service_action(
                backend, "stop", service, dry_run=dry_run,
            )
    if not dry_run:
        pending = active_managed_services(backend, host_role=host_role, **presence_options)
        if pending:
            raise LoadError("services not confirmed stopped; HOLD: " + ", ".join(pending))
    return dhcp_plan


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


def render_bootstrap_script_text(
    text: str, *, address: str, port: int, prefix: str,
    manual_urls: dict[str, str], upgrade_enabled: bool,
    key_names: tuple[str, ...] | list[str], eth_version: str | None,
    script_name: str,
) -> str:
    """Render one bootstrap without a filesystem side effect.

    The origin may contain a port; the route and reachability target must be
    the canonical host alone. Every required template slot is fail-closed.
    """
    endpoint = validate_service_endpoint(
        address, port, field=f"{script_name} ZTP service"
    )
    text, server_count = re.subn(
        r'^ZTP_SERVER="[^"]*"$',
        f'ZTP_SERVER="{service_url(endpoint, "", channel="bootstrap-origin")}"',
        text, count=1, flags=re.MULTILINE,
    )
    text, host_count = re.subn(
        r'^ZTP_SERVER_HOST="[^"]*"$', f'ZTP_SERVER_HOST="{endpoint.host}"',
        text, count=1, flags=re.MULTILINE,
    )
    text, prefix_count = re.subn(
        r'^ZTP_URL_PREFIX="[^"]*"$',
        f'ZTP_URL_PREFIX="{prefix}"', text, count=1,
        flags=re.MULTILINE,
    )
    text, manual_oob_count = re.subn(
        r'^MANUAL_ZTP_OOB_URL="[^"]*"$',
        f'MANUAL_ZTP_OOB_URL="{manual_urls.get("ztp-bootstrap_oob.sh", "")}"',
        text, count=1, flags=re.MULTILINE,
    )
    text, manual_oobofoob_count = re.subn(
        r'^MANUAL_ZTP_OOBOFOOB_URL="[^"]*"$',
        f'MANUAL_ZTP_OOBOFOOB_URL="{manual_urls.get("ztp-bootstrap_oobofoob.sh", "")}"',
        text, count=1, flags=re.MULTILINE,
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
        server_count != 1 or host_count != 1 or prefix_count != 1
        or manual_oob_count != 1 or manual_oobofoob_count != 1
        or upgrade_count != 1 or key_count != 1
    ):
        raise LoadError(
            f"无法安全更新 {script_name} 的服务器、手工 ZTP URL、升级开关或公钥参数"
        )
    if eth_version:
        text, version_count = re.subn(
            r'^TARGET_CL_VER="[^"]*"$',
            f'TARGET_CL_VER="{eth_version}"', text, count=1,
            flags=re.MULTILINE,
        )
        if version_count != 1:
            raise LoadError(f"无法安全更新 {script_name} 的 TARGET_CL_VER")
    return text


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
    http_endpoint = None
    if scripts or prod_oob_ips:
        if not settings.http_address:
            raise LoadError(
                "common.mgmt.http.address 必须显式指定独立的 HTTP 服务 IPv4"
            )
        try:
            http_endpoint = validate_service_endpoint(
                settings.http_address, settings.http_port,
                field="common.mgmt.http.address",
            )
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
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
    manual_urls = {}
    for filename, address in scripts:
        if filename == "ztp-bootstrap_oobofoob.sh":
            manual_urls[filename] = service_url(
                http_endpoint, f"/{filename}", prefix=settings.ztp_prefix,
                channel="bootstrap-manual-oobofoob",
            )
        else:
            manual_urls[filename] = service_url(
                http_endpoint, f"/{filename}", prefix=settings.ztp_prefix,
                channel="bootstrap-manual-oob",
            )
    for filename, address in scripts:
        script = ZTP_DIR / filename

        rendered = render_bootstrap_script_text(
            template_text, address=http_endpoint.host, port=settings.http_port,
            prefix=settings.ztp_prefix, manual_urls=manual_urls,
            upgrade_enabled=upgrade_enabled, key_names=key_names,
            eth_version=eth_version, script_name=script.name,
        )
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
            ping_hosts[0] = http_endpoint.host
            ztp["02-commands-list"]["url"] = (
                service_url(
                    http_endpoint, "/config/nvos/disable-password-hardening.nv",
                    prefix=settings.ztp_prefix, channel="nvos-commands-list",
                )
            )
            ztp["03-provisioning-script"]["url"] = (
                service_url(
                    http_endpoint, "/ztp-bootstrap_oob.sh",
                    prefix=settings.ztp_prefix, channel="nvos-provisioning",
                )
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
    if not settings.http_address:
        raise LoadError(
            "common.mgmt.http.address 必须显式指定独立的 HTTP 服务 IPv4；"
            "不得从 DHCP subnet 的 ztp_service_ip 推导"
        )
    try:
        return validate_service_endpoint(
            settings.http_address, field="common.mgmt.http.address",
        ).host
    except ValueError as exc:
        raise LoadError(str(exc)) from exc


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
    result = _run_subprocess(
        [lspci], text=True, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        check=False,
    )
    return "mellanox" in result.stdout.casefold()


def _resolve_infra_doca_action(skip_doca: bool, download_doca: bool) -> str:
    """Resolve the existing precedence once; no installation or new probe."""
    if skip_doca:
        return "skip"
    if download_doca:
        return "download"
    if not management_has_mellanox_nic():
        warn(
            "管理服务器未检测到 Mellanox/NVIDIA PCI 网卡；默认不下载或缓存 "
            "DOCA。若需要为其他离线客户端准备 DOCA，请重新执行并加 "
            "--download-doca。"
        )
        return "skip"
    return "default"


def prepare_infra(
    inputs: ProjectInputs,
    dry_run: bool = False,
    skip_doca: bool = False,
    download_doca: bool = False,
    *,
    _load_components: tuple[str, ...] | None = None,
    _resolved_doca_action: str | None = None,
) -> None:
    component_arguments: list[str] = []
    if _load_components is not None:
        try:
            packet = encode_load_components(_load_components)
        except ValueError as exc:
            raise LoadError("invalid LOAD component selection") from exc
        component_arguments = ["--load-components-v1", packet]
        # Finite input is data only; it cannot contradict real service flags.
        if (("http" in _load_components) != inputs.settings.http_enabled
                or ("dhcp" in _load_components) != inputs.settings.dhcp_enabled
                or ("ztp-runtime" in _load_components) != inputs.settings.ztp_enabled):
            raise LoadError("LOAD component/service mismatch")
    if _resolved_doca_action is not None and (
        type(_resolved_doca_action) is not str
        or _resolved_doca_action not in ("skip", "download", "default")
    ):
        raise LoadError("invalid resolved DOCA action")
    if _resolved_doca_action is not None and (
        (skip_doca and _resolved_doca_action != "skip")
        or (not skip_doca and download_doca and _resolved_doca_action != "download")
    ):
        raise LoadError("resolved DOCA action contradicts explicit choice")
    doca_action = _resolved_doca_action
    if _load_components is not None:
        if doca_action is None:
            doca_action = _resolve_infra_doca_action(skip_doca, download_doca)
        if ("doca" in _load_components) != (doca_action != "skip"):
            raise LoadError("LOAD component/DOCA mismatch")
    http_ip = select_http_ip(inputs.settings)
    run(
        [
            sys.executable, str(INFRA_DIR / "deploy_infra.py"), "--prepare-only",
            "--http-server-ip", http_ip,
            "--global-file", str(inputs.global_file),
            "--devices-file", str(inputs.devices_file),
            *component_arguments,
        ],
        cwd=INFRA_DIR,
        dry_run=dry_run,
    )
    # infra-setup.py only checks unless --apply.  Running load is the operator's authorization for
    # the local infra step, and load is non-interactive, so it applies with --yes; its own --dry-run
    # never executes this command.
    setup_command = sudo_command(
        sys.executable, "-B", str(INFRA_DIR / "infra-setup.py"), "--mgmt",
        "--defer-services", "--apply", "--yes",
    )
    # No packet/no resolved action keeps the original post-prepare probe order.
    if doca_action is None:
        doca_action = _resolve_infra_doca_action(skip_doca, download_doca)
    if doca_action == "skip":
        setup_command.append("--skip-doca")
    elif doca_action == "download":
        setup_command.append("--download-doca")
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
    setup_command.extend(component_arguments)
    run(
        setup_command,
        cwd=INFRA_DIR,
        dry_run=dry_run,
    )


def newest_directory(parent: Path, pattern: re.Pattern[str]) -> Path | None:
    candidates = [item for item in parent.iterdir() if item.is_dir() and pattern.fullmatch(item.name)]
    return max(candidates, key=lambda item: item.stat().st_mtime_ns) if candidates else None


def dhcp_file_mappings(source_directory: Path | None = None) -> dict[Path, Path]:
    dhcp_dir = source_directory or ZTP_DIR / "config/isc-dhcp-server"
    return {
        dhcp_dir / "dhcpd.conf": Path("/etc/dhcp/dhcpd.conf"),
        dhcp_dir / "dhcpd_eth.hosts": Path("/etc/dhcp/dhcpd_eth.hosts"),
        dhcp_dir / "dhcpd_ib.hosts": Path("/etc/dhcp/dhcpd_ib.hosts"),
        dhcp_dir / "dhcpd_nvl.hosts": Path("/etc/dhcp/dhcpd_nvl.hosts"),
    }


def _create_dhcp_candidate_dir(project: Path) -> Path:
    """Create one LOAD-owned private child without replacing a committed A."""
    canonical_project = project.resolve(strict=True)
    output = canonical_project / "99-output-dhcp"
    output.mkdir(mode=0o755, exist_ok=True)
    metadata = output.lstat()
    if (not stat.S_ISDIR(metadata.st_mode)
            or output.resolve(strict=True) != output):
        raise LoadError("DHCP output directory is not canonical")
    for _ in range(3):
        candidate = output / f".load-dhcp-candidate-{secrets.token_hex(16)}"
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise LoadError("cannot allocate a unique DHCP candidate directory")


def _validated_dhcp_candidate_dir(project: Path, candidate: Path) -> Path:
    """Require one complete, private c1 candidate under this project only."""
    canonical_project = project.resolve(strict=True)
    output = canonical_project / "99-output-dhcp"
    candidate_name = candidate.name
    if not re.fullmatch(r"\.load-dhcp-candidate-[A-Za-z0-9-]{8,64}", candidate_name):
        raise LoadError("DHCP candidate name is not LOAD-owned")
    try:
        output_stat = output.lstat()
        candidate_stat = candidate.lstat()
        if (not stat.S_ISDIR(output_stat.st_mode)
                or not stat.S_ISDIR(candidate_stat.st_mode)
                or stat.S_IMODE(candidate_stat.st_mode) != 0o700
                or candidate_stat.st_uid != os.geteuid()
                or candidate.resolve(strict=True) != output / candidate_name
                or candidate.parent.resolve(strict=True) != output):
            raise LoadError("DHCP candidate is not a private canonical project directory")
        names = {item.name for item in candidate.iterdir()}
        expected = {
            "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
            "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
        }
        if names != expected:
            raise LoadError("DHCP candidate does not contain exactly five artifacts")
        for name in expected:
            metadata = (candidate / name).lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LoadError(f"DHCP candidate artifact is not a regular single-link file: {name}")
    except LoadError:
        raise
    except OSError as exc:
        raise LoadError(f"DHCP candidate cannot be verified: {exc}") from exc
    return output / candidate_name


_DHCP_OUTPUT_NAMES = (
    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
    "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
)


def _discard_dhcp_candidate_dir(candidate: Path, identity: tuple[int, int]) -> None:
    """Remove an uncommitted LOAD candidate with DEV's discard rules (G22).

    Only single-link regular files are removed; anything else (a directory, a symlink,
    a hard link, a FIFO) is refused with "unexpected DHCP stage entry" and left in place
    as evidence instead of being swept by rmtree.
    """
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = os.open(candidate.parent, flags)
    try:
        stage_fd = os.open(candidate.name, flags, dir_fd=parent_fd)
        try:
            held = os.fstat(stage_fd)
            if (held.st_dev, held.st_ino) != identity:
                raise LoadError("private DHCP candidate identity changed before cleanup")
            for name in os.listdir(stage_fd):
                item = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                    raise LoadError(f"unexpected DHCP stage entry: {name}")
                os.unlink(name, dir_fd=stage_fd)
        finally:
            os.close(stage_fd)
        os.rmdir(candidate.name, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def publish_committed_dhcp_candidate(
    project: Path, candidate: Path, switch_scope: str,
) -> None:
    """Publish the validated candidate to the flat DHCP outputs, then delete it.

    T+ (agreed by http test and http dev, 2026-10-25): TEST's private candidate stays the
    authority up to the parent commit; after the commit the flat 99-output-dhcp files that
    activate.py, c1's scoped carry-over and 13-unload read must equal it (DEV G2), and a
    successful load leaves no candidate behind (DEV G20).  The publish/rollback/cleanup
    rules are DEV's DeferredDHCPOutput (G6-G9, G22): backup-name collision refused, prior
    outputs must be single-link regular files, a partial publish restores every replaced
    file, and cleanup refuses anything that is not a single-link regular file.  Called only
    after the parent release (and pinned generation) commit; a failure here leaves the
    committed release with the previous flat outputs and the candidate as HOLD evidence.
    """
    candidate = _validated_dhcp_candidate_dir(project, candidate)
    output = candidate.parent
    links = ZTP_DIR / "config/isc-dhcp-server"
    targets = {(links / name).resolve(strict=False).parent for name in _DHCP_OUTPUT_NAMES}
    if targets != {output}:
        raise LoadError("DHCP output links do not resolve to this project's 99-output-dhcp")
    if switch_scope == "all":
        names = _DHCP_OUTPUT_NAMES
    elif switch_scope in {"eth", "ib", "nvl"}:
        names = ("dhcpd.conf", f"dhcpd_{switch_scope}.hosts", "dhcp-release-manifest.json")
    else:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    parent_fd = os.open(output, flags)
    try:
        stage_fd = os.open(candidate.name, flags, dir_fd=parent_fd)
    except BaseException:
        os.close(parent_fd)
        raise
    expected_stage = candidate.lstat()

    def verify_visible() -> None:
        held = os.fstat(stage_fd)
        named = os.stat(candidate.name, dir_fd=parent_fd, follow_symlinks=False)
        if ((held.st_dev, held.st_ino) != (named.st_dev, named.st_ino)
                or (held.st_dev, held.st_ino) != (expected_stage.st_dev, expected_stage.st_ino)):
            raise LoadError("DHCP candidate directory changed")

    published: list[tuple[str, bool]] = []
    try:
        try:
            verify_visible()
            for name in names:
                try:
                    os.stat(f"backup-{name}", dir_fd=stage_fd, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    raise LoadError(f"DHCP backup name collision: {name}")
            for name in names:
                verify_visible()
                staged = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
                if not stat.S_ISREG(staged.st_mode) or staged.st_nlink != 1:
                    raise LoadError(f"unsafe DHCP candidate: {name}")
                try:
                    previous = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
                except FileNotFoundError:
                    previous = None
                if previous is not None and (
                        not stat.S_ISREG(previous.st_mode) or previous.st_nlink != 1):
                    raise LoadError(f"unsafe prior DHCP output: {name}")
                # The private candidate is 0600; the published file keeps the flat mode.
                mode = stat.S_IMODE(previous.st_mode) if previous is not None else 0o644
                descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC,
                                     dir_fd=stage_fd)
                try:
                    if (os.fstat(descriptor).st_dev, os.fstat(descriptor).st_ino) != (
                            staged.st_dev, staged.st_ino):
                        raise LoadError(f"DHCP candidate changed before publish: {name}")
                    os.fchmod(descriptor, mode)
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                if previous is not None:
                    os.replace(name, f"backup-{name}", src_dir_fd=parent_fd, dst_dir_fd=stage_fd)
                try:
                    os.replace(name, name, src_dir_fd=stage_fd, dst_dir_fd=parent_fd)
                except BaseException:
                    if previous is not None:
                        os.replace(f"backup-{name}", name, src_dir_fd=stage_fd, dst_dir_fd=parent_fd)
                    raise
                published.append((name, previous is not None))
                verify_visible()
            os.fsync(parent_fd)
        except BaseException:
            for name, existed in reversed(published):
                os.unlink(name, dir_fd=parent_fd)
                if existed:
                    os.replace(f"backup-{name}", name, src_dir_fd=stage_fd, dst_dir_fd=parent_fd)
            os.fsync(parent_fd)
            raise
        # Accept: the parent is already committed, so the backups and the candidate go.
        verify_visible()
        for name in os.listdir(stage_fd):
            item = os.stat(name, dir_fd=stage_fd, follow_symlinks=False)
            if not stat.S_ISREG(item.st_mode) or item.st_nlink != 1:
                raise LoadError(f"unexpected DHCP stage entry: {name}")
            os.unlink(name, dir_fd=stage_fd)
        os.rmdir(candidate.name, dir_fd=parent_fd)
        os.fsync(parent_fd)
    finally:
        os.close(stage_fd)
        os.close(parent_fd)
    ok("DHCP 候选已在父 release 提交后发布到 99-output-dhcp，候选目录已删除")


_UNFREEZABLE_CHANGED = "输入已改动"
_UNFREEZABLE_ABSENT = "来源已不存在"
_UNFREEZABLE_NOT_OWNED = "来源不是项目内的普通文件（经链接或多链接）"
_UNFREEZABLE_UNSAFE = "来源路径不安全"
_UNFREEZABLE_UNREADABLE = "来源无法读取"
_UNFREEZABLE_FORMAT = "旧 release 格式无法迁移"


class FlatParentUnfreezable(LoadError):
    """Per-source reasons why a committed flat parent cannot be frozen.

    Raised only for ``99-output-ztp/current-release.json`` (the pre-generation
    layout), after every source was examined.  ``findings`` holds
    ``(category, label)`` pairs such as ``("输入已改动", "inputs/global")``;
    the message is the first finding's.
    """

    def __init__(self, message: str, findings: tuple[tuple[str, str], ...]) -> None:
        super().__init__(message)
        self.findings = findings


class PinnedSourceChangedWhileReading(LoadError):
    """A pinned source changed identity during its read: a concurrent writer."""


def _user_linked_input_target(project: Path, key: str, relative: str) -> Path | None:
    """The real file behind a release input that is one of R-014 第 3 条's two user-link shapes, else None.

    ``02-devices_config.csv`` as the user's own link (read_project_input_links), or ``p2p/<workbook>`` reached
    through the user's ``p2p.xlsx -> p2p/<workbook>`` link where ``p2p/`` may link outside the project
    (project_p2p_user_link).  Both readers are the ones setup, packaging and sync use; every other input keeps
    the project-local regular-file contract (review 4 B1).
    """
    try:
        if key == "devices" and relative == "02-devices_config.csv":
            return next((item.real_path for item in read_project_input_links(project)
                         if item.name == relative), None)
        if (key == "p2p" and relative.startswith("p2p/")
                and project_p2p_user_link(project) == project / relative):
            return (project / relative).resolve(strict=True)
    except (OSError, ValueError, RuntimeError) as exc:
        raise LoadError(f"pinned input {key} user link is invalid: {exc}") from exc
    return None


def _pinned_generation_payloads(
    project: Path, parent_file: Path, dhcp_source_dir: Path | None,
) -> tuple[str, dict[str, bytes]]:
    """Freeze a schema-2 parent, its source inputs and bound DHCP child bytes."""
    canonical_project = project.resolve(strict=True)
    output = canonical_project / "99-output-ztp"
    parent_directory = parent_file.parent.resolve(strict=True)
    snapshot_directory = (
        parent_directory.parent == output / "generations"
        and bool(re.fullmatch(r"[0-9a-f]{20}", parent_directory.name))
    )
    # Only the committed flat parent collects per-source findings and reports
    # them together; generation snapshots and B candidates still fail at once.
    flat_parent = not snapshot_directory and parent_file.name == "current-release.json"
    findings: list[tuple[str, str, str]] = []
    source_name_valid = (
        parent_file.name == "current-release.json"
        or (parent_directory == output and bool(re.fullmatch(
            r"\.current-release\.[A-Za-z0-9_-]+\.tmp", parent_file.name,
        )))
    )
    if (parent_directory != output and not snapshot_directory
            or not source_name_valid
            or not stat.S_ISREG(parent_file.lstat().st_mode)
            or parent_file.lstat().st_nlink != 1):
        raise LoadError("pinned parent source is not an owned regular file")
    parent_bytes = parent_file.read_bytes()
    try:
        parent = json.loads(parent_bytes)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"pinned parent is not JSON: {exc}") from exc
    if not isinstance(parent, dict) or parent.get("schema_version") != 2:
        raise LoadError("pinned generation requires a schema 2 parent")
    release_id = parent.get("release_id")
    if not isinstance(release_id, str) or not re.fullmatch(r"[0-9a-f]{20}", release_id):
        raise LoadError("pinned parent release ID is invalid")
    if snapshot_directory and parent_directory.name != release_id:
        raise LoadError("pinned generation directory differs from parent ID")
    basis_keys = (
        "project", "deployment_scope", "switch_scope", "inputs",
        "input_sources", "components", "inventory", "dhcp_status",
    )
    if "generated_inputs" in parent:
        basis_keys += ("generated_inputs",)
    if "imported_configs" in parent:
        basis_keys += ("imported_configs",)
    if any(key not in parent for key in basis_keys):
        raise LoadError("pinned parent basis is incomplete")
    basis = {key: parent[key] for key in basis_keys}
    calculated = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]
    dhcp_status = parent.get("dhcp_status")
    if (calculated != release_id or parent.get("project") != canonical_project.name
            or dhcp_status not in {"enabled", "disabled"}
            or parent.get("validation") != "passed"):
        raise LoadError("pinned parent basis/project/DHCP does not match release ID")
    components = parent["components"]
    child = components.get("dhcp") if isinstance(components, dict) else None
    expected_manifest = None
    if dhcp_status == "enabled":
        expected_manifest = child.get("manifest_sha256") if isinstance(child, dict) else None
        if (not isinstance(expected_manifest, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected_manifest)
                or dhcp_source_dir is None):
            raise LoadError("pinned parent has no valid DHCP child binding")
        if snapshot_directory:
            if dhcp_source_dir.resolve(strict=True) != parent_directory / "dhcp":
                raise LoadError("pinned snapshot DHCP directory is not generation-local")
        else:
            flat = ZTP_DIR / "config/isc-dhcp-server"
            if dhcp_source_dir.resolve(strict=True) != flat.resolve(strict=True):
                dhcp_source_dir = _validated_dhcp_candidate_dir(project, dhcp_source_dir)
    elif child is not None or dhcp_source_dir is not None:
        raise LoadError("pinned DHCP-disabled parent must not bind a DHCP child")
    names = (
        "dhcp-release-manifest.json", "dhcpd.conf", "dhcpd_eth.hosts",
        "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
    )
    input_hashes = parent.get("inputs")
    fixed_sources = {
        "global": "01-global.yaml",
        "devices": "02-devices_config.csv",
        "subnet": "02-dhcp-subnet_config.csv",
        "air_topology_policy": "03-air-topology-policy.json",
        "mini_air_devices": "04-air-mini-devices.txt",
    }
    if (not isinstance(input_hashes, dict)
            or not {"global", "devices", "subnet", "p2p"}.issubset(input_hashes)
            or set(input_hashes) - (set(fixed_sources) | {"p2p"})):
        raise LoadError("pinned parent input inventory is incomplete or unsupported")
    p2p_record = parent.get("input_sources", {}).get("p2p")
    if (not isinstance(p2p_record, dict)
            or p2p_record.get("sha256") != input_hashes["p2p"]):
        raise LoadError("pinned P2P source does not match parent input")
    source_names = dict(fixed_sources)
    source_names["p2p"] = p2p_record.get("path")
    generated = parent.get("generated_inputs", {})
    if generated:
        if (not isinstance(generated, dict)
                or set(generated) != {"effective_devices"}
                or not isinstance(generated["effective_devices"], dict)):
            raise LoadError("pinned generated input inventory is unsupported")
        source_names["effective_devices"] = generated["effective_devices"].get("path")
        input_hashes = {**input_hashes,
                        "effective_devices": generated["effective_devices"].get("sha256")}
    source_names = {key: source_names[key] for key in input_hashes}
    if snapshot_directory:
        expected_entries = {"current-release.json", "inputs"}
        if dhcp_status == "enabled":
            expected_entries.add("dhcp")
        if {entry.name for entry in parent_directory.iterdir()} != expected_entries:
            raise LoadError("pinned generation contains an unexpected artifact")
        if dhcp_status == "enabled":
            assert dhcp_source_dir is not None
            if (not stat.S_ISDIR(dhcp_source_dir.lstat().st_mode)
                    or {entry.name for entry in dhcp_source_dir.iterdir()} != set(names)):
                raise LoadError("pinned generation DHCP directory is incomplete or extended")
        frozen_inputs = parent_directory / "inputs"
        if (not stat.S_ISDIR(frozen_inputs.lstat().st_mode)
                or {entry.name for entry in frozen_inputs.iterdir()} != set(input_hashes)):
            raise LoadError("pinned generation input directory is incomplete or extended")
    payloads = {"current-release.json": parent_bytes}
    for key, expected in input_hashes.items():
        label = f"inputs/{key}"
        relative_text = source_names[key]
        if not isinstance(relative_text, str):
            raise LoadError(f"pinned input {key} has no source path")
        relative = Path(relative_text)
        if (relative.is_absolute() or not relative.parts
                or any(part in {".", ".."} for part in relative.parts)
                or relative.as_posix() != relative_text
                or not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            if not flat_parent:
                raise LoadError(f"pinned input {key} has an unsafe source or digest")
            findings.append((_UNFREEZABLE_UNSAFE, label,
                             f"pinned input {key} has an unsafe source or digest"))
            continue
        source = ((parent_directory / "inputs" / key) if snapshot_directory
                  else canonical_project / relative)
        if flat_parent:
            try:
                source.lstat()
            except FileNotFoundError:
                # The recorded source is gone (e.g. a renamed P2P workbook whose old
                # file was deleted): A can no longer be rebuilt from current files.
                findings.append((_UNFREEZABLE_ABSENT, label, f"pinned input {key} is missing"))
                continue
        linked_target = None
        if (not stat.S_ISREG(source.lstat().st_mode)
                or source.lstat().st_nlink != 1
                or source.resolve(strict=True) != source):
            if not snapshot_directory and not flat_parent:
                # Candidate B of a formal load: R-014 第 3 条's two user links are frozen by their target's
                # bytes (review 4 B1); the frozen generation keeps a copy, never the link.
                linked_target = _user_linked_input_target(canonical_project, key, relative_text)
            if linked_target is None:
                if not flat_parent:
                    raise LoadError(f"pinned input {key} is not an owned regular file")
                # E.g. `p2p/` linked to a directory outside the project (R-014 item 3).
                findings.append((_UNFREEZABLE_NOT_OWNED, label,
                                 f"pinned input {key} is not an owned regular file"))
                continue
        read_path = source if linked_target is None else linked_target
        before = read_path.stat()
        content = read_path.read_bytes()
        after = read_path.stat()
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, field) != getattr(after, field) for field in identity)
                or linked_target is not None and source.resolve(strict=True) != linked_target):
            raise PinnedSourceChangedWhileReading(
                f"pinned input {key} changed or differs from parent")
        if hashlib.sha256(content).hexdigest() != expected:
            if not flat_parent:
                raise LoadError(f"pinned input {key} changed or differs from parent")
            findings.append((_UNFREEZABLE_CHANGED, label,
                             f"pinned input {key} changed or differs from parent"))
        payloads[label] = content
    if dhcp_status == "enabled":
        assert dhcp_source_dir is not None and isinstance(child, dict)
        for name in names:
            source = dhcp_source_dir / name
            if flat_parent:
                try:
                    source.stat()
                except FileNotFoundError:
                    # Flat outputs are reached through SETUP's links; a missing file or
                    # link target means A can no longer be rebuilt from current files.
                    findings.append((_UNFREEZABLE_ABSENT, f"dhcp/{name}",
                                     f"pinned DHCP child is missing: {name}"))
                    continue
            if not source.is_file():
                if not flat_parent:
                    raise LoadError(f"pinned DHCP child is missing: {name}")
                findings.append((_UNFREEZABLE_NOT_OWNED, f"dhcp/{name}",
                                 f"pinned DHCP child is missing: {name}"))
                continue
            if snapshot_directory:
                source_stat = source.lstat()
                if (not stat.S_ISREG(source_stat.st_mode)
                        or source_stat.st_nlink != 1):
                    raise LoadError(f"pinned DHCP child is not an owned regular file: {name}")
            data = source.read_bytes()
            if _sha256_path(source) != hashlib.sha256(data).hexdigest():
                raise PinnedSourceChangedWhileReading(
                    f"pinned DHCP child changed while freezing: {name}")
            payloads[f"dhcp/{name}"] = data
        manifest_bytes = payloads.get("dhcp/dhcp-release-manifest.json")
        if manifest_bytes is None:
            pass  # A flat manifest without bytes is already a finding.
        elif hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest:
            if not flat_parent:
                raise LoadError("pinned DHCP manifest differs from parent component")
            # A later load's flat manifest says nothing about this parent's outputs.
            findings.append((_UNFREEZABLE_CHANGED, "dhcp/dhcp-release-manifest.json",
                             "pinned DHCP manifest differs from parent component"))
        else:
            try:
                manifest = json.loads(manifest_bytes)
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise LoadError(f"pinned DHCP manifest is not JSON: {exc}") from exc
            outputs = manifest.get("outputs") if isinstance(manifest, dict) else None
            if (not isinstance(outputs, dict) or set(outputs) != set(names[1:])
                    or manifest.get("release_id") != child.get("release_id")):
                raise LoadError("pinned DHCP child identity/outputs are incomplete")
            for name in names[1:]:
                record = outputs[name]
                expected = record.get("sha256") if isinstance(record, dict) else None
                data = payloads.get(f"dhcp/{name}")
                if data is None or expected != hashlib.sha256(data).hexdigest():
                    if not (flat_parent and isinstance(expected, str)
                            and re.fullmatch(r"[0-9a-f]{64}", expected)):
                        raise LoadError(f"pinned DHCP output differs from child manifest: {name}")
                    if data is not None:  # an output without bytes is already a finding
                        findings.append((_UNFREEZABLE_CHANGED, f"dhcp/{name}",
                                         f"pinned DHCP output differs from child manifest: {name}"))
    if findings:
        raise FlatParentUnfreezable(
            findings[0][2], tuple((category, label) for category, label, _ in findings),
        )
    return release_id, payloads


def stage_pinned_generation(
    project: Path, parent_file: Path, dhcp_source_dir: Path | None,
) -> Path:
    """Persist an unselected generation; never change the public selector."""
    release_id, payloads = _pinned_generation_payloads(
        project, parent_file, dhcp_source_dir,
    )
    output = project.resolve(strict=True) / "99-output-ztp"
    generations = output / "generations"
    generations.mkdir(mode=0o755, exist_ok=True)
    if (not stat.S_ISDIR(generations.lstat().st_mode)
            or generations.resolve(strict=True) != generations):
        raise LoadError("pinned generations directory is not canonical")
    destination = generations / release_id
    if destination.exists():
        if not stat.S_ISDIR(destination.lstat().st_mode):
            raise LoadError("existing generation is not a real directory")
        expected_entries = {Path(relative).parts[0] for relative in payloads}
        if {entry.name for entry in destination.iterdir()} != expected_entries:
            raise LoadError("existing generation contains an unexpected artifact")
        existing = {}
        for path in destination.rglob("*"):
            metadata = path.lstat()
            if stat.S_ISDIR(metadata.st_mode):
                continue
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LoadError("existing generation contains a non-regular artifact")
            existing[path.relative_to(destination).as_posix()] = path.read_bytes()
        if existing != payloads:
            raise LoadError("existing generation differs from the selected parent")
        return destination
    stage = Path(tempfile.mkdtemp(prefix=".load-generation-", dir=generations))
    stage_parent_identity = _setup_switch_directory_identity(generations)
    stage_descriptor = os.open(
        stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    stage_identity = os.fstat(stage_descriptor)
    try:
        named_stage = stage.lstat()
        if (not stat.S_ISDIR(stage_identity.st_mode)
                or (named_stage.st_dev, named_stage.st_ino)
                != (stage_identity.st_dev, stage_identity.st_ino)):
            raise LoadError("generation staging owner changed while opening")
        (stage / "inputs").mkdir(mode=0o755)
        if any(relative.startswith("dhcp/") for relative in payloads):
            (stage / "dhcp").mkdir(mode=0o755)
        for relative, content in payloads.items():
            target = stage / relative
            with target.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fchmod(stream.fileno(), 0o644)
                os.fsync(stream.fileno())
        directories = [stage / "inputs", stage]
        if (stage / "dhcp").exists():
            directories.insert(0, stage / "dhcp")
        for directory in directories:
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        if destination.exists() or destination.is_symlink():
            raise LoadError("generation destination appeared during staging")
        os.rename(stage, destination)
        descriptor = os.open(generations, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        try:
            if os.path.lexists(stage):
                remaining = stage.lstat()
                held = os.fstat(stage_descriptor)
                if (not stat.S_ISDIR(remaining.st_mode)
                        or stage_parent_identity != _setup_switch_directory_identity(generations)
                        or (remaining.st_dev, remaining.st_ino)
                        != (stage_identity.st_dev, stage_identity.st_ino)
                        or (held.st_dev, held.st_ino)
                        != (stage_identity.st_dev, stage_identity.st_ino)):
                    raise LoadError("generation staging name rebound; preserve evidence; HOLD")
                shutil.rmtree(stage)
        finally:
            os.close(stage_descriptor)
    return destination


def commit_pinned_generation(
    project: Path, generation: Path, *, expected_current: str | None,
) -> None:
    """Make one already-frozen generation visible with one atomic link replace."""
    output = project.resolve(strict=True) / "99-output-ztp"
    if (generation.parent != output / "generations"
            or not re.fullmatch(r"[0-9a-f]{20}", generation.name)
            or not stat.S_ISDIR(generation.lstat().st_mode)
            or generation.resolve(strict=True) != generation):
        raise LoadError("generation selection target is not canonical")
    selector = output / "current"
    before = selector.lstat() if os.path.lexists(selector) else None
    if before is not None and not stat.S_ISLNK(before.st_mode):
        raise LoadError("generation selector changed before commit")
    before_target = os.readlink(selector) if before is not None else None
    if before_target != expected_current:
        raise LoadError("generation selector changed before commit")
    parent = generation / "current-release.json"
    generation_dhcp = generation / "dhcp"
    _pinned_generation_payloads(
        project, parent, generation_dhcp if generation_dhcp.is_dir() else None,
    )
    after = selector.lstat() if os.path.lexists(selector) else None
    if ((before is None) != (after is None)
            or after is not None and not stat.S_ISLNK(after.st_mode)
            or after is not None and any(
                getattr(before, field) != getattr(after, field)
                for field in ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
            )
            or (os.readlink(selector) if after is not None else None)
            != expected_current):
        raise LoadError("generation selector changed before commit")
    target = f"generations/{generation.name}"
    temporary = output / f".current-{secrets.token_hex(16)}"
    temporary_identity = None
    try:
        temporary.symlink_to(target)
        temporary_identity = temporary.lstat()
        if (not stat.S_ISLNK(temporary_identity.st_mode)
                or temporary_identity.st_nlink != 1
                or os.readlink(temporary) != target):
            raise LoadError("generation selector temporary changed before commit")
        os.replace(temporary, selector)
        descriptor = os.open(output, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        # A failed exclusive create grants no ownership of the colliding name.
        # Likewise, a failed replace must not clean up a later foreign object.
        if temporary_identity is not None:
            try:
                remaining = temporary.lstat()
            except FileNotFoundError:
                remaining = None
            if (remaining is not None and stat.S_ISLNK(remaining.st_mode)
                    and all(getattr(remaining, field) == getattr(temporary_identity, field)
                            for field in ("st_dev", "st_ino", "st_mode", "st_nlink",
                                          "st_mtime_ns", "st_ctime_ns"))
                    and os.readlink(temporary) == target):
                temporary.unlink()


def _skip_unfreezable_flat_parent(findings: tuple[tuple[str, str], ...]) -> None:
    """Warn once, grouped by reason category, that A keeps no fallback point."""
    grouped: dict[str, list[str]] = {}
    for category, label in findings:
        grouped.setdefault(category, []).append(label)
    reasons = "；".join(f"{category}：{'、'.join(labels)}" for category, labels in grouped.items())
    warn(f"旧版 release 无法冻结（{reasons}），本次 load 不保留旧版回退点")
    return None


def ensure_previous_generation_frozen(project: Path) -> str | None:
    """Keep a committed A recoverable before a later load can generate B.

    A pre-versioned flat parent can be migrated only while its original
    project inputs and DHCP child still validate.  DEV never froze it, so a
    flat parent that cannot be migrated (edited, removed or linked sources,
    an unsafe record, an old or invalid format) is skipped with a warning and
    no fallback point, as when no parent exists (owner 2026-11-07, plan A;
    R-016 recovers forward by rerunning load).  A source that changes while
    it is read, a non-canonical output directory, and every selector or
    selected-generation error still refuse.
    """
    output = project.resolve(strict=True) / "99-output-ztp"
    if os.path.lexists(output) and (
        not stat.S_ISDIR(output.lstat().st_mode)
        or output.resolve(strict=True) != output
    ):
        raise LoadError("previous generation output directory is not canonical")
    selector = output / "current"
    if os.path.lexists(selector):
        selector_before = selector.lstat()
        if not stat.S_ISLNK(selector_before.st_mode):
            raise LoadError("previous generation selector is not a symlink")
        target = os.readlink(selector)
        match = re.fullmatch(r"generations/([0-9a-f]{20})", target)
        if match is None:
            raise LoadError("previous generation selector has an unsafe target")
        generation = output / target
        generation_dhcp = generation / "dhcp"
        release_id, _payloads = _pinned_generation_payloads(
            project, generation / "current-release.json",
            generation_dhcp if generation_dhcp.is_dir() else None,
        )
        try:
            selector_after = selector.lstat()
            current_target = os.readlink(selector)
        except OSError as exc:
            raise LoadError("previous generation selector changed while validating") from exc
        identity_fields = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
        if (release_id != match.group(1) or current_target != target
                or any(getattr(selector_before, field) != getattr(selector_after, field)
                       for field in identity_fields)):
            raise LoadError("previous generation selector changed while validating")
        return target

    parent = output / "current-release.json"
    if not os.path.lexists(parent):
        return None
    # DEV never froze its flat parent, so a flat parent that cannot be frozen
    # is skipped with a warning (owner 2026-11-07, plan A); only a concurrent
    # writer still refuses.
    parent_label = "current-release.json"
    try:
        parent_payload = json.loads(parent.read_text(encoding="utf-8"))
    except OSError:
        return _skip_unfreezable_flat_parent(((_UNFREEZABLE_UNREADABLE, parent_label),))
    except (UnicodeError, json.JSONDecodeError):
        return _skip_unfreezable_flat_parent(((_UNFREEZABLE_FORMAT, parent_label),))
    if not isinstance(parent_payload, dict) or parent_payload.get("schema_version") != 2:
        return _skip_unfreezable_flat_parent(((_UNFREEZABLE_FORMAT, parent_label),))
    flat_dhcp = (
        ZTP_DIR / "config/isc-dhcp-server"
        if parent_payload.get("dhcp_status") == "enabled" else None
    )
    try:
        release_id, _payloads = _pinned_generation_payloads(
            project, parent, flat_dhcp,
        )
    except PinnedSourceChangedWhileReading:
        raise
    except FlatParentUnfreezable as exc:
        return _skip_unfreezable_flat_parent(exc.findings)
    except LoadError:
        return _skip_unfreezable_flat_parent(((_UNFREEZABLE_FORMAT, parent_label),))
    except OSError as exc:
        category = (_UNFREEZABLE_ABSENT if isinstance(exc, FileNotFoundError)
                    else _UNFREEZABLE_UNREADABLE)
        return _skip_unfreezable_flat_parent(
            ((category, Path(exc.filename).name if exc.filename else type(exc).__name__),),
        )
    generation = stage_pinned_generation(
        project, parent, flat_dhcp,
    )
    if generation.name != release_id:
        raise LoadError("previous generation changed during migration")
    commit_pinned_generation(project, generation, expected_current=None)
    return f"generations/{release_id}"


_ROLLBACK_RUNTIME_FILES = (
    "ztp-bootstrap_oob.sh", "ztp-bootstrap_oobofoob.sh", "ztp.json",
)
_ROLLBACK_PAYLOAD_LIMIT = 32 * 1024 * 1024
_ROLLBACK_TOTAL_LIMIT = 128 * 1024 * 1024
_ROLLBACK_RECEIPT_LIMIT = 1024 * 1024
_ROLLBACK_MARKER_LIMIT = 128 * 1024


def _read_rollback_regular(
    path: Path, *, limit: int = _ROLLBACK_PAYLOAD_LIMIT,
    missing_ok: bool = False,
) -> tuple[bytes, int] | None:
    """Read one immutable-by-name rollback input through a held descriptor."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        if missing_ok and not os.path.lexists(path):
            return None
        raise LoadError(f"rollback input disappeared while opening: {path}")
    except OSError as exc:
        raise LoadError(f"rollback input cannot be inspected: {path}: {exc}") from exc
    if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
            or before.st_size < 0 or before.st_size > limit):
        raise LoadError(f"rollback input is not a bounded single-link file: {path}")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        opened = os.fstat(descriptor)
        # A same-inode writer can restore size, bytes and mtime after an ABA
        # mutation. Such a read is not a stable recovery authority even when
        # the returned bytes happen to match the final disk contents.
        identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                    "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, field) != getattr(opened, field) for field in identity):
            raise LoadError(f"rollback input changed while opening: {path}")
        chunks = []
        remaining = limit + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        after_fd = os.fstat(descriptor)
        after_name = path.lstat()
        if len(payload) > limit or any(
            getattr(opened, field) != getattr(after_fd, field)
            or getattr(opened, field) != getattr(after_name, field)
            for field in identity
        ):
            raise LoadError(f"rollback input changed while reading: {path}")
        return payload, stat.S_IMODE(opened.st_mode)
    except OSError as exc:
        raise LoadError(f"rollback input cannot be read safely: {path}: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _describe_receipt_file(path: Path) -> dict[str, object]:
    opened = _read_rollback_regular(path, missing_ok=True)
    if opened is None:
        return {"state": "missing"}
    payload, mode = opened
    return {
        "state": "file", "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": mode,
    }


_RUNTIME_KEY_IDENTITY_FIELDS = (
    "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
    "st_mtime_ns", "st_ctime_ns",
)


def _runtime_key_identity(metadata: os.stat_result) -> dict[str, int]:
    return {field: getattr(metadata, field) for field in _RUNTIME_KEY_IDENTITY_FIELDS}


def _require_through_pointer(
    project: Path, lexical: Path, relative: str, label: str, *, live: bool = False,
) -> None:
    """Admit a SETUP link only when its lexical target is DAY0-Prepare/activate-project/<relative> beside
    this canonical project and that pointer selects it (R-016 §2: the text names the pointer, the pointer
    names the project).  A refusal names its cause; only a real escape says "escaped" (review 3 A3).
    The direct text may be a v3.1.0 A receipt only in a receipt record; a live link in it is setup's to
    migrate (review 5 A4)."""
    if lexical == project / relative:
        if live:
            raise LoadError(f"{label}：链接是 v3.1.1 之前的直连写法，请先运行 01-a-setup.py <项目> 迁移")
        raise LoadError(
            f"{label}：链接原文是 activate-project 之前（v3.1.0）的直连写法，不是经指针的写法，"
            "可能是 v3.1.0 留下的 A 回执；不能复用，HOLD，处理见发布说明「v3.1.0 的 A 回执」")
    if lexical == project.parent / "activate-project" / relative:
        try:
            selected = active_project_dir(project.parent.parent)
        except ActiveProjectPointerError as exc:
            raise LoadError(f"{label}：活动项目指针无效：{exc}；请先运行 01-a-setup.py <项目> 重建指针") from exc
        if selected is None:
            raise LoadError(
                f"{label}：没有激活的项目（DAY0-Prepare/activate-project 不存在）；"
                "请先运行 01-a-setup.py <项目> 激活项目")
        if selected == project:
            return
    raise LoadError(f"{label} escaped its owning project")


def _runtime_key_source(path: Path, project: Path, target: object, *, live: bool = False) -> Path:
    """Admit only SETUP's relative publication of this project's same-name key."""
    if (not isinstance(target, str) or not target or os.path.isabs(target)
            or os.path.normpath(target) != target or not path.name.endswith(".pub")):
        raise LoadError("rollback public key source link is invalid")
    canonical = project.resolve(strict=True)
    lexical = Path(os.path.normpath(str(path.parent.resolve(strict=True) / target)))
    _require_through_pointer(canonical, lexical, path.name, "rollback public key source", live=live)
    return canonical / path.name


def _read_runtime_key_source(source: Path) -> tuple[bytes, int, dict[str, int]]:
    try:
        before = source.lstat()
        opened = _read_rollback_regular(source)
        after = source.lstat()
    except (OSError, LoadError) as exc:
        raise LoadError(f"rollback public key source is unavailable or unsafe: {source}: {exc}") from exc
    if opened is None or _runtime_key_identity(before) != _runtime_key_identity(after):
        raise LoadError("rollback public key source changed while reading")
    payload, mode = opened
    if not payload:
        raise LoadError("rollback public key source is empty")
    return payload, mode, _runtime_key_identity(after)


def _read_runtime_publickey(
    path: Path, project: Path,
) -> tuple[dict[str, object], bytes | None]:
    """Keep managed links as links; never relax the ordinary nofollow reader."""
    try:
        before = path.lstat()
    except FileNotFoundError:
        if os.path.lexists(path):
            raise LoadError("rollback public key publication changed while opening")
        return {"state": "missing"}, None
    if not stat.S_ISLNK(before.st_mode):
        opened = _read_rollback_regular(path)
        assert opened is not None
        payload, mode = opened
        return {"state": "file", "sha256": hashlib.sha256(payload).hexdigest(), "mode": mode}, payload
    try:
        parent = _setup_switch_link_parent_identity(path)
        target = os.readlink(path)
        if before.st_nlink != 1:
            raise LoadError("rollback public key publication is not a single link")
        source = _runtime_key_source(path, project, target, live=True)
        payload, mode, identity = _read_runtime_key_source(source)
        if (_runtime_key_identity(before) != _runtime_key_identity(path.lstat())
                or os.readlink(path) != target
                or _setup_switch_link_parent_identity(path) != parent):
            raise LoadError("rollback public key publication changed while reading")
    except OSError as exc:
        raise LoadError(f"rollback public key publication cannot be inspected: {exc}") from exc
    return {
        "state": "link", "sha256": hashlib.sha256(payload).hexdigest(), "mode": mode,
        "target": target, "source_identity": identity, "parent_identity": parent,
    }, payload


def _validate_runtime_key_binding(path: Path, project: Path, record: dict[str, object]) -> None:
    """Check original P source and directory authority before any flat restore."""
    source = _runtime_key_source(path, project, record["target"])
    payload, mode, identity = _read_runtime_key_source(source)
    if (identity != record["source_identity"] or mode != record["mode"]
            or hashlib.sha256(payload).hexdigest() != record["sha256"]):
        raise LoadError("rollback public key source identity or payload changed")
    if _setup_switch_link_parent_identity(path) != record["parent_identity"]:
        raise LoadError("rollback public key parent identity changed")


def _require_runtime_publickey_parent(receipt: dict[str, object]) -> None:
    """A legacy payload digest cannot authorize writes into a rebound directory."""
    expected = receipt.get("publickey_parent")
    if receipt.get("schema_version") not in (3, 4) or not isinstance(expected, dict):
        raise LoadError("rollback public key parent identity is missing; preserve legacy receipt")
    try:
        actual = _setup_switch_link_parent_identity(ZTP_DIR / "config/publickey/.receipt-parent")
    except (OSError, LoadError) as exc:
        raise LoadError(f"rollback public key parent is unavailable or unsafe: {exc}") from exc
    if actual != expected:
        raise LoadError("rollback public key parent identity changed")


def _write_rollback_receipt_payload(path: Path, payload: bytes, mode: int) -> None:
    """Complete one private new receipt file before publishing its directory."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
        os.fchmod(stream.fileno(), mode)
        stream.flush()
        os.fsync(stream.fileno())


def _snapshot_receipt_file(path: Path, snapshot: Path) -> dict[str, object]:
    opened = _read_rollback_regular(path, missing_ok=True)
    if opened is None:
        return {"state": "missing"}
    payload, mode = opened
    record = {
        "state": "file", "sha256": hashlib.sha256(payload).hexdigest(),
        "mode": mode,
    }
    if record["state"] == "file":
        snapshot.parent.mkdir(parents=True, exist_ok=True)
        _write_rollback_receipt_payload(snapshot, payload, int(record["mode"]))
    return record


def _receipt_authority(path: Path) -> dict[str, object]:
    opened = _read_rollback_regular(path, missing_ok=True)
    if opened is None:
        return {"state": "missing"}
    payload, _mode = opened
    return {"state": "file", "sha256": hashlib.sha256(payload).hexdigest()}


_RUNTIME_DHCP_NAMES = frozenset({
    "dhcp-release-manifest.json", "dhcpd.conf", "dhcpd_eth.hosts",
    "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
})


def _runtime_dhcp_link_source(project: Path, path: Path, target: object, *, live: bool = False) -> Path:
    """Only SETUP's same-name, project-local DHCP publication is admissible."""
    if (path.parent != ZTP_DIR / "config/isc-dhcp-server"
            or path.name not in _RUNTIME_DHCP_NAMES
            or not isinstance(target, str) or not target or os.path.isabs(target)
            or os.path.normpath(target) != target):
        raise LoadError("rollback DHCP publication link is invalid")
    canonical = project.resolve(strict=True)
    source = canonical / "99-output-dhcp" / path.name
    # A real escape says so whatever the text or where it came from, so it is judged first (review 5 A4).
    if source.parent.resolve() != source.parent:
        raise LoadError("rollback DHCP publication escaped its owning project")
    lexical = Path(os.path.normpath(str(path.parent.resolve(strict=True) / target)))
    _require_through_pointer(canonical, lexical, "99-output-dhcp/" + path.name, "rollback DHCP publication",
                             live=live)
    return source


def _receipt_dhcp_authority(project: Path, path: Path) -> dict[str, object]:
    """Bind both a normal SETUP link and its held, nofollow source authority."""
    try:
        before = path.lstat()
        if not stat.S_ISLNK(before.st_mode):
            return _receipt_authority(path)
        if before.st_nlink != 1:
            raise LoadError("rollback DHCP publication is not a single link")
        parent = _setup_switch_link_parent_identity(path)
        target = os.readlink(path)
        source = _runtime_dhcp_link_source(project, path, target, live=True)
        source_parent = _setup_switch_link_parent_identity(source)
        source_before = source.lstat()
        opened = _read_rollback_regular(source)
        source_after = source.lstat()
        if (opened is None or _import_member_owner(source_before) != _import_member_owner(source_after)
                or _import_member_owner(before) != _import_member_owner(path.lstat())
                or os.readlink(path) != target
                or _setup_switch_link_parent_identity(path) != parent
                or _setup_switch_link_parent_identity(source) != source_parent):
            raise LoadError("rollback DHCP publication authority changed while reading")
        payload, _mode = opened
        return {"state": "link", "target": target,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "identity": list(_import_member_owner(before)),
                "source_identity": list(_import_member_owner(source_after)),
                "parent_identity": parent, "source_parent_identity": source_parent}
    except (OSError, RuntimeError) as exc:
        raise LoadError(f"rollback DHCP publication cannot be safely read: {exc}") from exc


def _validate_receipt_dhcp_authority(project: Path, name: str, record: object) -> None:
    if not isinstance(record, dict):
        raise LoadError("rollback receipt DHCP authority record is invalid")
    digest = record.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise LoadError("rollback receipt DHCP authority digest is invalid")
    if record.get("state") == "file" and set(record) == {"state", "sha256"}:
        return
    expected = {"state", "sha256", "target", "identity", "source_identity",
                "parent_identity", "source_parent_identity"}
    if record.get("state") != "link" or set(record) != expected:
        raise LoadError("rollback receipt DHCP authority record is invalid")
    path = ZTP_DIR / "config/isc-dhcp-server" / name
    source = _runtime_dhcp_link_source(project, path, record["target"])
    for key, linked in (("identity", True), ("source_identity", False)):
        owner = record[key]
        if (not isinstance(owner, list) or len(owner) != 9
                or any(type(n) is not int or n < 0 for n in owner)
                or not (stat.S_ISLNK(owner[2]) if linked else stat.S_ISREG(owner[2]))
                or owner[5] != 1 or owner[6] > _ROLLBACK_PAYLOAD_LIMIT):
            raise LoadError("rollback receipt DHCP authority identity is invalid")
    for key, leaf in (("parent_identity", path), ("source_parent_identity", source)):
        parent = record[key]
        if (not isinstance(parent, dict) or set(parent) != {"path", "dev", "ino"}
                or parent.get("path") != str(leaf.parent.resolve(strict=True))
                or any(type(parent.get(field)) is not int or parent[field] < 0
                       for field in ("dev", "ino"))):
            raise LoadError("rollback receipt DHCP authority parent is invalid")


def _runtime_installed_dhcp_paths():
    """Trusted installer names, never receipt-supplied destination paths."""
    names = {"dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"}
    destinations = tuple(dhcp_file_mappings().values())
    if (len(destinations) != 4 or {path.name for path in destinations} != names
            or len({path.parent for path in destinations}) != 1
            or any(not path.is_absolute() or path.parent.resolve(strict=True) != path.parent
                   for path in destinations)):
        raise LoadError("installed DHCP owner names are invalid; HOLD")
    directory = destinations[0].parent.lstat()
    if not stat.S_ISDIR(directory.st_mode) or directory.st_mode & 0o022:
        raise LoadError("installed DHCP directory permissions are unsafe; HOLD")
    return {path.name: path for path in destinations}


def _runtime_selected_generation(project, generation):
    return _setup_switch_a_generation_authority(project, "generations/" + generation.name)


def _capture_runtime_selected_dhcp(project, generation):
    """Qualify selected bytes, installed owners, and historical flat separately."""
    from project_contract import open_selected_dhcp_release, recheck_selected_dhcp_release
    try:
        selected = open_selected_dhcp_release(project)
    except (ValueError, OSError) as exc:
        raise LoadError(f"selected DHCP capture unavailable; HOLD: {exc}") from exc
    if (selected.generation_dir != generation
            or selected.mode not in {"pinned", "disabled"}):
        raise LoadError("runtime receipt requires current selected generation; HOLD")
    immutable = _runtime_selected_generation(project, generation)
    installed = None
    if selected.mode == "pinned":
        paths = _runtime_installed_dhcp_paths()
        directory = _setup_switch_directory_identity(next(iter(paths.values())).parent)
        leaves = {name: _setup_switch_dhcp_owned_leaf(path) for name, path in paths.items()}
        trusted_uid = next(iter(paths.values())).parent.lstat().st_uid
        if any(row is not None and (row["identity"][3] != trusted_uid
                                   or row["identity"][2] & 0o022) for row in leaves.values()):
            raise LoadError("installed DHCP leaf owner/permissions are unsafe; HOLD")
        if any(row is None or row["state"]["state"] != "file"
               or row["state"]["sha256"] != selected.output_hashes[name]
               for name, row in leaves.items()):
            raise LoadError("installed DHCP differs from selected generation; HOLD")
        installed = dict(directory=directory, leaves=leaves)
        if (directory != _setup_switch_directory_identity(next(iter(paths.values())).parent)
                or trusted_uid != next(iter(paths.values())).parent.lstat().st_uid
                or leaves != {name: _setup_switch_dhcp_owned_leaf(path)
                              for name, path in paths.items()}):
            raise LoadError("installed DHCP owner changed during capture; HOLD")
    try:
        recheck_selected_dhcp_release(project, selected.binding)
    except (ValueError, OSError) as exc:
        raise LoadError(f"selected DHCP capture changed; HOLD: {exc}") from exc
    if immutable != _runtime_selected_generation(project, generation):
        raise LoadError("selected immutable generation changed during capture; HOLD")
    # Persist the existing immutable-generation owner/tree representation, not
    # transient project/output directory mtimes that authorized future LOAD
    # inputs or receipt creation may change. The shared reader still holds and
    # verifies all nine fields throughout each capture/preflight.
    return dict(generation=immutable, installed=installed)


def _validate_runtime_selected_dhcp(project, receipt):
    """Schema 4 has no interpretation upgrade for schema 1/2/3 fields."""
    if receipt["schema_version"] != 4:
        return
    qualification = receipt.get("selected_dhcp")
    if not isinstance(qualification, dict) or set(qualification) != {"generation", "installed"}:
        raise LoadError("schema4 selected DHCP qualification is incomplete; HOLD")
    generation = project / "99-output-ztp" / receipt["selector_target"]
    if (_setup_switch_canonical_payload(qualification["generation"])
            != _setup_switch_canonical_payload(_runtime_selected_generation(project, generation))):
        raise LoadError("schema4 selected immutable owner/tree changed; HOLD")
    frozen_parent = generation_report.decode_release_record(
        _read_rollback_regular(generation / "current-release.json")[0], "frozen parent")
    generation_report.validate_parent_release_basis(frozen_parent, project.name)
    if (frozen_parent["release_id"] != receipt["release_id"]
            or frozen_parent.get("dhcp_status") != receipt["dhcp_status"]):
        raise LoadError("schema4 selected parent identity differs; HOLD")
    installed = qualification["installed"]
    if receipt["dhcp_status"] == "disabled":
        if installed is not None:
            raise LoadError("schema4 disabled DHCP has installed authority; HOLD")
        return
    paths = _runtime_installed_dhcp_paths()
    if (not isinstance(installed, dict) or set(installed) != {"directory", "leaves"}
            or _setup_switch_canonical_payload(installed["directory"])
               != _setup_switch_canonical_payload(_setup_switch_directory_identity(
                   next(iter(paths.values())).parent))
            or not isinstance(installed["leaves"], dict) or set(installed["leaves"]) != set(paths)):
        raise LoadError("schema4 installed DHCP directory/inventory differs; HOLD")
    trusted_uid = next(iter(paths.values())).parent.lstat().st_uid
    tree = qualification["generation"]["tree"]
    for name, row in installed["leaves"].items():
        if not isinstance(row, dict) or set(row) != {"identity", "state"}:
            raise LoadError("schema4 installed DHCP owner shape differs; HOLD")
        owner, state = row["identity"], row["state"]
        if (not isinstance(owner, list) or len(owner) != 9
                or any(type(value) is not int or value < 0 for value in owner)
                or owner[5] != 1 or not stat.S_ISREG(owner[2])
                or not isinstance(state, dict)
                or set(state) != {"state", "mode", "uid", "gid", "mtime_ns", "size", "sha256"}
                or state["state"] != "file"
                or any(type(state[key]) is not int or state[key] < 0
                       for key in ("mode", "uid", "gid", "mtime_ns", "size"))
                or state["mode"] != stat.S_IMODE(owner[2])
                or (state["uid"], state["gid"], state["size"], state["mtime_ns"])
                   != (owner[3], owner[4], owner[6], owner[7])
                or state["size"] > _ROLLBACK_PAYLOAD_LIMIT
                or not isinstance(state["sha256"], str)
                or re.fullmatch(r"[0-9a-f]{64}", state["sha256"]) is None
                or state["sha256"] != tree["dhcp/" + name]["sha256"]):
            raise LoadError("schema4 installed metadata/hash differs from selected bytes; HOLD")
        if owner[3] != trusted_uid or owner[2] & 0o022:
            raise LoadError("schema4 installed leaf owner/permissions are unsafe; HOLD")


def _verify_active_selected_dhcp(project, receipt):
    if receipt["schema_version"] != 4:
        return
    _validate_runtime_selected_dhcp(project, receipt)
    generation = project / "99-output-ztp" / receipt["selector_target"]
    if _capture_runtime_selected_dhcp(project, generation) != receipt["selected_dhcp"]:
        raise LoadError("schema4 active selected/installed authority changed; HOLD")


def prepare_runtime_rollback_receipt(
    project: Path, generation: Path, *, capture_selected_dhcp: bool = False,
) -> Path:
    """Persist every flat surface needed to recover A after B generation fails.

    The receipt does not authorize rollback after a new parent has committed.
    It binds the still-active A parent/report/DHCP authorities and snapshots the
    flat bootstrap, key, YAML-latest and prefix surfaces which generation may
    change before the parent commit.
    """
    canonical_project = project.resolve(strict=True)
    output = canonical_project / "99-output-ztp"
    selector = output / "current"
    if (not selector.is_symlink()
            or os.readlink(selector) != f"generations/{generation.name}"):
        raise LoadError("A rollback receipt requires the selected frozen generation")
    generation_dhcp = generation / "dhcp"
    release_id, _payloads = _pinned_generation_payloads(
        canonical_project, generation / "current-release.json",
        generation_dhcp if generation_dhcp.is_dir() else None,
    )
    try:
        parent = json.loads(
            (generation / "current-release.json").read_text(encoding="utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"A rollback parent is invalid: {exc}") from exc
    dhcp_status = parent.get("dhcp_status")
    # The URL publication belongs to A.  Project inputs may already contain
    # B, so derive this policy only from A's immutable generation snapshot.
    settings = load_global(generation / "inputs/global")
    report_path = output / generation_report.REPORT_NAME
    if os.path.lexists(report_path):
        try:
            report = generation_report.inspect_generation_report(
                canonical_project, published_dir=ZTP_DIR / "config/publickey",
            )
        except generation_report.GenerationReportError as exc:
            raise LoadError(f"A generation report is invalid: {exc}") from exc
        if report.get("release_id") != release_id:
            raise LoadError("A generation report does not bind the selected parent")
    receipts = output / "rollback-receipts"
    receipts.mkdir(mode=0o755, exist_ok=True)
    if (not stat.S_ISDIR(receipts.lstat().st_mode)
            or receipts.resolve(strict=True) != receipts):
        raise LoadError("A rollback receipt root is not canonical")
    # Its own fsync cannot persist a newly-created receipt-root name.
    _fsync_parent_directory(output)
    destination = receipts / release_id
    if os.path.lexists(destination):
        if not stat.S_ISDIR(destination.lstat().st_mode):
            raise LoadError("existing A rollback receipt is not a directory")
        # A receipt is immutable. Reuse is allowed only after full validation.
        existing = _load_runtime_rollback_receipt(canonical_project, destination)
        _require_runtime_publickey_parent(existing)
        if capture_selected_dhcp and existing["schema_version"] != 4:
            raise LoadError("existing legacy receipt cannot satisfy schema4 active capture; HOLD")
        if capture_selected_dhcp:
            _verify_active_selected_dhcp(canonical_project, existing)
        return destination
    stage = Path(tempfile.mkdtemp(prefix=".rollback-receipt-", dir=receipts))
    try:
        files = stage / "files"
        keys = stage / "publickeys"
        files.mkdir(mode=0o755)
        keys.mkdir(mode=0o755)
        frozen_files = {
            name: _snapshot_receipt_file(ZTP_DIR / name, files / name)
            for name in _ROLLBACK_RUNTIME_FILES
        }
        publickey_name = ZTP_DIR / "config/publickey"
        if not publickey_name.is_dir() or publickey_name.is_symlink():
            raise LoadError("A rollback publickey directory is not canonical")
        publickey_dir = publickey_name.resolve(strict=True)
        publickey_dir.relative_to(ZTP_DIR.resolve(strict=True))
        publickey_parent = _setup_switch_link_parent_identity(publickey_dir / ".receipt-parent")
        publickeys: dict[str, dict[str, object]] = {}
        for source in sorted(publickey_dir.glob("*.pub"), key=lambda item: item.name):
            record, payload = _read_runtime_publickey(source, canonical_project)
            if payload is not None:
                _write_rollback_receipt_payload(keys / source.name, payload, int(record["mode"]))
            publickeys[source.name] = record
        if not publickeys or any(record.get("state") not in {"file", "link"} for record in publickeys.values()):
            raise LoadError("A rollback receipt requires at least one published public key")
        yaml_latest: dict[str, dict[str, object]] = {}
        for relative in ("99-output-eth/latest", "99-output-ib_nvl/latest"):
            path = canonical_project / relative
            if not os.path.lexists(path):
                yaml_latest[relative] = {"state": "missing"}
                continue
            if not path.is_symlink():
                raise LoadError(f"A rollback YAML latest is not a symlink: {relative}")
            target = os.readlink(path)
            resolved = path.resolve(strict=True)
            resolved.relative_to(path.parent.resolve(strict=True))
            manifest = resolved / "release-manifest.json"
            if not manifest.is_file():
                raise LoadError(f"A rollback YAML release has no manifest: {relative}")
            yaml_latest[relative] = {
                "state": "link", "target": target,
                "manifest_sha256": _sha256_path(manifest),
            }
        # /ztp itself is not an alias, but an earlier managed custom prefix and
        # its ownership marker are still part of the flat A runtime surface.
        prefix = snapshot_ztp_prefix_publication(settings)
        prefix_links = {}
        for path, (kind, target) in prefix.links.items():
            relative = path.relative_to(HTTP_ROOT).as_posix()
            prefix_links[relative] = {"kind": kind, "target": target}
        unchanged = {
            "parent": _receipt_authority(output / "current-release.json"),
            "report": _receipt_authority(output / generation_report.REPORT_NAME),
        }
        if dhcp_status == "enabled":
            unchanged["dhcp"] = {
                name: _receipt_dhcp_authority(canonical_project, ZTP_DIR / "config/isc-dhcp-server" / name)
                for name in (
                    "dhcp-release-manifest.json", "dhcpd.conf",
                    "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
                )
            }
        selected_qualification = (_capture_runtime_selected_dhcp(canonical_project, generation)
                                  if capture_selected_dhcp else None)
        receipt = {
            "schema_version": 4 if capture_selected_dhcp else 3,
            "record_type": "http-ztp-runtime-rollback-receipt",
            "project": canonical_project.name,
            "release_id": release_id,
            "selector_target": f"generations/{release_id}",
            "dhcp_status": dhcp_status,
            "frozen_files": frozen_files,
            "publickeys": publickeys,
            "publickey_parent": publickey_parent,
            "yaml_latest": yaml_latest,
            "prefix": {
                "marker_b64": (
                    base64.b64encode(prefix.marker).decode("ascii")
                    if prefix.marker is not None else None
                ),
                "links": prefix_links,
            },
            "unchanged_authorities": unchanged,
        }
        if capture_selected_dhcp:
            receipt["selected_dhcp"] = selected_qualification
        receipt_path = stage / "receipt.json"
        _require_runtime_publickey_parent(receipt)
        _write_rollback_receipt_payload(
            receipt_path,
            (json.dumps(receipt, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode("ascii"),
            0o644,
        )
        for directory in (files, keys, stage):
            descriptor = os.open(directory, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        os.rename(stage, destination)
        descriptor = os.open(receipts, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    _require_runtime_publickey_parent(_load_runtime_rollback_receipt(canonical_project, destination))
    return destination


def _load_runtime_rollback_receipt(
    project: Path, receipt_directory: Path,
) -> dict[str, object]:
    """Validate a receipt and every frozen payload before any restore write."""
    canonical_project = project.resolve(strict=True)
    root = canonical_project / "99-output-ztp/rollback-receipts"
    try:
        directory_stat = receipt_directory.lstat()
        if (not stat.S_ISDIR(directory_stat.st_mode)
                or receipt_directory.is_symlink()
                or directory_stat.st_nlink < 2):
            raise LoadError("rollback receipt directory is not a real directory")
        relative = receipt_directory.resolve(strict=True).relative_to(root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise LoadError("rollback receipt path is outside the project authority") from exc
    if len(relative.parts) != 1 or not re.fullmatch(r"[0-9a-f]{20}", relative.name):
        raise LoadError("rollback receipt path is invalid")
    expected_top = {"receipt.json", "files", "publickeys"}
    if {entry.name for entry in receipt_directory.iterdir()} != expected_top:
        raise LoadError("rollback receipt tree contains unknown or missing entries")
    for name in ("files", "publickeys"):
        child = receipt_directory / name
        child_stat = child.lstat()
        if (not stat.S_ISDIR(child_stat.st_mode) or child.is_symlink()
                or child.resolve(strict=True).parent != receipt_directory.resolve(strict=True)):
            raise LoadError("rollback receipt payload directory is unsafe")
    path = receipt_directory / "receipt.json"
    try:
        opened = _read_rollback_regular(path, limit=_ROLLBACK_RECEIPT_LIMIT)
        assert opened is not None
        receipt = generation_report.decode_release_record(opened[0], "runtime rollback receipt")
    except (OSError, UnicodeError, json.JSONDecodeError, LoadError,
            generation_report.GenerationReportError) as exc:
        raise LoadError(f"rollback receipt is incomplete or invalid: {exc}") from exc
    required = {
        "schema_version", "record_type", "project", "release_id",
        "selector_target", "dhcp_status", "frozen_files", "publickeys",
        "yaml_latest", "prefix", "unchanged_authorities",
    }
    if isinstance(receipt, dict) and receipt.get("schema_version") in (3, 4):
        required.add("publickey_parent")
        if receipt["schema_version"] == 4:
            required.add("selected_dhcp")
    if (not isinstance(receipt, dict) or set(receipt) != required
            or isinstance(receipt.get("schema_version"), bool)
            or not isinstance(receipt.get("schema_version"), int)
            or receipt.get("schema_version") not in (1, 2, 3, 4)
            or receipt.get("record_type") != "http-ztp-runtime-rollback-receipt"
            or receipt.get("project") != canonical_project.name
            or receipt.get("release_id") != relative.name
            or receipt.get("selector_target") != f"generations/{relative.name}"
            or receipt.get("dhcp_status") not in {"enabled", "disabled"}):
        raise LoadError("rollback receipt is incomplete or invalid")
    if receipt["schema_version"] in (3, 4):
        parent = receipt["publickey_parent"]
        if (not isinstance(parent, dict) or set(parent) != {"path", "dev", "ino"}
                or not isinstance(parent.get("path"), str)
                or parent["path"] != str((ZTP_DIR / "config/publickey").resolve(strict=True))
                or any(type(parent.get(field)) is not int or parent[field] < 0
                       for field in ("dev", "ino"))):
            raise LoadError("rollback receipt publickey parent binding is invalid")
    frozen = receipt.get("frozen_files")
    keys = receipt.get("publickeys")
    if not isinstance(frozen, dict) or set(frozen) != set(_ROLLBACK_RUNTIME_FILES):
        raise LoadError("rollback receipt frozen file inventory is incomplete")
    if not isinstance(keys, dict) or not keys:
        raise LoadError("rollback receipt public key inventory is incomplete")
    expected_payloads = {
        "files": {name for name, record in frozen.items()
                  if isinstance(record, dict) and record.get("state") == "file"},
        "publickeys": {name for name, record in keys.items()
                       if isinstance(record, dict) and record.get("state") in {"file", "link"}},
    }
    for directory, names in expected_payloads.items():
        actual = {entry.name for entry in (receipt_directory / directory).iterdir()}
        if actual != names:
            raise LoadError("rollback receipt payload inventory is incomplete or extended")
    for group, directory in ((frozen, "files"), (keys, "publickeys")):
        for name, record in group.items():
            if (not isinstance(name, str) or Path(name).name != name
                    or not isinstance(record, dict)
                    or record.get("state") not in ({"file", "link"} if directory == "publickeys" else {"file", "missing"})):
                raise LoadError("rollback receipt file record is incomplete")
            snapshot = receipt_directory / directory / name
            if record["state"] == "missing":
                if os.path.lexists(snapshot):
                    raise LoadError("rollback receipt contains an unexpected payload")
                continue
            opened = _read_rollback_regular(snapshot)
            if opened is None:
                raise LoadError("rollback receipt payload is absent")
            payload, payload_mode = opened
            expected_fields = {"state", "sha256", "mode"}
            if record["state"] == "link":
                expected_fields |= {"target", "source_identity", "parent_identity"}
                identity = record.get("source_identity")
                parent = record.get("parent_identity")
                if (receipt["schema_version"] not in (2, 3, 4)
                        or not isinstance(identity, dict) or set(identity) != set(_RUNTIME_KEY_IDENTITY_FIELDS)
                        or any(isinstance(value, bool) or not isinstance(value, int) for value in identity.values())
                        or not stat.S_ISREG(identity["st_mode"]) or identity["st_nlink"] != 1
                        or stat.S_IMODE(identity["st_mode"]) != record.get("mode")
                        or not 0 < identity["st_size"] <= _ROLLBACK_PAYLOAD_LIMIT
                        or not isinstance(parent, dict) or set(parent) != {"path", "dev", "ino"}
                        or not isinstance(parent.get("path"), str)
                        or any(isinstance(parent.get(field), bool) or not isinstance(parent.get(field), int)
                               for field in ("dev", "ino"))):
                    raise LoadError("rollback receipt public key binding is invalid")
                key_path = ZTP_DIR / "config/publickey" / name
                _runtime_key_source(key_path, canonical_project, record.get("target"))
                if parent["path"] != str(key_path.parent.resolve(strict=True)):
                    raise LoadError("rollback receipt public key parent path is invalid")
            if (set(record) != expected_fields
                    or isinstance(record.get("mode"), bool)
                    or not isinstance(record.get("mode"), int)
                    or int(record["mode"]) < 0 or int(record["mode"]) > 0o777
                    or not isinstance(record.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", str(record["sha256"]))
                    or payload_mode != record.get("mode")
                    or hashlib.sha256(payload).hexdigest() != record.get("sha256")):
                raise LoadError("rollback receipt payload is incomplete or changed")
    latest = receipt.get("yaml_latest")
    if not isinstance(latest, dict) or set(latest) != {
        "99-output-eth/latest", "99-output-ib_nvl/latest",
    }:
        raise LoadError("rollback receipt YAML inventory is incomplete")
    for relative, record in latest.items():
        if (not isinstance(record, dict)
                or record.get("state") not in {"missing", "link"}):
            raise LoadError("rollback receipt YAML record is invalid")
        if record["state"] == "missing" and set(record) != {"state"}:
            raise LoadError("rollback receipt missing YAML record is extended")
        if record["state"] == "link":
            target = record.get("target")
            digest = record.get("manifest_sha256")
            if (set(record) != {"state", "target", "manifest_sha256"}
                    or not isinstance(target, str) or Path(target).is_absolute()
                    or not target or any(part in {"", ".", ".."} for part in Path(target).parts)
                    or not isinstance(digest, str)
                    or not re.fullmatch(r"[0-9a-f]{64}", digest)):
                raise LoadError("rollback receipt YAML link record is invalid")
    prefix = receipt.get("prefix")
    if (not isinstance(prefix, dict) or set(prefix) != {"marker_b64", "links"}
            or prefix["marker_b64"] is not None
            and not isinstance(prefix["marker_b64"], str)
            or not isinstance(prefix["links"], dict)):
        raise LoadError("rollback receipt prefix record is incomplete")
    if prefix["marker_b64"] is not None:
        if len(prefix["marker_b64"]) > _ROLLBACK_MARKER_LIMIT * 2:
            raise LoadError("rollback receipt prefix marker is oversized")
        try:
            marker_payload = base64.b64decode(prefix["marker_b64"], validate=True)
        except (ValueError, binascii.Error) as exc:
            raise LoadError("rollback receipt prefix marker is invalid") from exc
        if len(marker_payload) > _ROLLBACK_MARKER_LIMIT:
            raise LoadError("rollback receipt prefix marker is oversized")
    for relative, record in prefix["links"].items():
        if not isinstance(relative, str):
            raise LoadError("rollback receipt prefix link record is invalid")
        path = Path(relative)
        if (path.is_absolute() or not path.parts
                or any(part in {"", ".", ".."} for part in path.parts)
                or not isinstance(record, dict)
                or set(record) != {"kind", "target"}
                or record.get("kind") not in {"link", "missing", "other"}
                or record.get("target") is not None
                and not isinstance(record.get("target"), str)):
            raise LoadError("rollback receipt prefix link record is invalid")
        kind = record["kind"]
        target = record.get("target")
        if kind == "link":
            if target is None:
                raise LoadError("rollback receipt prefix link target is absent")
            destination = HTTP_ROOT / path
            if (destination.parent / target).resolve(strict=False) != ZTP_DIR.resolve(strict=True):
                raise LoadError("rollback receipt prefix link target is outside ZTP")
        elif target is not None:
            raise LoadError("rollback receipt non-link prefix target must be null")
    authorities = receipt.get("unchanged_authorities")
    expected_authorities = {"parent", "report"}
    if receipt["dhcp_status"] == "enabled":
        expected_authorities.add("dhcp")
    if not isinstance(authorities, dict) or set(authorities) != expected_authorities:
        raise LoadError("rollback receipt unchanged authority inventory is incomplete")
    for name in ("parent", "report"):
        record = authorities.get(name)
        if (not isinstance(record, dict) or record.get("state") not in {"file", "missing"}
                or record["state"] == "missing" and set(record) != {"state"}
                or record["state"] == "file" and (
                    set(record) != {"state", "sha256"}
                    or not isinstance(record.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
                )):
            raise LoadError("rollback receipt unchanged authority record is invalid")
    if "dhcp" in authorities:
        expected_dhcp = {
            "dhcp-release-manifest.json", "dhcpd.conf", "dhcpd_eth.hosts",
            "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        }
        if not isinstance(authorities["dhcp"], dict) or set(authorities["dhcp"]) != expected_dhcp:
            raise LoadError("rollback receipt DHCP authority inventory is invalid")
        for name, record in authorities["dhcp"].items():
            _validate_receipt_dhcp_authority(canonical_project, name, record)
    _validate_runtime_selected_dhcp(canonical_project, receipt)
    return receipt


def _restore_receipt_file(
    path: Path, record: dict[str, object], payload: bytes | None,
) -> None:
    stage_prefix = f".{path.name}.rollback-"
    _require_no_pending_setup_stage(path, stage_prefix, "runtime file")
    if record["state"] == "missing":
        if payload is not None:
            raise LoadError("rollback missing-file record has an unexpected payload")
        if os.path.lexists(path):
            if path.is_dir() and not path.is_symlink():
                raise LoadError(f"rollback target became a directory: {path}")
            path.unlink()
        # Even an already-absent name may be a retry after unlink succeeded
        # but its directory sync failed.
        _fsync_parent_directory(path.parent)
        return
    if payload is None or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise LoadError("rollback receipt payload changed before restore")
    parent_identity = _setup_switch_link_parent_identity(path)
    descriptor, name = tempfile.mkstemp(prefix=stage_prefix, dir=path.parent)
    temporary = Path(name)
    held_descriptor = -1
    staged_identity = None
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")

    def require_owned_stage() -> None:
        try:
            named, held = temporary.lstat(), os.fstat(held_descriptor)
            if (staged_identity is None
                    or parent_identity != _setup_switch_link_parent_identity(path)
                    or any(getattr(staged_identity, field) != getattr(named, field)
                           or getattr(staged_identity, field) != getattr(held, field) for field in fields)
                    or _read_rollback_regular(temporary) != (payload, int(record["mode"]))):
                raise LoadError("runtime restore stage is not the held candidate; HOLD")
            after = temporary.lstat()
            if any(getattr(staged_identity, field) != getattr(after, field) for field in fields):
                raise LoadError("runtime restore stage changed during inspection; HOLD")
        except (OSError, ValueError, RuntimeError) as exc:
            raise LoadError(f"runtime restore stage inspection failed; HOLD: {exc}") from exc

    try:
        with os.fdopen(descriptor, "wb") as stream:
            held_descriptor = os.dup(stream.fileno())
            stream.write(payload)
            os.fchmod(stream.fileno(), int(record["mode"]))
            stream.flush()
            staged_identity = os.fstat(held_descriptor)
            os.fsync(stream.fileno())
        if os.path.lexists(path) and path.is_dir() and not path.is_symlink():
            raise LoadError(f"rollback target became a directory: {path}")
        require_owned_stage()
        os.replace(temporary, path)
        _fsync_parent_directory(path.parent)
    finally:
        try:
            if os.path.lexists(temporary):
                try:
                    require_owned_stage()
                except LoadError:
                    # Unknown or incompletely captured stages are incident
                    # evidence, not ours to remove by generated name.
                    pass
                else:
                    temporary.unlink()
        finally:
            if held_descriptor >= 0:
                os.close(held_descriptor)


def _verify_rollback_authorities(
    project: Path, receipt: dict[str, object],
) -> None:
    output = project / "99-output-ztp"
    authorities = receipt.get("unchanged_authorities")
    if not isinstance(authorities, dict):
        raise LoadError("rollback receipt authority inventory is incomplete")
    for name, path in {
        "parent": output / "current-release.json",
        "report": output / generation_report.REPORT_NAME,
    }.items():
        if authorities.get(name) != _receipt_authority(path):
            raise LoadError(f"{name} authority no longer equals A; rollback is blocked")
    if receipt["dhcp_status"] == "enabled":
        dhcp = authorities.get("dhcp")
        if not isinstance(dhcp, dict):
            raise LoadError("rollback receipt DHCP authority is incomplete")
        current = {
            name: _receipt_dhcp_authority(project, ZTP_DIR / "config/isc-dhcp-server" / name)
            for name in dhcp
        }
        if current != dhcp:
            raise LoadError("DHCP authority no longer equals A; rollback is blocked")
    elif "dhcp" in authorities:
        raise LoadError("rollback receipt disabled DHCP authority is invalid")


def _validate_rollback_yaml_release(
    project: Path, relative: str, record: dict[str, object],
) -> Path | None:
    if record["state"] == "missing":
        return None
    latest = project / relative
    resolved = (latest.parent / str(record["target"])).resolve(strict=True)
    resolved.relative_to(latest.parent.resolve(strict=True))
    metadata = resolved.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or resolved.is_symlink():
        raise LoadError("rollback YAML release target is not a real directory")
    manifest_path = resolved / "release-manifest.json"
    manifest = _load_release_json(manifest_path, f"{relative} rollback manifest")
    if _receipt_authority(manifest_path).get("sha256") != record["manifest_sha256"]:
        raise LoadError("rollback YAML release manifest no longer equals A")
    _nonempty_file(resolved / ".published-complete", f"{relative} completion marker")
    label = "cumulus" if relative == "99-output-eth/latest" else "nvos"
    _validate_child_artifacts(label=label, release_dir=resolved, manifest=manifest)
    return resolved


def _prevalidate_rollback_latest_targets(
    project: Path, records: dict[str, dict[str, object]],
) -> None:
    for relative, record in records.items():
        latest = project / relative
        parent = latest.parent
        if os.path.lexists(parent):
            if (not parent.is_dir() or parent.is_symlink()
                    or parent.resolve(strict=True) != parent):
                raise LoadError("rollback YAML latest parent is not canonical")
        elif record["state"] != "missing":
            raise LoadError("rollback YAML latest parent is absent")
        else:
            ancestor = parent.parent
            if (not ancestor.is_dir() or ancestor.is_symlink()
                    or ancestor.resolve(strict=True) != ancestor):
                raise LoadError("rollback YAML latest ancestor is not canonical")
        if os.path.lexists(latest) and not latest.is_symlink():
            raise LoadError("rollback YAML latest target became a non-link")
        _validate_rollback_yaml_release(project, relative, record)


def _verify_rollback_latest_state(
    project: Path, records: dict[str, dict[str, object]],
) -> None:
    for relative, record in records.items():
        latest = project / relative
        if record["state"] == "missing":
            if os.path.lexists(latest):
                raise LoadError("rollback YAML latest should be absent")
            continue
        if not latest.is_symlink() or os.readlink(latest) != record["target"]:
            raise LoadError("rollback YAML latest does not select A")
        _validate_rollback_yaml_release(project, relative, record)


def _prevalidate_prefix_restore(snapshot: ZtpPrefixPublicationSnapshot) -> None:
    if snapshot.marker is not None and len(snapshot.marker) > _ROLLBACK_MARKER_LIMIT:
        raise LoadError("rollback prefix marker is oversized")
    if os.path.lexists(ZTP_PREFIX_MARKER) and ZTP_PREFIX_MARKER.is_symlink():
        raise LoadError("rollback prefix marker became a symlink")
    for path, (kind, target) in snapshot.links.items():
        path.parent.resolve(strict=True).relative_to(HTTP_ROOT.resolve(strict=True))
        if kind == "other":
            if not os.path.lexists(path) or path.is_symlink():
                raise LoadError("rollback prefix non-link authority changed")
        elif os.path.lexists(path) and not path.is_symlink():
            raise LoadError("rollback prefix target became a non-link")
        if kind == "link" and target is None:
            raise LoadError("rollback prefix link target is absent")


def _verify_prefix_snapshot(snapshot: ZtpPrefixPublicationSnapshot) -> None:
    marker = None
    if os.path.lexists(ZTP_PREFIX_MARKER):
        opened = _read_rollback_regular(
            ZTP_PREFIX_MARKER, limit=_ROLLBACK_MARKER_LIMIT,
        )
        assert opened is not None
        marker = opened[0]
    if marker != snapshot.marker:
        raise LoadError("rollback prefix marker post-verify failed")
    for path, (kind, target) in snapshot.links.items():
        if kind == "missing":
            if os.path.lexists(path):
                raise LoadError("rollback prefix path should be absent")
        elif kind == "link":
            if not path.is_symlink() or os.readlink(path) != target:
                raise LoadError("rollback prefix link post-verify failed")
        elif kind == "other":
            if not os.path.lexists(path) or path.is_symlink():
                raise LoadError("rollback prefix non-link post-verify failed")
        else:
            raise LoadError("rollback prefix snapshot kind is invalid")


def _verify_active_runtime_receipt(
    project: Path, receipt_directory: Path, receipt: dict[str, object],
) -> None:
    """Prove a reusable receipt still describes the active flat A exactly."""
    _require_runtime_publickey_parent(receipt)
    _verify_rollback_authorities(project, receipt)
    _verify_active_selected_dhcp(project, receipt)
    for name, record in receipt["frozen_files"].items():
        if _describe_receipt_file(ZTP_DIR / name) != record:
            raise LoadError("existing rollback receipt no longer matches A runtime")
    publickey_dir = ZTP_DIR / "config/publickey"
    if not publickey_dir.is_dir() or publickey_dir.is_symlink():
        raise LoadError("existing rollback receipt publickey authority changed")
    records = receipt["publickeys"]
    actual_names = {path.name for path in publickey_dir.glob("*.pub")}
    if actual_names != set(records):
        raise LoadError("existing rollback receipt public key set changed")
    for name, record in records.items():
        if _read_runtime_publickey(publickey_dir / name, project)[0] != record:
            raise LoadError("existing rollback receipt public key changed")
    _verify_rollback_latest_state(project, receipt["yaml_latest"])
    prefix = receipt["prefix"]
    snapshot = ZtpPrefixPublicationSnapshot(
        marker=(None if prefix["marker_b64"] is None else base64.b64decode(
            prefix["marker_b64"], validate=True,
        )),
        links={
            HTTP_ROOT / relative: (record["kind"], record.get("target"))
            for relative, record in prefix["links"].items()
        },
    )
    _verify_prefix_snapshot(snapshot)


def prepare_active_runtime_rollback_receipt(
    project: Path, selector_target: str,
) -> Path | None:
    """Prepare/reuse A only when this project's A is the active Linux runtime.

    A selector created on a workstation is a preparation proof, not evidence
    that the flat Linux runtime belongs to A.  Cross-project switches retain
    their established behavior but cannot claim this same-project rollback.
    """
    canonical_project = project.resolve(strict=True)
    match = re.fullmatch(r"generations/([0-9a-f]{20})", selector_target)
    if match is None:
        raise LoadError("selected A generation target is invalid")
    try:
        active = active_project()
    except LoadError as exc:
        # As in activate_project: setup re-points DAY0-Prepare/activate-project, so an invalid
        # pointer is no valid active project here (review 3 S1).  main already refused the non-link
        # one setup cannot switch (review 5 A1).
        warn(f"{exc}；setup 将重建指针")
        active = None
    if active != canonical_project:
        if active is None:
            info(
                "selected A is preparation-only on this host; "
                "no flat runtime rollback receipt is created"
            )
        else:
            warn(
                f"active runtime belongs to {active.name}; target A rollback receipt "
                "is not reusable during this cross-project switch"
            )
        return None
    generation = canonical_project / "99-output-ztp" / selector_target
    receipt_path = (
        canonical_project / "99-output-ztp/rollback-receipts" / match.group(1)
    )
    if os.path.lexists(receipt_path):
        receipt = _load_runtime_rollback_receipt(canonical_project, receipt_path)
        if receipt["schema_version"] != 4:
            raise LoadError("legacy receipt remains recovery-only; new active capture requires schema4; HOLD")
        _verify_active_runtime_receipt(canonical_project, receipt_path, receipt)
        return receipt_path
    receipt_path = prepare_runtime_rollback_receipt(
        canonical_project, generation, capture_selected_dhcp=True,
    )
    receipt = _load_runtime_rollback_receipt(canonical_project, receipt_path)
    _verify_active_runtime_receipt(canonical_project, receipt_path, receipt)
    return receipt_path


def _require_runtime_restore_guard(
    *, deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> None:
    if (deployment_lock_descriptor is None or services_quiesced is not True
            or runtime_backend is None):
        raise LoadError("runtime rollback requires the deployment lock and quiesced services")
    _require_runtime_lock_guard(deployment_lock_descriptor)
    still_active = active_managed_services(
        runtime_backend,
        host_role="workstation" if runtime_os().casefold() == "darwin"
        else "management-server",
    )
    if still_active:
        raise LoadError(
            "runtime rollback requires every managed service to be stopped: "
            + ", ".join(still_active)
        )


_RUNTIME_LOCK_FDINFO_ROOT = Path("/proc/self/fdinfo")
_RUNTIME_LOCK_FDINFO_LIMIT = 65536


def _read_runtime_lock_fdinfo(descriptor: int) -> bytes:
    """Read only the current process's exact FD, never an inode-global lock list."""
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
    opened = os.open(_RUNTIME_LOCK_FDINFO_ROOT / str(descriptor), flags)
    try:
        if not stat.S_ISREG(os.fstat(opened).st_mode):
            raise LoadError("runtime rollback deployment lock fdinfo is not regular; HOLD")
        payload = bytearray()
        while True:
            block = os.read(opened, _RUNTIME_LOCK_FDINFO_LIMIT + 1 - len(payload))
            if not block:
                return bytes(payload)
            payload.extend(block)
            if len(payload) > _RUNTIME_LOCK_FDINFO_LIMIT:
                raise LoadError("runtime rollback deployment lock fdinfo exceeds bounded read; HOLD")
    finally:
        os.close(opened)


def _require_runtime_fdinfo_exclusive(payload: bytes, metadata) -> None:
    """Require one current-OFD, whole-file Linux BSD-flock EX row."""
    error = "runtime rollback deployment lock fdinfo lacks exact current exclusive authority; HOLD"
    if (not isinstance(payload, bytes) or not payload or len(payload) > _RUNTIME_LOCK_FDINFO_LIMIT
            or not payload.endswith(b"\n") or b"\0" in payload or b"\r" in payload):
        raise LoadError(error)
    try:
        lines = payload.decode("ascii").splitlines()
    except UnicodeError as exc:
        raise LoadError(error) from exc
    headers, locks = {}, []
    patterns = {"pos": r"[0-9]+", "flags": r"[0-7]+", "mnt_id": r"[0-9]+", "ino": r"[0-9]+"}
    lock_pattern = (r"lock:[ \t]+([1-9][0-9]*):[ \t]+FLOCK[ \t]+ADVISORY[ \t]+WRITE[ \t]+"
                    r"(-?[0-9]+)[ \t]+([0-9a-fA-F]+):([0-9a-fA-F]+):([0-9]+)[ \t]+0[ \t]+EOF")
    for line in lines:
        if line.startswith("lock:"):
            match = re.fullmatch(lock_pattern, line)
            if match is None:
                raise LoadError(error)
            locks.append(match)
        else:
            name, separator, value = line.partition(":")
            if (not separator or name not in patterns or name in headers
                    or re.fullmatch("[ \\t]+" + patterns[name], value) is None):
                raise LoadError(error)
            headers[name] = value.strip()
    if set(headers) != set(patterns) or len(locks) != 1:
        raise LoadError(error)
    row = locks[0]
    if (int(headers["ino"]) != metadata.st_ino
            or int(row.group(3), 16) != os.major(metadata.st_dev)
            or int(row.group(4), 16) != os.minor(metadata.st_dev)
            or int(row.group(5), 10) != metadata.st_ino):
        raise LoadError(error)
    # The original creator PID can survive dup/fork/exec; it is not the
    # authority. The kernel's current-FD file-description filter is.


def _require_runtime_lock_guard(deployment_lock_descriptor) -> None:
    """Check the original exclusive lock independently of service phase."""
    if type(deployment_lock_descriptor) is not int or deployment_lock_descriptor < 3:
        raise LoadError("runtime rollback deployment lock descriptor is invalid")
    try:
        descriptor_stat = os.fstat(deployment_lock_descriptor)
        lock_stat = DEPLOYMENT_LOCK.lstat()
    except (OSError, ValueError) as exc:
        raise LoadError(f"runtime rollback deployment lock is invalid: {exc}") from exc
    if (not stat.S_ISREG(descriptor_stat.st_mode)
            or not stat.S_ISREG(lock_stat.st_mode)
            or descriptor_stat.st_nlink != 1 or lock_stat.st_nlink != 1
            or (descriptor_stat.st_dev, descriptor_stat.st_ino)
            != (lock_stat.st_dev, lock_stat.st_ino)):
        raise LoadError("runtime rollback deployment lock identity is invalid")
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink")
    identity = tuple(getattr(descriptor_stat, name) for name in fields)
    if identity != tuple(getattr(lock_stat, name) for name in fields):
        raise LoadError("runtime rollback deployment lock metadata is invalid")
    if runtime_os().casefold() == "linux":
        try:
            for _ in range(2):
                _require_runtime_fdinfo_exclusive(
                    _read_runtime_lock_fdinfo(deployment_lock_descriptor), descriptor_stat,
                )
                if (tuple(getattr(os.fstat(deployment_lock_descriptor), name) for name in fields) != identity
                        or tuple(getattr(DEPLOYMENT_LOCK.lstat(), name) for name in fields) != identity):
                    raise LoadError("runtime rollback deployment lock changed during current-FD check; HOLD")
        except (OSError, ValueError) as exc:
            raise LoadError(f"runtime rollback deployment lock fdinfo unavailable; HOLD: {exc}") from exc
        return
    # Darwin: kernel-witnessed VERIFY_PREHELD (shared with the helper).  The
    # witness is registered before the independent SH probe; any release,
    # rename or revoke on the vnode before or around the caller's idempotent
    # EX re-assertion rejects, and a description that never held a flock is
    # rejected before any EX call.  The EX call is never accepted on its own.
    _require_darwin_witnessed_current_exclusive(
        DEPLOYMENT_LOCK, deployment_lock_descriptor, fields, identity, LoadError,
    )


def _atomic_restore_setup_link(path: Path, raw_target: str) -> None:
    _require_no_pending_setup_link_stage(path)
    parent_identity = _setup_switch_link_parent_identity(path)
    temporary = path.parent / (
        f".{path.name}.setup-rollback.{os.getpid()}.{secrets.token_hex(8)}"
    )
    staged_identity = None
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")

    def require_owned_stage() -> None:
        try:
            named = temporary.lstat()
            if (staged_identity is None
                    or parent_identity != _setup_switch_link_parent_identity(path)
                    or not stat.S_ISLNK(named.st_mode) or named.st_nlink != 1
                    or any(getattr(staged_identity, field) != getattr(named, field) for field in fields)
                    or os.readlink(temporary) != raw_target):
                raise LoadError("setup link stage ownership or target changed; HOLD")
            after = temporary.lstat()
            if any(getattr(staged_identity, field) != getattr(after, field) for field in fields):
                raise LoadError("setup link stage changed during inspection; HOLD")
        except (OSError, ValueError, RuntimeError) as exc:
            raise LoadError(f"setup link stage inspection failed; HOLD: {exc}") from exc

    try:
        temporary.symlink_to(raw_target)
        named = temporary.lstat()
        if (not stat.S_ISLNK(named.st_mode) or named.st_nlink != 1
                or os.readlink(temporary) != raw_target):
            raise LoadError("setup link stage is not the created candidate; HOLD")
        staged_identity = named
        require_owned_stage()
        os.replace(temporary, path)
        _fsync_parent_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            try:
                require_owned_stage()
            except LoadError:
                # The generated name does not license deleting another owner.
                # Incomplete initial capture also keeps incident evidence.
                pass
            else:
                temporary.unlink()


def _require_no_pending_setup_link_stage(path: Path) -> None:
    """Preserve unbound link stages; a new random name cannot erase evidence."""
    _require_no_pending_setup_stage(path, f".{path.name}.setup-rollback.", "link")


def _require_no_pending_runtime_restore_stages(
    receipt: dict[str, object], *, project: Path,
) -> None:
    """Scan only the validated A receipt's enumerated recovery names.

    Unknown prior stages have no ownership receipt. Never consume them or
    infer successful recovery from an independently verified managed target.
    The caller holds the deployment lock and keeps other writers quiescent.
    """
    _require_runtime_publickey_parent(receipt)
    stages = {(ZTP_DIR / name, "file") for name in receipt["frozen_files"]}
    stages.update((ZTP_DIR / "config/publickey" / name, "link" if record["state"] == "link" else "file")
                  for name, record in receipt["publickeys"].items())
    for path, kind in sorted(stages):
        if kind == "link":
            _require_no_pending_setup_link_stage(path)
        else:
            _require_no_pending_setup_stage(path, f".{path.name}.rollback-", "runtime file")
    canonical_project = project.resolve(strict=True)
    if canonical_project.name != receipt["project"]:
        raise LoadError("runtime restore stage project does not name receipt A; HOLD")
    latest_records = receipt["yaml_latest"]
    _prevalidate_rollback_latest_targets(canonical_project, latest_records)
    for relative in sorted(latest_records):
        path = canonical_project / relative
        # The validated missing-parent case cannot contain a stage. Do not
        # create it just to inspect absence; known real parents are scanned
        # even when latest itself is already absent on recovery reentry.
        if os.path.lexists(path.parent):
            _require_no_pending_setup_link_stage(path)
            _require_no_pending_setup_stage(path, f".{path.name}.rollback.", "YAML link")
    prefix = receipt["prefix"]
    if prefix["links"] or prefix["marker_b64"] is not None:
        snapshot = ZtpPrefixPublicationSnapshot(
            marker=None if prefix["marker_b64"] is None else base64.b64decode(prefix["marker_b64"], validate=True),
            links={HTTP_ROOT / relative: (row["kind"], row["target"])
                   for relative, row in prefix["links"].items()},
        )
        _prevalidate_prefix_restore(snapshot)
        for path, (kind, _target) in sorted(snapshot.links.items()):
            if kind != "other":
                _require_no_pending_setup_link_stage(path)
                _require_no_pending_setup_stage(path, f".{path.name}.rollback.", "prefix link")
        _require_no_pending_setup_stage(
            ZTP_PREFIX_MARKER, f".{ZTP_PREFIX_MARKER.name}.rollback.", "prefix marker",
        )


def _require_no_pending_setup_stage(path: Path, prefix: str, kind: str) -> None:
    descriptor = -1
    try:
        parent = _setup_switch_link_parent_identity(path)
        descriptor = os.open(parent["path"], os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                             | getattr(os, "O_NOFOLLOW", 0))
        held = os.fstat(descriptor)
        if (not stat.S_ISDIR(held.st_mode)
                or (held.st_dev, held.st_ino) != (parent["dev"], parent["ino"])):
            raise LoadError(f"setup {kind} stage parent changed; HOLD")
        with os.scandir(descriptor) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 4096:
                    raise LoadError(f"setup {kind} stage inspection exceeded its bound; HOLD")
                if entry.name.startswith(prefix):
                    raise LoadError(f"pending setup {kind} stage: {entry.name}; HOLD; preserve incident evidence")
        after = os.fstat(descriptor)
        if (parent != _setup_switch_link_parent_identity(path)
                or any(getattr(held, field) != getattr(after, field)
                       for field in ("st_dev", "st_ino", "st_mtime_ns", "st_ctime_ns"))):
            raise LoadError(f"setup {kind} stage parent changed during inspection; HOLD")
    except (OSError, ValueError, RuntimeError) as exc:
        raise LoadError(f"setup {kind} stage inspection failed; HOLD: {exc}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _setup_switch_directory_identity(path: Path) -> dict[str, object]:
    try:
        canonical = path.resolve(strict=True)
        metadata = canonical.lstat()
    except (OSError, RuntimeError) as exc:
        raise LoadError(f"setup switch directory is unavailable: {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise LoadError(f"setup switch authority is not a directory: {path}")
    return {"path": str(canonical), "dev": metadata.st_dev, "ino": metadata.st_ino}


def _setup_switch_link_parent_identity(path: Path) -> dict[str, object]:
    """Bind a WAL row to the directory that owns its lexical link name."""
    try:
        parent = path.parent.resolve(strict=True)
        metadata = parent.stat()
    except (OSError, RuntimeError) as exc:
        raise LoadError(f"setup switch link parent is unavailable: {path}: {exc}") from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise LoadError(f"setup switch link parent is not a directory: {path}")
    return {"path": str(parent), "dev": metadata.st_dev, "ino": metadata.st_ino}


def _setup_switch_canonical_payload(body: dict[str, object]) -> bytes:
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _setup_switch_a_generation_authority(project, selector_target):
    """Bind original immutable A files before Q's first shared write.

    Matching content is not permission to adopt a replacement generation or
    input inode. This stopped disk qualification alone never starts A.
    """
    project = project.resolve(strict=True)
    if (not isinstance(selector_target, str)
            or re.fullmatch(r"generations/[0-9a-f]{20}", selector_target) is None):
        raise LoadError("A generation selector is invalid; HOLD")
    generation = project / "99-output-ztp" / selector_target
    if generation.resolve(strict=True) != generation:
        raise LoadError("A generation path is not canonical; HOLD")
    parent_owner = _setup_switch_link_parent_identity(generation)
    dhcp = generation / "dhcp"
    release_id, payloads = _pinned_generation_payloads(project,
        generation / "current-release.json", dhcp if dhcp.is_dir() else None)
    if selector_target != "generations/" + release_id:
        raise LoadError("A generation selector differs; HOLD")
    tree = _setup_switch_comparison_tree(generation)
    files = {relative: row for relative, row in tree.items() if row["kind"] == "file"}
    if (set(files) != set(payloads)
            or any(files[name]["sha256"] != hashlib.sha256(payload).hexdigest()
                   for name, payload in payloads.items())
            or parent_owner != _setup_switch_link_parent_identity(generation)):
        raise LoadError("A generation owner or pinned payload changed; HOLD")
    return dict(path=str(generation), parent=parent_owner, tree=tree)


def _setup_switch_comparison_tree(path: Path, *, allow_hardlinks=False,
                                  bind_file_ctime=True) -> dict[str, object]:
    """Freeze a bounded regular-file tree via held, no-follow directory FDs.

    Directory ctime is deliberately not a payload identity: our authorized
    rename changes it. File ctime remains bound to reject write-and-restore.
    Symlinks, special files and hardlinked reports are never transferable.
    """
    tree = {}
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    identity = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")

    def walk(parent_fd, name, relative):
        named = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        directory = stat.S_ISDIR(named.st_mode)
        if not directory and (not stat.S_ISREG(named.st_mode)
                              or not allow_hardlinks and named.st_nlink != 1):
            raise ValueError("comparison entry is not a real directory/single-link regular file")
        descriptor = os.open(name, flags | (getattr(os, "O_DIRECTORY", 0) if directory
                                            else getattr(os, "O_NONBLOCK", 0)), dir_fd=parent_fd)
        try:
            before = os.fstat(descriptor)
            fields = identity + ("st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
            if any(getattr(named, key) != getattr(before, key) for key in fields):
                raise ValueError("comparison owner changed while opening")
            entry = {"kind": "directory" if directory else "file",
                     "dev": before.st_dev, "ino": before.st_ino, "mode": before.st_mode,
                     "uid": before.st_uid, "gid": before.st_gid}
            tree[relative] = entry
            if len(tree) > 4096:
                raise ValueError("comparison tree inventory exceeds bounded entry limit")
            if directory:
                names = sorted(os.listdir(descriptor))
                for child in names:
                    walk(descriptor, child, f"{relative}/{child}" if relative else child)
                if sorted(os.listdir(descriptor)) != names:
                    raise ValueError("comparison directory entries changed")
            else:
                digest = hashlib.sha256()
                while chunk := os.read(descriptor, 1024 * 1024):
                    digest.update(chunk)
                entry.update(size=before.st_size, mtime_ns=before.st_mtime_ns,
                             ctime_ns=before.st_ctime_ns, sha256=digest.hexdigest())
                if not bind_file_ctime:
                    del entry["ctime_ns"]
            after = os.fstat(descriptor)
            current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
            if any(getattr(before, key) != getattr(after, key)
                   or getattr(before, key) != getattr(current, key) for key in fields):
                raise ValueError("comparison tree changed while freezing")
        finally:
            os.close(descriptor)

    parent = os.open(path.parent, flags | getattr(os, "O_DIRECTORY", 0))
    try:
        walk(parent, path.name, "")
    finally:
        os.close(parent)
    return tree


def restore_runtime_rollback_receipt(
    project: Path, receipt_directory: Path, *, expected_current: str,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> None:
    """Restore A after an uncommitted B generation failure, then verify all.

    This is intentionally not an after-commit rollback API.  The A selector,
    parent, report and installed DHCP must still be unchanged.  Any mismatch
    fails before the first write and services must remain stopped.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    canonical_project = project.resolve(strict=True)
    output = canonical_project / "99-output-ztp"
    receipt = _load_runtime_rollback_receipt(canonical_project, receipt_directory)
    _require_runtime_publickey_parent(receipt)
    _require_no_pending_runtime_restore_stages(receipt, project=canonical_project)
    if active_project() != canonical_project:
        raise LoadError("runtime rollback project is not the active project")
    if expected_current != receipt["selector_target"]:
        raise LoadError("rollback expected selector does not name receipt A")
    selector = output / "current"
    if not selector.is_symlink() or os.readlink(selector) != expected_current:
        raise LoadError("rollback selector no longer selects A")
    selector_before = selector.lstat()
    generation = output / expected_current
    generation_dhcp = generation / "dhcp"
    _pinned_generation_payloads(
        canonical_project, generation / "current-release.json",
        generation_dhcp if generation_dhcp.is_dir() else None,
    )
    _verify_rollback_authorities(canonical_project, receipt)
    latest_records = receipt.get("yaml_latest")
    if not isinstance(latest_records, dict):
        raise LoadError("rollback receipt YAML inventory is incomplete")
    _prevalidate_rollback_latest_targets(canonical_project, latest_records)
    prefix_record = receipt.get("prefix")
    if not isinstance(prefix_record, dict) or set(prefix_record) != {"marker_b64", "links"}:
        raise LoadError("rollback receipt prefix record is incomplete")
    links = {}
    for relative, record in prefix_record["links"].items():
        path = HTTP_ROOT / relative
        path.resolve(strict=False).parent.relative_to(HTTP_ROOT.resolve())
        links[path] = (record["kind"], record.get("target"))
    marker = (
        None if prefix_record["marker_b64"] is None
        else base64.b64decode(prefix_record["marker_b64"], validate=True)
    )
    prefix_snapshot = ZtpPrefixPublicationSnapshot(marker=marker, links=links)
    _prevalidate_prefix_restore(prefix_snapshot)

    # All immutable and unchanged authorities are proven before the first write.
    frozen = receipt["frozen_files"]
    for name in frozen:
        target = ZTP_DIR / name
        if os.path.lexists(target) and target.is_dir() and not target.is_symlink():
            raise LoadError(f"rollback target became a directory: {target}")
    publickey_name = ZTP_DIR / "config/publickey"
    if not publickey_name.is_dir() or publickey_name.is_symlink():
        raise LoadError("rollback publickey directory changed; services must remain stopped")
    publickey_dir = publickey_name.resolve(strict=True)
    publickey_dir.relative_to(ZTP_DIR.resolve(strict=True))
    key_records = receipt["publickeys"]
    for name, record in key_records.items():
        if record["state"] == "link":
            _validate_runtime_key_binding(publickey_dir / name, canonical_project, record)
    for current in publickey_dir.glob("*.pub"):
        if current.is_dir() and not current.is_symlink():
            raise LoadError("rollback publickey target became a directory")
    # Hold every immutable receipt payload in memory before the first flat
    # write. A later receipt-tree race can no longer produce a half restore.
    payload_groups: dict[str, dict[str, bytes | None]] = {
        "files": {}, "publickeys": {},
    }
    payload_total = 0
    for group_name, records in (("files", frozen), ("publickeys", key_records)):
        for name, record in records.items():
            if record["state"] == "missing":
                payload_groups[group_name][name] = None
                continue
            opened = _read_rollback_regular(receipt_directory / group_name / name)
            if opened is None:
                raise LoadError("rollback receipt payload disappeared before restore")
            payload, mode = opened
            if (mode != record["mode"]
                    or hashlib.sha256(payload).hexdigest() != record["sha256"]):
                raise LoadError("rollback receipt payload changed before restore")
            payload_total += len(payload)
            if payload_total > _ROLLBACK_TOTAL_LIMIT:
                raise LoadError("rollback receipt payload set is oversized")
            payload_groups[group_name][name] = payload
    _require_runtime_publickey_parent(receipt)
    for name, record in frozen.items():
        _restore_receipt_file(ZTP_DIR / name, record, payload_groups["files"][name])
    for extra in set(path.name for path in publickey_dir.glob("*.pub")) - set(key_records):
        _require_runtime_publickey_parent(receipt)
        path = publickey_dir / extra
        if path.is_dir() and not path.is_symlink():
            raise LoadError("rollback publickey target became a directory")
        path.unlink()
    for name, record in key_records.items():
        _require_runtime_publickey_parent(receipt)
        if record["state"] == "link":
            _validate_runtime_key_binding(publickey_dir / name, canonical_project, record)
            _atomic_restore_setup_link(publickey_dir / name, record["target"])
        else:
            _restore_receipt_file(
                publickey_dir / name, record, payload_groups["publickeys"][name],
            )
    restore_release_links({
        canonical_project / relative: (
            record.get("target") if record["state"] == "link" else None
        )
        for relative, record in latest_records.items()
    })
    if prefix_snapshot.links or prefix_snapshot.marker is not None:
        restore_ztp_prefix_publication(prefix_snapshot)

    # A multi-path restore is not an atomic selector switch.  Report success
    # only after every surface and the unchanged selector have been rechecked.
    _require_runtime_publickey_parent(receipt)
    for name, record in frozen.items():
        path = ZTP_DIR / name
        actual = _describe_receipt_file(path)
        if actual != record:
            raise LoadError(f"rollback post-verify failed for {name}; services remain stopped")
    for name, record in key_records.items():
        if _read_runtime_publickey(publickey_dir / name, canonical_project)[0] != record:
            raise LoadError(f"rollback post-verify failed for public key {name}")
    if {path.name for path in publickey_dir.glob("*.pub")} != set(key_records):
        raise LoadError("rollback public key set post-verify failed")
    _verify_rollback_latest_state(canonical_project, latest_records)
    _verify_prefix_snapshot(prefix_snapshot)
    _verify_rollback_authorities(canonical_project, receipt)
    selector_after = selector.lstat()
    identity = ("st_dev", "st_ino", "st_mode", "st_mtime_ns", "st_ctime_ns")
    if (os.readlink(selector) != expected_current
            or any(getattr(selector_before, field) != getattr(selector_after, field)
                   for field in identity)):
        raise LoadError("rollback selector changed during A restore")
    _require_no_pending_runtime_restore_stages(receipt, project=canonical_project)
    ok(f"A runtime restore verified: {receipt['release_id']}")


def validate_dhcp_output_sources(mappings: dict[Path, Path]) -> None:
    """Admit an empty include only for a proven, unowned zero-host family.

    A fresh project's setup creates zero-byte output placeholders. Scoped c1
    generation owns only its selected family and preserves the other families,
    so an empty unowned include is a valid absence of host declarations. The
    exception never applies to dhcpd.conf or the currently selected family.
    The real staged and installed ``dhcpd -t`` checks remain mandatory.
    """
    empty_hosts: list[Path] = []
    conf_source: Path | None = None
    for source in mappings:
        if source.name == "dhcpd.conf":
            conf_source = source
        if not source.is_file():
            _nonempty_file(source, f"DHCP 输出 {source.name}")
        if source.stat().st_size:
            continue
        if source.name == "dhcpd.conf":
            _nonempty_file(source, f"DHCP 输出 {source.name}")
        if source.name not in {
            "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
        }:
            raise LoadError(f"未知的零字节 DHCP 输出：{source.name}")
        empty_hosts.append(source)
    if not empty_hosts:
        return
    if conf_source is None:
        raise LoadError("DHCP 输出缺少 dhcpd.conf")
    manifest = _load_release_json(
        conf_source.with_name("dhcp-release-manifest.json"),
        "DHCP release manifest",
    )
    counts = manifest.get("counts")
    declarations = (
        counts.get("host_declarations_by_family")
        if isinstance(counts, dict) else None
    )
    if (
        not isinstance(declarations, dict)
        or set(declarations) != {"eth", "ib", "nvl"}
        or any(type(value) is not int or value < 0
               for value in declarations.values())
    ):
        raise LoadError("DHCP release manifest 缺少有效的各 family host 计数")
    outputs = manifest.get("outputs")
    if not isinstance(outputs, dict):
        raise LoadError("DHCP release manifest 缺少 outputs hash")
    for source in mappings:
        item = outputs.get(source.name)
        expected_hash = item.get("sha256") if isinstance(item, dict) else None
        if expected_hash != _sha256_path(source):
            raise LoadError(f"DHCP release 输出 hash 漂移：{source.name}")
    # DEV ad0baea: every family's host declarations must equal the child receipt's exact
    # count, and an empty include is admitted only when that count is 0 (any scope).
    host_declaration = re.compile(
        rb"(?m)^\s*host\s+[A-Za-z0-9][A-Za-z0-9._-]*\s*\{\s*$"
    )
    for source in mappings:
        family = {
            "dhcpd_eth.hosts": "eth", "dhcpd_ib.hosts": "ib", "dhcpd_nvl.hosts": "nvl",
        }.get(source.name)
        if family is not None and (
            len(host_declaration.findall(source.read_bytes())) != declarations[family]
        ):
            raise LoadError(f"DHCP 空 hosts 子收据或内容不一致：{source.name}")
    for source in empty_hosts:
        family = source.name.removeprefix("dhcpd_").removesuffix(".hosts")
        if declarations[family] != 0:
            raise LoadError(
                f"DHCP 输出 {source.name} 大小为 0，但 manifest 声明了 host；"
                "请准备真实内容后再次执行 load"
            )


def bind_empty_dhcp_to_prepared_parent(
    mappings: dict[Path, Path], candidate: PreparedParentRelease | None,
) -> None:
    """Recheck the exact child manifest frozen in the prepared parent.

    A same-output-hash replacement manifest could otherwise change scope or
    counts between release validation and installation. A standalone call
    without a prepared parent remains a local install, not a formal release.
    """
    if candidate is None or not any(
        source.name in {"dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"}
        and source.stat().st_size == 0 for source in mappings
    ):
        return
    temporary = getattr(candidate, "temporary", None)
    if not isinstance(temporary, Path):
        raise LoadError("parent candidate 缺少已冻结的 DHCP manifest 绑定")
    try:
        parent = json.loads(temporary.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"parent candidate 无法复核 DHCP manifest：{exc}") from exc
    if not isinstance(parent, dict):
        raise LoadError("parent candidate 结构无效，无法复核 DHCP manifest")
    conf_source = next(
        (source for source in mappings if source.name == "dhcpd.conf"), None,
    )
    if conf_source is None:
        raise LoadError("DHCP 输出缺少 dhcpd.conf")
    manifest_path = conf_source.with_name("dhcp-release-manifest.json")
    manifest = _load_release_json(manifest_path, "DHCP release manifest")
    components = parent.get("components")
    dhcp = components.get("dhcp") if isinstance(components, dict) else None
    expected_hash = dhcp.get("manifest_sha256") if isinstance(dhcp, dict) else None
    if (
        parent.get("schema_version") != 2
        or parent.get("validation") != "passed"
        or parent.get("dhcp_status") != "enabled"
        or parent.get("release_id") != candidate.release_id
        or parent.get("deployment_scope") != manifest.get("deployment_scope")
        or parent.get("switch_scope") != manifest.get("switch_scope")
        or not isinstance(expected_hash, str)
        or not hmac.compare_digest(expected_hash, _sha256_path(manifest_path))
    ):
        raise LoadError(
            "parent candidate 与当前 DHCP manifest 的 scope/身份不一致；"
            "拒绝空 host 候选覆盖 live 文件"
        )


def recheck_prepared_dhcp_child(
    candidate: PreparedParentRelease, mappings: dict[Path, Path],
) -> None:
    """Keep the prepared parent's DHCP child bound through its final commit."""
    expected_manifest = candidate.dhcp_manifest_sha256
    if expected_manifest is None:
        return
    if candidate.dhcp_source_dir is not None:
        project = candidate.destination.parent.parent
        source = _validated_dhcp_candidate_dir(project, candidate.dhcp_source_dir)
        expected_mappings = dhcp_file_mappings(source)
        try:
            actual = {
                (path.parent.resolve(strict=True), path.name, destination)
                for path, destination in mappings.items()
            }
            expected = {
                (path.parent.resolve(strict=True), path.name, destination)
                for path, destination in expected_mappings.items()
            }
        except OSError as exc:
            raise LoadError(f"DHCP child mappings cannot be resolved: {exc}") from exc
        if actual != expected:
            raise LoadError("DHCP child mappings are not the prepared private candidate")
    try:
        parent = json.loads(candidate.temporary.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"DHCP parent candidate 无法复核：{exc}") from exc
    components = parent.get("components") if isinstance(parent, dict) else None
    dhcp = components.get("dhcp") if isinstance(components, dict) else None
    if (
        not isinstance(parent, dict)
        or parent.get("schema_version") != 2
        or parent.get("validation") != "passed"
        or parent.get("dhcp_status") != "enabled"
        or parent.get("release_id") != candidate.release_id
        or not isinstance(dhcp, dict)
        or dhcp.get("manifest_sha256") != expected_manifest
    ):
        raise LoadError("DHCP parent candidate authority changed before commit")
    conf = next((source for source in mappings if source.name == "dhcpd.conf"), None)
    if conf is None or len(mappings) != 4:
        raise LoadError("DHCP child mappings incomplete before parent commit")
    manifest_path = conf.with_name("dhcp-release-manifest.json")
    if not hmac.compare_digest(_sha256_path(manifest_path), expected_manifest):
        raise LoadError("DHCP child manifest changed before parent commit")
    manifest = _load_release_json(manifest_path, "DHCP release manifest")
    outputs = manifest.get("outputs")
    if (
        not isinstance(outputs, dict)
        or parent.get("deployment_scope") != manifest.get("deployment_scope", "all")
        or parent.get("switch_scope") != manifest.get("switch_scope", "all")
    ):
        raise LoadError("DHCP child manifest scope/outputs changed before parent commit")
    for source in mappings:
        record = outputs.get(source.name)
        expected = record.get("sha256") if isinstance(record, dict) else None
        if (
            not isinstance(expected, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected)
            or not hmac.compare_digest(_sha256_path(source), expected)
        ):
            raise LoadError(f"DHCP child output changed before parent commit: {source.name}")


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


def require_no_pending_dhcp_transaction(runtime_directory: Path | None = None) -> None:
    """Read-only fence for retained/unknown transactions; never recover or clean them.

    Ordinary LOAD calls under its deployment lock, and the install API checks
    again. Any occupied prefix is unresolved evidence, regardless of leaf type
    or payload. A held, no-follow directory read must match the named identity.
    """
    if runtime_directory is None:
        parents = {path.parent for path in dhcp_file_mappings().values()}
        if len(parents) != 1:
            raise LoadError("DHCP runtime directory authority is ambiguous; HOLD")
        runtime_directory = next(iter(parents))
    try:
        before = runtime_directory.lstat()
    except FileNotFoundError:
        return  # Initial installation may create a genuinely absent directory.
    except OSError as exc:
        raise LoadError(f"DHCP runtime directory unreadable; HOLD: {runtime_directory}: {exc}") from exc
    if not stat.S_ISDIR(before.st_mode):
        raise LoadError(f"DHCP runtime directory is not a regular directory; HOLD: {runtime_directory}")
    required = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC")
    if any(not hasattr(os, name) for name in required):
        raise LoadError("DHCP runtime directory requires no-follow directory capability; HOLD")
    descriptor = None
    try:
        descriptor = os.open(
            runtime_directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        )
        identity = _management_directory_identity(before)
        if _management_directory_identity(os.fstat(descriptor)) != identity:
            raise LoadError("DHCP runtime directory changed before scan; HOLD")
        with os.scandir(descriptor) as entries:
            for count, entry in enumerate(entries, 1):
                if count > 4096:
                    raise LoadError("DHCP runtime directory scan limit exceeded; HOLD")
                if entry.name.startswith(".load-dhcp-transaction-"):
                    raise LoadError(
                        f"pending DHCP transaction: {runtime_directory / entry.name}; HOLD，"
                        "保留 B/A 和原事务凭据，须人工核验；不得新安装、自动回退或清理"
                    )
        if (_management_directory_identity(os.fstat(descriptor)) != identity
                or _management_directory_identity(runtime_directory.lstat()) != identity):
            raise LoadError("DHCP runtime directory changed during scan; HOLD")
    except OSError as exc:
        raise LoadError(f"DHCP runtime directory scan failed; HOLD: {runtime_directory}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _dhcp_restore_leaf_state(path: Path) -> dict[str, object]:
    """Read a stable A leaf without following links; not a durable receipt."""
    descriptor = None
    fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
              "st_size", "st_mtime_ns", "st_ctime_ns")

    def identity(metadata):
        return tuple(getattr(metadata, field) for field in fields)

    try:
        try:
            before = path.lstat()
        except FileNotFoundError:
            if os.path.lexists(path):
                raise LoadError(f"DHCP A leaf changed during inspection: {path}")
            return {"state": "missing"}
        record = {
            "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
            "gid": before.st_gid, "mtime_ns": before.st_mtime_ns,
        }
        if stat.S_ISLNK(before.st_mode):
            record.update(state="link", target=os.readlink(path))
        elif stat.S_ISREG(before.st_mode):
            if not hasattr(os, "O_NOFOLLOW"):
                raise LoadError("DHCP A leaf requires nofollow read support")
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0))
            if identity(os.fstat(descriptor)) != identity(before):
                raise LoadError(f"DHCP A leaf changed while opening: {path}")
            digest, count, remaining = hashlib.sha256(), 0, before.st_size + 1
            while remaining:
                chunk = os.read(descriptor, min(1024 * 1024, remaining))
                if not chunk:
                    break
                digest.update(chunk)
                count += len(chunk)
                remaining -= len(chunk)
            if count != before.st_size or identity(os.fstat(descriptor)) != identity(before):
                raise LoadError(f"DHCP A leaf changed while reading: {path}")
            record.update(state="file", size=count, sha256=digest.hexdigest())
        else:
            raise LoadError(f"DHCP A leaf is neither a regular file nor link: {path}")
        if identity(path.lstat()) != identity(before):
            raise LoadError(f"DHCP A leaf changed after reading: {path}")
        return record
    except OSError as exc:
        raise LoadError(f"DHCP A leaf cannot be safely inspected: {path}: {exc}") from exc
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _sync_verified_dhcp_a_restore(
    runtime_directory: Path, original_states: dict[Path, dict[str, object]],
) -> None:
    """Sync restored regular leaves, then names, before backup cleanup.

    Held nofollow descriptors and postchecks reject known rebinds. This is
    neither a persistent grouped recovery receipt nor a power-loss witness.
    """
    try:
        if any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
            raise LoadError("restored DHCP A requires nofollow directory support")
        before_directory = runtime_directory.lstat()
        if not stat.S_ISDIR(before_directory.st_mode):
            raise LoadError("restored DHCP A runtime directory is not a real directory")
        directory_identity = _management_directory_identity(before_directory)
        flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        directory_fd = os.open(runtime_directory, flags | os.O_DIRECTORY)
        try:
            if _management_directory_identity(os.fstat(directory_fd)) != directory_identity:
                raise LoadError("restored DHCP A directory changed while opening")
            for path, expected_state in original_states.items():
                if path.parent != runtime_directory:
                    raise LoadError("restored DHCP A leaf escaped its runtime directory")
                if expected_state["state"] != "file":
                    continue  # Names/links are persisted by the parent fsync.
                before = path.lstat()
                descriptor = os.open(path.name, flags, dir_fd=directory_fd)
                try:
                    opened = os.fstat(descriptor)
                    if (not stat.S_ISREG(opened.st_mode)
                            or _runtime_key_identity(opened) != _runtime_key_identity(before)
                            or (opened.st_uid, opened.st_gid) != (before.st_uid, before.st_gid)):
                        raise LoadError("restored DHCP A leaf changed while opening for sync")
                    os.fsync(descriptor)
                    if (_runtime_key_identity(os.fstat(descriptor)) != _runtime_key_identity(before)
                            or _runtime_key_identity(path.lstat()) != _runtime_key_identity(before)):
                        raise LoadError("restored DHCP A leaf changed during sync")
                finally:
                    os.close(descriptor)
            os.fsync(directory_fd)
            if (_management_directory_identity(os.fstat(directory_fd)) != directory_identity
                    or _management_directory_identity(runtime_directory.lstat()) != directory_identity):
                raise LoadError("restored DHCP A directory changed during sync")
            for path, expected_state in original_states.items():
                if _dhcp_restore_leaf_state(path) != expected_state:
                    raise LoadError("restored DHCP A preimage changed during sync")
        finally:
            os.close(directory_fd)
    except (OSError, LoadError) as exc:
        raise LoadError(f"DHCP A restore durability unconfirmed; HOLD: {exc}") from exc


def _sync_verified_dhcp_a_backup(
    runtime_directory: Path, backup_directory: Path,
    original_states: dict[Path, dict[str, object]],
) -> None:
    """Persist verified A payloads and their names before the first B write.

    This bounds cooperative identity drift, not a grouped recovery receipt,
    ancestor compare-and-write or a power-loss witness.
    """
    descriptors = []
    try:
        transaction = backup_directory.parent
        if (transaction.parent != runtime_directory
                or not transaction.name.startswith(".load-dhcp-transaction-")
                or backup_directory.name != "backup"
                or any(path.parent != runtime_directory for path in original_states)):
            raise LoadError("A backup ancestry is outside the DHCP transaction")
        if any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
            raise LoadError("A backup requires nofollow directory support")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        for path in (runtime_directory, transaction, backup_directory):
            before = path.lstat()
            if not stat.S_ISDIR(before.st_mode):
                raise LoadError("A backup ancestor is not a real directory")
            if path == backup_directory and stat.S_IMODE(before.st_mode) != 0o700:
                raise LoadError("A backup directory is not private")
            identity = _management_directory_identity(before)
            descriptor = (os.open(path, flags) if not descriptors else
                          os.open(path.name, flags, dir_fd=descriptors[-1][1]))
            descriptors.append((path, descriptor, identity))
            if _management_directory_identity(os.fstat(descriptor)) != identity:
                raise LoadError("A backup ancestor changed while opening")

        def recheck() -> None:
            for path, descriptor, identity in descriptors:
                if (_management_directory_identity(os.fstat(descriptor)) != identity
                        or _management_directory_identity(path.lstat()) != identity):
                    raise LoadError("A backup ancestry changed during sync")
            for original, expected in original_states.items():
                if (_dhcp_restore_leaf_state(original) != expected
                        or _dhcp_restore_leaf_state(backup_directory / original.name) != expected):
                    raise LoadError("A or its backup preimage changed during sync")

        recheck()
        backup_states = {backup_directory / path.name: state
                         for path, state in original_states.items()}
        # The existing held-FD synchronizer persists regular payloads followed
        # by the backup directory, including symlink/absent-name preimages.
        _sync_verified_dhcp_a_restore(backup_directory, backup_states)
        recheck()
        for _path, descriptor, _identity in reversed(descriptors[:2]):
            os.fsync(descriptor)  # transaction name, then runtime ancestry
            recheck()
    except (OSError, LoadError) as exc:
        raise LoadError(f"DHCP A backup durability unconfirmed; HOLD: {exc}") from exc
    finally:
        for _path, descriptor, _identity in reversed(descriptors):
            os.close(descriptor)


def _dhcp_a_preimage_receipt_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return tuple(getattr(metadata, field) for field in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns",
    ))


def _prepare_dhcp_a_preimage_receipt(
    runtime_directory: Path, transaction: Path,
    original_states: dict[Path, dict[str, object]],
    after_sha256: dict[str, str], parent_candidate: PreparedParentRelease | None,
) -> tuple[Path, bytes, tuple[int, ...]]:
    """Persist a bounded four-file before-image before any B overwrite.

    The following backup synchronizer persists its containing ancestry. This
    record is evidence, not permission to restore A, retire a setup WAL or
    activate services. A fresh process must still HOLD on the transaction.
    """
    descriptors = []
    receipt_fd = None
    try:
        names = {"dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts"}
        if (transaction.parent != runtime_directory
                or not transaction.name.startswith(".load-dhcp-transaction-")
                or {path.name for path in original_states} != names
                or any(path.parent != runtime_directory for path in original_states)
                or set(after_sha256) != names
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in after_sha256.values())):
            raise LoadError("four-file preimage inventory is invalid")
        if any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW")):
            raise LoadError("preimage requires nofollow directory capability")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)

        def directory_identity(path, metadata):
            if not stat.S_ISDIR(metadata.st_mode):
                raise LoadError("preimage ancestor is not a real directory")
            return {"path": str(path), "dev": metadata.st_dev, "ino": metadata.st_ino,
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "uid": metadata.st_uid, "gid": metadata.st_gid}

        authorities = {}
        for path in (runtime_directory, transaction, transaction / "backup"):
            expected = directory_identity(path, path.lstat())
            descriptor = (os.open(path, flags) if not descriptors else
                          os.open(path.name, flags, dir_fd=descriptors[-1][1]))
            descriptors.append((path, descriptor, expected))
            if directory_identity(path, os.fstat(descriptor)) != expected:
                raise LoadError("preimage ancestor changed while opening")
            authorities[path] = expected
        if authorities[transaction / "backup"]["mode"] != 0o700:
            raise LoadError("preimage backup directory is not private")

        def recheck():
            for path, descriptor, expected in descriptors:
                if (directory_identity(path, os.fstat(descriptor)) != expected
                        or directory_identity(path, path.lstat()) != expected):
                    raise LoadError("preimage ancestry changed")
            for path, expected in original_states.items():
                if (_dhcp_restore_leaf_state(path) != expected
                        or _dhcp_restore_leaf_state(transaction / "backup" / path.name) != expected):
                    raise LoadError("preimage or backup changed")

        parent = None
        if parent_candidate is not None:
            candidate_bytes, _mode = _read_rollback_regular(parent_candidate.temporary)
            parent = {
                "destination": str(parent_candidate.destination),
                "directory": directory_identity(parent_candidate.destination.parent,
                                                parent_candidate.destination.parent.lstat()),
                "before": _dhcp_restore_leaf_state(parent_candidate.destination),
                "candidate": {"release_id": parent_candidate.release_id,
                              "sha256": hashlib.sha256(candidate_bytes).hexdigest(),
                              "size": len(candidate_bytes)},
            }
        body = {"schema_version": 1, "phase": "prepared-a",
                "runtime": authorities[runtime_directory],
                "transaction": authorities[transaction],
                "backup": authorities[transaction / "backup"],
                "before": {path.name: state for path, state in original_states.items()},
                "after_sha256": dict(after_sha256), "parent": parent}
        canonical = lambda value: json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        ).encode("utf-8")
        payload = canonical({"body": body, "sha256": hashlib.sha256(canonical(body)).hexdigest()}) + b"\n"
        if len(payload) > _ROLLBACK_MARKER_LIMIT:
            raise LoadError("preimage receipt exceeds bounded size")
        recheck()
        receipt = transaction / "a-preimage.json"
        receipt_fd = os.open(
            receipt.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
            | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=descriptors[1][1],
        )
        os.fchmod(receipt_fd, 0o600)
        pending = memoryview(payload)
        while pending:
            count = os.write(receipt_fd, pending)
            if count <= 0:
                raise LoadError("preimage receipt write made no progress")
            pending = pending[count:]
        os.fsync(receipt_fd)
        expected_identity = _dhcp_a_preimage_receipt_identity(os.fstat(receipt_fd))
        _verify_dhcp_a_preimage_receipt((receipt, payload, expected_identity))
        recheck()
        return receipt, payload, expected_identity
    except (OSError, ValueError, LoadError) as exc:
        raise LoadError(f"DHCP A preimage receipt unconfirmed; HOLD: {exc}") from exc
    finally:
        if receipt_fd is not None:
            os.close(receipt_fd)
        for _path, descriptor, _expected in reversed(descriptors):
            os.close(descriptor)


def _verify_dhcp_a_preimage_receipt(receipt_state, *, backup_required: bool = True) -> None:
    """Check the original receipt authority before its authorized cleanup."""
    path, payload, identity = receipt_state
    try:
        body = json.loads(payload)["body"]

        def require_ancestry():
            for role in ("runtime", "transaction", "backup") if backup_required else ("runtime", "transaction"):
                expected = body[role]
                directory = Path(expected["path"])
                metadata = directory.lstat()
                if (not stat.S_ISDIR(metadata.st_mode)
                        or {"path": str(directory), "dev": metadata.st_dev, "ino": metadata.st_ino,
                            "mode": stat.S_IMODE(metadata.st_mode),
                            "uid": metadata.st_uid, "gid": metadata.st_gid} != expected):
                    raise LoadError("preimage receipt ancestry changed")

        require_ancestry()
        if (_dhcp_a_preimage_receipt_identity(path.lstat()) != identity
                or _read_rollback_regular(path, limit=_ROLLBACK_MARKER_LIMIT) != (payload, 0o600)
                or _dhcp_a_preimage_receipt_identity(path.lstat()) != identity):
            raise LoadError("preimage receipt identity or bytes changed")
        require_ancestry()
    except (OSError, LoadError) as exc:
        raise LoadError(f"DHCP A preimage receipt changed; HOLD: {exc}") from exc


def _setup_switch_dhcp_owned_leaf(path):
    """Bounded no-follow leaf identity plus independent original metadata/bytes."""
    metadata = path.lstat() if os.path.lexists(path) else None
    owner = list(_dhcp_a_preimage_receipt_identity(metadata)) if metadata else None
    if metadata is not None and (metadata.st_nlink != 1 or metadata.st_size > _ROLLBACK_PAYLOAD_LIMIT):
        raise LoadError("DHCP compensation leaf owner is not bounded/single-link; HOLD")
    state = _dhcp_restore_leaf_state(path)
    after = path.lstat() if os.path.lexists(path) else None
    if owner != (list(_dhcp_a_preimage_receipt_identity(after)) if after else None):
        raise LoadError("DHCP compensation leaf owner changed during read; HOLD")
    return None if owner is None else dict(identity=owner, state=state)


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
    An incomplete restore instead retains its transaction and A evidence;
    command exit0 also requires exact restored leaf/content/metadata checks
    before syncing restored files/names and deleting backups. This still does
    not prove a complete persistent recovery receipt or healthy activation.
    A backups must also verify and sync their payloads and directory ancestry
    before the first B write; an unconfirmed backup leaves original A intact.
    Once B is visible, unconfirmed parent directory durability instead keeps
    installed B and the root-only A backup together for manual HOLD review.
    """
    if (parent_candidate is not None and parent_candidate.committed
            and not parent_candidate.directory_synced):
        raise LoadError(
            "DHCP 安装拒绝重入：B 已可见，但目录持久化仍未确认；HOLD，"
            "保留第一次事务的 B/A 备份，不得重新安装、回退或清理；须人工核验"
        )
    mappings = dhcp_file_mappings(
        parent_candidate.dhcp_source_dir if parent_candidate is not None else None
    )
    destination_parents = {destination.parent for destination in mappings.values()}
    if len(destination_parents) != 1:
        raise LoadError("四个 DHCP 运行文件必须位于同一目录，无法建立事务 staging")
    dhcp_runtime_dir = next(iter(destination_parents))
    if not dry_run:
        require_no_pending_dhcp_transaction(dhcp_runtime_dir)
    validate_dhcp_output_sources(mappings)
    bind_empty_dhcp_to_prepared_parent(mappings, parent_candidate)
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
    backup_unconfirmed = False
    restore_incomplete = False
    preimage_receipt = None
    build_workspace: tempfile.TemporaryDirectory[str] | None = None
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

        build_workspace = tempfile.TemporaryDirectory(prefix="load-dhcp-build-")
        build_dir = Path(build_workspace.name)
        for source in mappings:
            shutil.copy2(source.resolve(), build_dir / source.name)
        frozen_hashes = {
            source.name: _sha256_path(build_dir / source.name) for source in mappings
        }
        staged_text = _rewrite_dhcp_staging_includes(
            (build_dir / "dhcpd.conf").read_text(encoding="utf-8"), staged_dir,
        )
        staged_build_conf = build_dir / "staged-dhcpd.conf"
        staged_build_conf.write_text(staged_text, encoding="utf-8")
        for source in mappings:
            stage_source = (
                staged_build_conf if source.name == "dhcpd.conf"
                else build_dir / source.name
            )
            run(sudo_command(
                "install", "-m", "0644", "--",
                str(stage_source), str(staged_dir / source.name),
            ))

        staged_conf = staged_dir / "dhcpd.conf"
        run(sudo_command("dhcpd", "-t", "-cf", str(staged_conf)))
        for source in mappings:
            if _sha256_path(source) != frozen_hashes[source.name]:
                raise LoadError(f"DHCP source changed after staged syntax: {source.name}")
        if parent_candidate is not None:
            recheck_prepared_dhcp_child(parent_candidate, mappings)

        original_states = {destination: _dhcp_restore_leaf_state(destination) for destination in mappings.values()}
        existed: dict[Path, bool] = {}
        for destination in mappings.values():
            existed[destination] = original_states[destination]["state"] != "missing"
            if existed[destination]:
                run(
                    sudo_command(
                        "cp", "-a", "--", str(destination),
                        str(backup_dir / destination.name),
                    )
                )

        # A successful copy command is not proof of a usable A preimage.
        # Check every backup (including original absence/links) before the
        # first B install. Keep an invalid/unknown backup as incident evidence.
        backup_unconfirmed = True
        for destination, expected_state in original_states.items():
            try:
                backup_state = _dhcp_restore_leaf_state(backup_dir / destination.name)
            except LoadError as exc:
                raise LoadError(
                    f"DHCP A backup verification failed; HOLD: {destination.name}: {exc}"
                ) from exc
            if backup_state != expected_state:
                raise LoadError(
                    f"DHCP A backup verification failed; HOLD: {destination.name}"
                )
        preimage_receipt = _prepare_dhcp_a_preimage_receipt(
            dhcp_runtime_dir, transaction_dir, original_states, frozen_hashes, parent_candidate,
        )
        _sync_verified_dhcp_a_backup(dhcp_runtime_dir, backup_dir, original_states)
        _verify_dhcp_a_preimage_receipt(preimage_receipt)
        backup_unconfirmed = False

        try:
            for source, destination in mappings.items():
                # AppArmor resolves symlink targets and can deny HTTP-root
                # paths.  The installed runtime artifact must be a regular
                # file below /etc/dhcp. Install the same original bytes used
                # to build the staged candidate, never a second source read.
                run(
                    sudo_command(
                        "install", "-m", "0644", str(build_dir / source.name),
                        str(destination),
                    )
                )
            run(sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"))
            for source, destination in mappings.items():
                expected = frozen_hashes[source.name]
                if (_sha256_path(source) != expected
                        or _sha256_path(destination) != expected):
                    raise LoadError(
                        f"DHCP source/installed output changed before parent commit: {source.name}"
                    )
            # A cleanup failure must occur while rollback is still possible.
            build_workspace.cleanup()
            build_workspace = None
            if parent_candidate is not None:
                # Keep the old DHCP files available until the only externally
                # visible commit marker has been atomically replaced.  If the
                # parent commit fails, this exception path restores all four
                # installed files before load releases its deployment lock.
                commit_prepared_release(parent_candidate)
        except BaseException:
            if parent_candidate is not None and parent_candidate.committed:
                # Directory fsync can fail after the atomic parent replace.
                # Keep visible B and installed B DHCP together, but propagate
                # the HOLD before any service start. Rolling DHCP back behind
                # the new parent would create the inverse split-brain.
                raise
            # Set before any rollback command (or warning). Return-code failure,
            # exception, interruption or death cannot license A backup deletion.
            restore_incomplete = True
            warn("DHCP 安装或最终语法检查失败；正在恢复本次操作前的四个文件")
            restore_errors = []
            for destination in mappings.values():
                result = _run_subprocess(
                    sudo_command("rm", "-f", "--", str(destination)), check=False,
                )
                if result.returncode != 0:
                    restore_errors.append(str(destination))
                    continue
                if existed[destination]:
                    result = _run_subprocess(
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
            for destination, expected_state in original_states.items():
                try:
                    actual_state = _dhcp_restore_leaf_state(destination)
                except LoadError as exc:
                    raise LoadError(
                        f"DHCP A restore verification failed; HOLD: {destination}: {exc}"
                    ) from exc
                if actual_state != expected_state:
                    raise LoadError(
                        f"DHCP A restore verification failed; HOLD: {destination}"
                    )
            _sync_verified_dhcp_a_restore(dhcp_runtime_dir, original_states)
            restore_incomplete = False
            raise
    finally:
        if build_workspace is not None:
            build_workspace.cleanup()
        if transaction_created and (backup_unconfirmed or restore_incomplete or (
                parent_candidate is not None and parent_candidate.committed
                and not parent_candidate.directory_synced)):
            # Invalid backups, partial A restore and uncertain visible B may
            # not erase incident evidence. Retention alone proves neither
            # complete rollback, activation nor power-loss durability.
            try:
                warn(
                    ("HOLD：DHCP 原 A 备份校验/持久化未确认；" if backup_unconfirmed
                     else "HOLD：DHCP 旧文件恢复未完成；" if restore_incomplete
                     else "HOLD：B 已可见但目录持久化未确认；")
                    + f"保留 DHCP 事务及 root-only A 备份：{transaction_dir}；"
                    "服务保持停止，须人工核验实际 A/B 状态，不自动回退或清理"
                )
            except BrokenPipeError:
                pass
        elif transaction_created:
            # Never delete the backups when their new persisted authority was
            # replaced or changed by an unknown writer after B installation.
            if preimage_receipt is not None:
                _verify_dhcp_a_preimage_receipt(preimage_receipt)
            cleanup_failed = False
            for directory in (staged_dir, backup_dir):
                for name in mappings:
                    result = _run_subprocess(
                        sudo_command("rm", "-f", "--", str(directory / name.name)),
                        check=False,
                    )
                    cleanup_failed = cleanup_failed or result.returncode != 0
            for directory in (backup_dir, staged_dir):
                result = _run_subprocess(
                    sudo_command("rmdir", "--", str(directory)), check=False,
                )
                cleanup_failed = cleanup_failed or result.returncode != 0
            if not cleanup_failed and preimage_receipt is not None:
                _verify_dhcp_a_preimage_receipt(preimage_receipt, backup_required=False)
                preimage_receipt[0].unlink()
                _fsync_parent_directory(transaction_dir)
            result = _run_subprocess(
                sudo_command("rmdir", "--", str(transaction_dir)), check=False,
            )
            cleanup_failed = cleanup_failed or result.returncode != 0
            if cleanup_failed:
                warn(f"DHCP 事务目录清理失败，请手工删除：{transaction_dir}")
    ok("四个 DHCP 文件已事务式复制到 /etc/dhcp，dhcpd -t 检查通过；服务尚未启动")


def _device_types_after_dhcp(
    device_types: frozenset[str], *, dry_run: bool,
    schema_version: int = GLOBAL_SCHEMA_VERSION,
    deployment_scope: str = "all",
    switch_scope: str = "all",
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
        effective_types = set(load_device_types(
            devices_csv, schema_version, switch_scope=switch_scope,
        ))
    # AIR-only nodes intentionally stay out of the unified CSV, but they still
    # require baseline Cumulus YAML and MAC-link publication.  Inspect the
    # actual topology nodes in both normal and dry-run paths rather than using
    # a non-empty JSON file as a proxy.
    if p2p_air_json.is_file() and any(
        item.get("type") == "air"
        for item in _augment_air_json_inventory([], p2p_air_json)
    ):
        effective_types.add("air")
    if deployment_scope == "air":
        effective_types &= {"air"}
    elif deployment_scope == "prod":
        effective_types.discard("air")
    elif deployment_scope != "all":
        raise LoadError(f"无法识别 deployment scope：{deployment_scope!r}")
    return filter_device_types_for_switch_scope(effective_types, switch_scope)


def _sha256_path(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def p2p_release_source_binding(project: Path, selected_input: Path) -> dict[str, str]:
    """Bind the selected real project-root workbook, not its canonical link."""
    try:
        source = select_upload_p2p(project)
        if selected_input.resolve(strict=True) != source.resolve(strict=True):
            raise LoadError(
                "P2P release 输入与 p2p.xlsx 选择记录不一致："
                f"input={selected_input.name} selected={source.name}"
            )
        return {"path": p2p_source_relative(project, source), "sha256": _sha256_path(source)}
    except (OSError, ValueError) as exc:
        raise LoadError(f"P2P release 真实来源无效：{exc}") from exc


def _project_source_identities(inputs: ProjectInputs) -> dict[str, str]:
    sources = {
        "global": inputs.global_file,
        "devices": inputs.devices_file,
        "subnet": inputs.subnet_file,
        "p2p": inputs.p2p_file,
    }
    if inputs.air_topology_policy is not None:
        sources["air_topology_policy"] = inputs.air_topology_policy
    if inputs.mini_devices_file is not None:
        sources["mini_air_devices"] = inputs.mini_devices_file
    try:
        return {name: _sha256_path(path) for name, path in sources.items()}
    except OSError as exc:
        raise LoadError(f"无法读取 release 输入 authority：{exc}") from exc


def _require_mini_sampling_policy(path: Path | None) -> None:
    if path is None:
        raise LoadError(
            "--mini requires 03-air-topology-policy.json field mini_sampling"
        )
    try:
        with path.open(encoding="utf-8") as stream:
            document = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"AIR 拓扑策略 JSON 无效：{exc}") from exc
    if not isinstance(document, dict) or not isinstance(
        document.get("mini_sampling"), dict,
    ):
        raise LoadError(
            "03-air-topology-policy.json is missing required mini_sampling"
        )


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
            # Server rows are not release devices; a server_ufm row may stop
            # after eth0_mac, so skip them before the identity-width check.
            device_type = row[type_col].casefold() if type_col < len(row) else ""
            if device_type in SERVER_TYPES:
                continue
            if max(hostname_col, type_col, eth0_mac_col, eth1_mac_col) >= len(row):
                raise LoadError(f"统一 release：devices_config.csv 第 {lineno} 行列数不足")
            hostname = row[hostname_col]
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


def _inventory_for_release_scope(
    inventory: list[dict[str, object]], *,
    deployment_scope: str, switch_scope: str,
) -> list[dict[str, object]]:
    """Apply environment and platform selectors to one release inventory."""
    if deployment_scope == "air":
        scoped = [item for item in inventory if item["type"] == "air"]
    elif deployment_scope == "prod":
        scoped = [item for item in inventory if item["type"] != "air"]
    elif deployment_scope == "all":
        scoped = list(inventory)
    else:
        raise LoadError(
            f"无法识别 parent release deployment scope：{deployment_scope!r}"
        )
    allowed = SWITCH_SCOPE_TYPES.get(switch_scope)
    if allowed is None:
        raise LoadError(
            f"无法识别 parent release switch scope：{switch_scope!r}"
        )
    return [item for item in scoped if str(item["type"]) in allowed]


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
    elif label == "nvos":
        fixed_names = {
            "ib": "default_ib.yaml",
            "nvl": "default_nvl.yaml",
        }
        families = {
            str(item.get("type") or "").strip()
            for item in rows if isinstance(item, dict)
        }
        if not families or not families <= set(fixed_names):
            raise LoadError(f"nvos release 包含无效 family 集合：{sorted(families)}")
        defaults = manifest.get("effective_defaults")
        if not isinstance(defaults, dict) or set(defaults) != families:
            raise LoadError(
                "nvos effective_defaults family 集合漂移："
                f"expected={sorted(families)} actual="
                f"{sorted(defaults) if isinstance(defaults, dict) else '<invalid>'}"
            )
        declared_names: set[str] = set()
        for family in sorted(families):
            row = defaults.get(family)
            if not isinstance(row, dict):
                raise LoadError(f"nvos {family} effective default manifest 无效")
            name = str(row.get("name") or "").strip()
            if name != fixed_names[family]:
                raise LoadError(
                    f"nvos {family} effective default 名称必须为 "
                    f"{fixed_names[family]!r}，实际为 {name!r}"
                )
            declared_names.add(name)
            path = release_dir / name
            try:
                metadata = path.lstat()
            except OSError as exc:
                raise LoadError(f"nvos {family} effective default 缺失：{path}") from exc
            if (
                path.is_symlink()
                or not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o644
                or metadata.st_size <= 0
            ):
                raise LoadError(
                    f"nvos {family} effective default 必须是 0644、非空、"
                    f"单链接普通文件：{path}"
                )
            try:
                expected_size = int(row.get("size"))
            except (TypeError, ValueError) as exc:
                raise LoadError(f"nvos {family} effective default size 无效") from exc
            if metadata.st_size != expected_size:
                raise LoadError(f"nvos {family} effective default size 漂移：{path}")
            expected_hash = str(row.get("sha256") or "").strip().casefold()
            if not expected_hash or _sha256_path(path) != expected_hash:
                raise LoadError(f"nvos {family} effective default hash 漂移：{path}")
            try:
                document = _strict_yaml_document(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, yaml.YAMLError, ValueError) as exc:
                raise LoadError(f"nvos {family} effective default YAML 无效：{exc}") from exc
            systems = [
                item.get("set", {}).get("system")
                for item in document if isinstance(item, dict)
                and isinstance(item.get("set"), dict)
                and isinstance(item.get("set", {}).get("system"), dict)
            ] if isinstance(document, list) else []
            if len(systems) != 1:
                raise LoadError(f"nvos {family} effective default 缺少唯一 set.system")
            def contains_null(value: object) -> bool:
                if value is None:
                    return True
                if isinstance(value, dict):
                    return any(
                        key is None or contains_null(child)
                        for key, child in value.items()
                    )
                if isinstance(value, list):
                    return any(contains_null(child) for child in value)
                return False
            if contains_null(document):
                raise LoadError(f"nvos {family} effective default 不允许 null")

        actual_names = {
            path.name for path in release_dir.iterdir()
            if re.fullmatch(r"default(?:_[A-Za-z0-9-]+)?\.yaml", path.name)
        }
        if actual_names != declared_names:
            raise LoadError(
                "nvos effective default 文件集合漂移："
                f"expected={sorted(declared_names)} actual={sorted(actual_names)}"
            )


def _published_breakouts(path: Path) -> dict[str, str]:
    """Read exact physical breakout intent from one already-published YAML."""
    try:
        document = _strict_yaml_document(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise LoadError(f"cumulus breakout YAML 无法解析：{path}: {exc}") from exc
    fragments = document if isinstance(document, list) else [document]
    found: dict[str, str] = {}
    for fragment in fragments:
        if not isinstance(fragment, dict):
            continue
        settings = fragment.get("set")
        interfaces = settings.get("interface") if isinstance(settings, dict) else None
        if interfaces is None:
            continue
        if not isinstance(interfaces, dict):
            raise LoadError(f"cumulus interface YAML 不是 mapping：{path}")
        for parent, interface in interfaces.items():
            link = interface.get("link") if isinstance(interface, dict) else None
            if not isinstance(link, dict) or "breakout" not in link:
                continue
            breakout = link["breakout"]
            if (not isinstance(parent, str)
                    or not re.fullmatch(r"swp[0-9]+", parent)
                    or not isinstance(breakout, dict)
                    or len(breakout) != 1):
                raise LoadError(f"cumulus breakout 结构无效：{path}:{parent}")
            mode, value = next(iter(breakout.items()))
            count = {"2x": 2, "4x": 4, "8x": 8}.get(mode)
            if (count is None or not isinstance(value, dict)
                    or set(value) != {"lanes-per-port"}
                    or isinstance(value["lanes-per-port"], bool)
                    or str(value["lanes-per-port"]) != str(8 // count)
                    or parent in found):
                raise LoadError(f"cumulus breakout mode/lanes 无效或重复：{path}:{parent}")
            found[parent] = f"1to{count}"
    return found


def _source_yaml_receipts(path: Path, schema_version: int) -> dict[str, bytes]:
    """Independently validate the generator's CSV source-receipt contract."""
    receipts: dict[str, bytes] = {}
    try:
        with path.open(newline="", encoding="utf-8-sig") as stream:
            reader = csv.reader(stream)
            header = [str(cell or "").strip().casefold() for cell in next(reader, [])]
            metadata = ("source_yaml_b64", "source_yaml_sha256", "source_fields_sha256")
            if not any(name in header for name in metadata):
                return receipts
            layout = parse_device_csv_layout(header, schema_version)
            if tuple(header[layout.metadata_start:]) != metadata:
                raise ValueError("source YAML metadata columns are incomplete")
            for lineno, raw in enumerate(reader, 2):
                if not any(raw):
                    continue
                require_device_csv_row_width(raw, len(header), schema_version,
                                             lineno=lineno)
                row = [str(cell or "").strip() for cell in raw]
                row.extend([""] * max(0, len(header) - len(row)))
                hostname = row[0].casefold()
                if not hostname or hostname in receipts:
                    raise ValueError(f"duplicate/empty source receipt hostname: {hostname!r}")
                encoded, source_sha, fields_sha = row[layout.metadata_start:len(header)]
                if not encoded or encoded.casefold() == "na":
                    continue
                actual_fields = hashlib.sha256(json.dumps(
                    row[:layout.metadata_start], ensure_ascii=False,
                    separators=(",", ":"),
                ).encode("utf-8")).hexdigest()
                if (not re.fullmatch(r"[0-9a-fA-F]{64}", fields_sha)
                        or not hmac.compare_digest(fields_sha.casefold(), actual_fields)
                        or not re.fullmatch(r"[0-9a-fA-F]{64}", source_sha)):
                    raise ValueError(f"source YAML metadata digest invalid: {hostname}")
                prefix = "gzip+base64:"
                compressed = encoded.startswith(prefix)
                payload = encoded[len(prefix):] if compressed else encoded
                source = base64.b64decode(payload, validate=True)
                if compressed:
                    source = gzip.decompress(source)
                if not hmac.compare_digest(
                    hashlib.sha256(source).hexdigest(), source_sha.casefold(),
                ):
                    raise ValueError(f"source YAML digest changed: {hostname}")
                source_document = _strict_yaml_document(source.decode("utf-8"))
                if not (isinstance(source_document, list) and any(
                    isinstance(item, dict) and isinstance(item.get("set"), dict)
                    for item in source_document
                )):
                    raise ValueError(f"source YAML must contain set mapping: {hostname}")
                receipts[hostname] = source
    except (OSError, UnicodeError, ValueError, binascii.Error, EOFError) as exc:
        raise LoadError(f"cumulus source YAML receipt 无效：{path}: {exc}") from exc
    return receipts


def _sidecar_profiles_for_child(
    expected: dict[str, dict[str, str]], hostname: str,
) -> dict[str, str] | None:
    """Resolve one child hostname against P2P's site-qualified device keys.

    The Cumulus child accepts either an exact key or one ``-hostname``
    boundary suffix.  AIR child releases use the managed ``AIR-`` prefix but
    retain the production topology's breakout authority, so that prefix is
    also removed for matching.  More than one matching owner is ambiguous
    even when its profile happens to be identical, so parent provenance must
    fail closed.
    """
    identities = {hostname}
    if hostname.startswith("air-"):
        identities.add(hostname[len("air-"):])
    matches = [
        host for host in expected
        if any(host == identity or host.endswith("-" + identity)
               for identity in identities)
    ]
    if len(matches) > 1:
        raise ValueError(
            f"ambiguous splitter sidecar device ownership for {hostname}: "
            f"{sorted(matches)}"
        )
    return expected[matches[0]] if matches else None


def _project_inventory_authority(
    project: Path, devices_file: Path,
) -> tuple[str, dict[str, object]]:
    """Bind one safe inventory file to its canonical project-relative path."""
    try:
        project_root = project.resolve(strict=True)
        if not project_root.is_dir():
            raise LoadError(f"splitter inventory project 不是目录：{project}")
        resolved = devices_file.resolve(strict=True)
        relative = resolved.relative_to(project_root)
    except LoadError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise LoadError(
            f"splitter inventory 必须位于当前 project 内：{devices_file}: {exc}"
        ) from exc
    if not relative.parts or any(part in {"", ".", ".."} for part in relative.parts):
        raise LoadError(f"splitter inventory project-relative path 无效：{relative}")
    identity = _stable_regular_identity(
        devices_file, "splitter inventory", maximum_size=64 * 1024 * 1024,
        # The customer-authored project-root CSV historically permits normal
        # collaborative 0664 permissions. Only load's private derived file is
        # a generated trust anchor and must reject group/world write bits.
        allow_writable=relative == Path("02-devices_config.csv"),
    )
    return PurePosixPath(*relative.parts).as_posix(), identity


def _current_splitter_provenance(
    project: Path, devices_file: Path, p2p_file: Path, release_dir: Path,
    manifest: dict[str, object], schema_version: int,
) -> dict[str, object] | None:
    """Bind published breakout YAML to current source authority, not a stale cache."""
    rows = manifest.get("devices")
    if not isinstance(rows, list):
        raise LoadError("cumulus manifest.devices 必须是 list")
    breakouts: dict[str, dict[str, str]] = {}
    configs: dict[str, Path] = {}
    for row in rows:
        if not isinstance(row, dict):
            raise LoadError("cumulus manifest.devices 包含非 object 元素")
        hostname = str(row.get("hostname") or "").strip()
        config = release_dir / str(row.get("config") or "")
        profiles = _published_breakouts(config)
        if profiles:
            key = hostname.casefold()
            breakouts[key] = profiles
            configs[key] = config
    if not breakouts:
        return None

    devices_path, devices_identity = _project_inventory_authority(
        project, devices_file,
    )
    receipts = _source_yaml_receipts(devices_file, schema_version)
    devices_path_after, devices_identity_after = _project_inventory_authority(
        project, devices_file,
    )
    if (
        devices_path_after != devices_path
        or devices_identity_after != devices_identity
    ):
        raise LoadError("splitter inventory 在 provenance 读取期间发生变化")
    source_yaml: dict[str, str] = {}
    generated: dict[str, dict[str, str]] = {}
    for hostname, profiles in breakouts.items():
        if hostname in receipts:
            source = receipts[hostname]
            if configs[hostname].read_bytes() != source:
                raise LoadError(f"cumulus source YAML 与 child 发布字节不一致：{hostname}")
            source_yaml[hostname] = hashlib.sha256(source).hexdigest()
        else:
            generated[hostname] = profiles

    provenance: dict[str, object] = {
        "schema_version": 1,
        "devices_schema_version": schema_version,
        "devices_name": devices_file.name,
        "devices_path": devices_path,
        "devices_sha256": devices_identity["sha256"],
        "published_profiles": breakouts,
        "source_yaml_sha256": source_yaml,
    }
    if not generated:
        return provenance

    try:
        selected = select_upload_p2p(project)
        if p2p_file.resolve(strict=True) != selected.resolve(strict=True):
            raise LoadError("P2P splitter workbook 与本次选择不一致")
        p2p = ZTP_DIR / "config/cumulus/template/P2P"
        workbook = p2p / "p2p.xlsx"
        if workbook.resolve(strict=True) != selected.resolve(strict=True):
            raise LoadError("P2P splitter 固定 workbook 不是本次项目来源")
        output = p2p / "output-p2p"
        sidecar = output / f"{selected.stem}-splitter-profiles.json"
        lldpq = output / f"{selected.stem}-lldpq.dot"
        metadata = sidecar.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LoadError("P2P splitter sidecar 不是单链接普通文件")

        def unique_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
            result: dict[str, object] = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError(f"duplicate splitter sidecar key: {key}")
                result[key] = value
            return result

        document = json.loads(sidecar.read_text(encoding="utf-8"),
                              object_pairs_hook=unique_keys)
        keys = {"schema_version", "source_workbook", "workbook_sha256",
                "inventory_sha256", "port_mapping_sha256", "lldpq_sha256",
                "profiles"}
        if (not isinstance(document, dict) or set(document) != keys
                or type(document["schema_version"]) is not int
                or document["schema_version"] != 1
                or document["source_workbook"] != selected.name
                or not isinstance(document["profiles"], list)):
            raise ValueError("invalid splitter sidecar schema/source")
        bindings = {
            "workbook_sha256": selected,
            "inventory_sha256": p2p / "01-inventory.log",
            "port_mapping_sha256": p2p / "02-port-mapping.log",
            "lldpq_sha256": lldpq,
        }
        for field, path in bindings.items():
            actual = _sha256_path(path)
            if not isinstance(document[field], str) or not hmac.compare_digest(
                document[field].casefold(), actual,
            ):
                raise ValueError(f"splitter sidecar source binding changed: {field}")
        expected: dict[str, dict[str, str]] = {}
        for item in document["profiles"]:
            if (not isinstance(item, dict)
                    or set(item) != {"device", "parent", "profile"}
                    or not isinstance(item["device"], str)
                    or not SAFE_HOSTNAME.fullmatch(item["device"])
                    or not isinstance(item["parent"], str)
                    or not re.fullmatch(r"swp[0-9]+", item["parent"])
                    or not isinstance(item["profile"], str)
                    or item["profile"] not in {"1to2", "1to4", "1to8"}):
                raise ValueError("invalid splitter sidecar profile entry")
            host = item["device"].casefold()
            profiles = expected.setdefault(host, {})
            if item["parent"] in profiles:
                raise ValueError(f"duplicate splitter sidecar profile: {host}:{item['parent']}")
            profiles[item["parent"]] = item["profile"]
        for hostname, profiles in generated.items():
            if _sidecar_profiles_for_child(expected, hostname) != profiles:
                raise ValueError(f"splitter profiles disagree with child YAML: {hostname}")
        provenance["splitter_sidecar_sha256"] = _sha256_path(sidecar)
        provenance["splitter_sources"] = {
            field: _sha256_path(path) for field, path in bindings.items()
        }
        provenance["generator_profiles"] = generated
    except (OSError, UnicodeError, ValueError) as exc:
        raise LoadError(f"P2P splitter current authority 无效：{exc}") from exc
    return provenance


def validate_and_publish_release(
    project: Path, inputs: ProjectInputs, *, dry_run: bool = False,
    publish: bool = True,
    dhcp_candidate_dir: Path | None = None,
    imported_configs: ImportedConfigSnapshot | None = None,
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

    if inputs.mini_devices_file is not None:
        _require_mini_sampling_policy(inputs.air_topology_policy)
    current_identities = _project_source_identities(inputs)
    if inputs.source_identities is not None and any(
        current_identities.get(name) != digest
        for name, digest in inputs.source_identities.items()
        if name != "mini_air_customer_source"
    ):
        raise LoadError(
            "project input authority changed after validation and before "
            "release_basis"
        )
    if (
        inputs.air_topology_policy is not None
        and inputs.mini_devices_file is not None
    ):
        generation_key = (
            os.path.realpath(os.fspath(inputs.air_topology_policy)),
            os.path.realpath(os.fspath(inputs.mini_devices_file)),
        )
        generated = _MINI_GENERATION_AUTHORITIES.get(generation_key)
        if inputs.source_identities is not None and generated is None:
            raise LoadError(
                "mini generation authority is missing before release_basis"
            )
        expected_customer = (
            inputs.source_identities or {}
        ).get("mini_air_customer_source")
        if expected_customer is not None:
            customer = inputs.mini_source_file
            if customer is None:
                raise LoadError(
                    "mini AIR customer source authority is missing before "
                    "release_basis"
                )
            try:
                customer_stat = customer.lstat()
                if stat.S_ISLNK(customer_stat.st_mode):
                    expected_target = inputs.mini_devices_file.name
                    if os.readlink(customer) != expected_target:
                        raise LoadError(
                            "mini AIR customer source changed after generation"
                        )
                elif (
                    not stat.S_ISREG(customer_stat.st_mode)
                    or customer_stat.st_nlink != 1
                    or _sha256_path(customer) != expected_customer
                ):
                    raise LoadError(
                        "mini AIR customer source changed after validation"
                    )
            except LoadError:
                raise
            except OSError as exc:
                raise LoadError(
                    "mini AIR customer source changed after validation: "
                    f"{exc}"
                ) from exc
        if generated is not None and (
            generated[:2] != (
                current_identities["air_topology_policy"],
                current_identities["mini_air_devices"],
            )
            or (
                expected_customer is not None
                and generated[2] != expected_customer
            )
        ):
            raise LoadError(
                "AIR topology policy or mini device selection changed after "
                "generation and before release_basis"
            )

    effective_devices = inputs.effective_devices_file or inputs.devices_file
    if inputs.effective_devices_file is not None:
        metadata = effective_devices.lstat()
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
                or not effective_devices.resolve().is_relative_to(project.resolve())
                or _sha256_path(effective_devices) != inputs.effective_devices_sha256):
            raise LoadError("derived inventory authority changed before release_basis")
    inventory = _augment_air_json_inventory(
        _release_inventory(effective_devices),
        ZTP_DIR / "config/isc-dhcp-server/p2p-air.json",
    )
    inventory = _inventory_for_release_scope(
        inventory,
        deployment_scope=inputs.deployment_scope,
        switch_scope=inputs.switch_scope,
    )
    if not inventory:
        raise LoadError(
            f"deployment scope={inputs.deployment_scope}, "
            f"switch scope={inputs.switch_scope} 没有可发布设备"
        )
    dhcp_status = "enabled" if inputs.settings.dhcp_enabled else "disabled"
    if dhcp_candidate_dir is not None and dhcp_status != "enabled":
        raise LoadError("disabled DHCP release cannot bind a DHCP candidate")
    dhcp_source = (
        _validated_dhcp_candidate_dir(project, dhcp_candidate_dir)
        if dhcp_candidate_dir is not None else ZTP_DIR / "config/isc-dhcp-server"
    )
    components: dict[str, dict[str, object]] = {}
    if inputs.settings.dhcp_enabled:
        dhcp_path = dhcp_source / "dhcp-release-manifest.json"
        dhcp = _load_release_json(dhcp_path, "DHCP release manifest")
        if str(dhcp.get("deployment_scope") or "all") != inputs.deployment_scope:
            raise LoadError(
                "DHCP release deployment scope 与本次 load 不一致："
                f"manifest={dhcp.get('deployment_scope') or 'all'} "
                f"requested={inputs.deployment_scope}"
            )
        if str(dhcp.get("switch_scope") or "all") != inputs.switch_scope:
            raise LoadError(
                "DHCP release switch scope 与本次 load 不一致："
                f"manifest={dhcp.get('switch_scope') or 'all'} "
                f"requested={inputs.switch_scope}"
            )
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
        counts = dhcp.get("counts")
        family_counts = (counts.get("host_declarations_by_family")
                         if isinstance(counts, dict) else None)
        legacy_nonempty = counts is None or (
            isinstance(counts, dict)
            and "host_declarations_by_family" not in counts
        )
        if not legacy_nonempty and (
            not isinstance(family_counts, dict)
            or set(family_counts) != {"eth", "ib", "nvl"}
            or any(type(value) is not int or value < 0
                   for value in family_counts.values())
        ):
            raise LoadError("DHCP release host_declarations_by_family 无效")
        host_declaration = re.compile(
            rb"(?m)^\s*host\s+[A-Za-z0-9][A-Za-z0-9._-]*\s*\{\s*$"
        )
        for source in dhcp_file_mappings(dhcp_source):
            item = output_hashes.get(source.name)
            expected_hash = item.get("sha256") if isinstance(item, dict) else None
            family = {
                "dhcpd_eth.hosts": "eth",
                "dhcpd_ib.hosts": "ib",
                "dhcpd_nvl.hosts": "nvl",
            }.get(source.name)
            if family is None:
                actual_hash = _sha256_path(source)
            else:
                host_bytes = source.read_bytes()
                actual_hash = hashlib.sha256(host_bytes).hexdigest()
            if expected_hash != actual_hash:
                raise LoadError(f"DHCP release 输出 hash 漂移：{source.name}")
            if family is not None:
                if legacy_nonempty:
                    if not host_bytes:
                        raise LoadError(
                            f"DHCP release {source.name} 无计数证明且内容为空"
                        )
                    continue
                actual_count = len(host_declaration.findall(host_bytes))
                if actual_count != family_counts[family]:
                    raise LoadError(
                        f"DHCP release {source.name} host count 与当前内容不一致"
                    )
        components["dhcp"] = {
            "release_id": str(dhcp["release_id"]),
            "manifest_sha256": _sha256_path(dhcp_path),
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
        if str(manifest.get("deployment_scope") or "all") != inputs.deployment_scope:
            raise LoadError(
                f"{label} release deployment scope 与本次 load 不一致："
                f"manifest={manifest.get('deployment_scope') or 'all'} "
                f"requested={inputs.deployment_scope}"
            )
        if str(manifest.get("switch_scope") or "all") != inputs.switch_scope:
            raise LoadError(
                f"{label} release switch scope 与本次 load 不一致："
                f"manifest={manifest.get('switch_scope') or 'all'} "
                f"requested={inputs.switch_scope}"
            )
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
        if label == "cumulus":
            if imported_configs is not None:
                for name, expected_bytes in imported_configs.files:
                    candidate = release_dir / name
                    try:
                        metadata = candidate.lstat()
                        if (not stat.S_ISREG(metadata.st_mode)
                                or metadata.st_nlink != 1
                                or candidate.read_bytes() != expected_bytes):
                            raise LoadError(
                                f"imported Cumulus child differs from frozen source: {name}"
                            )
                    except OSError as exc:
                        raise LoadError(
                            f"imported Cumulus child is missing: {name}: {exc}"
                        ) from exc
            splitter_provenance = _current_splitter_provenance(
                project, effective_devices, inputs.p2p_file, release_dir,
                manifest, inputs.settings.schema_version,
            )
            if splitter_provenance is not None:
                if inputs.effective_devices_file is not None and (
                    splitter_provenance.get("devices_path")
                    != effective_devices.resolve().relative_to(project.resolve()).as_posix()
                    or splitter_provenance.get("devices_sha256") != inputs.effective_devices_sha256
                ):
                    raise LoadError("splitter and derived inventory authorities disagree")
                components[label]["splitter_provenance"] = splitter_provenance

    input_files = {
        "global": inputs.global_file,
        "devices": inputs.devices_file,
        "subnet": inputs.subnet_file,
        "p2p": inputs.p2p_file,
    }
    if inputs.air_topology_policy is not None:
        input_files["air_topology_policy"] = inputs.air_topology_policy
    if inputs.mini_devices_file is not None:
        input_files["mini_air_devices"] = inputs.mini_devices_file
    # Keep the accepted snapshot: a later read must not silently adopt edits
    # made while component validation was running.
    input_hashes = {name: current_identities[name] for name in input_files}
    p2p_source = p2p_release_source_binding(project, inputs.p2p_file)
    if input_hashes["p2p"] != p2p_source["sha256"]:
        raise LoadError("P2P release 输入在摘要绑定时发生变化")
    release_basis = {
        "project": project.name,
        "deployment_scope": inputs.deployment_scope,
        "switch_scope": inputs.switch_scope,
        "dhcp_status": dhcp_status,
        "inputs": input_hashes,
        "input_sources": {"p2p": p2p_source},
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
    if inputs.effective_devices_file is not None:
        release_basis["generated_inputs"] = {"effective_devices": {
            "path": effective_devices.resolve().relative_to(project.resolve()).as_posix(),
            "sha256": inputs.effective_devices_sha256,
        }}
    if imported_configs is not None:
        release_basis["imported_configs"] = {
            "source_name": imported_configs.source_name,
            "sha256": imported_configs.digest,
        }
    release_id = hashlib.sha256(
        json.dumps(
            release_basis, ensure_ascii=False, sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()[:20]
    input_paths = {}
    for name, path in input_files.items():
        try:
            input_paths[name] = (
                (path.parent.resolve() / path.name).relative_to(project.resolve()).as_posix())
        except ValueError:
            # R-014 第 3 条: the user's p2p/<workbook> link may lead outside the project (review 4 B1);
            # p2p_release_source_binding above bound this input to that link's workbook.
            if name != "p2p" or _user_linked_input_target(project, name, p2p_source["path"]) is None:
                raise
            input_paths[name] = p2p_source["path"]
    parent = {
        "schema_version": 2,
        "release_id": release_id,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "validation": "passed",
        **release_basis,
        # Transaction metadata, not a change to the established release-ID basis.
        # Preserve the selected alias itself so retargeting is rechecked too.
        "input_paths": input_paths,
    }
    if publish:
        publish_current_release(project, parent)
    else:
        pending = sum(item["identity_state"] == "identity_pending" for item in inventory)
        ok(
            f"统一 release {release_id} 已验证：{len(inventory)} 台设备，"
            f"identity_pending={pending}；"
            + ("等待 DHCP 事务安装后提交" if inputs.settings.dhcp_enabled
               else "DHCP 已禁用，等待原子提交")
        )
    return parent


def prepare_current_release(
    project: Path, parent: dict[str, object],
    *, dhcp_candidate_dir: Path | None = None,
) -> PreparedParentRelease:
    """Write and fsync a parent candidate without making it visible yet."""
    if parent.get("schema_version") == 2:
        hashes = parent.get("inputs")
        paths = parent.get("input_paths")
        if (not isinstance(hashes, dict) or not isinstance(paths, dict)
                or not {"global", "devices", "subnet", "p2p"}.issubset(hashes)
                or set(paths) != set(hashes)
                or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                       for value in hashes.values())):
            raise LoadError("schema 2 parent input authority map is incomplete or invalid")
        for relative in paths.values():
            if not isinstance(relative, str):
                raise LoadError("schema 2 parent input authority map contains an invalid path")
            parsed = PurePosixPath(relative)
            if (parsed.is_absolute() or not parsed.parts or ".." in parsed.parts
                    or parsed.as_posix() != relative):
                raise LoadError("schema 2 parent input authority map contains an unsafe path")
    dhcp_source_dir = None
    if dhcp_candidate_dir is not None:
        if parent.get("schema_version") != 2 or parent.get("dhcp_status") != "enabled":
            raise LoadError("private DHCP candidate requires enabled schema 2 parent")
        dhcp_source_dir = _validated_dhcp_candidate_dir(project, dhcp_candidate_dir)
        components = parent.get("components")
        dhcp = components.get("dhcp") if isinstance(components, dict) else None
        expected = dhcp.get("manifest_sha256") if isinstance(dhcp, dict) else None
        if (not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)
                or _sha256_path(dhcp_source_dir / "dhcp-release-manifest.json") != expected):
            raise LoadError("private DHCP candidate does not match prepared parent")
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
    components = parent.get("components")
    cumulus = components.get("cumulus") if isinstance(components, dict) else None
    dhcp = components.get("dhcp") if isinstance(components, dict) else None
    dhcp_manifest_sha256 = None
    if parent.get("schema_version") == 2 and parent.get("dhcp_status") == "enabled":
        dhcp_manifest_sha256 = (
            dhcp.get("manifest_sha256") if isinstance(dhcp, dict) else None
        )
        if (
            not isinstance(dhcp_manifest_sha256, str)
            or not re.fullmatch(r"[0-9a-f]{64}", dhcp_manifest_sha256)
        ):
            Path(temporary).unlink(missing_ok=True)
            raise LoadError("schema 2 parent 缺少有效 DHCP child manifest hash")
    provenance = (
        cumulus.get("splitter_provenance")
        if isinstance(cumulus, dict) else None
    )
    guard = None
    if provenance is not None:
        guard = {
            "expected": provenance,
            "release_dir": cumulus.get("release_dir"),
            "manifest_sha256": cumulus.get("manifest_sha256"),
            "published_marker_sha256": cumulus.get("published_marker_sha256"),
        }
    return PreparedParentRelease(
        destination=destination,
        temporary=Path(temporary),
        release_id=str(parent.get("release_id") or ""),
        splitter_provenance=guard,
        generated_inventory=(
            dict(parent["generated_inputs"]["effective_devices"])
            if "generated_inputs" in parent else None
        ),
        source_inventory_sha256=(parent.get("inputs", {}).get("devices")
                                 if "generated_inputs" in parent else None),
        source_authorities={
            name: (relative, parent["inputs"][name])
            for name, relative in parent.get("input_paths", {}).items()
        },
        dhcp_manifest_sha256=dhcp_manifest_sha256,
        dhcp_source_dir=dhcp_source_dir,
    )


def _recheck_prepared_splitter_provenance(candidate: PreparedParentRelease) -> None:
    """Close cooperative precommit drift, without claiming a same-UID lock."""
    guard = candidate.splitter_provenance
    if guard is None:
        return
    expected = guard.get("expected")
    release_name = guard.get("release_dir")
    devices_path = expected.get("devices_path") if isinstance(expected, dict) else None
    if (not isinstance(expected, dict)
            or not isinstance(release_name, str)
            or not isinstance(expected.get("devices_name"), str)
            or Path(expected["devices_name"]).name != expected["devices_name"]
            or not isinstance(devices_path, str)):
        raise LoadError("P2P splitter prepared provenance 结构无效")
    parsed_devices_path = PurePosixPath(devices_path)
    if (
        parsed_devices_path.is_absolute()
        or not parsed_devices_path.parts
        or any(part in {"", ".", ".."} for part in parsed_devices_path.parts)
        or parsed_devices_path.as_posix() != devices_path
        or parsed_devices_path.name != expected["devices_name"]
    ):
        raise LoadError("P2P splitter prepared provenance devices_path 无效")
    project = candidate.destination.parent.parent
    release_dir = project / release_name
    inventory_path = project.joinpath(*parsed_devices_path.parts)
    try:
        if (release_dir.resolve(strict=True)
                != (ZTP_DIR / "config/cumulus/latest_yaml").resolve(strict=True)):
            raise LoadError("cumulus latest_yaml 在 parent commit 前已切换")
        manifest_path = release_dir / "release-manifest.json"
        marker = release_dir / ".published-complete"
        if (_sha256_path(manifest_path) != guard.get("manifest_sha256")
                or _sha256_path(marker) != guard.get("published_marker_sha256")):
            raise LoadError("cumulus child release 在 parent commit 前已变化")
        manifest = _load_release_json(manifest_path, "cumulus release manifest")
        current = _current_splitter_provenance(
            project, inventory_path, project / "p2p.xlsx",
            release_dir, manifest, expected["devices_schema_version"],
        )
    except (OSError, ValueError, RuntimeError) as exc:
        raise LoadError(f"P2P splitter precommit 复验失败：{exc}") from exc
    if current != expected:
        raise LoadError("P2P splitter provenance 在 parent commit 前已变化")


def commit_prepared_release(candidate: PreparedParentRelease) -> Path:
    """Commit an already-fsynced parent candidate with one atomic replace."""
    if candidate.committed:
        if not candidate.directory_synced:
            raise LoadError(
                "current-release B 已可见，但目录持久化仍未确认；HOLD，"
                "保留 B 与原凭据，不得假报成功、自动回退或启动服务"
            )
        return candidate.destination
    authority = candidate.generated_inventory
    if authority is not None:
        try:
            project = candidate.destination.parent.parent
            if _sha256_path(project / "02-devices_config.csv") != candidate.source_inventory_sha256:
                raise ValueError("customer source inventory changed")
            relative = authority["path"]
            path = PurePosixPath(relative)
            if (not isinstance(relative, str) or path.is_absolute()
                    or not path.parts or ".." in path.parts
                    or path.as_posix() != relative):
                raise ValueError("unsafe derived path")
            actual_path, identity = _project_inventory_authority(
                project, project.joinpath(*path.parts))
            if actual_path != relative or identity["sha256"] != authority["sha256"]:
                raise ValueError("derived content/path changed")
        except (KeyError, TypeError, ValueError, OSError, LoadError) as exc:
            raise LoadError(f"derived inventory changed before parent commit: {exc}") from exc
    _recheck_prepared_splitter_provenance(candidate)
    # Recheck every frozen input, including loads with no derived inventory or
    # splitter. This bounds cooperative drift, not an adversarial same-UID race.
    project = candidate.destination.parent.parent
    for name, (relative, expected) in (candidate.source_authorities or {}).items():
        try:
            path = PurePosixPath(relative)
            if (path.is_absolute() or not path.parts or ".." in path.parts
                    or path.as_posix() != relative):
                raise ValueError("unsafe input path")
            source = project.joinpath(*path.parts)
            try:
                source.resolve(strict=True).relative_to(project.resolve())
            except ValueError:
                # R-014 第 3 条's two user links resolve outside the project; their target's bytes are
                # rechecked below like any input (review 4 B1).
                if _user_linked_input_target(project, name, relative) is None:
                    raise
            if _sha256_path(source) != expected:
                raise ValueError("content changed")
            if name == "p2p":
                binding = p2p_release_source_binding(project, source)
                if binding["sha256"] != expected:
                    raise ValueError("P2P source changed")
        except (OSError, ValueError, RuntimeError, LoadError) as exc:
            raise LoadError(
                f"project input authority {name} changed before parent commit: {exc}"
            ) from exc
    if candidate.dhcp_manifest_sha256 is not None:
        recheck_prepared_dhcp_child(
            candidate, dhcp_file_mappings(candidate.dhcp_source_dir),
        )
    if candidate.precommit_check is not None:
        candidate.precommit_check()
    os.replace(candidate.temporary, candidate.destination)
    candidate.committed = True
    # Visibility and confirmed persistence are distinct. A sync failure must
    # propagate while committed remains True, so outer cleanup stops services
    # without restoring A behind an already externally visible B marker.
    try:
        descriptor = os.open(
            candidate.destination.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    except OSError as exc:
        raise LoadError(
            f"current-release B 已可见，但目录持久化未确认：{exc}；HOLD，"
            "保留 B 与原凭据，不得自动回退或启动服务"
        ) from exc
    candidate.directory_synced = True
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


def retire_unselected_release_links(
    project: Path, switch_scope: str, *, dry_run: bool,
) -> None:
    """Prevent an old platform release from remaining live after a scoped load."""
    selected = str(switch_scope or "").strip().casefold()
    if selected not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    if selected == "all":
        return
    paths = {
        "eth": project / "99-output-eth/latest",
        "nvos": project / "99-output-ib_nvl/latest",
    }
    retire = (paths["nvos"],) if selected == "eth" else (paths["eth"],)
    for path in retire:
        if dry_run:
            info(f"dry-run：选择 --switch {selected} 时将退役旧发布入口 {path}")
            continue
        if os.path.lexists(path) and not path.is_symlink():
            raise LoadError(f"拒绝退役非软链接 release 入口：{path}")
        # I-022: rename to a fixed same-directory name; main deletes it only
        # after the parent release commits and restores it on any earlier
        # failure or interruption.  Not a ".latest.rollback." or
        # ".latest.setup-rollback." name: those HOLD the same-project A restore.
        retired = path.parent / ".latest.retired"
        if os.path.lexists(retired):
            raise LoadError(f"latest 退役记录已存在，拒绝覆盖：{retired}")
        if path.is_symlink():
            os.replace(path, retired)
            _fsync_parent_directory(path.parent)


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


def _select_cumulus_description_publication(base: Path) -> Path:
    """Choose C2's immutable current pointer, never an unsafe legacy fallback.

    The publisher independently validates the pointed-to version manifest and
    every file hash.  LOAD checks the namespace before handing it off so a
    malformed or dangling current pointer cannot silently choose legacy/base.
    """
    output_root = base.parent
    pointer = output_root / f"{base.name}_with_desc_current"
    if os.path.lexists(pointer):
        metadata = pointer.lstat()
        if not stat.S_ISLNK(metadata.st_mode):
            raise LoadError("Cumulus description current pointer is not a symlink")
        target_name = os.readlink(pointer)
        if not re.fullmatch(
            rf"\.{re.escape(base.name)}_with_desc\.version\.[0-9a-f]{{32}}",
            target_name,
        ):
            raise LoadError("Cumulus description current pointer target is invalid")
        version = output_root / target_name
        try:
            version_stat = version.lstat()
            canonical_parent = output_root.resolve(strict=True)
            canonical_version = version.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LoadError(f"Cumulus description current pointer is broken: {exc}") from exc
        if (not stat.S_ISDIR(version_stat.st_mode)
                or canonical_version != canonical_parent / target_name):
            raise LoadError("Cumulus description current pointer escaped its version")
        return pointer
    legacy = output_root / f"{base.name}_with_desc"
    if os.path.lexists(legacy):
        if not stat.S_ISDIR(legacy.lstat().st_mode):
            raise LoadError("Cumulus legacy description output is not a real directory")
        return legacy
    return base


IB_CVT_CONVERTER = "p2p-to-validation.py"


def _ib_topology_provenance():
    """The CVT provenance reader shipped with the converter (ztp/config)."""
    path = ZTP_DIR / "config/ib_topology_provenance.py"
    name = f"_http_ib_topology_provenance_{abs(hash(os.fspath(path)))}"
    existing = sys.modules.get(name)
    if existing is not None:
        return existing
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise LoadError(f"cannot load IB CVT provenance reader: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(name, None)
        raise
    return module


def verify_ib_cvt(source_identities: dict[str, str] | None = None) -> dict[str, str]:
    """Bind the CVT that p2p-to-validation.py published to this load's P2P.

    Owner 2026-10-21: load treats IB devices as it treats Ethernet. Ethernet's b-xlsx_to_dot.py output
    is checked through its splitter sidecar at the parent release; the IB expected topology
    <p2p>-cvt.xlsx (in the project's 99-output-p2p, beside <p2p>-lldpq.dot) is checked through its
    provenance sidecar. generate_configs already makes the converter refuse another P2P
    (--expect-p2p-sha256); this check is for the parent release step (UFM-MONITOR.md section 13):
    - the fixed nvos/template/P2P/p2p.xlsx link still resolves to the workbook the CVT was made from,
      and its bytes are the ones this load validated (source_identities["p2p"]);
    - the CVT and its sidecar are single-link regular files;
    - every source the converter recorded (P2P, inventory, port map, splitter, converter, rules) still
      has the recorded bytes, and the CVT bytes match the record (read_cvt_provenance).
    """
    p2p_dir = ZTP_DIR / "config/nvos/template/P2P"
    try:
        selected = (p2p_dir / "p2p.xlsx").resolve(strict=True)
        cvt = (p2p_dir / "output-p2p").resolve(strict=True) / f"{selected.stem}-cvt.xlsx"
        provenance = _ib_topology_provenance()
        sidecar = provenance.sidecar_path(cvt)
        for path in (cvt, sidecar):
            metadata = path.lstat()
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise LoadError(f"IB CVT 不是单链接普通文件：{path}")
        record = provenance.read_cvt_provenance(cvt)
        p2p = record["sources"]["p2p"]
        if p2p.get("resolved_path") != os.fspath(selected):
            raise LoadError("IB CVT 的 P2P 来源与本次选择不一致")
        expected = (source_identities or {}).get("p2p")
        if expected is not None and p2p.get("sha256") != expected:
            raise LoadError("IB CVT 的 P2P 字节与本次 load 校验的输入不一致")
        return {"cvt": os.fspath(cvt), "cvt_sha256": str(record["cvt_sha256"]),
                "provenance_sha256": _sha256_path(sidecar)}
    except LoadError:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise LoadError(f"IB CVT 校验失败：{exc}") from exc


def generate_configs(
    device_types: frozenset[str], *, install_dhcp: bool, dry_run: bool = False,
    dhcp_enabled: bool = True,
    schema_version: int = GLOBAL_SCHEMA_VERSION,
    eth_version: str | None = None,
    air_topology_policy: Path | None = None,
    p2p_legacy_columns: bool = False,
    mini_air: bool = False,
    mini_devices_file: Path | None = None,
    deployment_scope: str = "all",
    switch_scope: str = "all",
    deployment_lock_descriptor: int | None = None,
    source_identities: dict[str, str] | None = None,
    inventory_directory: Path | None = None,
    dhcp_candidate_dir: Path | None = None,
    imported_configs: ImportedConfigSnapshot | None = None,
    import_selection: ImportConfigSelection | None = None,
    import_devices_file: Path | None = None,
    import_output_timestamp: str | None = None,
) -> DerivedInventory | None:
    if dhcp_candidate_dir is not None and not dhcp_enabled:
        raise LoadError("DHCP disabled generation cannot accept a DHCP candidate")
    mini_policy_hash_before: str | None = None
    mini_customer_hash: str | None = None
    mini_generation_key: tuple[str, str] | None = None
    if mini_air:
        if air_topology_policy is None:
            raise LoadError(
                "--mini requires project 03-air-topology-policy.json with "
                "mini_sampling"
            )
        if mini_devices_file is None:
            raise LoadError("--mini 缺少项目设备清单路径")
        canonical = Path(mini_devices_file).parent / MINI_AIR_DEVICES_NAME
        mini_generation_key = (
            os.path.realpath(os.fspath(air_topology_policy)),
            os.path.realpath(os.fspath(canonical)),
        )
        # A failed/retried generation must never inherit an authority receipt
        # from an earlier call in the same long-lived load process.
        _MINI_GENERATION_AUTHORITIES.pop(mini_generation_key, None)
        try:
            mini_policy_hash_before = _sha256_path(air_topology_policy)
            if Path(mini_devices_file).name != MINI_AIR_DEVICES_NAME:
                mini_customer_hash = _sha256_path(Path(mini_devices_file))
        except OSError as exc:
            raise LoadError(f"无法读取 --mini AIR 拓扑策略：{exc}") from exc
        expected_customer = (source_identities or {}).get(
            "mini_air_customer_source"
        )
        if expected_customer is not None and mini_customer_hash != expected_customer:
            raise LoadError("mini AIR customer source changed before generation")
    scope_args = (
        [] if deployment_scope == "all"
        else ["--deployment-scope", deployment_scope]
    )
    selected_switch = str(switch_scope or "").strip().casefold()
    if selected_switch not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{switch_scope!r}")
    switch_args = (
        [] if selected_switch == "all"
        else ["--switch", selected_switch]
    )
    p2p_dir = ZTP_DIR / "config/cumulus/template/P2P"
    inherited_lock = (
        {}
        if deployment_lock_descriptor is None
        else {"inherited_lock_descriptor": deployment_lock_descriptor}
    )
    p2p_command = [
        sys.executable, "b-xlsx_to_dot.py", "-y", *scope_args,
    ]
    if p2p_legacy_columns:
        p2p_command.append("--legacy-columns")
    if eth_version:
        p2p_command.extend(["--os-version", eth_version])
    if air_topology_policy is not None:
        p2p_command.extend([
            "--air-link-policy", str(air_topology_policy),
        ])
    if mini_air:
        p2p_command.extend(["--mini", str(mini_devices_file)])
    if selected_switch in {"all", "eth"}:
        run(
            p2p_command, cwd=p2p_dir, dry_run=dry_run,
            **inherited_lock,
        )

    # AIR node identity/MAC comes from p2p-air.json. c1-generate_dhcp.py copies
    # template/IP/netmask/gateway from the matching production CSV row. It must
    # run before hostname2mac validates each pair and points both MACs at the
    # same production full-config YAML.
    derived_path = None
    source_inventory = ZTP_DIR / "config/isc-dhcp-server/02-devices_config.csv"
    source_hash = None
    inventory_options = []
    if (not dry_run and selected_switch in {"all", "eth"}
            and deployment_scope != "prod"
            and (ZTP_DIR / "config/isc-dhcp-server/p2p-air.json").is_file()):
        source_inventory = source_inventory.resolve(strict=True)
        source_hash = _sha256_path(source_inventory)
        if (source_identities is not None
                and source_identities.get("devices") != source_hash):
            raise LoadError("customer inventory changed before generation")
        private = inventory_directory or Path(tempfile.mkdtemp(
            prefix=".load-inventory-", dir=source_inventory.parent))
        private_stat = private.lstat()
        if (not stat.S_ISDIR(private_stat.st_mode)
                or stat.S_IMODE(private_stat.st_mode) != 0o700
                or private.parent.resolve() != source_inventory.parent):
            raise LoadError("derived inventory directory must be private and project-local")
        derived_path = private / "02-devices_config.csv"
        inventory_options = ["--inventory-output", str(derived_path)]
    if dhcp_enabled or derived_path is not None:
        run(
            [
                sys.executable, "c1-generate_dhcp.py", "-y",
                "--preserve-input-csv",
                *scope_args, *switch_args,
                *inventory_options,
                *(["--candidate-dir", str(dhcp_candidate_dir)]
                  if dhcp_candidate_dir is not None else []),
                *([] if dhcp_enabled else ["--inventory-only"]),
            ],
            cwd=ZTP_DIR / "config/isc-dhcp-server",
            dry_run=dry_run,
            expected_global_sha256=(source_identities or {}).get("global"),
            **inherited_lock,
        )
    derived_sha = None
    if derived_path is not None:
        metadata = derived_path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LoadError("derived inventory must be a single-link regular file")
        derived_sha = _sha256_path(derived_path)
    effective_options = ["--csv", str(derived_path)] if derived_path else []
    device_types = _device_types_after_dhcp(
        device_types, dry_run=dry_run, schema_version=schema_version,
        deployment_scope=deployment_scope,
        switch_scope=selected_switch,
    )

    if device_types & {"eth", "eth_spx", "spx", "air"}:
        template_dir = ZTP_DIR / "config/cumulus/template"
        if imported_configs is None:
            run(
                [sys.executable, "90-c2-generate_configs.py", "--branch", "eth", "-y",
                 "--presentation-context", "load-parent",
                 *scope_args, *switch_args, *effective_options],
                cwd=template_dir, dry_run=dry_run,
                expected_global_sha256=(source_identities or {}).get("global"),
            )
        elif (deployment_scope != "prod" or selected_switch != "eth"
              or import_selection is None or import_devices_file is None
              or import_output_timestamp is None):
            raise LoadError("import-configs requires Production Cumulus source authority")
        if not dry_run:
            output_root = template_dir / "99-output"
            if imported_configs is None:
                generated = newest_directory(output_root, re.compile(r"\d{8}_\d{6}"))
            else:
                assert_import_source_unchanged(
                    import_selection, imported_configs, import_devices_file,
                )
                generated = publish_imported_output(
                    imported_configs, output_root, import_output_timestamp,
                )
            if not generated:
                raise LoadError("Cumulus 生成器执行成功但没有找到输出目录")
            publish = _select_cumulus_description_publication(generated)
            run(
                [sys.executable, "d-hostname2mac.py", "-y",
                 "--presentation-context", "load-parent", *scope_args,
                 *switch_args, *effective_options,
                 str(publish)],
                cwd=ZTP_DIR / "config/cumulus",
            )

    if deployment_scope != "air" and device_types & {"ib", "nvl"}:
        template_dir = ZTP_DIR / "config/nvos/template"
        if "ib" in device_types:
            # Like b-xlsx_to_dot.py for Ethernet (owner 2026-10-21): the project P2P becomes the IB
            # expected topology <p2p>-cvt.xlsx in 99-output-p2p before IB configs are generated. The
            # converter runs from its own directory with its default inputs (self-contained) and
            # refuses to publish unless p2p.xlsx has the bytes this load validated.
            converter = [sys.executable, IB_CVT_CONVERTER]
            expected_p2p = (source_identities or {}).get("p2p")
            if expected_p2p:
                converter += ["--expect-p2p-sha256", expected_p2p]
            run(converter, cwd=template_dir / "P2P", dry_run=dry_run)
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "ib", "-y",
             "--presentation-context", "load-parent",
             *scope_args, *switch_args],
            cwd=template_dir, dry_run=dry_run,
            expected_global_sha256=(source_identities or {}).get("global"),
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
                [sys.executable, "d-hostname2mac.py", "-y",
                 "--presentation-context", "load-parent", *scope_args,
                 *switch_args,
                 *map(str, kinds)],
                cwd=ZTP_DIR / "config/nvos",
            )

    if not dhcp_enabled:
        info("global 中 DHCP 已禁用；未生成、读取或安装五个 DHCP 制品")
    elif install_dhcp:
        info("DHCP 安装已延后到统一 release 验证通过之后")
    else:
        warn("本机没有可用 service_ip：已生成 DHCP 文件，但不复制到 /etc/dhcp，也不执行 dhcpd -t")
    if mini_air:
        canonical = Path(mini_devices_file).parent / MINI_AIR_DEVICES_NAME
        try:
            policy_hash_after = _sha256_path(Path(air_topology_policy))
            canonical_hash = _sha256_path(canonical)
        except OSError:
            # A normal dry-run executes no generators and creates no canonical
            # selection.  A materializing test or real run must bind both.
            if not dry_run:
                raise LoadError(
                    "--mini generation did not produce its canonical authority"
                )
        else:
            if policy_hash_after != mini_policy_hash_before:
                raise LoadError("AIR topology policy changed during mini generation")
            assert mini_generation_key is not None
            _MINI_GENERATION_AUTHORITIES[mini_generation_key] = (
                policy_hash_after, canonical_hash, mini_customer_hash,
            )
    if derived_path is not None:
        if (_sha256_path(source_inventory) != source_hash
                or _sha256_path(derived_path) != derived_sha):
            raise LoadError("source or derived inventory changed during generation")
        return DerivedInventory(derived_path, derived_sha)
    return None


def _service_start_declined_message(
    *, http_available: bool, dhcp_available: bool,
) -> str:
    labels = "/".join(
        name for available, name in (
            (http_available, "Apache"), (dhcp_available, "DHCP"),
        ) if available
    )
    if not labels:
        return "当前 runtime plan 没有本机可启动的 HTTP/DHCP 服务"
    return labels + " 未启动。确认输出后可重新执行并加 --start-services。"


def confirm_service_start(
    *, http_available: bool = True, dhcp_available: bool = True,
) -> bool:
    if not http_available and not dhcp_available:
        return False
    prompt_label = " 和 ".join(
        name for available, name in (
            (http_available, "Apache"), (dhcp_available, "DHCP"),
        ) if available
    )
    warning_label = "/".join(
        name for available, name in (
            (http_available, "Apache"), (dhcp_available, "DHCP"),
        ) if available
    )
    if not sys.stdin.isatty():
        warn(f"非交互终端默认不启动 {warning_label}；使用 --start-services 明确启用")
        return False
    print(
        f"是否启动 {prompt_label}？直接回车或 "
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
    """Stop every detached Native monitor through the canonical PID authority."""
    del project  # The canonical stop validates and quiesces every active project.
    return list(stop_native_ztp_monitors(HTTP_ROOT))


def resolve_ztp_monitor_scope(
    project: Path, requested: str, *, deployment_scope: str = "all",
    prompt_fn=None,
) -> str:
    """Resolve the environment reachable from this management server.

    AIR and Production intentionally reuse management IP addresses, while one
    management server normally reaches only one environment.  Do not guess an
    environment for collection or completion handling.
    """
    if deployment_scope not in {"all", "prod", "air"}:
        raise LoadError(f"无法识别 deployment scope：{deployment_scope!r}")
    if requested != "auto":
        if deployment_scope in {"prod", "air"} and requested != deployment_scope:
            raise LoadError(
                f"部署范围 {deployment_scope} 与监控范围 {requested} 冲突"
            )
        return requested
    if deployment_scope in {"prod", "air"}:
        info(f"ZTP 监控采集范围继承部署范围：{deployment_scope}")
        return deployment_scope
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


def print_ztp_monitor_access(
    service_ips: tuple[str, ...], *, port: int = 80,
) -> None:
    """Show operators where the live ZTP status can be inspected."""
    status_csv = ZTP_DIR / "status" / "latest" / "devices.csv"
    info(f"ZTP 状态 CSV：{status_csv}")
    for address in dict.fromkeys(service_ips):
        endpoint = validate_service_endpoint(
            address, port, field="ZTP monitor service IPv4"
        )
        info("ZTP 状态页面：" + service_url(
            endpoint, "/monitor/monitor.html", channel="console-monitor"
        ))


def _canonical_apache_listener_addresses(
    service_ips: tuple[str, ...],
    *, port: int = 80,
) -> tuple[ServiceEndpoint, ...]:
    endpoints = []
    for raw in service_ips:
        try:
            endpoint = validate_service_endpoint(
                raw, port, field="Apache service IPv4"
            )
        except ValueError as exc:
            raise LoadError(f"Apache service IPv4 无效：{raw!r}") from exc
        if endpoint in endpoints:
            raise LoadError(f"Apache service IPv4 重复：{endpoint.host}")
        endpoints.append(endpoint)
    if not endpoints:
        raise LoadError("Apache exact listener 缺少 service IPv4")
    return tuple(endpoints)


def render_native_apache_listener_config(
    service_ips: tuple[str, ...],
    *, port: int = 80,
) -> str:
    """Render Native Apache listeners bound only to canonical service IPv4s."""
    addresses = _canonical_apache_listener_addresses(service_ips, port=port)
    lines = [
        "# Generated by DAY0-Prepare/11-load.py; do not edit.",
        "# Exact service-IP listeners only; wildcard binds are forbidden.",
    ]
    for endpoint in addresses:
        lines.append(endpoint.listen_directive)
    for endpoint in addresses:
        virtual_host = [
            "",
            f"<VirtualHost {endpoint.host}:{endpoint.port}>",
            f"    ServerName {endpoint.host}",
            "    DocumentRoot /var/www/html",
            "    ErrorLog /var/log/apache2/error.log",
            "    CustomLog /var/log/apache2/access.log combined",
        ]
        if endpoint.port != 80:
            virtual_host.append(f"    SetEnv CONTROL_SERVICE_PORT {endpoint.port}")
        virtual_host.append("</VirtualHost>")
        lines.extend(virtual_host)
    lines.append("")
    return "\n".join(lines)


def _fsync_parent_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def publish_native_apache_listener_config(
    service_ips: tuple[str, ...], *,
    port: int = 80,
    destination: Path = NATIVE_APACHE_LISTENER_CONF,
    command_runner=run,
    dry_run: bool = False,
) -> None:
    """Publish exact listeners; retain original A if rollback cannot complete."""
    rendered = render_native_apache_listener_config(
        service_ips, port=port
    ).encode("utf-8")
    destination = Path(destination)
    if dry_run:
        info(
            "dry-run：将原子发布 Apache exact listener："
            + ", ".join(
                endpoint.host
                for endpoint in _canonical_apache_listener_addresses(
                    service_ips, port=port
                )
            )
        )
        return
    try:
        parent = destination.parent
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise LoadError(f"Apache listener 目录不可用：{destination.parent}: {exc}") from exc
    if not stat.S_ISDIR(parent_metadata.st_mode) or parent.is_symlink():
        raise LoadError(f"Apache listener 目录不安全：{parent}")

    original_exists = False
    original_metadata = None
    try:
        original_metadata = destination.lstat()
        original_exists = True
    except FileNotFoundError:
        pass
    except OSError as exc:
        raise LoadError(f"无法检查 Apache listener：{destination}: {exc}") from exc
    if original_exists and (
        original_metadata is None
        or not stat.S_ISREG(original_metadata.st_mode)
        or original_metadata.st_nlink != 1
    ):
        raise LoadError(f"Apache listener 不是 single-link regular file：{destination}")

    stale_authorities = sorted(
        (
            *parent.glob(f".{destination.name}.*.rollback"),
            *parent.glob(f".{destination.name}.*.recovery"),
        ),
        key=lambda path: path.name,
    )
    if stale_authorities:
        raise LoadError(
            "Apache listener 存在滞留 rollback/recovery authority；"
            "请停止 Apache 并人工处理后重试："
            + ", ".join(path.name for path in stale_authorities)
        )

    candidate_fd, candidate_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=parent,
    )
    candidate = Path(candidate_name)
    backup = parent / f".{destination.name}.{secrets.token_hex(16)}.rollback"
    recovery = parent / f".{destination.name}.{secrets.token_hex(16)}.recovery"
    backup_linked = False
    recovery_linked = False
    published = False
    committed = False
    try:
        with os.fdopen(candidate_fd, "wb") as stream:
            stream.write(rendered)
            stream.flush()
            os.fchmod(stream.fileno(), 0o644)
            if original_metadata is not None and hasattr(os, "fchown"):
                os.fchown(
                    stream.fileno(), original_metadata.st_uid,
                    original_metadata.st_gid,
                )
            os.fsync(stream.fileno())
        # Candidate creation/sync can take time.  The initial A or missing
        # snapshot is not permission to adopt an object which arrived during
        # that interval, even if its bytes and mtime match the original.
        try:
            current_original = destination.lstat()
        except FileNotFoundError:
            current_original = None
        except OSError as exc:
            raise LoadError(f"Apache listener 原前像无法重核；HOLD：{exc}") from exc
        if ((original_metadata is None) != (current_original is None)
                or (original_metadata is not None and current_original is not None
                    and _dhcp_a_preimage_receipt_identity(original_metadata)
                    != _dhcp_a_preimage_receipt_identity(current_original))):
            raise LoadError("Apache listener 原前像身份已变化；HOLD，拒绝备份或覆盖")
        if original_exists:
            os.link(destination, backup, follow_symlinks=False)
            backup_linked = True
        os.replace(candidate, destination)
        published = True
        _fsync_parent_directory(parent)
        try:
            command_runner(sudo_command("apache2ctl", "configtest"))
        except BaseException:
            if backup_linked:
                os.replace(backup, destination)
                backup_linked = False
            else:
                destination.unlink(missing_ok=True)
            published = False
            _fsync_parent_directory(parent)
            raise
        if backup_linked:
            os.link(backup, recovery, follow_symlinks=False)
            recovery_linked = True
            backup.unlink()
            backup_linked = False
        _fsync_parent_directory(parent)
        committed = True
        if recovery_linked:
            recovery.unlink()
            recovery_linked = False
            try:
                _fsync_parent_directory(parent)
            except OSError as exc:
                raise LoadError(
                    "Apache listener 新配置已提交；"
                    "rollback/recovery cleanup durability unknown："
                    f"{exc}"
                ) from exc
    except BaseException:
        if published and not committed:
            try:
                if recovery_linked:
                    os.replace(recovery, destination)
                    recovery_linked = False
                elif backup_linked:
                    os.replace(backup, destination)
                    backup_linked = False
                elif not original_exists:
                    destination.unlink(missing_ok=True)
                _fsync_parent_directory(parent)
            except OSError as rollback_error:
                raise LoadError(
                    "Apache listener 发布失败且旧配置回滚失败；Apache 必须保持停止："
                    f"{rollback_error}"
                ) from rollback_error
        raise
    finally:
        candidate.unlink(missing_ok=True)
        # Once B is visible, an unsuccessful restore must not consume the
        # remaining original A hardlink.  The next publisher already fences
        # these names before any write; only a verified offline recovery may
        # resolve them.  Pre-publication cleanup and committed-B cleanup keep
        # their existing contract.
        if not published or committed:
            if backup_linked:
                backup.unlink(missing_ok=True)
            if recovery_linked:
                recovery.unlink(missing_ok=True)


def _reload_apache_if_active(
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    backend = runtime_backend or service_runtime_backend()
    verify_control_auth(runtime_backend=backend)
    verify_apache_publication_boundary()
    if backend.name == "systemd":
        if _run_subprocess(
            ["systemctl", "is-active", "--quiet", "apache2"], check=False,
        ).returncode == 0:
            run(sudo_command("apache2ctl", "configtest"))
            run(sudo_command("systemctl", "reload", "apache2"))
        return
    if _runtime_service_active(backend, "apache2"):
        run(sudo_command("apache2ctl", "configtest"))
        _runtime_service_action(backend, "reload", "apache2")


def _start_supervisor_program(
    service: str, scope: str, *,
    runtime_backend: ServiceRuntimeBackend | None = None,
    monitor_interval: int | None = None,
) -> bool:
    """Start/restart a long-running worker only when Supervisor owns it."""
    backend = runtime_backend or service_runtime_backend()
    if backend.name != "supervisor":
        return False
    configured_scope = str(os.environ.get("HTTP_ZTP_SCOPE") or "").strip().casefold()
    if configured_scope not in {"air", "prod"}:
        raise LoadError(
            "Supervisor worker 启动需要 HTTP_ZTP_SCOPE=air 或 prod"
        )
    if configured_scope != scope:
        raise LoadError(
            f"请求的 monitor scope={scope} 与容器 HTTP_ZTP_SCOPE="
            f"{configured_scope} 不一致"
        )
    if monitor_interval is not None:
        raw_interval = str(
            os.environ.get("HTTP_ZTP_MONITOR_INTERVAL") or "30"
        ).strip()
        try:
            configured_interval = int(raw_interval)
        except ValueError as exc:
            raise LoadError(
                "HTTP_ZTP_MONITOR_INTERVAL 必须是整数"
            ) from exc
        if configured_interval != monitor_interval:
            raise LoadError(
                f"请求的 monitor interval={monitor_interval} 与容器 "
                f"HTTP_ZTP_MONITOR_INTERVAL={configured_interval} 不一致"
            )
    action = "restart" if _runtime_service_active(backend, service) else "start"
    _runtime_service_action(backend, action, service)
    return True


def start_switch_collection_worker(
    scope: str, *, dry_run: bool = False,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    """Start the Switch Status collector with resources separate from ZTP control."""
    status_dir = HTTP_ROOT / "monitor/status"
    request_file = status_dir / "switch-collection.request"
    pid_file = status_dir / "switch-collection.pid"
    log_file = status_dir / "switch-collection.log"
    command = [
        sys.executable, "-u", str(SWITCH_COLLECTION_WORKER), "--scope", scope,
    ]
    display = " ".join(shlex_quote(item) for item in command)
    backend = runtime_backend or service_runtime_backend()
    verify_control_auth(runtime_backend=backend, dry_run=dry_run)
    verify_apache_publication_boundary(dry_run=dry_run)
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
    _reload_apache_if_active(backend)
    if _start_supervisor_program(
        "switch-collection", scope, runtime_backend=backend,
    ):
        ok(f"Supervisor Switch 收集 worker 已启动：scope={scope}")
        return

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
        process = _popen_subprocess(
            command, cwd=HTTP_ROOT, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if process.poll() is not None:
        pid_file.unlink(missing_ok=True)
        raise LoadError(f"Switch 收集 worker 启动后立即退出；请检查 {log_file}")
    ok(f"独立 Switch 收集 worker 已启动：PID={process.pid}，scope={scope}，日志={log_file}")


def start_manual_ztp_worker(
    scope: str, *, dry_run: bool = False,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    """Start the restricted per-device manual ZTP GUI worker."""
    if scope not in {"air", "prod"}:
        raise LoadError("手工 ZTP worker 必须使用 air 或 prod scope")
    status_dir = HTTP_ROOT / "monitor/status"
    request_file = status_dir / "manual-ztp.request.json"
    pid_file = status_dir / "manual-ztp.pid"
    log_file = status_dir / "manual-ztp.log"
    command = [sys.executable, "-u", str(MANUAL_ZTP_WORKER), "--scope", scope]
    display = " ".join(shlex_quote(item) for item in command)
    backend = runtime_backend or service_runtime_backend()
    verify_control_auth(runtime_backend=backend, dry_run=dry_run)
    verify_apache_publication_boundary(dry_run=dry_run)
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
    _reload_apache_if_active(backend)
    if _start_supervisor_program(
        "manual-ztp", scope, runtime_backend=backend,
    ):
        ok(f"Supervisor 手工 ZTP worker 已启动：scope={scope}")
        return

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
        process = _popen_subprocess(
            command, cwd=HTTP_ROOT, stdin=subprocess.DEVNULL,
            stdout=output, stderr=subprocess.STDOUT, start_new_session=True,
        )
    pid_file.write_text(f"{process.pid}\n", encoding="utf-8")
    if process.poll() is not None:
        pid_file.unlink(missing_ok=True)
        raise LoadError(f"手工 ZTP worker 启动后立即退出；请检查 {log_file}")
    ok(f"手工 ZTP worker 已启动：PID={process.pid}，scope={scope}，日志={log_file}")


def _terminate_failed_ztp_monitor_start(process: subprocess.Popen) -> None:
    try:
        process.terminate()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        process.kill()
    except (OSError, ProcessLookupError):
        pass
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def reset_completion_handoff_state(*, dry_run: bool = False) -> None:
    """Owner 2026-10-23: after every successful load the monitor collects again.

    12-ztp-monitor.py remembers the ZTP completion rounds it already handed to
    collection (.ztp-completion-handoff.json), so a monitor restart alone never
    collects twice. A new load forgets them: the restarted monitor then collects,
    analyses and refreshes the page for every type that is, or becomes, fully
    provisioned (native: cron.sh; Docker: one switch-collection worker cycle).
    """
    status_dir, _pid_file, _log_file = _ztp_monitor_paths()
    state = status_dir / ".ztp-completion-handoff.json"
    if dry_run:
        print(f"[DRY] 清除 ZTP→Switch 交接签名：{state}")
        return
    try:
        metadata = os.lstat(state)
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode):
        warn(f"ZTP→Switch 交接签名不是普通文件，未处理：{state}")
        return
    try:
        state.unlink()
    except PermissionError:
        run(sudo_command("rm", "-f", "--", str(state)))
    info("已清除 ZTP→Switch 交接签名：各类型达到 100% 时会重新采集、分析并刷新页面")


def start_ztp_monitor(
    project: Path, *, interval: int = DEFAULT_ZTP_MONITOR_INTERVAL,
    scope: str = "all",
    service_ips: tuple[str, ...] = (),
    http_port: int = 80,
    dry_run: bool = False,
    runtime_backend: ServiceRuntimeBackend | None = None,
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
        "--collect-on-complete",
        "--known-hosts", str(known_hosts),
        "--scope", scope,
    ]
    display = " ".join(shlex_quote(item) for item in command)
    backend = runtime_backend or service_runtime_backend()
    verify_control_auth(runtime_backend=backend, dry_run=dry_run)
    verify_apache_publication_boundary(dry_run=dry_run)
    if dry_run:
        print(
            f"[DRY] 安装 ZTP 页面控制端点：{ZTP_MONITOR_CONTROL_SOURCE} -> "
            f"{ZTP_MONITOR_CONTROL_DEST}"
        )
        print(f"[DRY] 后台启动：{display}")
        print(f"[DRY] PID: {pid_file}；日志: {log_file}")
        print_ztp_monitor_access(service_ips, port=http_port)
        return

    status_dir.mkdir(parents=True, exist_ok=True)
    if not ZTP_MONITOR_CONTROL_SOURCE.is_file():
        raise LoadError(f"ZTP 页面控制脚本不存在：{ZTP_MONITOR_CONTROL_SOURCE}")
    run(sudo_command("install", "-d", "-m", "0755", str(ZTP_MONITOR_CONTROL_DEST.parent)))
    run(sudo_command(
        "install", "-m", "0755", str(ZTP_MONITOR_CONTROL_SOURCE),
        str(ZTP_MONITOR_CONTROL_DEST),
    ))
    run(sudo_command("a2enconf", "serve-cgi-bin"))
    with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8") as control_source:
        control_source.write("running\n")
        control_source.flush()
        run(sudo_command(
            "install", "-m", "0664", "-o", "root", "-g", "www-data",
            control_source.name, str(control_file),
        ))
    _reload_apache_if_active(backend)
    if _start_supervisor_program(
        "ztp-monitor", scope, runtime_backend=backend,
        monitor_interval=interval,
    ):
        ok(
            "Supervisor ZTP 后台监控已启动："
            f"间隔由容器运行态管理，scope={scope}"
        )
        print_ztp_monitor_access(service_ips, port=http_port)
        return
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
    with log_file.open("a", encoding="utf-8") as output:
        output.write(
            f"\n[{time.strftime('%Y-%m-%d %H:%M:%S')}] "
            f"load.py starting: {display}\n"
        )
        output.flush()
        with monitor_pid_lock(pid_file):
            if pid_file.exists():
                pid_file.unlink()
            process = _popen_subprocess(
                command,
                cwd=HTTP_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=output,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
            try:
                write_monitor_pid_record_locked(pid_file, process.pid)
            except BaseException:
                _terminate_failed_ztp_monitor_start(process)
                raise
            if process.poll() is not None:
                pid_file.unlink(missing_ok=True)
                raise LoadError(
                    f"ZTP 后台监控启动后立即退出；请检查 {log_file}"
                )
    ok(
        f"ZTP 后台监控已启动：PID={process.pid}，间隔={interval}s，"
        f"scope={scope}，日志={log_file}；停止命令：kill $(cat {pid_file})"
    )
    print_ztp_monitor_access(service_ips, port=http_port)


def local_ipv4_addresses() -> set[str]:
    addresses: set[str] = set()
    if shutil.which("ip"):
        result = _run_subprocess(
            ["ip", "-4", "-o", "addr", "show"], capture_output=True, text=True
        )
        if result.returncode == 0:
            addresses.update(re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)/", result.stdout))
    if not addresses and shutil.which("ifconfig"):
        result = _run_subprocess(["ifconfig"], capture_output=True, text=True)
        if result.returncode == 0:
            addresses.update(re.findall(r"\binet\s+(\d+\.\d+\.\d+\.\d+)\b", result.stdout))
    validated = set()
    for address in addresses:
        try:
            validated.add(
                validate_service_endpoint(
                    address, field="local HTTP service IPv4"
                ).host
            )
        except ValueError:
            continue
    return validated


def service_ip_bindings(inputs: ProjectInputs) -> tuple[str, ...]:
    """Return service IP/prefix pairs sourced from enabled endpoint rows."""
    allowed = set(inputs.settings.service_ips)
    bindings: dict[str, int] = {}
    with _snapshot_subnet_input_stream(
        _open_subnet_input_file(inputs.subnet_file)
    ) as stream:
        line_starts = _subnet_record_lines(stream)
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for index, row in enumerate(reader):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            lineno = line_starts[index]
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
    result = _run_subprocess(
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
            check = _run_subprocess(
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
                _run_subprocess(
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
            current = _run_subprocess(
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
                _run_subprocess(
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
    configured_ips = set(settings.http_listener_ips)
    local_ips = local_ipv4_addresses()
    matching_local = sorted(configured_ips & local_ips)
    missing_local = sorted(configured_ips - local_ips, key=ipaddress.IPv4Address)
    if not matching_local:
        problems.append(
            "HTTP listener 地址中没有任何地址配置在本机接口"
            f"（listener={','.join(sorted(configured_ips)) or 'none'}；"
            f"local={','.join(sorted(local_ips)) or 'none'}）"
        )
    elif missing_local:
        warn(
            "以下 HTTP listener 地址尚未配置在本机接口，将在 DHCP 重启前逐一门禁并"
            "提供重试提示：" + ", ".join(missing_local)
        )
    if settings.http_address and settings.http_address not in local_ips:
        problems.append(
            "common.mgmt.http.address 未配置在本机接口："
            + settings.http_address
        )
    disabled = []
    if not settings.http_enabled:
        disabled.append("http")
    if not settings.dhcp_enabled:
        info("global 中 dhcp-server 已禁用；独立校验 HTTP 发布条件")
    if disabled:
        problems.append("以下服务在 global 中未启用：" + ", ".join(disabled))
    if not problems:
        ok("管理服务器 HTTP 根目录和本机 listener 基础检查通过：" + ", ".join(matching_local))
        return True
    message = "；".join(problems)
    warn("服务不可用，不能在本机部署/启动 Apache 与 DHCP：" + message)
    info("load 将继续完成项目 setup、bootstrap 渲染和配置文件生成")
    return False


def supervisor_http_required(inputs: ProjectInputs, plan: DhcpRuntimePlan) -> bool:
    """Include explicit HTTP authority even when DHCP has no local plan."""
    return bool(
        plan.endpoint_ips
        or (inputs.settings.http_enabled and inputs.settings.http_address)
    )


def supervisor_service_availability(
    inputs: ProjectInputs, plan: DhcpRuntimePlan, dry_run: bool = False,
) -> tuple[bool, bool]:
    """Return independent HTTP and DHCP availability for one container plan.

    A DHCP-only shared network deliberately has no ZTP service endpoint.  The
    legacy management-host gate couples Apache, DHCP, and ZTP and therefore
    cannot classify that valid Supervisor case.  The live planner is already
    the authority for local endpoint/listener ownership; this adapter keeps
    the legacy systemd decision unchanged while allowing only the services
    explicitly justified by the container plan.
    """
    # A disabled local DHCP server has no DHCP runtime endpoints, but an
    # independently configured HTTP listener can still serve this host.
    http_available = supervisor_http_required(inputs, plan)
    dhcp_available = bool(plan.listener_names)
    if http_available and not validate_management_host(inputs.settings, dry_run):
        raise LoadError(
            "Supervisor runtime 需要启动 Apache，但 HTTP/ZTP 管理服务器门禁未通过"
        )
    if dhcp_available and not inputs.settings.dhcp_enabled:
        raise LoadError(
            "DHCP listener 规划非空，但 global 中 dhcp-server 未启用"
        )
    if dhcp_available:
        info(
            "Supervisor DHCP 服务可用：listeners="
            + ", ".join(plan.listener_names)
        )
    if not http_available and dhcp_available:
        info("当前为 DHCP-only/relay 运行态；没有 HTTP endpoint，不启动 Apache")
    return http_available, dhcp_available


def _explicit_http_only(settings: GlobalSettings) -> bool:
    """Independent declared HTTP authority, not merely an enabled flag."""
    if getattr(settings, "http_address", None) is None:
        return False
    if not (settings.http_enabled and not settings.dhcp_enabled
            and not settings.ztp_enabled):
        return False
    try:
        validate_service_endpoint(settings.http_address, settings.http_port,
                                  field="common.mgmt.http.address")
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    return True


def verify_http_publication(inputs: ProjectInputs, images: dict[str, Path], dry_run: bool) -> None:
    plan = publication_plan_for(
        inputs.settings,
        pubkey_names=tuple(
            pubkey.name for pubkey in deployable_pubkeys(inputs.pubkeys)
        ),
        image_names=tuple(
            ("cumulus" if kind == "eth" else "nvos", image.name)
            for kind, image in images.items()
        ),
    )
    probed_channels = frozenset({
        "pubkey", "dhcp-provision-url", "dhcp-bootfile", "image",
    })
    urls = dict.fromkeys(
        item.url for item in device_visible_urls(plan)
        if item.channel in probed_channels
    )
    if (getattr(inputs.settings, "http_address", None) is not None
            and inputs.settings.http_enabled):
        try:
            endpoint = validate_service_endpoint(
                inputs.settings.http_address, inputs.settings.http_port,
                field="common.mgmt.http.address",
            )
            for name in plan.pubkey_names:
                urls[service_url(endpoint, f"/config/publickey/{name}",
                                 prefix=inputs.settings.ztp_prefix,
                                 channel="pubkey")] = None
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
        if not urls:
            raise LoadError("explicit HTTP publication has no qualified public probe; HOLD")
    for url in urls:
        run(["curl", "-fsSI", "--max-time", "5", url], dry_run=dry_run)


def require_http_project_source_access(
    project: Path, *, http_root: Path | None = None, ztp_dir: Path | None = None,
) -> None:
    """Read-only necessary POSIX access gate, never a chmod or HTTP success proof.

    Require every user class to traverse public directories, and declare only
    the two public-key leaves for early source admission. Native key parsing,
    output/manifest gates and actual HTTP health remain separately mandatory.
    Extended ACLs need an explicit separate access contract; do not guess.
    """
    root_name, project_name = Path(HTTP_ROOT if http_root is None else http_root), Path(project)
    ztp_name = Path(ZTP_DIR if ztp_dir is None else ztp_dir)
    root = root_name.resolve(strict=True)
    canonical = project_name.resolve(strict=True)
    if canonical == root or not canonical.is_relative_to(root):
        raise LoadError("HTTP public project source escapes HTTP_ROOT")
    directory_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_ctime_ns")
    exterior_directory_fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid")
    leaf_fields = (*directory_fields, "st_nlink", "st_size", "st_mtime_ns")
    held = []
    descriptors = []
    directories = set()
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)

    def identity(metadata, fields):
        return tuple(getattr(metadata, field) for field in fields)

    def open_object(path, *, directory, inside):
        before = os.lstat(path)
        mode = stat.S_IMODE(before.st_mode)
        if directory:
            if not stat.S_ISDIR(before.st_mode) or mode & 0o111 != 0o111:
                raise LoadError(f"HTTP public directory is not traversable without permission repair: {path} mode={mode:04o}")
            if before.st_uid not in (0, os.geteuid()):
                raise LoadError(f"HTTP public ancestor has foreign owner: {path}")
            if mode & 0o022 and not (mode & stat.S_ISVTX and before.st_uid == 0 and not inside):
                raise LoadError(f"HTTP public directory has unqualified writable ancestor: {path}")
            if inside and (before.st_uid, before.st_gid) != (os.geteuid(), os.getegid()):
                raise LoadError(f"HTTP public directory owner uid/gid differs from current authority: {path}")
            selected = directory_fields if inside else exterior_directory_fields
        else:
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or mode != 0o644
                    or (before.st_uid, before.st_gid) != (os.geteuid(), os.getegid())):
                raise LoadError(f"HTTP public key must be owned single-link regular 0644; no implicit repair: {path}")
            selected = leaf_fields
        descriptor = os.open(path, flags | (os.O_DIRECTORY if directory else 0))
        # Record ownership before fstat can fail; not-yet-qualified descriptors
        # remain ours to close, never an excuse to leak or retry a reused FD.
        descriptors.append(descriptor)
        opened = os.fstat(descriptor)
        held.append((path, descriptor, selected, identity(opened, selected)))
        if identity(before, selected) != identity(opened, selected):
            raise LoadError(f"HTTP public object changed while opening: {path}")

    try:
        # Give a precise root/project/key reason before broader ancestor
        # admission. No file data, directory children or private key is read.
        for path in (root, canonical):
            open_object(path, directory=True, inside=True)
            directories.add(path)
        for name in (LAPTOP_PUBKEY_NAME, MANAGEMENT_PUBKEY_NAME):
            path = canonical / name
            if os.path.lexists(path):
                open_object(path, directory=False, inside=True)
            # An absent initialization placeholder is not approved for HTTP;
            # Native prepare_pubkeys must later supply exact 0644 authority.
        if ztp_name.parent.resolve(strict=True) != root:
            raise LoadError("HTTP public ZTP root is outside the held document root")
        core_ztp = root / ztp_name.name
        public_parents = (core_ztp, core_ztp / "config", core_ztp / "config/publickey",
                          root / "infiniband", root / "infiniband/publickey", root / "image")
        for path in public_parents:
            if os.path.lexists(path):
                if not path.is_relative_to(root):
                    raise LoadError(f"HTTP public parent escapes HTTP_ROOT: {path}")
                open_object(path, directory=True, inside=True)
                directories.add(path)
        for original in tuple(directories):
            for parent in original.parents:
                if parent not in directories:
                    open_object(parent, directory=True, inside=parent.is_relative_to(root))
                    directories.add(parent)
                if len(directories) > 128:
                    raise LoadError("HTTP public directory access inventory exceeds bound")
        introspect_acl = getattr(os, "listxattr", None)
        if not callable(introspect_acl):
            raise LoadError("HTTP public ACL introspection is unavailable; HOLD")
        def require_acl_absent(path):
            try:
                attributes = introspect_acl(path, follow_symlinks=False)
            except (NotImplementedError, TypeError) as exc:
                raise LoadError("HTTP public ACL introspection is unsupported; HOLD") from exc
            if any(name in attributes for name in ("system.posix_acl_access", "system.posix_acl_default")):
                raise LoadError(f"HTTP public ACL requires an explicit reader-access contract: {path}")
        for path, _descriptor, _selected, _baseline in held:
            require_acl_absent(path)
        for path, descriptor, selected, baseline in held:
            if (identity(os.fstat(descriptor), selected) != baseline
                    or identity(os.lstat(path), selected) != baseline):
                raise LoadError(f"HTTP public object rebound or permission changed before publication: {path}")
        if (root_name.resolve(strict=True) != root
                or project_name.resolve(strict=True) != canonical):
            raise LoadError("HTTP public root/project alias changed before publication")
        # Exterior directory ctime is volatile child bookkeeping, not release
        # authority. Retain a second explicit ACL absence check instead of
        # interpreting unrelated sibling mkdir as a permission change.
        for path, _descriptor, _selected, _baseline in held:
            require_acl_absent(path)
        for path, descriptor, selected, baseline in held:
            if (identity(os.fstat(descriptor), selected) != baseline
                    or identity(os.lstat(path), selected) != baseline):
                raise LoadError(f"HTTP public object rebound or permission changed before publication: {path}")
    except OSError as exc:
        raise LoadError(f"HTTP public source access cannot be safely qualified: {exc}") from exc
    finally:
        preserving_exception = sys.exc_info()[0] is not None
        first_close_error = None
        for descriptor in reversed(descriptors):
            try:
                os.close(descriptor)
            except OSError as exc:
                # A failed close may have consumed the number. Do not retry;
                # continue once over the remaining retained owned descriptors.
                if first_close_error is None: first_close_error = exc
        if first_close_error is not None and not preserving_exception:
            raise LoadError("HTTP public source descriptor close failed; HOLD") from first_close_error


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


def _verified_control_auth_payload(path: Path, label: str) -> bytes:
    """Read one single-link regular helper and bind it to the frozen source."""
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if no_follow is None:
        raise LoadError("Monitor control auth helper 校验要求 O_NOFOLLOW")
    flags = (
        os.O_RDONLY
        | no_follow
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise LoadError(f"{label}不可用：{path}: {exc}") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise LoadError(f"{label}必须是 single-link regular file：{path}")
        if metadata.st_size <= 0 or metadata.st_size > CONTROL_AUTH_HELPER_MAX_BYTES:
            raise LoadError(f"{label}大小超出安全范围：{path}")
        chunks = []
        total = 0
        while True:
            chunk = os.read(
                descriptor,
                min(65536, CONTROL_AUTH_HELPER_MAX_BYTES + 1 - total),
            )
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > CONTROL_AUTH_HELPER_MAX_BYTES:
                raise LoadError(f"{label}大小超出安全范围：{path}")
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError as exc:
        raise LoadError(f"{label}读取失败：{path}: {exc}") from exc
    finally:
        os.close(descriptor)

    def identity(value: os.stat_result) -> tuple[int, ...]:
        return (
            value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_uid, value.st_gid, value.st_size,
            getattr(value, "st_mtime_ns", 0),
            getattr(value, "st_ctime_ns", 0),
        )

    try:
        named = path.lstat()
    except OSError as exc:
        raise LoadError(f"{label}在校验期间发生变化：{path}") from exc
    if (
        identity(metadata) != identity(after)
        or identity(after) != identity(named)
        or len(payload) != after.st_size
    ):
        raise LoadError(f"{label}在校验期间发生变化：{path}")
    actual = hashlib.sha256(payload).hexdigest()
    if actual != CONTROL_AUTH_SOURCE_SHA256:
        raise LoadError(
            f"{label} source/helper hash 不一致：{path} sha256={actual}，"
            f"期望={CONTROL_AUTH_SOURCE_SHA256}"
        )
    return payload


def verify_control_auth(
    *, runtime_backend: ServiceRuntimeBackend | None = None,
    dry_run: bool = False,
) -> None:
    """Bind source + installed helper bytes and validate persistent auth state."""
    backend = runtime_backend or service_runtime_backend()
    helpers = {
        "systemd": CONTROL_AUTH_NATIVE_HELPER,
        "supervisor": CONTROL_AUTH_CONTAINER_HELPER,
    }
    try:
        helper = helpers[backend.name]
    except KeyError as exc:
        raise LoadError(f"不支持的 control auth runtime backend：{backend.name}") from exc
    if dry_run:
        print(
            f"[DRY] 校验 Monitor control auth：source={CONTROL_AUTH_SOURCE}，"
            f"helper={helper}，sha256={CONTROL_AUTH_SOURCE_SHA256}"
        )
        return
    source_payload = _verified_control_auth_payload(
        CONTROL_AUTH_SOURCE, "Monitor control auth 源码",
    )
    installed_payload = _verified_control_auth_payload(
        helper, "Monitor control auth 已安装 helper",
    )
    if not hmac.compare_digest(source_payload, installed_payload):
        raise LoadError("Monitor control auth source/helper bytes 不一致")
    run(sudo_command(str(helper), "validate"), dry_run=False)
    ok(f"Monitor control auth 已验证：{helper}")


def verify_monitor_authority(
    *, runtime_backend: ServiceRuntimeBackend | None = None,
    dry_run: bool = False,
) -> None:
    """Attest only; lifecycle setup owns all Monitor authority provisioning."""
    backend = runtime_backend or service_runtime_backend()
    helpers = {
        "systemd": CONTROL_AUTH_NATIVE_HELPER,
        "supervisor": CONTROL_AUTH_CONTAINER_HELPER,
    }
    try:
        helper = helpers[backend.name]
    except KeyError as exc:
        raise LoadError(
            f"不支持的 Monitor authority runtime backend：{backend.name}"
        ) from exc
    if dry_run:
        print(f"[DRY] 只读校验 Monitor cache authority：helper={helper}")
        return
    source_payload = _verified_control_auth_payload(
        CONTROL_AUTH_SOURCE, "Monitor control auth 源码",
    )
    installed_payload = _verified_control_auth_payload(
        helper, "Monitor control auth 已安装 helper",
    )
    if not hmac.compare_digest(source_payload, installed_payload):
        raise LoadError("Monitor control auth source/helper bytes 不一致")
    command = sudo_command(str(helper), "monitor-authority-attest")
    print(f"[RUN] ({Path.cwd()}) {' '.join(shlex_quote(item) for item in command)}")
    result = _run_subprocess(
        command, capture_output=True, text=True, check=False,
    )
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    unsafe_output = (
        len(stdout.encode("utf-8", errors="replace")) > CONTROL_AUTH_STATUS_MAX_BYTES
        or len(stderr.encode("utf-8", errors="replace")) > CONTROL_AUTH_STATUS_MAX_BYTES
        or "\x00" in stdout
        or "\x00" in stderr
    )
    returncode = int(getattr(result, "returncode", 1))
    if not unsafe_output and returncode == 4:
        try:
            payload = json.loads(stdout)
        except (json.JSONDecodeError, TypeError, ValueError):
            payload = None
        if (
            isinstance(payload, dict)
            and set(payload) == {"classification", "valid"}
            and payload.get("valid") is False
            and payload.get("classification") in {
                "recovery-in-progress",
                "recovery-committed-cleanup-pending",
            }
            and stdout == (
                json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n"
            )
        ):
            classification = str(payload["classification"])
            recovery_command = {
                "systemd": (
                    "sudo ./infra/infra-setup.py --recover-monitor-authority --apply"
                ),
                "supervisor": (
                    "sudo ./infra/docker/deploy.sh recover-monitor-authority"
                ),
            }[backend.name]
            if classification == "recovery-committed-cleanup-pending":
                raise LoadError(
                    "classification=recovery-committed-cleanup-pending；previous "
                    "Monitor authority recovery COMPLETED；the repaired authority "
                    "itself is not in question；仅需重新只读验证并完成 marker cleanup："
                    f"{recovery_command}"
                )
            raise LoadError(
                "classification=recovery-in-progress；Monitor authority recovery "
                "尚未提交，服务必须保持停止；请严格运行："
                f"{recovery_command}"
            )
    if unsafe_output or returncode != 0 or stdout or stderr:
        raise LoadError("Monitor cache authority 只读验证失败；服务保持停止")
    ok(f"Monitor cache authority 已只读验证：{helper}")


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
            "缺少 Apache 静态发布边界；请先运行当前 infra-setup.py --mgmt --apply："
            f"{APACHE_PUBLIC_BOUNDARY_CONF}: {exc}"
        ) from exc
    actual = hashlib.sha256(payload).hexdigest()
    if actual != APACHE_PUBLIC_BOUNDARY_SHA256:
        raise LoadError(
            "Apache 静态发布边界与当前 load 版本不一致："
            f"{APACHE_PUBLIC_BOUNDARY_CONF} sha256={actual}，"
            f"期望={APACHE_PUBLIC_BOUNDARY_SHA256}；请重新运行当前 infra-setup.py --mgmt --apply"
        )
    ok(f"Apache 静态发布边界已验证：{APACHE_PUBLIC_BOUNDARY_CONF}")


def _selected_service_dhcp_guard(project: Path, expected_parent=None):
    """Use committed DHCP authority, not SETUP's historical flat placeholders.

    This read-only gate neither republishes flat output nor authorizes service
    activation. Installed bytes must match the selected immutable generation;
    a present but invalid selector can never fall back to legacy source paths.
    """
    from project_contract import open_selected_dhcp_release, recheck_selected_dhcp_release
    try:
        selected = open_selected_dhcp_release(project, expected_parent=expected_parent)
    except (ValueError, OSError) as exc:
        raise LoadError(f"selected DHCP service authority is invalid: {exc}") from exc
    if selected.mode != "pinned":
        raise LoadError("selected DHCP service gate requires an enabled pinned release")

    def installed_snapshot():
        paths = _runtime_installed_dhcp_paths()
        directory = next(iter(paths.values())).parent
        owner = _setup_switch_directory_identity(directory)
        uid = directory.lstat().st_uid
        leaves = {name: _setup_switch_dhcp_owned_leaf(path) for name, path in paths.items()}
        if any(row is None or not stat.S_ISREG(row["identity"][2])
               or row["identity"][3] != uid or row["identity"][2] & 0o022
               or row["state"]["state"] != "file"
               or row["state"]["sha256"] != selected.output_hashes[name]
               for name, row in leaves.items()):
            raise LoadError("installed DHCP owner/bytes differ from selected release; HOLD")
        return owner, uid, leaves

    try:
        installed = installed_snapshot()
        validate_dhcp_output_sources({selected.output_paths[name]: path
                                      for name, path in _runtime_installed_dhcp_paths().items()})
    except (ValueError, OSError) as exc:
        raise LoadError(f"installed DHCP service authority unavailable; HOLD: {exc}") from exc

    def guard():
        try:
            recheck_selected_dhcp_release(project, selected.binding)
            if installed_snapshot() != installed:
                raise LoadError("installed DHCP owner changed during service preflight; HOLD")
        except (ValueError, OSError) as exc:
            raise LoadError(f"selected DHCP service authority changed; HOLD: {exc}") from exc

    guard()
    return guard


def preflight_services(
    inputs: ProjectInputs, images: dict[str, Path], dry_run: bool = False, *,
    dhcp_runtime_plan: DhcpRuntimePlan | None = None,
    runtime_backend: ServiceRuntimeBackend | None = None,
    committed_dhcp_parent=None,
) -> None:
    dhcp_guard = None

    def checked(function, *args, **kwargs):
        # Once bound, the selected-DHCP guard brackets every later step.
        if dhcp_guard is not None:
            dhcp_guard()
        result = function(*args, **kwargs)
        if dhcp_guard is not None:
            dhcp_guard()
        return result

    def check_dhcp_sources():
        nonlocal dhcp_guard
        project = inputs.global_file.parent
        selected_present = committed_dhcp_parent is not None
        if not selected_present:
            try:
                (project / "99-output-ztp/current").lstat()
                selected_present = True
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise LoadError(f"selected DHCP selector unavailable; HOLD: {exc}") from exc
        if selected_present:
            dhcp_guard = checked(_selected_service_dhcp_guard, project, committed_dhcp_parent)
        else:
            checked(validate_dhcp_output_sources, dhcp_file_mappings())

    # A backend was given exactly when it is not None (not by truth value).
    backend = service_runtime_backend() if runtime_backend is None else runtime_backend
    if backend.name == "supervisor":
        plan = dhcp_runtime_plan or checked(plan_local_dhcp_runtime, inputs)
        http_required, dhcp_required = checked(supervisor_service_availability,
            inputs, plan, dry_run,
        )
        if http_required:
            checked(verify_control_auth, runtime_backend=backend, dry_run=dry_run)
            checked(verify_published_files, inputs, images, dry_run=dry_run)
            checked(verify_apache_publication_boundary, dry_run=dry_run)
            checked(run, sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
        if dhcp_required:
            check_dhcp_sources()
            checked(run,
                sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"),
                dry_run=dry_run,
            )
        if not http_required and not dhcp_required:
            info("Supervisor runtime plan 不需要启动 Apache/DHCP")
        else:
            labels = [
                name for required, name in (
                    (http_required, "Apache"), (dhcp_required, "DHCP"),
                ) if required
            ]
            ok("启动前检查通过：" + "/".join(labels) + " 配置有效")
        return
    http_required = bool(
        inputs.settings.http_enabled and inputs.settings.http_listener_ips
    )
    dhcp_required = inputs.settings.dhcp_enabled
    if not http_required and not dhcp_required:
        info("当前项目没有需启动的 Apache/DHCP 服务")
        return
    if http_required:
        if not checked(validate_management_host, inputs.settings, dry_run):
            raise LoadError("本机服务启动条件不满足")
        checked(verify_control_auth, runtime_backend=backend, dry_run=dry_run)
        checked(verify_published_files, inputs, images, dry_run=dry_run)
        checked(verify_apache_publication_boundary, dry_run=dry_run)
    if dhcp_required:
        check_dhcp_sources()
        checked(run,
            sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"),
            dry_run=dry_run,
        )
    if http_required:
        checked(run, sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
    ok(
        "启动前检查通过："
        + ("Apache/HTTP 有效" if http_required else "Apache/HTTP 不启动")
        + ("；DHCP 配置有效" if dhcp_required else "；DHCP 已禁用")
    )


def ztp_url_network_requirements(
    inputs: ProjectInputs,
) -> tuple[tuple[str, ...], dict[str, list[tuple[str, str, str]]]]:
    """Return URL service CIDRs and the DHCP networks which reference each IP."""
    bindings = service_ip_bindings(inputs)
    references: dict[str, list[tuple[str, str, str]]] = {}
    with _snapshot_subnet_input_stream(
        _open_subnet_input_file(inputs.subnet_file)
    ) as stream:
        line_starts = _subnet_record_lines(stream)
        reader = csv.DictReader(stream)
        _prepare_subnet_reader(reader)
        for index, row in enumerate(reader):
            if not any(str(value or "").strip() for value in row.values()):
                continue
            lineno = line_starts[index]
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
    addresses = inputs.settings.http_listener_ips
    if not addresses:
        raise LoadError("ZTP URL 发布需要启用 common.mgmt.http.address")
    if dry_run:
        info(
            "dry-run：重启 DHCP 前将逐一检查本地 endpoint："
            + ", ".join(addresses)
        )
        return
    while True:
        assignments = _local_ipv4_assignments()
        missing_addresses = missing_service_ip_addresses(
            addresses, assignments,
        )
        if not missing_addresses:
            details = []
            for address in addresses:
                names = ",".join(
                    sorted(
                        f"{name}/{prefix}"
                        for name, prefix in assignments.get(address, set())
                    )
                )
                details.append(f"{address} dev {names}")
            ok(
                "DHCP 重启门禁：全部 HTTP URL endpoint 均已配置在本地接口（"
                + "；".join(details) + "）"
            )
            return
        if missing_addresses:
            warn(
                "以下 HTTP URL endpoint IP 未配置在本机任何接口："
                + ", ".join(missing_addresses)
            )
            for address in missing_addresses:
                print(f"  - {address}（请按管理网络规划配置正确 CIDR）")
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


@dataclass(frozen=True)
class _NativeHttpOnlyLoadedUnit:
    unit_state: object
    runtime: ServiceRuntimeState


@dataclass(frozen=True)
class _NativeHttpOnlyAbsentIsc:
    """Invocation-local exact absence, never a rollback bool codec value."""


@dataclass(frozen=True)
class _NativeHttpOnlyPresence:
    apache: _NativeHttpOnlyLoadedUnit
    isc: _NativeHttpOnlyLoadedUnit | _NativeHttpOnlyAbsentIsc


def _snapshot_native_http_only_presence(
    inputs: ProjectInputs, *, runtime_backend: ServiceRuntimeBackend,
) -> _NativeHttpOnlyPresence:
    if (type(runtime_backend) is not SystemdRuntimeBackend
            or not _explicit_http_only(inputs.settings)):
        raise LoadError("optional ISC presence requires explicit native HTTP-only target")
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise LoadError("optional ISC presence requires systemctl; HOLD")

    def query(command, **kwargs):
        arguments = list(command)
        if arguments and arguments[0] == "systemctl":
            arguments[0] = systemctl
        return _run_subprocess(arguments, **kwargs)

    try:
        reader = runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=query,
        )
        # Qualify the complete fixed pair before quiet queries or controls.
        apache = reader.read_unit_state("apache2")
        isc = reader.read_unit_state("isc-dhcp-server")
        apache.require_loaded()
        apache_runtime = ServiceRuntimeState(
            active=reader.is_active("apache2"), enabled=reader.is_enabled("apache2"),
        )
        apache_present = _NativeHttpOnlyLoadedUnit(apache, apache_runtime)
        if isc.load_state == "not-found":
            return _NativeHttpOnlyPresence(apache_present, _NativeHttpOnlyAbsentIsc())
        isc.require_loaded()
        return _NativeHttpOnlyPresence(
            apache_present,
            _NativeHttpOnlyLoadedUnit(isc, ServiceRuntimeState(
                active=reader.is_active("isc-dhcp-server"),
                enabled=reader.is_enabled("isc-dhcp-server"),
            )),
        )
    except (RuntimeContractError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise LoadError("cannot qualify explicit HTTP-only service presence; HOLD") from exc


def _converge_native_http_only_services(
    inputs: ProjectInputs, *, runtime_backend: ServiceRuntimeBackend,
    disable_apache: bool = False,
) -> None:
    if type(disable_apache) is not bool:
        raise LoadError("invalid HTTP-only stopped convergence policy")
    presence = _snapshot_native_http_only_presence(inputs, runtime_backend=runtime_backend)
    commands = []
    for service, entry in (("isc-dhcp-server", presence.isc), ("apache2", presence.apache)):
        if isinstance(entry, _NativeHttpOnlyAbsentIsc):
            continue
        # quiet3/activeFalse never establishes stopped state, including no-op.
        if not entry.unit_state.loaded_quiescent():
            commands.append(("stop", service))
    if (isinstance(presence.isc, _NativeHttpOnlyLoadedUnit)
            and presence.isc.runtime.enabled):
        commands.append(("disable", "isc-dhcp-server"))
    if disable_apache and presence.apache.runtime.enabled:
        commands.append(("disable", "apache2"))
    failures = []
    for action, service in commands:
        try:
            run(sudo_command("systemctl", action, service))
        except (LoadError, OSError, subprocess.SubprocessError) as exc:
            failures.append(exc)
    # Even a failed action may have changed a service; always freshly qualify
    # the complete pair before reporting success or incomplete convergence.
    current = presence
    if commands:
        try:
            current = _snapshot_native_http_only_presence(inputs, runtime_backend=runtime_backend)
        except (LoadError, OSError, subprocess.SubprocessError) as exc:
            failures.append(exc)
    if failures:
        raise LoadError("HTTP-only stopped convergence incomplete; HOLD") from failures[0]
    if not current.apache.unit_state.loaded_quiescent():
        raise LoadError("Apache not confirmed stopped; HOLD")
    if isinstance(current.isc, _NativeHttpOnlyLoadedUnit):
        if not current.isc.unit_state.loaded_quiescent() or current.isc.runtime.enabled:
            raise LoadError("ISC not confirmed stopped and disabled; HOLD")
    if disable_apache and current.apache.runtime.enabled:
        raise LoadError("Apache not confirmed disabled; HOLD")


def _start_native_http_only_services(
    inputs: ProjectInputs, images: dict[str, Path], *, runtime_backend: ServiceRuntimeBackend,
) -> None:
    # Internal start_services branch; actual main management-role gate remains
    # authoritative. No new CLI/env or persisted absence permission is added.
    presence = _snapshot_native_http_only_presence(inputs, runtime_backend=runtime_backend)
    try:
        isc_changed = False
        if isinstance(presence.isc, _NativeHttpOnlyLoadedUnit):
            if not presence.isc.unit_state.loaded_quiescent():
                run(sudo_command("systemctl", "stop", "isc-dhcp-server"))
                isc_changed = True
            if presence.isc.runtime.enabled:
                run(sudo_command("systemctl", "disable", "isc-dhcp-server"))
                isc_changed = True
        if isc_changed:
            presence = _snapshot_native_http_only_presence(inputs, runtime_backend=runtime_backend)
            if isinstance(presence.isc, _NativeHttpOnlyLoadedUnit):
                if not presence.isc.unit_state.loaded_quiescent() or presence.isc.runtime.enabled:
                    raise LoadError("ISC not confirmed stopped before HTTP activation; HOLD")
        if not presence.apache.runtime.active or not presence.apache.runtime.enabled:
            run(sudo_command("systemctl", "enable", "--now", "apache2"))
        verify_http_publication(inputs, images, False)
    except BaseException as exc:
        cleanup_failure = None
        try:
            _converge_native_http_only_services(
                inputs, runtime_backend=runtime_backend, disable_apache=True,
            )
        except BaseException as cleanup_exc:
            cleanup_failure = cleanup_exc
        if cleanup_failure is not None:
            if isinstance(exc, Exception):
                raise LoadError(
                    f"{exc}; explicit HTTP-only failed activation cleanup incomplete; HOLD"
                ) from exc
            print("[ERROR] explicit HTTP-only cleanup incomplete; HOLD", file=sys.stderr)
        raise
    ok("DHCP 已禁用；Apache HTTP 发布检查通过，DHCP 保持停止")


def snapshot_service_states(
    services: tuple[str, ...], *,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> dict[str, ServiceRuntimeState]:
    """Capture service state after all read-only gates and before first mutation."""
    backend = runtime_backend or service_runtime_backend()
    if backend.name == "supervisor":
        return {
            service: ServiceRuntimeState(
                enabled=True,
                active=_runtime_service_active(backend, service),
            )
            for service in services
        }
    systemctl = shutil.which("systemctl")
    if not systemctl:
        raise LoadError("服务启动门禁失败：未找到 systemctl")
    def snapshot_command(command, **kwargs):
        arguments = list(command)
        if arguments and arguments[0] == "systemctl":
            arguments[0] = systemctl
        return _run_subprocess(arguments, **kwargs)

    states: dict[str, ServiceRuntimeState] = {}
    try:
        reader = runtime_backend_from_environment(
            {"HTTP_ZTP_RUNTIME_BACKEND": "systemd"}, command_runner=snapshot_command,
        )
        for service in services:
            reader.read_unit_state(service).require_loaded()
            active = reader.is_active(service)
            enabled = reader.is_enabled(service)
            states[service] = ServiceRuntimeState(enabled=enabled, active=active)
    except (RuntimeContractError, OSError, subprocess.SubprocessError, UnicodeError) as exc:
        raise LoadError("无法读取所需服务的状态快照；HOLD") from exc
    return states


def restore_service_states(
    states: dict[str, ServiceRuntimeState], *,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    """Best-effort restoration after a partial service activation failure."""
    backend = runtime_backend or service_runtime_backend()
    if backend.name == "supervisor":
        errors = []
        for service in states:
            try:
                if _runtime_service_active(backend, service):
                    _runtime_service_action(backend, "stop", service)
            except (LoadError, OSError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        for service, state in states.items():
            if not state.active:
                continue
            try:
                _runtime_service_action(backend, "start", service)
            except (LoadError, OSError, subprocess.SubprocessError) as exc:
                errors.append(str(exc))
        if errors:
            raise LoadError("服务状态回滚失败：" + "；".join(errors))
        warn("服务启动未完成；已恢复进入启动阶段前的 Supervisor 运行状态")
        return
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


def start_services(
    inputs: ProjectInputs, images: dict[str, Path], dry_run: bool = False, *,
    dhcp_runtime_plan: DhcpRuntimePlan | None = None,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    services = ("apache2", "isc-dhcp-server")
    plan = dhcp_runtime_plan or plan_local_dhcp_runtime(inputs)
    backend = runtime_backend or service_runtime_backend()
    if backend.name == "supervisor":
        http_required, dhcp_required = supervisor_service_availability(
            inputs, plan, dry_run,
        )
        # This endpoint check can prompt the operator, so it must finish before
        # the first Supervisor mutation.  DHCP-only plans have no URL endpoint
        # and must not be forced through an Apache-specific gate.
        if plan.endpoint_ips:
            ensure_ztp_url_network_ready(inputs, dry_run=dry_run)
        if dry_run:
            if http_required:
                _runtime_service_action(
                    backend, "start", "apache2", dry_run=True,
                )
            if dhcp_required:
                _runtime_service_action(
                    backend, "restart", "isc-dhcp-server", dry_run=True,
                )
            if not http_required:
                info("dry-run：没有 HTTP endpoint，Apache 保持停止")
            if not dhcp_required:
                info("dry-run：DHCP listener 为 0，DHCP 保持停止")
            if http_required:
                verify_http_publication(inputs, images, True)
        else:
            states = snapshot_service_states(
                services, runtime_backend=backend,
            )
            try:
                desired = {
                    "apache2": http_required,
                    "isc-dhcp-server": dhcp_required,
                }
                # First remove services which the new release no longer owns;
                # then activate only the exact services selected by the plan.
                for service in services:
                    if not desired[service] and states[service].active:
                        _runtime_service_action(backend, "stop", service)
                if http_required and not states["apache2"].active:
                    _runtime_service_action(backend, "start", "apache2")
                if dhcp_required:
                    action = (
                        "restart" if states["isc-dhcp-server"].active else "start"
                    )
                    _runtime_service_action(
                        backend, action, "isc-dhcp-server",
                    )
                if http_required:
                    verify_http_publication(inputs, images, False)
            except BaseException as exc:
                rollback_error = ""
                try:
                    restore_service_states(states, runtime_backend=backend)
                except (
                    LoadError, OSError, subprocess.SubprocessError,
                ) as rollback_exc:
                    rollback_error = str(rollback_exc)
                if rollback_error:
                    print(f"[ERROR] {rollback_error}", file=sys.stderr)
                    if isinstance(exc, Exception):
                        raise LoadError(
                            "服务启动失败且状态回滚不完整："
                            f"{exc}；{rollback_error}"
                        ) from exc
                raise
        selected = []
        if http_required:
            selected.append("Apache")
        if dhcp_required:
            selected.append(
                "DHCP(" + ",".join(plan.listener_names) + ")"
            )
        ok(
            "Supervisor 服务已收敛："
            + (", ".join(selected) if selected else "全部保持停止")
        )
        return
    # Preserve the established systemd gate and activation semantics.
    explicit_http_only = _explicit_http_only(inputs.settings)
    ensure_ztp_url_network_ready(inputs, dry_run=dry_run)
    if not inputs.settings.dhcp_enabled:
        if not inputs.settings.http_enabled:
            raise LoadError("DHCP 与 HTTP 均已禁用，没有可启动的原生服务")
        if dry_run:
            run(sudo_command("systemctl", "enable", "--now", "apache2"), dry_run=True)
            info("dry-run：DHCP 已禁用，保持 isc-dhcp-server 停止")
            verify_http_publication(inputs, images, True)
            return
        if explicit_http_only and type(backend) is SystemdRuntimeBackend:
            _start_native_http_only_services(inputs, images, runtime_backend=backend)
            return
        states = snapshot_service_states(services, runtime_backend=backend)
        try:
            if states["isc-dhcp-server"].active:
                run(sudo_command("systemctl", "stop", "isc-dhcp-server"))
            if states["isc-dhcp-server"].enabled:
                run(sudo_command("systemctl", "disable", "isc-dhcp-server"))
            if not states["apache2"].active or not states["apache2"].enabled:
                run(sudo_command("systemctl", "enable", "--now", "apache2"))
            verify_http_publication(inputs, images, False)
        except BaseException as exc:
            if explicit_http_only:
                # An entry-state snapshot is not a sealed healthy A. Never
                # restart an unqualified publication or target-disabled DHCP.
                failures = []
                for action, service in (("stop", "apache2"), ("stop", "isc-dhcp-server"),
                                        ("disable", "apache2"), ("disable", "isc-dhcp-server")):
                    try:
                        run(sudo_command("systemctl", action, service))
                    except (LoadError, OSError, subprocess.SubprocessError) as cleanup_exc:
                        failures.append(str(cleanup_exc))
                if failures:
                    message = "explicit HTTP-only failed activation cleanup incomplete; HOLD: " + "; ".join(failures)
                    if isinstance(exc, Exception):
                        raise LoadError(f"{exc}; {message}") from exc
                    print(f"[ERROR] {message}", file=sys.stderr)
                raise
            rollback_error = ""
            try:
                restore_service_states(states, runtime_backend=backend)
            except (LoadError, OSError, subprocess.SubprocessError) as rollback_exc:
                rollback_error = str(rollback_exc)
            if rollback_error:
                print(f"[ERROR] {rollback_error}", file=sys.stderr)
                if isinstance(exc, Exception):
                    raise LoadError(
                        f"HTTP-only 服务启动失败且状态回滚不完整：{exc}；{rollback_error}"
                    ) from exc
            raise
        ok("DHCP 已禁用；Apache HTTP 发布检查通过，DHCP 保持停止")
        return
    if not plan.listener_names:
        if dry_run:
            info("dry-run：DHCP listener 为 0，Apache/DHCP 保持停止")
            return
        states = snapshot_service_states(services, runtime_backend=backend)
        for service, state in states.items():
            if state.active:
                run(sudo_command("systemctl", "stop", service))
        ok("DHCP listener 为 0；Apache/DHCP 已保持停止，未执行宽泛 DHCP 监听")
        return
    if dry_run:
        run(sudo_command("systemctl", "enable", "--now", "apache2"), dry_run=True)
        run(sudo_command("systemctl", "enable", "isc-dhcp-server"), dry_run=True)
        run(sudo_command("systemctl", "restart", "isc-dhcp-server"), dry_run=True)
        verify_http_publication(inputs, images, True)
    else:
        states = snapshot_service_states(
            services, runtime_backend=backend,
        )
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
                restore_service_states(states, runtime_backend=backend)
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
    project: Path, args: argparse.Namespace, *,
    allow_management_key_generation: bool,
    host_role: str | None = None,
) -> tuple[ProjectInputs, dict[str, Path]]:
    host_role = resolve_host_role(host_role or getattr(args, "host_role", None))
    global_file = project / "01-global.yaml"
    devices_file = project / "02-devices_config.csv"
    subnet_file = project / "02-dhcp-subnet_config.csv"
    switch_scope = str(getattr(args, "switch_scope", "all") or "all")
    global_data = _load_global_document(global_file)
    settings = load_global(
        global_file, global_data=global_data, switch_scope=switch_scope,
    )
    if host_role == "management-server" and settings.http_enabled and not args.dry_run:
        require_http_project_source_access(project)
    placeholder_sections = find_placeholder_password_sections(
        global_data, switch_scope=switch_scope,
    )
    if placeholder_sections:
        raise _placeholder_password_error(
            project, placeholder_sections, host_role=host_role,
        )
    validation_errors = []
    device_types: frozenset[str] = frozenset()
    device_methods: dict[str, str] = {}
    p2p_file = project / (args.p2p_file or "p2p.xlsx")
    air_topology_policy = None
    mini_devices_file = None
    mini_source_file = None
    preview_images: dict[str, Path] = {}
    deployment_scope = str(getattr(args, "deployment_scope", "all") or "all")
    try:
        settings = apply_subnet_service_ips(settings, subnet_file)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        subnet_source_before = _subnet_source_token(subnet_file)
        validate_subnet_file(subnet_file, settings)
        subnet_source_after = _subnet_source_token(subnet_file)
        if subnet_source_after != subnet_source_before:
            raise LoadError("DHCP subnet source changed after validation")
    except LoadError as exc:
        validation_errors.append(str(exc))
    # P2P selection may migrate a legacy workbook.  An invalid subnet must
    # stop before that or any later image/receipt preparation is attempted.
    if validation_errors:
        raise LoadError("项目输入检查失败：\n  - " + "\n  - ".join(validation_errors))
    try:
        device_types = load_device_types(
            devices_file, settings.schema_version, switch_scope=switch_scope,
            methods_out=device_methods,
        )
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        p2p_file = select_p2p(
            project, args.p2p_file, migrate_legacy_canonical=True,
            management_server=host_role == "management-server",
        )
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        air_topology_policy = project_air_topology_policy(project)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        mini_source_file, mini_devices_file = project_mini_air_devices(
            project, getattr(args, "mini", None),
        )
    except LoadError as exc:
        validation_errors.append(str(exc))
    if getattr(args, "mini", None):
        try:
            _require_mini_sampling_policy(air_topology_policy)
        except LoadError as exc:
            validation_errors.append(str(exc))
    if device_types and not args.no_upgrade:
        try:
            # First pass is read-only so all customer-input errors are reported
            # together before a project image is copied into the shared store.
            preview_images = prepare_images(
                project,
                expected_images(
                    settings, device_types,
                    deployment_scope=deployment_scope, switch_scope=switch_scope,
                ),
                dry_run=True, quiet=True,
            )
        except LoadError as exc:
            validation_errors.append(str(exc))
    if validation_errors:
        raise LoadError("项目输入检查失败：\n  - " + "\n  - ".join(validation_errors))
    provisional_inputs = ProjectInputs(
        global_file=global_file,
        devices_file=devices_file,
        subnet_file=subnet_file,
        p2p_file=p2p_file,
        device_types=device_types,
        device_methods=device_methods,
        pubkeys=(),
        settings=settings,
        air_topology_policy=air_topology_policy,
        mini_devices_file=mini_devices_file,
        mini_source_file=mini_source_file,
        deployment_scope=deployment_scope,
        switch_scope=switch_scope,
    )
    customer_source: Path | None = None
    if (
        mini_source_file is not None
        and mini_source_file.name != MINI_AIR_DEVICES_NAME
    ):
        try:
            customer_stat = mini_source_file.lstat()
        except OSError as exc:
            raise LoadError(f"无法读取 mini AIR customer source：{exc}") from exc
        if stat.S_ISREG(customer_stat.st_mode) and customer_stat.st_nlink == 1:
            customer_source = mini_source_file
        elif not stat.S_ISLNK(customer_stat.st_mode):
            raise LoadError("mini AIR customer source 必须是 single-link regular file")
    source_identities = {
        name: _sha256_path(path)
        for name, path in {
            "global": global_file,
            "devices": devices_file,
            "subnet": subnet_file,
            "p2p": p2p_file,
            **(
                {"air_topology_policy": air_topology_policy}
                if air_topology_policy is not None else {}
            ),
            **(
                {"mini_air_customer_source": customer_source}
                if customer_source is not None
                else {}
            ),
        }.items()
    }
    if (
        source_identities["subnet"] != subnet_source_after[-1]
        or _subnet_source_token(subnet_file) != subnet_source_after
    ):
        raise LoadError("DHCP subnet source changed before release prewrite admission")
    provisional_inputs = replace(
        provisional_inputs, source_identities=source_identities,
    )
    # A receipt-managed image must be bound before management-key injection or
    # any project image copy can mutate live state.
    validate_shared_artifact_receipts(
        project,
        provisional_inputs,
        preview_images,
        upgrade_enabled=not args.no_upgrade,
    )
    pubkeys = prepare_pubkeys(
        project,
        ssh_dir=args.ssh_dir,
        dry_run=args.dry_run,
        inject_management_key=host_role == "management-server",
        allow_management_key_generation=allow_management_key_generation,
    )
    if args.no_upgrade:
        images: dict[str, Path] = {}
        info("--no-upgrade：跳过项目及共享 image 目录中的全部 .bin 检查")
    else:
        images = prepare_images(
            project,
            expected_images(
                settings, device_types,
                deployment_scope=deployment_scope, switch_scope=switch_scope,
            ),
            dry_run=args.dry_run,
        )
    ok(
        f"输入检查通过：types={','.join(sorted(device_types))}，"
        f"P2P={p2p_file.name}，keys={','.join(item.name for item in pubkeys[:2])}"
    )
    return replace(provisional_inputs, pubkeys=pubkeys), images


def validate_password_update_options(args: argparse.Namespace) -> None:
    """Reject password-rotation combinations with misleading load semantics."""
    if bool(getattr(args, "update_passwords", False)) and bool(
        getattr(args, "dry_run", False)
    ):
        raise LoadError(
            "--update-passwords 不能与 11-load.py --dry-run 同时使用；"
            "请先单独运行 tools/password-update.py --dry-run"
        )


def validate_deployment_scope_options(args: argparse.Namespace) -> str:
    """Validate the end-to-end generation scope before the first mutation."""
    scope = str(getattr(args, "deployment_scope", "all") or "").casefold()
    if scope not in {"all", "prod", "air"}:
        raise LoadError(f"无法识别 deployment scope：{scope!r}")
    if getattr(args, "mini", None) is not None:
        if scope == "all":
            scope = "air"
        elif scope != "air":
            raise LoadError("--mini 已隐含 AIR 部署范围，不能与 --prod 同时使用")
    monitor_scope = str(
        getattr(args, "ztp_monitor_scope", "auto") or "auto"
    ).casefold()
    if (
        monitor_scope != "auto"
        and scope in {"prod", "air"}
        and monitor_scope != scope
    ):
        raise LoadError(
            f"部署范围 {scope} 与监控范围 {monitor_scope} 冲突"
        )
    return scope


def validate_switch_scope_options(
    args: argparse.Namespace, deployment_scope: str,
) -> str:
    """Resolve the platform selector before the deployment lock or any write."""
    requested = getattr(args, "switch_scope", None)
    selected = str(requested or ("eth" if deployment_scope == "air" else "all"))
    selected = selected.strip().casefold()
    if selected not in SWITCH_SCOPE_TYPES:
        raise LoadError(f"无法识别 switch scope：{selected!r}")
    if deployment_scope == "air" and selected != "eth":
        raise LoadError("AIR 环境目前只支持 Cumulus；请使用 --switch eth")
    return selected


def prompt_password_update_selection(*, reader=input, printer=print) -> tuple[str, bool]:
    """Prompt for one of the five operator-visible password rotation scopes."""
    options = {
        "1": ("Cumulus Ethernet", "cumulus"),
        "2": ("NVOS IB", "ib"),
        "3": ("NVOS NVLink", "nvl"),
        "4": ("NVOS IB/NVLink", "nvos"),
        "5": ("ALL", "all"),
    }
    printer("请选择要更新的密码：")
    for choice, (label, _platform) in options.items():
        printer(f"  {choice}) {label}")
    while True:
        try:
            choice = reader("选择 [1-5]: ").strip()
        except EOFError as exc:
            raise LoadError("未能从终端读取密码更新范围") from exc
        if choice in options:
            break
        warn("请输入 1、2、3、4 或 5")

    platform = options[choice][1]
    if platform not in {"nvos", "all"}:
        return platform, False
    while True:
        try:
            answer = reader("所选系统是否使用同一个密码？[y/N]: ").strip().casefold()
        except EOFError as exc:
            raise LoadError("未能从终端读取共用密码选择") from exc
        if answer in {"", "n", "no"}:
            return platform, False
        if answer in {"y", "yes"}:
            return platform, True
        warn("请输入 y 或 n")


def _load_password_update_module():
    """Load the packaged password tool without duplicating credential logic."""
    module_name = "_http_password_update_for_load"
    existing = sys.modules.get(module_name)
    if existing is not None:
        return existing
    try:
        metadata = PASSWORD_UPDATE_SCRIPT.lstat()
    except OSError as exc:
        raise LoadError(f"缺少密码更新脚本：{PASSWORD_UPDATE_SCRIPT}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LoadError("tools/password-update.py 必须是 single-link regular file")
    spec = importlib.util.spec_from_file_location(module_name, PASSWORD_UPDATE_SCRIPT)
    if spec is None or spec.loader is None:
        raise LoadError(f"无法加载密码更新脚本：{PASSWORD_UPDATE_SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    try:
        spec.loader.exec_module(module)
    except BaseException:
        sys.modules.pop(module_name, None)
        raise
    if not callable(getattr(module, "rotate_project_passwords", None)):
        sys.modules.pop(module_name, None)
        raise LoadError("tools/password-update.py 缺少 rotate_project_passwords 接口")
    if not callable(getattr(module, "validate_hash_backend", None)):
        sys.modules.pop(module_name, None)
        raise LoadError("tools/password-update.py 缺少 validate_hash_backend 接口")
    return module


def preflight_password_update_backend() -> str:
    """Prove both required hash methods before lock, prompts, or writes."""
    module = _load_password_update_module()
    try:
        return module.validate_hash_backend(("eth", "ib", "nvl"))
    except module.PasswordUpdateError as exc:
        raise LoadError(f"密码哈希更新失败：{exc}") from exc


def update_passwords_before_load(
    project: Path,
    *,
    platform: str,
    same_password: bool,
    root: Path = HTTP_ROOT,
    day0: Path = HERE,
    reader=None,
):
    """Rotate project hashes while the caller holds the load deployment lock."""
    module = _load_password_update_module()
    try:
        result = module.rotate_project_passwords(
            project,
            platform=platform,
            same_password=same_password,
            dry_run=False,
            root=root,
            day0=day0,
            lock_already_held=True,
            reader=reader,
        )
    except module.PasswordUpdateError as exc:
        raise LoadError(f"密码哈希更新失败：{exc}") from exc
    ok(f"密码哈希已原子更新：{result.path.name}")
    info(
        "系统映射：Cumulus=SHA-512 crypt；NVOS IB/NVLink=yescrypt；"
        "本次 load 将使用更新后的 global"
    )
    return result


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("project", help="DAY0-Prepare 下的部署项目目录或其绝对路径")
    parser.add_argument(
        "--host-role", choices=("workstation", "management-server"),
        help="Linux 必须显式声明本机角色；Darwin 默认为 workstation",
    )
    parser.add_argument("--p2p-file", help="明确选择项目根目录内任意非空普通 XLSX 文件名")
    parser.add_argument(
        "--import-configs", nargs="?", const="", metavar="YYYYMMDD_HHMMSS",
        help=("从项目 import-configs/ 下导入 Cumulus 配置；无值选择最新命名目录，"
              "带值则选择指定的时间戳目录"),
    )
    parser.add_argument(
        "--p2p-legacy-columns", action="store_true",
        help="显式允许 P2P 未识别表头使用历史固定列；默认严格检查，不自动回退",
    )
    parser.add_argument(
        "--mini", nargs="?", const=MINI_AIR_DEVICES_NAME,
        metavar="DEVICES.txt",
        help=(
            "自动选择 AIR/eth，仅为 AIR DOT/JSON 保留代表性小拓扑；"
            "可选指定项目根目录下的客户设备清单"
            "（默认 04-air-mini-devices.txt）"
        ),
    )
    parser.add_argument("--dry-run", action="store_true", help="仅显示动作，不安装、生成或启动")
    parser.add_argument(
        "--validation-only", action="store_true",
        help=("仅 AIR/prod 验证：正式门禁只接受精确三项 ISSUE-0016 已知 FAIL；"
              "不是最终生产发布证明"),
    )
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
        "--update-passwords",
        action="store_true",
        help="load 开始时显示五项菜单，并交互更新所选 global 密码",
    )
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
    deployment = parser.add_mutually_exclusive_group()
    deployment.add_argument(
        "--deployment-scope", choices=("all", "prod", "air"),
        help="端到端生成范围；默认 all 同时生成 Production 与 AIR",
    )
    deployment.add_argument(
        "--air", action="store_const", const="air", dest="deployment_scope",
        help="仅生成并发布 AIR；monitor scope=auto 时自动继承 air",
    )
    deployment.add_argument(
        "--prod", action="store_const", const="prod", dest="deployment_scope",
        help="仅生成并发布 Production；monitor scope=auto 时自动继承 prod",
    )
    parser.add_argument(
        "--switch", choices=("eth", "ib", "nvl"), dest="switch_scope",
        help=("只校验、生成并发布一个设备族；eth 包含 eth/eth_spx/spx/AIR。"
              "不指定时处理全部设备族；--air 未指定本项时自动选择 eth"),
    )
    monitor_environment = parser.add_mutually_exclusive_group()
    monitor_environment.add_argument(
        "--ztp-monitor-scope", choices=("auto", "prod", "air"),
        dest="ztp_monitor_scope",
        help=("本管理服务器可达的 ZTP 环境：auto 在交互终端询问；"
              "prod/air 仅采集指定环境"),
    )
    monitor_environment.add_argument(
        "--type", choices=("auto", "prod", "air"), dest="ztp_monitor_scope",
        help="旧的 monitor-only 别名；等价于 --ztp-monitor-scope",
    )
    parser.set_defaults(
        deployment_scope="all", switch_scope=None, ztp_monitor_scope="auto",
    )
    parser.add_argument(
        "--ssh-dir", type=Path, default=_default_ssh_dir(), help=argparse.SUPPRESS,
    )
    parser.epilog = (
        "AIR inventory 说明：生成阶段以 p2p-air.json 为权威来源，原子重建 "
        "02-devices_config.csv 末尾的 type=air 行。\n"
        "完整、受支持的操作流程见仓库根目录 USER_MANUAL.md。"
    )
    return parser


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = _build_parser()
    return parser.parse_args(argv)


def actual_run_command(requested_argv: list[str]) -> list[str]:
    """Return the exact non-preview rerun while preserving all other intent."""
    actual_argv = [item for item in requested_argv if item != "--dry-run"]
    return sudo_command(
        sys.executable, str(Path(__file__).resolve()), *actual_argv,
    )


def dry_run_next_step(requested_argv: list[str]) -> str:
    """Render the exact non-preview command without dropping other options."""
    return (
        "[NEXT] dry-run 已完成；确认输出后执行实际事务："
        + " ".join(
            shlex_quote(part) for part in actual_run_command(requested_argv)
        )
    )


def main(
    argv: list[str] | None = None, *,
    import_started_at: datetime | None = None,
) -> int:
    requested_argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    import_selector = getattr(args, "import_configs", None)
    import_output_timestamp = (
        (import_started_at or datetime.now().astimezone()).strftime("%Y%m%d_%H%M%S")
        if import_selector is not None else None
    )
    import_selection: ImportConfigSelection | None = None
    import_snapshot: ImportedConfigSnapshot | None = None
    release_link_snapshot: dict[Path, Optional[str]] = {}
    release_committed = False
    inventory_directory = None
    inventory_directory_identity = None
    dhcp_candidate_dir: Path | None = None
    dhcp_candidate_identity: tuple[int, int] | None = None
    previous_selector_target: str | None = None
    pinned_generation_candidate: Path | None = None
    runtime_rollback_receipt: Path | None = None
    deployment_lock_descriptor: int | None = None
    parent_candidate: PreparedParentRelease | None = None
    report_candidate = None
    prefix_publication_snapshot: ZtpPrefixPublicationSnapshot | None = None
    dhcp_runtime_plan: DhcpRuntimePlan | None = None
    runtime_backend_instance: ServiceRuntimeBackend | None = None
    http_service_available = False
    dhcp_service_available = False
    services_must_remain_stopped = False
    runtime_restore_safe = False
    runtime_mutation_started = False
    native_monitor_quiesced = False
    allow_management_key_generation=False
    should_monitor = False
    monitor_scope: str | None = None
    failure_phase = "启动前参数检查"
    primary_failure = False
    completed_successfully = False
    host_role: str | None = None
    native_http_only_inputs: ProjectInputs | None = None
    try:
        host_os = runtime_os()
        host_role = resolve_host_role(getattr(args, "host_role", None), host_os)
        if host_os.casefold() == "linux" and host_role == "workstation" and (
            args.start_services or args.start_ztp_monitor
        ):
            raise LoadError("workstation host role cannot start local ZTP services or monitor")
        deployment_scope = validate_deployment_scope_options(args)
        switch_scope = validate_switch_scope_options(args, deployment_scope)
        args.deployment_scope = deployment_scope
        args.switch_scope = switch_scope
        if (import_selector is not None
                and (deployment_scope != "prod" or switch_scope != "eth")):
            raise LoadError(
                "--import-configs 首批仅支持 --prod --switch eth；"
                "不得隐式混入 AIR/NVOS 生成"
            )
        if host_os.casefold() == "darwin":
            macos_requirements = print_macos_client_requirements(
                update_passwords=bool(getattr(args, "update_passwords", False)),
            )
            validate_macos_client_requirements(macos_requirements)
        validate_password_update_options(args)
        if bool(getattr(args, "update_passwords", False)):
            preflight_password_update_backend()
        if args.skip_doca and args.download_doca:
            raise LoadError("--skip-doca 和 --download-doca 不能同时使用")
        if args.skip_generate and not args.dry_run:
            raise LoadError(
                "--skip-generate 已禁止用于实际 load：现有子 release 不包含 "
                "global/devices/subnet/p2p 来源证明，不能把旧制品重新签名为当前输入；"
                "请执行完整配置生成"
            )
        local_services_supported = host_role == "management-server"
        if local_services_supported:
            runtime_backend_instance = service_runtime_backend()
            validate_runtime_options(args, runtime_backend_instance)
            allow_management_key_generation = (
                runtime_backend_instance.name != "supervisor"
            )
            if (
                runtime_backend_instance.name == "supervisor"
                and args.ssh_dir != Path("/root/.ssh")
            ):
                raise LoadError(
                    "Supervisor management SSH authority 固定为 /root/.ssh；"
                    "不接受 --ssh-dir override"
                )
        if not args.dry_run:
            deployment_lock_descriptor = acquire_deployment_lock(exclusive=True)
            if local_services_supported:
                failure_phase = "未结清 DHCP 事务前置闸门"
                require_no_pending_dhcp_transaction()
        info(f"运行平台：{host_os}")
        if not local_services_supported:
            warn(
                f"{host_os} 配置准备模式：继续 setup 和配置生成；跳过 infra、"
                "Apache/ISC DHCP 文件安装、语法检查及服务启停"
            )
        failure_phase = "项目解析与同步状态检查"
        project = resolve_project(args.project)
        sync_marker = HERE.parent / ".sync-code-in-progress"
        if sync_marker_present(sync_marker):
            raise LoadError(
                f"检测到代码/项目同步尚未完成：{sync_marker}\n"
                "请等待 sync-code.py 打印 [OK] 同步完成后再执行 load；"
                "若同步进程已异常退出，请先重新完成一次 sync-code.py"
            )
        # setup's step 4 refuses to switch a pointer that exists and is not a link (01-a-setup.py
        # _switch_active_project, same test), the one invalid pointer setup cannot repair: stop before any
        # write, in every mode, instead of leaving it to setup (review 5 A1).
        activate_pointer = HTTP_ROOT / "DAY0-Prepare/activate-project"
        if os.path.lexists(activate_pointer) and not os.path.islink(activate_pointer):
            raise LoadError(
                f"活动项目指针 {activate_pointer} 是实际文件/目录，不是链接，setup 不能切换；"
                "请先把它挪走（移出 DAY0-Prepare），再重跑 load"
            )
        # No monitor stop, A freeze, template/password/key mutation or shared
        # image publication may precede the initial public-source access gate.
        if local_services_supported and not args.dry_run and project.is_dir() and _meaningful_entries(project):
            early_http_settings = load_global(project / "01-global.yaml", switch_scope=switch_scope)
            if early_http_settings.http_enabled:
                failure_phase = "HTTP public source access prewrite gate"
                require_http_project_source_access(project)

        if import_selector is not None:
            if not project.is_dir() or not _meaningful_entries(project):
                raise LoadError("--import-configs requires an initialized project")
            failure_phase = "外部 Cumulus 配置只读前置闸门"
            import_selection = select_import_config_set(project, import_selector)
            import_snapshot = preflight_import_configs(
                import_selection, project / "02-devices_config.csv",
            )
        if (
            local_services_supported
            and runtime_backend_instance.name == "systemd"
            and not args.dry_run
        ):
            failure_phase = "停止旧 Native Monitor"
            stop_native_ztp_monitors(HTTP_ROOT)
            native_monitor_quiesced = True
        if (
            local_services_supported
            and runtime_backend_instance is not None
            and runtime_backend_instance.name == "supervisor"
        ):
            # The fixed container authority is attested before *any* project
            # template/password mutation, including the empty-project branch.
            ensure_management_key(
                args.ssh_dir,
                dry_run=args.dry_run,
                allow_generation=False,
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

        if not args.dry_run:
            # Freeze an already committed generation before template backfill,
            # key placeholders, or password updates can change A's sources.
            failure_phase = "冻结旧版 release 以供显式回退"
            # A cross-project load has no automatic rollback to the previously active
            # project (owner 2026-11-04, R-016 decision C): on failure the services stay
            # stopped and the operator reruns load.  prepare_active_runtime_rollback_receipt
            # returns None (with a warning) when another project owns the runtime.
            previous_selector_target = ensure_previous_generation_frozen(project)
            if local_services_supported and previous_selector_target:
                # Capture/revalidate the truly active A before any template,
                # password, public-key, setup, or project-input mutation.
                runtime_rollback_receipt = prepare_active_runtime_rollback_receipt(
                    project, previous_selector_target,
                )

        if (
            local_services_supported
            and runtime_backend_instance is not None
            and runtime_backend_instance.name == "supervisor"
        ):
            # This gate precedes template/password/project mutation.  The host
            # locked helper is the only Supervisor key writer; 11-load merely
            # holds and attests its exact service pair and project placeholders.
            prepare_pubkeys(
                project,
                ssh_dir=args.ssh_dir,
                dry_run=True,
                inject_management_key=True,
                allow_management_key_generation=False,
            )

        failure_phase = "补齐项目模板合同"
        section("补齐项目模板合同")
        initialize_from_template(project, args.dry_run)

        if bool(getattr(args, "update_passwords", False)):
            section("更新 Cumulus/NVOS 登录密码")
            password_platform, same_password = prompt_password_update_selection()
            update_passwords_before_load(
                project,
                platform=password_platform,
                same_password=same_password,
            )

        failure_phase = "项目输入合法性与制品检查"
        section("项目输入合法性与制品检查")
        inputs, images = validate_inputs(
            project,
            args,
            allow_management_key_generation=allow_management_key_generation,
            host_role=host_role,
        )
        if (host_role == "management-server" and local_services_supported
                and not args.dry_run
                and type(runtime_backend_instance) is SystemdRuntimeBackend
                and _explicit_http_only(inputs.settings)):
            native_http_only_inputs = inputs
        section("活动项目 setup 检查/切换")
        if local_services_supported and runtime_backend_instance.name == "supervisor":
            # The exact listener/ifindex plan is a pre-mutation gate.  If this
            # fails, the catch path must leave currently healthy services alone.
            dhcp_runtime_plan = plan_local_dhcp_runtime(inputs)
            (
                http_service_available,
                dhcp_service_available,
            ) = supervisor_service_availability(
                inputs, dhcp_runtime_plan, args.dry_run,
            )
        elif local_services_supported:
            legacy_service_available = validate_management_host(
                inputs.settings, args.dry_run,
            )
            http_service_available = (
                legacy_service_available and inputs.settings.http_enabled
            )
            dhcp_service_available = (
                legacy_service_available and inputs.settings.dhcp_enabled
            )
            if legacy_service_available:
                dhcp_runtime_plan = plan_local_dhcp_runtime(inputs)
        runtime_services_available = (
            http_service_available or dhcp_service_available
        )
        if (
            local_services_supported
            and http_service_available
            and dhcp_service_available
        ):
            failure_phase = "ZTP 后台监控启动意图与范围预检"
            should_monitor = args.start_ztp_monitor or (
                not args.dry_run and confirm_ztp_monitor_start()
            )
            if should_monitor:
                monitor_scope = resolve_ztp_monitor_scope(
                    project, args.ztp_monitor_scope,
                    deployment_scope=deployment_scope,
                )
        if runtime_services_available:
            # Set the cleanup obligation only after the planner passes but
            # before the first stop: an interrupt partway through quiescing
            # must retry the stop rather than leave a split old runtime.
            services_must_remain_stopped = (
                local_services_supported and not args.dry_run
            )
            failure_phase = "停止旧运行态服务"
            native_preinstall_options = {}
            if (
                type(runtime_backend_instance) is SystemdRuntimeBackend
                and local_services_supported and host_role == "management-server"
                and not args.dry_run and not args.skip_infra
            ):
                native_preinstall_options["_native_preinstall_absence"] = True
            elif native_http_only_inputs is not None:
                native_preinstall_options["_native_http_only_inputs"] = native_http_only_inputs
            quiesce_services(
                args.dry_run,
                dhcp_runtime_plan=dhcp_runtime_plan,
                runtime_backend=runtime_backend_instance,
                native_monitor_already_quiesced=native_monitor_quiesced,
                host_role=host_role,
                **native_preinstall_options,
            )
            runtime_restore_safe = True
        elif local_services_supported:
            require_artifact_builder_services_inactive(
                args.dry_run, runtime_backend=runtime_backend_instance,
                host_role=host_role,
            )
            runtime_restore_safe = True
        if not args.dry_run:
            # I-022: a load killed between retiring the unselected latest and
            # the parent commit left the original link only under
            # .latest.retired.  Restore it after quiesce and before setup, so
            # setup starts from the pre-interruption state.
            failure_phase = "恢复被打断的 latest 退役"
            for latest in (
                project / "99-output-eth/latest",
                project / "99-output-ib_nvl/latest",
            ):
                retired = latest.parent / ".latest.retired"
                if not os.path.lexists(retired):
                    continue
                if not retired.is_symlink():
                    raise LoadError(f"拒绝处理非软链接的 latest 退役记录：{retired}")
                if os.path.lexists(latest):
                    retired.unlink()
                    warn(f"latest 已存在，删除被打断留下的退役记录：{retired}")
                else:
                    os.replace(retired, latest)
                    warn(f"已恢复被打断的 latest 退役：{latest} -> {os.readlink(latest)}")
                _fsync_parent_directory(latest.parent)
        failure_phase = "活动项目 setup 检查/切换"
        # setup is the first post-quiesce operation allowed to rewrite managed
        # links.  Mark before entry because a child failure may be partial.
        if local_services_supported and inputs.settings.http_enabled and not args.dry_run:
            require_http_project_source_access(project)
        runtime_mutation_started = local_services_supported and not args.dry_run
        activate_project(
            project, inputs.p2p_file,
            # Configuration-only platforms cannot inject the management-host
            # key and therefore cannot satisfy the Linux deployment gate.
            strict=local_services_supported and not args.no_upgrade,
            dry_run=args.dry_run,
            deployment_lock_descriptor=deployment_lock_descriptor,
            host_role=host_role,
            switch_scope=switch_scope,
            no_upgrade=args.no_upgrade,
        )
        if not args.dry_run and (project / "p2p.xlsx").is_symlink():
            selected_runtime_p2p = project / os.readlink(project / "p2p.xlsx")
            inputs = replace(inputs, p2p_file=selected_runtime_p2p)

        failure_phase = "同步 ZTP 运行时参数"
        section("同步 ZTP 运行时参数")
        if http_service_available:
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
            inputs.settings, inputs.pubkeys,
            _device_types_after_dhcp(
                inputs.device_types, dry_run=True,
                schema_version=inputs.settings.schema_version,
                deployment_scope=deployment_scope,
                switch_scope=switch_scope,
            ),
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
        elif runtime_services_available and not args.skip_infra:
            failure_phase = "安装/检查 ZTP 管理服务器"
            section("安装/检查 ZTP 管理服务器")
            component_options: dict[str, object] = {}
            # This finite current-call profile is deliberately narrower than
            # the independent CLI/tool capabilities. Every other call is legacy.
            if (
                host_os.casefold() == "linux"
                and host_role == "management-server"
                and type(runtime_backend_instance) is SystemdRuntimeBackend
                and not args.dry_run and args.no_upgrade
                and not args.update_passwords and not args.mini
                and import_selector is None
                and deployment_scope == "prod" and switch_scope == "ib"
                and inputs.device_types == frozenset({"ib"})
                and _explicit_http_only(inputs.settings)
                and inputs.settings.http_package == "apache2"
                and inputs.p2p_file is not None
            ):
                doca_action = _resolve_infra_doca_action(
                    args.skip_doca, args.download_doca,
                )
                component_options["_resolved_doca_action"] = doca_action
                if doca_action == "skip":
                    component_options["_load_components"] = select_load_components(
                        http_enabled=True, dhcp_enabled=False, ztp_enabled=False,
                        device_types=("ib",), workbook_selected=True, features=(),
                    )
            prepare_infra(
                inputs,
                args.dry_run,
                skip_doca=args.skip_doca,
                download_doca=args.download_doca,
                **component_options,
            )
        elif not runtime_services_available:
            warn("本机不具备服务地址，跳过 infra 部署；load 继续")
        else:
            warn("已按参数跳过 infra 安装")

        if local_services_supported and http_service_available:
            failure_phase = "只读校验 Monitor cache authority"
            verify_monitor_authority(
                runtime_backend=runtime_backend_instance,
                dry_run=args.dry_run,
            )

        if not args.skip_generate:
            failure_phase = "生成 P2P、YAML 和 DHCP 配置"
            section("生成 P2P、YAML 和 DHCP 配置")
            if not args.dry_run:
                release_link_snapshot = snapshot_release_links(project)
            generation_options = {
                "source_identities": inputs.source_identities,
                "install_dhcp": dhcp_service_available,
                "dry_run": args.dry_run,
                "schema_version": inputs.settings.schema_version,
                "eth_version": inputs.settings.versions.get("eth"),
                "air_topology_policy": inputs.air_topology_policy,
                "deployment_scope": deployment_scope,
                "switch_scope": switch_scope,
            }
            if not args.dry_run:
                inventory_directory = Path(tempfile.mkdtemp(
                    prefix=".load-inventory-", dir=project))
                private_stat = inventory_directory.lstat()
                inventory_directory_identity = (private_stat.st_dev, private_stat.st_ino)
                generation_options["inventory_directory"] = inventory_directory
                if inputs.settings.dhcp_enabled:
                    dhcp_candidate_dir = _create_dhcp_candidate_dir(project)
                    candidate_stat = dhcp_candidate_dir.lstat()
                    dhcp_candidate_identity = (
                        candidate_stat.st_dev, candidate_stat.st_ino,
                    )
                    generation_options["dhcp_candidate_dir"] = dhcp_candidate_dir
            if not inputs.settings.dhcp_enabled:
                generation_options["dhcp_enabled"] = False
            # Keep the established full-topology call contract byte-for-byte
            # compatible for embedders which wrap generate_configs().
            if getattr(args, "p2p_legacy_columns", False):
                generation_options["p2p_legacy_columns"] = True
            if getattr(args, "mini", False):
                generation_options["mini_air"] = True
                mini_source, _mini_canonical = project_mini_air_devices(
                    project, args.mini,
                )
                generation_options["mini_devices_file"] = mini_source
                generation_options["source_identities"] = inputs.source_identities
            if import_snapshot is not None:
                generation_options.update({
                    "imported_configs": import_snapshot,
                    "import_selection": import_selection,
                    "import_devices_file": project / "02-devices_config.csv",
                    "import_output_timestamp": import_output_timestamp,
                })
            generated_inventory = generate_configs(
                inputs.device_types,
                deployment_lock_descriptor=deployment_lock_descriptor,
                **generation_options,
            )
            if isinstance(generated_inventory, DerivedInventory):
                inputs = replace(inputs,
                    effective_devices_file=generated_inventory.path,
                    effective_devices_sha256=generated_inventory.sha256)
            elif inventory_directory is not None:
                inventory_directory.rmdir()
                inventory_directory = None
            retire_unselected_release_links(
                project, switch_scope, dry_run=args.dry_run,
            )
        else:
            warn(
                "dry-run：仅展示跳过生成的调试路径；实际 load 会安全拒绝 "
                "--skip-generate"
            )

        failure_phase = "统一 release 一致性与 DHCP 事务安装"
        section("统一 release 一致性与 DHCP 事务安装")
        dhcp_candidate_option = (
            {} if dhcp_candidate_dir is None
            else {"dhcp_candidate_dir": dhcp_candidate_dir}
        )
        if import_snapshot is not None:
            assert_import_source_unchanged(
                import_selection, import_snapshot, project / "02-devices_config.csv",
            )
        parent_release = validate_and_publish_release(
            project, inputs, dry_run=args.dry_run, publish=False,
            **({"imported_configs": import_snapshot} if import_snapshot is not None else {}),
            **dhcp_candidate_option,
        )
        if parent_release is not None:
            # Materialize and fsync the parent before touching /etc/dhcp.  The
            # remaining commit is one os.replace performed while DHCP backups
            # and the global deployment lock are still held.
            parent_candidate = prepare_current_release(
                project, parent_release, **dhcp_candidate_option,
            )
            if import_snapshot is not None:
                parent_candidate.precommit_check = lambda: assert_import_source_unchanged(
                    import_selection, import_snapshot, project / "02-devices_config.csv",
                )
            if (not args.dry_run and parent_release.get("schema_version") == 2):
                # Freeze B while its private DHCP candidate and generated
                # inputs still exist.  No selector changes before the
                # installation and report gates have completed.
                pinned_generation_candidate = stage_pinned_generation(
                    project, parent_candidate.temporary, dhcp_candidate_dir,
                )
        if local_services_supported and not args.dry_run and parent_release is not None:
            failure_phase = "准备本次实际使用公钥报告"
            actual_key_report = generation_report.build_report(
                project, parent_release,
                published_dir=ZTP_DIR / "config/publickey",
            )
            report_candidate = generation_report.prepare_generation_report(
                project, actual_key_report,
            )
        failure_phase = "统一 release 一致性与 DHCP 事务安装"
        if import_snapshot is not None:
            # The report and candidate preparation can take time.  Never
            # commit B using a source which ceased to match the frozen bytes.
            assert_import_source_unchanged(
                import_selection, import_snapshot, project / "02-devices_config.csv",
            )
        if local_services_supported and dhcp_service_available:
            mount_and_test_dhcp(args.dry_run, parent_candidate=parent_candidate)
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
        if release_committed:
            # I-022: the committed parent no longer needs the retired latest.
            for latest in release_link_snapshot:
                retired = latest.parent / ".latest.retired"
                if retired.is_symlink():
                    retired.unlink()
                    _fsync_parent_directory(latest.parent)
        if report_candidate is not None:
            # Parent and report are two separate atomic replacements, not one
            # transaction.  A crash between them leaves an absent/stale report;
            # the inspector fails closed until a full rerun under this lock.
            failure_phase = "提交本次实际使用公钥报告"
            generation_report.commit_prepared_generation_report(report_candidate)
        if pinned_generation_candidate is not None:
            failure_phase = "提交本轮已封存代次指针"
            commit_pinned_generation(
                project, pinned_generation_candidate,
                expected_current=previous_selector_target,
            )

        if dhcp_candidate_dir is not None and release_committed and not args.dry_run:
            # Only after the commit: TEST's runtime rollback receipts bind the flat DHCP
            # sources by (ino, mtime, ctime), and even a rename round trip changes ctime
            # (measured on APFS 2026-10-25), so touching flat before the commit would turn
            # every later pre-commit failure into "rollback is blocked".
            failure_phase = "发布已提交的 DHCP 候选"
            try:
                publish_committed_dhcp_candidate(project, dhcp_candidate_dir, switch_scope)
            except (LoadError, OSError) as exc:
                raise LoadError(
                    "HOLD：父 release 已提交，但 DHCP 候选未能发布到 99-output-dhcp；"
                    "flat DHCP 输出仍是提交前的内容，activate/unload 会拒绝它们。"
                    f"候选目录已保留作为证据：{dhcp_candidate_dir}。"
                    f"修复原因后重新运行 load 即可恢复：{exc}"
                ) from exc

        failure_phase = "服务启动门禁"
        section("服务启动门禁")
        if not local_services_supported:
            if args.start_services:
                warn(f"{host_os} 不支持本流程的 --start-services，已忽略")
            info(f"{host_os} 配置准备完成；未检查或启动 Apache/ISC DHCP")
        elif not runtime_services_available:
            warn("当前 runtime plan 没有本机可启动的 HTTP/DHCP 服务")
        else:
            if runtime_backend_instance.name == "systemd":
                publish_native_apache_listener_config(
                    inputs.settings.http_listener_ips,
                    port=inputs.settings.http_port,
                    dry_run=args.dry_run,
                )
            preflight_services(
                inputs, images, args.dry_run,
                dhcp_runtime_plan=dhcp_runtime_plan,
                runtime_backend=runtime_backend_instance,
                **({"committed_dhcp_parent": parent_release}
                   if pinned_generation_candidate is not None and not args.dry_run else {}),
            )
            should_start = args.start_services or (
                not args.dry_run and confirm_service_start(
                    http_available=http_service_available,
                    dhcp_available=dhcp_service_available,
                )
            )
            if should_start:
                start_services(
                    inputs, images, args.dry_run,
                    dhcp_runtime_plan=dhcp_runtime_plan,
                    runtime_backend=runtime_backend_instance,
                )
            else:
                info(_service_start_declined_message(
                    http_available=http_service_available,
                    dhcp_available=dhcp_service_available,
                ))

        if local_services_supported:
            section("ZTP 状态后台监控")
            reset_completion_handoff_state(dry_run=args.dry_run)
            if not (http_service_available and dhcp_service_available):
                warn("当前 runtime plan 不同时具备 HTTP endpoint 与 DHCP listener，不启动 ZTP 后台监控")
            else:
                if should_monitor:
                    if monitor_scope is None:
                        raise LoadError("ZTP 后台监控范围未在事务开始前完成预检")
                    failure_phase = "启动 ZTP 后台监控与控制 worker"
                    start_ztp_monitor(
                        project, interval=args.ztp_monitor_interval,
                        scope=monitor_scope,
                        service_ips=inputs.settings.service_ips,
                        http_port=inputs.settings.http_port,
                        dry_run=args.dry_run,
                        runtime_backend=runtime_backend_instance,
                    )
                    start_switch_collection_worker(
                        monitor_scope, dry_run=args.dry_run,
                        runtime_backend=runtime_backend_instance,
                    )
                    start_manual_ztp_worker(
                        monitor_scope, dry_run=args.dry_run,
                        runtime_backend=runtime_backend_instance,
                    )
                else:
                    info(
                        "ZTP 后台监控未启动。可重新执行并加 --start-ztp-monitor，"
                        f"或手工运行 {ZTP_MONITOR_SCRIPT.name}。"
                    )
        elif args.start_ztp_monitor:
            warn(f"{host_os} 不运行 ZTP 后台监控，已忽略 --start-ztp-monitor")
        if args.dry_run:
            print(dry_run_next_step(requested_argv))

        completed_successfully = True
        return 0
    except BaseException as exc:
        primary_failure = True
        cleanup_errors = []
        release_committed = release_committed or bool(
            parent_candidate is not None and parent_candidate.committed
        )
        if services_must_remain_stopped:
            try:
                quiesce_services(
                    False,
                    dhcp_runtime_plan=dhcp_runtime_plan,
                    runtime_backend=runtime_backend_instance,
                    native_monitor_already_quiesced=native_monitor_quiesced,
                    host_role=host_role,
                    **({"_native_http_only_inputs": native_http_only_inputs}
                       if native_http_only_inputs is not None else {}),
                )
            except (LoadError, OSError, subprocess.SubprocessError) as cleanup_exc:
                cleanup_errors.append(f"服务停止清理失败：{cleanup_exc}")
        if release_link_snapshot and not release_committed:
            try:
                restore_release_links(release_link_snapshot)
                # I-022: the snapshot restored latest; drop the retired copy.
                for latest in release_link_snapshot:
                    retired = latest.parent / ".latest.retired"
                    if retired.is_symlink():
                        retired.unlink()
                        _fsync_parent_directory(latest.parent)
            except (LoadError, OSError) as rollback_exc:
                cleanup_errors.append(str(rollback_exc))
                for latest in release_link_snapshot:
                    retired = latest.parent / ".latest.retired"
                    # os.path.islink never raises here, inside the cleanup path.
                    if os.path.islink(retired):
                        cleanup_errors.append(
                            f"退役前的 latest 保留在 {retired}；若 {latest} 不存在，"
                            f"可手工执行 mv {retired} {latest} 恢复"
                        )
        if prefix_publication_snapshot is not None and not release_committed:
            try:
                restore_ztp_prefix_publication(prefix_publication_snapshot)
            except (LoadError, OSError) as rollback_exc:
                cleanup_errors.append(str(rollback_exc))
        if (runtime_rollback_receipt is not None and not release_committed
                and runtime_mutation_started):
            try:
                if previous_selector_target is None:
                    raise LoadError("A runtime rollback selector target is absent")
                restore_runtime_rollback_receipt(
                    project, runtime_rollback_receipt,
                    expected_current=previous_selector_target,
                    deployment_lock_descriptor=deployment_lock_descriptor,
                    services_quiesced=runtime_restore_safe,
                    runtime_backend=runtime_backend_instance,
                )
            except (LoadError, OSError, ValueError) as rollback_exc:
                cleanup_errors.append(f"A runtime rollback failed: {rollback_exc}")
        print(f"[FAILED] load 阶段失败：{failure_phase}", file=sys.stderr)
        if services_must_remain_stopped:
            print(
                "[SAFE] 受管服务保持停止，避免运行未完成或跨代配置",
                file=sys.stderr,
            )
            if not release_committed and not cleanup_errors:
                print(
                    "[SAFE] 未提交 release 的发布状态已回滚",
                    file=sys.stderr,
                )
            elif release_committed:
                if parent_candidate is not None and not parent_candidate.directory_synced:
                    print(
                        "[STATE] release B 已可见，目录持久化未确认；"
                        "HOLD，受管服务保持停止，不自动回退 A",
                        file=sys.stderr,
                    )
                else:
                    print(
                        "[STATE] release 已提交，但受管服务因后续失败保持停止",
                        file=sys.stderr,
                    )
        rerun = sudo_command(
            sys.executable, str(Path(__file__).resolve()), *requested_argv,
        )
        print(
            "[NEXT] 修复上述错误后完整重跑："
            + " ".join(shlex_quote(part) for part in rerun),
            file=sys.stderr,
        )
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
        final_cleanup_errors: list[tuple[str, BaseException]] = []
        if dhcp_candidate_dir is not None and not release_committed:
            try:
                private_stat = dhcp_candidate_dir.lstat()
                if (not stat.S_ISDIR(private_stat.st_mode)
                        or (private_stat.st_dev, private_stat.st_ino)
                        != dhcp_candidate_identity):
                    raise LoadError("private DHCP candidate identity changed before cleanup")
                _discard_dhcp_candidate_dir(dhcp_candidate_dir, dhcp_candidate_identity)
            except BaseException as cleanup_exc:
                final_cleanup_errors.append(("DHCP 候选暂存清理", cleanup_exc))
        if inventory_directory is not None and not release_committed:
            try:
                # This exact private directory was created by this invocation;
                # never sweep other runs' directories or a committed authority.
                private_stat = inventory_directory.lstat()
                if (not stat.S_ISDIR(private_stat.st_mode)
                        or (private_stat.st_dev, private_stat.st_ino) != inventory_directory_identity):
                    raise LoadError("private inventory directory identity changed before cleanup")
                shutil.rmtree(inventory_directory)
            except BaseException as cleanup_exc:
                final_cleanup_errors.append(("派生库存暂存清理", cleanup_exc))
        try:
            generation_report.discard_prepared_generation_report(report_candidate)
        except BaseException as cleanup_exc:
            final_cleanup_errors.append(("公钥报告暂存清理", cleanup_exc))
        try:
            discard_prepared_release(parent_candidate)
        except BaseException as cleanup_exc:
            final_cleanup_errors.append(("release 暂存清理", cleanup_exc))
        try:
            release_deployment_lock(deployment_lock_descriptor)
        except BaseException as cleanup_exc:
            final_cleanup_errors.append(("部署锁释放", cleanup_exc))
        if import_selection is not None:
            try:
                import_selection.close()
            except BaseException as cleanup_exc:
                final_cleanup_errors.append(("导入来源描述符关闭", cleanup_exc))
        for label, cleanup_exc in final_cleanup_errors:
            print(f"[ERROR] {label}失败：{cleanup_exc}", file=sys.stderr)
        if final_cleanup_errors and not primary_failure:
            # A successful load must not silently accept incomplete cleanup.
            # During a failed load, preserve its original failure/exit status.
            raise final_cleanup_errors[0][1]
        if completed_successfully and not final_cleanup_errors:
            ok(f"load 流程完成：{project}")


def cli(argv: list[str] | None = None) -> int:
    """Own the workstation test gate while keeping Linux production load lean."""
    invocation_started_at = datetime.now().astimezone()
    requested_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse_args(requested_argv)
        deployment_scope = validate_deployment_scope_options(args)
        validate_switch_scope_options(args, deployment_scope)
        validation_only = getattr(args, "validation_only", False)
        if validation_only and (deployment_scope not in {"air", "prod"} or args.dry_run):
            raise LoadError("--validation-only 仅可用于正式 AIR/prod 验证 load")
        local_formal_load = (
            runtime_os().casefold() == "darwin" and not args.dry_run
        )
        if local_formal_load:
            run_local_full_test_gate(**({"validation_only": True} if validation_only else {}))
        result = (
            main(requested_argv, import_started_at=invocation_started_at)
            if getattr(args, "import_configs", None) is not None else main(requested_argv)
        )
        if result == 0 and local_formal_load:
            verify_local_full_test_attestation(**({"validation_only": True} if validation_only else {}))
        return result
    except (LoadError, OSError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
