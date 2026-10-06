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
except ModuleNotFoundError:
    yaml = None


HERE = Path(__file__).resolve().parent
HTTP_ROOT = HERE.parent
TOOLS_DIR = HTTP_ROOT / "tools"
if str(TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(TOOLS_DIR))
import generation_report
import ssh_key_preparation as ssh_keys
from project_contract import (
    GLOBAL_SCHEMA_VERSION,
    PublicationPlan,
    ServiceEndpoint,
    SWITCH_CREDENTIAL_FAMILY_ORDER,
    SWITCH_CREDENTIAL_PATHS,
    SWITCH_SCHEMA_FAMILIES,
    detect_global_schema_version,
    device_visible_urls,
    merge_http_listener_addresses,
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
    validate_service_endpoint,
    validate_ztp_url_prefix,
)
from _package_common import (
    P2PSelectionError,
    assert_p2p_source_snapshot,
    p2p_source_snapshot,
    p2p_source_relative,
    project_p2p_candidates,
    read_p2p_receipt,
    select_project_p2p_source,
    select_upload_p2p,
)
from deployment_lock import (
    DeploymentLockError,
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
LOCAL_PRE_PUSH_HOOK = HTTP_ROOT / ".githooks/pre-push"
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
}
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


def preflight_import_configs(
    selected: ImportConfigSelection, devices_file: Path,
) -> ImportedConfigSnapshot:
    """Read only fd-bound input bytes and reject an incomplete foreign set."""
    publisher = _import_publisher_module()
    try:
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
                if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
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
            if identity != after_identity:
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
            seen.add(host)
            total += len(data)
            if total > 256 * 1024 * 1024:
                raise LoadError("import-configs set exceeds the total byte limit")
        missing = expected - seen
        if missing:
            raise LoadError("import-configs is missing Cumulus hosts: "
                            + ", ".join(sorted(missing)[:10]))
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
    if selected.directory_fd < 0 or selected.root_fd < 0:
        raise LoadError("import-configs source descriptor is already closed")
    try:
        if _import_root_alias_identity(selected.root_path) != selected.root_alias_identity:
            raise LoadError("import-configs root alias changed during load")
        root = os.fstat(selected.root_fd)
        if (root.st_dev, root.st_ino) != selected.root_identity:
            raise LoadError("import-configs root changed during load")
        child = os.stat(selected.name, dir_fd=selected.root_fd,
                        follow_symlinks=False)
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


def _eth_jump_configuration_intent(
    fields: list[str], row: list[str],
) -> tuple[str, ...]:
    conflicts = set()
    for index, field in enumerate(fields):
        if field in ETH_JUMP_CONFIG_ONLY_FIELDS and not _device_csv_na(row[index]):
            conflicts.add(field)
    template_index = fields.index("template")
    if not _device_csv_na(row[template_index]):
        conflicts.add("template")
    return tuple(sorted(conflicts))


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
class ActiveSetupState:
    """Exact setup manifest and managed-link state for the active project."""

    project: Path
    manifest: bytes
    manifest_mode: int
    links: dict[Path, str]


@dataclass(frozen=True)
class CrossProjectRollbackContext:
    """Old active runtime authority retained while another project is built."""

    project: Path
    selector_target: str
    runtime_receipt: Path
    setup_state: ActiveSetupState


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
        """Apache listens on the union of ZTP and independent HTTP authority."""
        return merge_http_listener_addresses(self.service_ips, self.http_address)


def publication_plan_for(
    settings: GlobalSettings, *, pubkey_names: tuple[str, ...],
    image_names: tuple[tuple[str, str], ...],
) -> PublicationPlan:
    """Bind declarative project URLs to the same endpoints Apache will listen on."""
    return PublicationPlan(
        endpoints_by_role=tuple(
            (role, tuple(
                validate_service_endpoint(
                    address, settings.http_port,
                    field=f"{role} ZTP service IPv4",
                )
                for address in settings.ztp_ips.get(role, ())
            ))
            for role in SERVICE_IP_PRIORITY
            if settings.ztp_ips.get(role)
        ),
        boot_endpoints=tuple(dict.fromkeys(
            validate_service_endpoint(
                address, settings.http_port,
                field="NVOS boot service IPv4",
            )
            for address in settings.boot_ips
        )),
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


def configure_local_pre_push_proof_gate() -> None:
    """Bind Git push to the same interpreter and exact proof used by load."""
    try:
        hook_info = LOCAL_PRE_PUSH_HOOK.lstat()
    except FileNotFoundError as exc:
        raise LoadError(f"Git pre-push proof hook 不存在：{LOCAL_PRE_PUSH_HOOK}") from exc
    if (
        not stat.S_ISREG(hook_info.st_mode)
        or hook_info.st_nlink != 1
        or LOCAL_PRE_PUSH_HOOK.is_symlink()
        or not hook_info.st_mode & stat.S_IXUSR
    ):
        raise LoadError("Git pre-push proof hook 必须是单链接、当前用户可执行的普通文件")

    def git(*arguments: str) -> str:
        completed = _run_subprocess(
            ["git", "-C", str(HTTP_ROOT), *arguments],
            cwd=HTTP_ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            check=False,
        )
        if completed.returncode != 0:
            detail = completed.stderr.strip() or "git command failed"
            raise LoadError(f"无法配置 Git pre-push proof gate：{detail}")
        return completed.stdout.strip()

    repository = Path(git("rev-parse", "--show-toplevel")).resolve()
    if repository != HTTP_ROOT.resolve():
        raise LoadError(f"load 工作树不是预期 Git 根目录：{repository}")
    git("ls-files", "--error-unmatch", "--", ".githooks/pre-push")
    git("ls-files", "--error-unmatch", "--", "tools/pre-push-proof.py")
    git("config", "--local", "core.hooksPath", ".githooks")
    git(
        "config", "--local", "http.fullProofPython",
        str(Path(sys.executable).resolve()),
    )
    if git("config", "--local", "--get", "core.hooksPath") != ".githooks":
        raise LoadError("Git core.hooksPath 配置后复核失败")
    if git("config", "--local", "--get", "http.fullProofPython") != str(
        Path(sys.executable).resolve()
    ):
        raise LoadError("Git full proof Python 配置后复核失败")
    info("已启用 Git pre-push proof gate：push 必须携带已提交的有效 full proof")


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
        if source.suffix.casefold() == ".bin":
            # Image names come from the selected device families and global
            # versions, never from a static project-template placeholder.
            continue
        if relative.parts and relative.parts[0] == "p2p":
            # p2p/ is customer-owned and may be an external directory link.
            continue
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


def _require_subnet_input_file(path: Path) -> os.stat_result:
    """Reject missing, linked, non-regular and zero-byte subnet authorities."""
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise LoadError(f"缺少 02-dhcp-subnet_config.csv：{exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise LoadError("02-dhcp-subnet_config.csv 必须是非软链接普通文件")
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
        if (not stat.S_ISREG(opened.st_mode)
                or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)):
            raise LoadError("02-dhcp-subnet_config.csv 在检查后被替换或不是普通文件")
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
    if "address" in http:
        try:
            http_address = validate_service_endpoint(
                http["address"], field="common.mgmt.http.address"
            ).host
        except ValueError as exc:
            raise LoadError(str(exc)) from exc
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
            types: set[str] = set()
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
                    conflicts = _eth_jump_configuration_intent(fields, row)
                    if conflicts:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 {hostname} type=eth_jump "
                            f"字段 {', '.join(conflicts)} 与零配置意图冲突"
                        )
                    try:
                        ipaddress.IPv4Address(raw_address)
                    except ValueError as exc:
                        raise LoadError(
                            f"devices_config.csv 第 {lineno} 行 eth_jump "
                            f"eth0_ip={raw_address!r} 无效"
                        ) from exc
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
                        "但全局 ZTP disabled"
                    )
            rows.append((lineno, row))
    try:
        validate_dhcp_subnet_placements(rows, service_ips=settings.service_ips)
    except ValueError as exc:
        raise LoadError(str(exc)) from exc
    if not rows and settings.dhcp_enabled:
        raise LoadError("02-dhcp-subnet_config.csv 没有 subnet 记录")
    if rows and not settings.dhcp_enabled:
        raise LoadError("DHCP disabled 时不能包含 subnet 记录")
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
    """Preserve the configuration-only behavior on platforms without services."""
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
    host_role: str | None = None,
    switch_scope: str = "all",
    no_upgrade: bool = False,
    prepare_switch_wal: bool = False,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    host_role = resolve_host_role(host_role)
    current = active_project()
    if current == project:
        mode = "严格" if strict else "配置准备/no-upgrade（跳过部署门禁）"
        info(f"当前活动项目就是目标项目；重新执行{mode} setup 以检查并修复全部链接")
    elif current:
        info(f"活动项目将从 {current.name} 切换到 {project.name}")
    else:
        info(f"当前没有有效活动项目；将激活 {project.name}")
    if prepare_switch_wal and not dry_run and current is not None and current != project:
        # The production LOAD owns the lock and has already quiesced services.
        # Freeze every P name before SETUP can remove one.  Q values are
        # discovered by SETUP and durably filled into their rows at write edge.
        prepare_setup_switch_journal(
            current, project, expected_new_links={},
            allow_late_q_values=True,
            deployment_lock_descriptor=deployment_lock_descriptor,
            services_quiesced=True, runtime_backend=runtime_backend,
        )
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
    if p2p_argument != "p2p.xlsx" or p2p_file.is_symlink():
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
        raise LoadError("01-a-setup.py 返回成功，但活动项目清单未指向目标项目")
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
    if not inputs.settings.dhcp_enabled:
        # The CSV still supplies HTTP/ZTP endpoint identity, but a disabled
        # DHCP service must not inherit a listener from otherwise valid rows.
        plan = replace(
            plan, listener_names=(), listener_ifindexes=(),
            direct_shared_networks=(), relay_shared_networks=(),
            dhcp_only_shared_networks=(),
        )
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
) -> tuple[str, ...]:
    """Return the managed units that are currently active, without mutation."""
    host_role = resolve_host_role(host_role)
    if host_role != "management-server":
        return ()
    backend = runtime_backend or service_runtime_backend()
    services = (SUPERVISOR_QUIESCE_SERVICES if backend.name == "supervisor"
                else ("isc-dhcp-server", "apache2"))
    # Use the backend's explicit inactive result, not "any nonzero is stopped".
    # A missing command or failed manager query is unknown, never authority to
    # restore P or change links while services may still be running.
    return tuple(service for service in services
                 if _runtime_service_active(backend, service))


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
) -> DhcpRuntimePlan | None:
    """Stop services before changing project links; failed loads remain safely stopped."""
    host_role = resolve_host_role(host_role)
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
    if (
        backend.name == "systemd" and not dry_run
        and not native_monitor_already_quiesced
    ):
        stop_native_ztp_monitors(HTTP_ROOT)
    if backend.name == "systemd" and not shutil.which("systemctl"):
        info("未找到 systemctl，跳过旧服务状态检查")
        return dhcp_plan
    active = list(active_managed_services(backend, host_role=host_role))
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
        endpoint = validate_service_endpoint(
            address, settings.http_port, field="bootstrap service IPv4"
        )
        if filename == "ztp-bootstrap_oobofoob.sh":
            manual_urls[filename] = service_url(
                endpoint, f"/{filename}", prefix=settings.ztp_prefix,
                channel="bootstrap-manual-oobofoob",
            )
        else:
            manual_urls[filename] = service_url(
                endpoint, f"/{filename}", prefix=settings.ztp_prefix,
                channel="bootstrap-manual-oob",
            )
    for filename, address in scripts:
        script = ZTP_DIR / filename

        rendered = render_bootstrap_script_text(
            template_text, address=address, port=settings.http_port,
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
            ping_hosts[0] = prod_oob_ips[0]
            endpoint = validate_service_endpoint(
                prod_oob_ips[0], settings.http_port, field="NVOS ZTP service IPv4"
            )
            ztp["02-commands-list"]["url"] = (
                service_url(
                    endpoint, "/config/nvos/disable-password-hardening.nv",
                    prefix=settings.ztp_prefix, channel="nvos-commands-list",
                )
            )
            ztp["03-provisioning-script"]["url"] = (
                service_url(
                    endpoint, "/ztp-bootstrap_oob.sh",
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
    result = _run_subprocess(
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
        relative_text = source_names[key]
        if not isinstance(relative_text, str):
            raise LoadError(f"pinned input {key} has no source path")
        relative = Path(relative_text)
        if (relative.is_absolute() or not relative.parts
                or any(part in {".", ".."} for part in relative.parts)
                or relative.as_posix() != relative_text
                or not isinstance(expected, str)
                or not re.fullmatch(r"[0-9a-f]{64}", expected)):
            raise LoadError(f"pinned input {key} has an unsafe source or digest")
        source = ((parent_directory / "inputs" / key) if snapshot_directory
                  else canonical_project / relative)
        if (not stat.S_ISREG(source.lstat().st_mode)
                or source.lstat().st_nlink != 1
                or source.resolve(strict=True) != source):
            raise LoadError(f"pinned input {key} is not an owned regular file")
        before = source.stat()
        content = source.read_bytes()
        after = source.stat()
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (any(getattr(before, field) != getattr(after, field) for field in identity)
                or hashlib.sha256(content).hexdigest() != expected):
            raise LoadError(f"pinned input {key} changed or differs from parent")
        payloads[f"inputs/{key}"] = content
    if dhcp_status == "enabled":
        assert dhcp_source_dir is not None and isinstance(child, dict)
        for name in names:
            source = dhcp_source_dir / name
            if not source.is_file():
                raise LoadError(f"pinned DHCP child is missing: {name}")
            if snapshot_directory:
                source_stat = source.lstat()
                if (not stat.S_ISREG(source_stat.st_mode)
                        or source_stat.st_nlink != 1):
                    raise LoadError(f"pinned DHCP child is not an owned regular file: {name}")
            data = source.read_bytes()
            if _sha256_path(source) != hashlib.sha256(data).hexdigest():
                raise LoadError(f"pinned DHCP child changed while freezing: {name}")
            payloads[f"dhcp/{name}"] = data
        if hashlib.sha256(payloads["dhcp/dhcp-release-manifest.json"]).hexdigest() != expected_manifest:
            raise LoadError("pinned DHCP manifest differs from parent component")
        try:
            manifest = json.loads(payloads["dhcp/dhcp-release-manifest.json"])
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise LoadError(f"pinned DHCP manifest is not JSON: {exc}") from exc
        outputs = manifest.get("outputs") if isinstance(manifest, dict) else None
        if (not isinstance(outputs, dict) or set(outputs) != set(names[1:])
                or manifest.get("release_id") != child.get("release_id")):
            raise LoadError("pinned DHCP child identity/outputs are incomplete")
        for name in names[1:]:
            record = outputs[name]
            expected = record.get("sha256") if isinstance(record, dict) else None
            if expected != hashlib.sha256(payloads[f"dhcp/{name}"]).hexdigest():
                raise LoadError(f"pinned DHCP output differs from child manifest: {name}")
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
    try:
        (stage / "inputs").mkdir(mode=0o755)
        if any(relative.startswith("dhcp/") for relative in payloads):
            (stage / "dhcp").mkdir(mode=0o755)
        for relative, content in payloads.items():
            target = stage / relative
            with target.open("xb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            target.chmod(0o644)
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
        if stage.exists():
            shutil.rmtree(stage)
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
    try:
        temporary.symlink_to(target)
        os.replace(temporary, selector)
        descriptor = os.open(output, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        temporary.unlink(missing_ok=True)


def ensure_previous_generation_frozen(project: Path) -> str | None:
    """Keep a committed A recoverable before a later load can generate B.

    A pre-versioned flat parent can be migrated only while its original
    project inputs and DHCP child still validate.  If those bytes have already
    changed, refusing before generation is safer than signing B over A.
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
    try:
        parent_payload = json.loads(parent.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise LoadError(f"previous parent release is invalid: {exc}") from exc
    if not isinstance(parent_payload, dict) or parent_payload.get("schema_version") != 2:
        raise LoadError("previous parent release must use schema 2")
    flat_dhcp = (
        ZTP_DIR / "config/isc-dhcp-server"
        if parent_payload.get("dhcp_status") == "enabled" else None
    )
    release_id, _payloads = _pinned_generation_payloads(
        project, parent, flat_dhcp,
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
_SETUP_MANIFEST_LIMIT = 4 * 1024 * 1024


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


def _setup_link_target_allowed(target: Path, project: Path) -> bool:
    """Limit a setup receipt to its project or the shared image authority."""
    canonical_project = project.resolve(strict=True)
    if target == canonical_project or canonical_project in target.parents:
        return True
    try:
        image_root = IMAGE_DIR.resolve(strict=True)
    except OSError:
        return False
    return target == image_root or image_root in target.parents


def _parse_active_setup_state(
    payload: bytes, mode: int, *, expected_project: Path | None,
) -> ActiveSetupState:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise LoadError(f"setup rollback manifest is not UTF-8: {exc}") from exc
    lines = text.splitlines()
    prefix = "# setup manifest — proj: "
    if not lines or not lines[0].startswith(prefix):
        raise LoadError("setup rollback manifest header is invalid")
    try:
        project = Path(lines[0][len(prefix):]).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LoadError(f"setup rollback project is unavailable: {exc}") from exc
    if not project.is_dir():
        raise LoadError("setup rollback project is not a directory")
    if expected_project is not None:
        try:
            expected = expected_project.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LoadError(f"expected setup rollback project is unavailable: {exc}") from exc
        if project != expected:
            raise LoadError("setup rollback manifest names a different active project")
    try:
        root = HTTP_ROOT.resolve(strict=True)
    except OSError as exc:
        raise LoadError(f"setup rollback HTTP root is unavailable: {exc}") from exc
    links: dict[Path, str] = {}
    for value in lines[1:]:
        if not value:
            raise LoadError("setup rollback manifest contains an empty managed link")
        link = Path(value)
        if (not link.is_absolute() or os.path.normpath(value) != value
                or link in links):
            raise LoadError("setup rollback manifest link inventory is invalid")
        try:
            link.parent.resolve(strict=True).relative_to(root)
            metadata = link.lstat()
            raw_target = os.readlink(link)
            resolved_target = link.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise LoadError(f"setup rollback managed link is invalid: {link}: {exc}") from exc
        if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1
                or os.path.isabs(raw_target)
                or os.path.normpath(raw_target) != raw_target
                or not _setup_link_target_allowed(resolved_target, project)):
            raise LoadError(f"setup rollback managed link is unsafe: {link}")
        links[link] = raw_target
    if not links:
        raise LoadError("setup rollback manifest has no managed links")
    return ActiveSetupState(
        project=project, manifest=payload, manifest_mode=mode, links=links,
    )


def snapshot_active_setup_state(
    *, expected_project: Path | None = None,
) -> ActiveSetupState:
    """Read the active setup authority through one held regular-file FD."""
    opened = _read_rollback_regular(MANIFEST, limit=_SETUP_MANIFEST_LIMIT)
    if opened is None:  # pragma: no cover - missing_ok is deliberately false.
        raise LoadError("setup rollback manifest is absent")
    payload, mode = opened
    state = _parse_active_setup_state(
        payload, mode, expected_project=expected_project,
    )
    if active_project() != state.project:
        raise LoadError("setup rollback manifest is not the active project authority")
    return state


def _validate_setup_state_receipt(state: ActiveSetupState) -> ActiveSetupState:
    """Validate a detached in-memory setup receipt without consulting live links."""
    if not isinstance(state, ActiveSetupState):
        raise LoadError("setup rollback state type is invalid")
    try:
        text = state.manifest.decode("utf-8")
        project = state.project.resolve(strict=True)
        root = HTTP_ROOT.resolve(strict=True)
    except (UnicodeDecodeError, OSError, RuntimeError) as exc:
        raise LoadError(f"setup rollback receipt is invalid: {exc}") from exc
    lines = text.splitlines()
    prefix = "# setup manifest — proj: "
    if (not lines or not lines[0].startswith(prefix)
            or Path(lines[0][len(prefix):]).resolve(strict=True) != project
            or not isinstance(state.manifest_mode, int)
            or state.manifest_mode < 0 or state.manifest_mode > 0o777):
        raise LoadError("setup rollback receipt header is invalid")
    paths = [Path(value) for value in lines[1:]]
    if (not paths or len(paths) != len(set(paths))
            or set(paths) != set(state.links)):
        raise LoadError("setup rollback receipt inventory is invalid")
    for path in paths:
        raw_target = state.links.get(path)
        if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                or not isinstance(raw_target, str) or not raw_target
                or os.path.isabs(raw_target)
                or os.path.normpath(raw_target) != raw_target):
            raise LoadError("setup rollback receipt link record is invalid")
        try:
            path.parent.resolve(strict=True).relative_to(root)
            resolved = (path.parent / raw_target).resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise LoadError(f"setup rollback receipt target is invalid: {path}: {exc}") from exc
        if not _setup_link_target_allowed(resolved, project):
            raise LoadError(f"setup rollback receipt target escaped its authority: {path}")
    return state


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


def _runtime_key_source(path: Path, project: Path, target: object) -> Path:
    """Admit only SETUP's relative publication of this project's same-name key."""
    if (not isinstance(target, str) or not target or os.path.isabs(target)
            or os.path.normpath(target) != target or not path.name.endswith(".pub")):
        raise LoadError("rollback public key source link is invalid")
    source = project.resolve(strict=True) / path.name
    lexical = Path(os.path.normpath(str(path.parent.resolve(strict=True) / target)))
    if lexical != source:
        raise LoadError("rollback public key source escaped its owning project")
    return source


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
        source = _runtime_key_source(path, project, target)
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


def prepare_runtime_rollback_receipt(
    project: Path, generation: Path,
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
        _load_runtime_rollback_receipt(canonical_project, destination)
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
                name: _receipt_authority(ZTP_DIR / "config/isc-dhcp-server" / name)
                for name in (
                    "dhcp-release-manifest.json", "dhcpd.conf",
                    "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
                )
            }
        receipt = {
            "schema_version": (2 if any(record["state"] == "link" for record in publickeys.values()) else 1),
            "record_type": "http-ztp-runtime-rollback-receipt",
            "project": canonical_project.name,
            "release_id": release_id,
            "selector_target": f"generations/{release_id}",
            "dhcp_status": dhcp_status,
            "frozen_files": frozen_files,
            "publickeys": publickeys,
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
        receipt_path = stage / "receipt.json"
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
    _load_runtime_rollback_receipt(canonical_project, destination)
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
        receipt = json.loads(opened[0].decode("ascii"))
    except (OSError, UnicodeError, json.JSONDecodeError, LoadError) as exc:
        raise LoadError(f"rollback receipt is incomplete or invalid: {exc}") from exc
    required = {
        "schema_version", "record_type", "project", "release_id",
        "selector_target", "dhcp_status", "frozen_files", "publickeys",
        "yaml_latest", "prefix", "unchanged_authorities",
    }
    if (not isinstance(receipt, dict) or set(receipt) != required
            or isinstance(receipt.get("schema_version"), bool)
            or not isinstance(receipt.get("schema_version"), int)
            or receipt.get("schema_version") not in (1, 2)
            or receipt.get("record_type") != "http-ztp-runtime-rollback-receipt"
            or receipt.get("project") != canonical_project.name
            or receipt.get("release_id") != relative.name
            or receipt.get("selector_target") != f"generations/{relative.name}"
            or receipt.get("dhcp_status") not in {"enabled", "disabled"}):
        raise LoadError("rollback receipt is incomplete or invalid")
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
                if (receipt["schema_version"] != 2
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
        for record in authorities["dhcp"].values():
            if (not isinstance(record, dict) or set(record) != {"state", "sha256"}
                    or record.get("state") != "file"
                    or not isinstance(record.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])):
                raise LoadError("rollback receipt DHCP authority record is invalid")
    return receipt


def _restore_receipt_file(
    path: Path, record: dict[str, object], payload: bytes | None,
) -> None:
    if record["state"] == "missing":
        if payload is not None:
            raise LoadError("rollback missing-file record has an unexpected payload")
        if os.path.lexists(path):
            if path.is_dir() and not path.is_symlink():
                raise LoadError(f"rollback target became a directory: {path}")
            path.unlink()
        # Even an already-absent name may be a retry after unlink succeeded
        # but its directory sync failed. Do not retire the WAL before sync.
        _fsync_parent_directory(path.parent)
        return
    if payload is None or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise LoadError("rollback receipt payload changed before restore")
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.rollback-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            os.fchmod(stream.fileno(), int(record["mode"]))
            stream.flush()
            os.fsync(stream.fileno())
        if os.path.lexists(path) and path.is_dir() and not path.is_symlink():
            raise LoadError(f"rollback target became a directory: {path}")
        os.replace(temporary, path)
        _fsync_parent_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


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
            name: _receipt_authority(ZTP_DIR / "config/isc-dhcp-server" / name)
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
    _verify_rollback_authorities(project, receipt)
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
    active = active_project()
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
        _verify_active_runtime_receipt(canonical_project, receipt_path, receipt)
        return receipt_path
    receipt_path = prepare_runtime_rollback_receipt(canonical_project, generation)
    receipt = _load_runtime_rollback_receipt(canonical_project, receipt_path)
    _verify_active_runtime_receipt(canonical_project, receipt_path, receipt)
    return receipt_path


def prepare_cross_project_rollback_context(
    target_project: Path,
) -> tuple[str | None, CrossProjectRollbackContext | None]:
    """Freeze the actual active P before a load switches setup links to Q.

    The target project's historical receipt is never a runtime authority for
    the current host.  A legacy active project without a selected generation
    keeps the established switch behavior, but cannot claim complete rollback.
    """
    target = target_project.resolve(strict=True)
    active = active_project()
    if active is None or active == target:
        raise LoadError("cross-project rollback requires a different active project")
    setup_state = snapshot_active_setup_state(expected_project=active)
    active_selector = ensure_previous_generation_frozen(active)
    if active_selector is None:
        warn(
            f"active project {active.name} has no frozen generation; "
            "cross-project runtime rollback remains unavailable"
        )
        return ensure_previous_generation_frozen(target), None
    receipt = prepare_active_runtime_rollback_receipt(active, active_selector)
    if receipt is None:
        raise LoadError("active project rollback receipt was not created")
    target_selector = ensure_previous_generation_frozen(target)
    return target_selector, CrossProjectRollbackContext(
        project=active,
        selector_target=active_selector,
        runtime_receipt=receipt,
        setup_state=setup_state,
    )


def _require_runtime_restore_guard(
    *, deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> None:
    if (deployment_lock_descriptor is None or services_quiesced is not True
            or runtime_backend is None):
        raise LoadError("runtime rollback requires the deployment lock and quiesced services")
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
    probe = os.open(DEPLOYMENT_LOCK, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
    try:
        try:
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            pass
        else:
            fcntl.flock(probe, fcntl.LOCK_UN)
            raise LoadError("runtime rollback deployment lock is not held")
    finally:
        os.close(probe)
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


def _atomic_restore_setup_link(path: Path, raw_target: str) -> None:
    temporary = path.parent / (
        f".{path.name}.setup-rollback.{os.getpid()}.{secrets.token_hex(8)}"
    )
    try:
        temporary.symlink_to(raw_target)
        os.replace(temporary, path)
        _fsync_parent_directory(path.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()


def _atomic_restore_setup_manifest(state: ActiveSetupState) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{MANIFEST.name}.rollback.", dir=MANIFEST.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(state.manifest)
            # Persist the final P mode on the same held inode as its bytes.
            # chmod after fsync leaves recovery metadata outside the durable
            # file boundary even if the manifest name's parent is synced.
            os.fchmod(stream.fileno(), state.manifest_mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, MANIFEST)
        parent_descriptor = os.open(MANIFEST.parent, os.O_RDONLY)
        try:
            os.fsync(parent_descriptor)
        finally:
            os.close(parent_descriptor)
    finally:
        if os.path.exists(temporary):
            temporary.unlink()


def restore_active_setup_state(
    state: ActiveSetupState, *, current_project: Path,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> None:
    """Restore every setup-managed P link after an uncommitted Q failure.

    This multi-path operation is deliberately fail-closed and is reported as
    successful only after the old manifest and every link are re-read.  The
    caller must keep services stopped if any write or post-check fails.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    old_project = state.project.resolve(strict=True)
    target = current_project.resolve(strict=True)
    if target == old_project:
        raise LoadError("cross-project setup restore target equals old active project")

    # Validate the detached receipt before inspecting mutable Q.  Parsing it
    # against live links would accidentally validate Q using P's manifest.
    expected = _validate_setup_state_receipt(state)
    current = snapshot_active_setup_state()
    if current.project == old_project:
        if current.manifest != expected.manifest or current.links != expected.links:
            raise LoadError("old setup authority is only partially restored")
        return
    if current.project != target:
        raise LoadError("setup rollback current project is neither P nor expected Q")

    # Complete preflight: no real file/directory may be overwritten or removed,
    # and every saved P target must still resolve inside P/shared-image authority.
    for path, raw_target in expected.links.items():
        if os.path.lexists(path) and not path.is_symlink():
            raise LoadError(f"setup rollback managed link became a real path: {path}")
        try:
            resolved = (path.parent / raw_target).resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise LoadError(f"setup rollback P target is unavailable: {path}: {exc}") from exc
        if not _setup_link_target_allowed(resolved, old_project):
            raise LoadError(f"setup rollback P target escaped its authority: {path}")
    for path, raw_target in current.links.items():
        if not path.is_symlink() or os.readlink(path) != raw_target:
            raise LoadError(f"setup rollback Q managed link changed before restore: {path}")

    for path, raw_target in expected.links.items():
        if not (path.is_symlink() and os.readlink(path) == raw_target):
            _atomic_restore_setup_link(path, raw_target)
    for path in sorted(
        set(current.links) - set(expected.links),
        key=lambda item: len(item.parts), reverse=True,
    ):
        if not path.is_symlink() or os.readlink(path) != current.links[path]:
            raise LoadError(f"setup rollback target-only link changed during restore: {path}")
        path.unlink()
        _fsync_parent_directory(path.parent)
    _atomic_restore_setup_manifest(expected)
    verified = snapshot_active_setup_state(expected_project=old_project)
    if verified.manifest != expected.manifest or verified.links != expected.links:
        raise LoadError("setup rollback post-verify failed; services remain stopped")
    ok(f"active setup restore verified: {old_project.name}")


_SETUP_SWITCH_JOURNAL_LIMIT = 12 * 1024 * 1024


def _setup_switch_journal_path() -> Path:
    return MANIFEST.parent / ".setup-switch-journal.json"


def require_no_pending_setup_switch_journal() -> None:
    """Fence a new ordinary LOAD before project mutation, not recover a WAL.

    Any occupied authority name, including malformed bytes or a dangling
    symlink, is unresolved evidence. The caller must not delete it or infer
    that either project committed. Production main checks under its lock.
    """
    journal = _setup_switch_journal_path()
    try:
        journal.lstat()
    except FileNotFoundError:
        return
    # Do not use lexists(): it converts permission/type errors to False and
    # would incorrectly authorize project writes with an unreadable WAL path.
    raise LoadError(
        f"pending setup switch WAL: {journal}; "
        "保留原始凭据并完成独立恢复核验后再运行新 load；"
        "不得删除 WAL、继续模板写入或自动启动旧 A"
    )


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


def _setup_switch_q_target(target: Path, project: Path) -> Path:
    """Validate a Q link target while preserving its final raw symlink leaf.

    Setup can publish a link to a Q output before producing that file.  Only
    that final absent leaf is allowed: its parent must already exist, and an
    existing (including dangling) symlink must resolve strictly.
    """
    parent = target.parent.resolve(strict=True)
    if not parent.is_dir():
        raise ValueError("Q target parent is not a directory")
    raw = parent / target.name
    resolved = target.resolve(strict=True) if os.path.lexists(target) else raw
    if not _setup_link_target_allowed(resolved, project):
        raise ValueError("Q target escaped its authority")
    return raw


def _setup_switch_recovery_q_target(target: Path, project: Path, rows) -> Path:
    """Resolve exact WAL-owned Q aliases without consulting a restored P leaf.

    A Q temporary link can point at another shared link. On recovery reentry
    that shared name may already select P or be absent. Only exact registered
    link names participate here; unregistered prefixes/targets still use the
    normal strict Q authority check. Cycles and invalid raw values fail closed.
    The caller validates every row's parent and actual P/Q state before writes.
    """
    aliases = {row["path"]: row for row in rows}
    seen = set()
    planned = target
    while str(planned) in aliases:
        if planned in seen:
            raise ValueError("cyclic Q alias in setup switch WAL")
        seen.add(planned)
        raw = aliases[str(planned)]["after"]
        if raw is None:
            break
        if (not isinstance(raw, str) or not raw or os.path.isabs(raw)
                or os.path.normpath(raw) != raw):
            raise ValueError("invalid Q alias in setup switch WAL")
        planned = Path(os.path.normpath(str(planned.parent / raw)))
    return _setup_switch_q_target(planned, project)


def _setup_switch_q_parent_authority(project: Path) -> dict[str, object]:
    """Snapshot Q's parent commit marker without following output aliases."""
    path = project / "99-output-ztp/current-release.json"
    try:
        parent = None
        if os.path.lexists(path.parent):
            if (not stat.S_ISDIR(path.parent.lstat().st_mode)
                    or path.parent.resolve(strict=True) != path.parent):
                raise ValueError("parent output is not a canonical real directory")
            parent = _setup_switch_directory_identity(path.parent)
        file = None
        descriptor = -1
        fields = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                  "st_mtime_ns", "st_ctime_ns")
        try:
            try:
                before = path.lstat()
            except FileNotFoundError:
                before = None
            if before is not None:
                if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                        or before.st_size < 0 or before.st_size > _ROLLBACK_PAYLOAD_LIMIT):
                    raise ValueError("parent is not a bounded single-link file")
                flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
                descriptor = os.open(path, flags)
                held = os.fstat(descriptor)
                if any(getattr(before, field) != getattr(held, field) for field in fields):
                    raise ValueError("parent identity changed while opening")
            # Freeze identity/absence before the first read, and keep that
            # inode alive. A later same-byte owner is not its continuation.
            opened = _read_rollback_regular(path, missing_ok=True)
            if before is None:
                if opened is not None or os.path.lexists(path):
                    raise ValueError("absent parent appeared while freezing")
            else:
                if opened is None or _read_rollback_regular(path) != opened:
                    raise ValueError("parent bytes changed while freezing")
                after, held = path.lstat(), os.fstat(descriptor)
                if any(getattr(before, field) != getattr(after, field)
                       or getattr(before, field) != getattr(held, field) for field in fields):
                    raise ValueError("parent identity changed while freezing")
                file = {
                    "sha256": hashlib.sha256(opened[0]).hexdigest(), "mode": opened[1],
                    "identity": {field: getattr(before, field) for field in fields},
                }
            current_parent = (
                _setup_switch_directory_identity(path.parent)
                if os.path.lexists(path.parent) else None
            )
            if parent != current_parent:
                raise ValueError("parent output directory changed while freezing")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
        return {"path": str(path), "parent": parent, "file": file}
    except (OSError, ValueError, RuntimeError, LoadError) as exc:
        raise LoadError(f"setup switch Q parent authority is unknown: {exc}") from exc


def _require_setup_switch_q_parent_preimage(body) -> None:
    """P rollback is allowed only while Q's parent is still precommit."""
    before = body.get("q_parent_preimage")
    if not isinstance(before, dict) or set(before) != {"path", "parent", "file"}:
        raise LoadError("setup switch Q parent preimage is missing or invalid; HOLD")
    current = _setup_switch_q_parent_authority(Path(body["new_project"]["path"]))
    # A missing Q-local output directory may be prepared after freezing the
    # WAL. It must remain canonical and its commit marker must remain absent.
    if (before["path"] != current["path"] or before["file"] != current["file"]
            or (before["parent"] is not None and before["parent"] != current["parent"])):
        raise LoadError("setup switch Q parent changed or committed; P rollback is blocked")


def prepare_setup_switch_journal(
    old_project: Path, new_project: Path, *,
    expected_new_links: dict[Path, Path],
    allow_late_q_values: bool = False,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Durably freeze P and the permitted Q link values before setup's first write.

    This narrow primitive does not switch projects, start services, or imply
    that Q committed.  A caller must enumerate every path it permits setup to
    mutate; any later dynamic path must be durably registered before writing.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    old = _setup_switch_directory_identity(old_project)
    new = _setup_switch_directory_identity(new_project)
    root = _setup_switch_directory_identity(HTTP_ROOT)
    if old == new or old["path"] == new["path"]:
        raise LoadError("setup switch journal requires distinct P and Q")
    state = snapshot_active_setup_state(expected_project=Path(str(old["path"])))
    _validate_setup_state_receipt(state)
    if not isinstance(expected_new_links, dict):
        raise LoadError("setup switch Q link inventory is invalid")
    if not isinstance(allow_late_q_values, bool):
        raise LoadError("setup switch late Q registration policy is invalid")
    q_links: dict[Path, str] = {}
    for raw_path, raw_target in expected_new_links.items():
        path = Path(raw_path)
        if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                or path in q_links):
            raise LoadError("setup switch Q link path is invalid")
        try:
            path.parent.resolve(strict=True).relative_to(Path(str(root["path"])))
            target_path = Path(raw_target)
            if (not target_path.is_absolute()
                    or os.path.normpath(str(target_path)) != str(target_path)):
                raise ValueError("Q link target path is not canonical")
            raw_target_in_physical_parent = _setup_switch_q_target(
                target_path, Path(str(new["path"])),
            )
        except (OSError, RuntimeError, ValueError) as exc:
            raise LoadError(f"setup switch Q link target is invalid: {path}: {exc}") from exc
        # The link's parent may use macOS' /var -> /private/var alias.  Both
        # operands must share one physical namespace before deriving a raw
        # relative symlink value.
        q_links[path] = os.path.relpath(
            raw_target_in_physical_parent, path.parent.resolve(strict=True),
        )
    rows = []
    for path in sorted(set(state.links) | set(q_links), key=str):
        before = state.links.get(path)
        after = q_links.get(path)
        if os.path.lexists(path):
            metadata = path.lstat()
            if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1
                    or os.readlink(path) != before):
                raise LoadError(f"setup switch P link changed before journal: {path}")
        elif before is not None:
            raise LoadError(f"setup switch P link disappeared before journal: {path}")
        rows.append({
            "path": str(path), "parent": _setup_switch_link_parent_identity(path),
            "before": before, "after": after,
        })
    body = {
        "schema_version": 2, "phase": "prepared",
        "root": root, "old_project": old, "new_project": new,
        "manifest": base64.b64encode(state.manifest).decode("ascii"),
        "manifest_sha256": hashlib.sha256(state.manifest).hexdigest(),
        "manifest_mode": state.manifest_mode, "links": rows,
        "allow_late_q_values": allow_late_q_values,
        "q_parent_preimage": _setup_switch_q_parent_authority(Path(new["path"])),
    }
    body_bytes = _setup_switch_canonical_payload(body)
    envelope = {
        "body": body, "sha256": hashlib.sha256(body_bytes).hexdigest(),
    }
    payload = _setup_switch_canonical_payload(envelope) + b"\n"
    if len(payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
        raise LoadError("setup switch journal exceeds the bounded size limit")
    journal = _setup_switch_journal_path()
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(journal, flags, 0o600)
    except OSError as exc:
        raise LoadError(f"setup switch journal cannot be exclusively created: {exc}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_parent_directory(journal.parent)
    except BaseException:
        # A potentially partial WAL is evidence, never silently removed.
        raise
    return journal


def register_setup_switch_journal_link(
    journal: Path, link: Path, target: Path, *,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
    allow_existing_exact: bool = False,
    raw_target: str | None = None,
) -> Path:
    """Durably register one newly discovered Q-only link before its first write.

    This narrow primitive does not authorize setup itself.  Every shared
    writer must still enforce its own complete WAL fence before mutation.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    journal = Path(journal)
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    try:
        before_name = journal.lstat()
    except FileNotFoundError as exc:
        raise LoadError("setup switch journal is absent") from exc
    opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
    if opened is None or opened[1] != 0o600:
        raise LoadError("setup switch journal is absent or not private")
    payload, _mode = opened
    try:
        envelope = json.loads(payload)
        body = envelope["body"]
        if (not isinstance(body, dict) or body["schema_version"] != 2
                or body["phase"] != "prepared"
                or hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest()
                != envelope["sha256"]):
            raise ValueError("journal envelope is invalid")
        late_q_values = body.get("allow_late_q_values", False)
        if not isinstance(late_q_values, bool):
            raise ValueError("journal late Q registration policy is invalid")
        root = body["root"]
        old = body["old_project"]
        new = body["new_project"]
        if (root != _setup_switch_directory_identity(HTTP_ROOT)
                or old != _setup_switch_directory_identity(Path(old["path"]))
                or new != _setup_switch_directory_identity(Path(new["path"]))
                or old == new):
            raise ValueError("journal directory identity changed")
        _require_setup_switch_q_parent_preimage(body)
        old_manifest = base64.b64decode(body["manifest"], validate=True)
        if (hashlib.sha256(old_manifest).hexdigest() != body["manifest_sha256"]
                or _read_rollback_regular(MANIFEST, limit=_SETUP_MANIFEST_LIMIT)
                != (old_manifest, body["manifest_mode"])):
            raise ValueError("P manifest is no longer exact")
        rows = body["links"]
        if (not isinstance(rows, list) or not rows
                or len({row["path"] for row in rows}) != len(rows)):
            raise ValueError("journal link inventory is invalid")
        _validate_setup_state_receipt(ActiveSetupState(
            project=Path(old["path"]), manifest=old_manifest,
            manifest_mode=body["manifest_mode"],
            links={Path(row["path"]): row["before"] for row in rows
                   if row["before"] is not None},
        ))
        root_path = Path(root["path"])
        q_local_states = _setup_switch_q_local_link_states(body)
        for row in rows:
            path = Path(row["path"])
            if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                    or (row["before"] is None and row["after"] is None)):
                raise ValueError("journal link row is invalid")
            path.parent.resolve(strict=True).relative_to(root_path)
            if row["parent"] != _setup_switch_link_parent_identity(path):
                raise ValueError("journal link parent identity changed")
            after = row["after"]
            if after is not None:
                if (not isinstance(after, str) or not after
                        or os.path.isabs(after) or os.path.normpath(after) != after):
                    raise ValueError("journal Q link value is invalid")
                _setup_switch_q_target(
                    Path(os.path.normpath(str(path.parent / after))),
                    Path(new["path"]),
                )
            if os.path.lexists(path):
                actual = path.lstat()
                if (not stat.S_ISLNK(actual.st_mode) or actual.st_nlink != 1
                        or os.readlink(path) not in (row["before"], row["after"])):
                    raise ValueError("journal link disk state is unknown")
        physical_link = Path(link).parent.resolve(strict=True) / Path(link).name
        for local_path, local_row in q_local_states:
            if physical_link != local_path:
                continue
            physical_target = Path(target).parent.resolve(strict=True) / Path(target).name
            if (physical_target != Path(local_row["after_target"]["path"])
                    or raw_target != local_row["after"]):
                raise ValueError("Q-local latest writer differs from its frozen plan")
            return journal
        path = Path(link)
        if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                or (not allow_existing_exact and
                    str(path) in {row["path"] for row in rows})):
            raise ValueError("dynamic Q-only link path is not new or canonical")
        path.parent.resolve(strict=True).relative_to(root_path)
        target_path = Path(target)
        if (not target_path.is_absolute()
                or os.path.normpath(str(target_path)) != str(target_path)):
            raise ValueError("dynamic Q-only target path is not canonical")
        raw_target_in_physical_parent = _setup_switch_q_target(
            target_path, Path(new["path"]),
        )
        after = os.path.relpath(
            raw_target_in_physical_parent,
            path.parent.resolve(strict=True),
        )
        if raw_target is not None:
            if (not isinstance(raw_target, str) or not raw_target
                    or os.path.isabs(raw_target) or os.path.normpath(raw_target) != raw_target):
                raise ValueError("writer relative link bytes are invalid")
            planned = Path(os.path.normpath(str(path.parent / raw_target)))
            if (_setup_switch_q_target(planned, Path(new["path"]))
                    != raw_target_in_physical_parent):
                raise ValueError("writer relative link bytes name a different Q target")
            after = raw_target
        if os.path.isabs(after) or os.path.normpath(after) != after:
            raise ValueError("dynamic Q-only relative target is invalid")
        existing = next((row for row in rows if row["path"] == str(path)), None)
        if existing is not None:
            if existing["after"] == after:
                return journal
            if (not late_q_values or existing["after"] is not None
                    or existing["before"] is None):
                raise ValueError("existing Q link value differs from the writer")
            # A production LOAD can first durably freeze every P name without
            # guessing Q's dynamic targets.  SETUP may fill a P row's one Q
            # value, but only before writing that value.  The loop above has
            # already proved the name is still exact P or absent after cleanup.
            next_rows = [
                dict(row, after=after) if row is existing else row
                for row in rows
            ]
        else:
            if os.path.lexists(path):
                raise ValueError("dynamic Q-only link is not a new absent path")
            next_rows = [*rows, {
                "path": str(path), "parent": _setup_switch_link_parent_identity(path),
                "before": None, "after": after,
            }]
    except (KeyError, TypeError, ValueError, OSError, RuntimeError, binascii.Error,
            LoadError) as exc:
        raise LoadError(f"setup switch journal registration is invalid: {exc}") from exc
    next_body = dict(body)
    next_body["links"] = sorted(next_rows, key=lambda row: row["path"])
    body_bytes = _setup_switch_canonical_payload(next_body)
    next_payload = _setup_switch_canonical_payload({
        "body": next_body, "sha256": hashlib.sha256(body_bytes).hexdigest(),
    }) + b"\n"
    if len(next_payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
        raise LoadError("setup switch journal exceeds the bounded size limit")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".setup-switch-journal.", dir=journal.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(next_payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if any(getattr(before_name, name) != getattr(now, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")):
            raise LoadError("setup switch journal changed before registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return journal


def _setup_switch_q_local_link_states(body) -> list[tuple[Path, dict]]:
    """Validate Q's existing latest preimages separately from P's manifest."""
    try:
        rows = body.get("q_local_links", [])
        if (not isinstance(rows, list) or len(rows) > 2
                or len({row["path"] for row in rows}) != len(rows)):
            raise ValueError("invalid Q-local link inventory")
        q = Path(body["new_project"]["path"])
        shared_names = {row["path"] for row in body["links"]}
        states = []
        for row in rows:
            path = Path(row["path"])
            if (path not in {q / "99-output-eth/latest", q / "99-output-ib_nvl/latest"}
                    or str(path) in shared_names
                    or row["parent"] != _setup_switch_link_parent_identity(path)
                    or path.parent.resolve(strict=True) != path.parent):
                raise ValueError("Q-local latest path or parent differs")
            for phase in ("before", "after"):
                raw = row[phase]
                pattern = (r"\d{8}_\d{6}_combine" if path.parent.name == "99-output-eth"
                           else r"\d{8}_\d{6}-(?:ib|nvl|combine)")
                if not isinstance(raw, str) or re.fullmatch(pattern, raw) is None:
                    raise ValueError("Q-local latest target is not a complete release basename")
                target = path.parent / raw
                if (not stat.S_ISDIR(target.lstat().st_mode)
                        or row[phase + "_target"]["path"] != str(target)
                        or row[phase + "_target"] != _setup_switch_directory_identity(target)):
                    raise ValueError("Q-local complete release identity changed")
                _read_rollback_regular(target / ".published-complete", limit=_ROLLBACK_MARKER_LIMIT)
            info = path.lstat()
            if (not stat.S_ISLNK(info.st_mode) or info.st_nlink != 1
                    or os.readlink(path) not in (row["before"], row["after"])):
                raise ValueError("Q-local latest pointer is not its frozen preimage or candidate")
            states.append((path, row))
        return states
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, LoadError) as exc:
        raise LoadError(f"setup switch Q-local latest state is unknown: {exc}") from exc


def register_setup_switch_q_local_latest(
    journal: Path, path: Path, target: Path, *, deployment_lock_descriptor: int | None,
    services_quiesced: bool, runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Freeze an existing Q-local latest pointer before the first shared write."""
    journal, path, target = Path(journal), Path(path), Path(target)
    # Normalize the parent namespace only, never resolve away the pointer
    # leaf itself (Darwin's /var and /private/var may denote the same parent).
    path = path.parent.resolve(strict=True) / path.name
    target = target.parent.resolve(strict=True) / target.name
    # Only the untouched P state licenses this preimage capture. A late writer
    # cannot adopt an in-flight or unregistered pointer as the original Q state.
    recover_setup_switch_journal(
        journal, deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        verify_only=True,
    )
    before_name = journal.lstat()
    opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
    try:
        envelope = json.loads(opened[0])
        body = envelope["body"]
        if "q_manifest_intent" in body:
            raise ValueError("Q manifest intent is already frozen")
        q = Path(body["new_project"]["path"])
        if (path not in {q / "99-output-eth/latest", q / "99-output-ib_nvl/latest"}
                or target.parent != path.parent):
            raise ValueError("Q-local latest path or candidate is outside its output")
        row = {
            "path": str(path), "parent": _setup_switch_link_parent_identity(path),
            "before": os.readlink(path), "after": target.name,
            "before_target": _setup_switch_directory_identity(path.parent / os.readlink(path)),
            "after_target": _setup_switch_directory_identity(target),
        }
        rows = body.get("q_local_links", [])
        existing = next((item for item in rows if item["path"] == str(path)), None)
        if existing is not None:
            if existing != row:
                raise ValueError("Q-local latest preimage cannot be changed")
            return journal
        next_body = dict(body, q_local_links=[*rows, row])
        _setup_switch_q_local_link_states(next_body)
        payload = _setup_switch_canonical_payload({
            "body": next_body,
            "sha256": hashlib.sha256(_setup_switch_canonical_payload(next_body)).hexdigest(),
        }) + b"\n"
        if len(payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
            raise ValueError("journal exceeds the bounded size limit")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, LoadError) as exc:
        raise LoadError(f"setup switch Q-local latest registration is invalid: {exc}") from exc
    descriptor, name = tempfile.mkstemp(prefix=".setup-switch-journal.", dir=journal.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if (any(getattr(before_name, field) != getattr(now, field) for field in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns"))
                or _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT) != opened):
            raise LoadError("setup switch journal changed before Q-local registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return journal


def register_setup_switch_created_directory(
    journal: Path, path: Path, staged: Path, *,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool, runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Freeze an empty private directory's identity before shared installation.

    The staged inode remains recovery evidence until the no-replace rename has
    installed it.  Neither an existing target nor a different inode is owned.
    """
    journal, path, staged = map(Path, (journal, path, staged))
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
    )
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    before = journal.lstat()
    opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
    recover_setup_switch_journal(
        journal, deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        inspect_only=True,
    )
    body = dict(json.loads(opened[0])["body"])
    try:
        if "q_manifest_intent" in body:
            raise ValueError("Q manifest intent already freezes the setup write set")
        if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                or not staged.is_absolute() or os.path.normpath(str(staged)) != str(staged)
                or staged.parent != path.parent
                or not staged.name.startswith(f".{path.name}.setup-")):
            raise ValueError("created directory names are not canonical")
        path.parent.resolve(strict=True).relative_to(HTTP_ROOT.resolve(strict=True))
        physical_path = path.parent.resolve(strict=True) / path.name
        for project in (body["old_project"]["path"], body["new_project"]["path"]):
            if os.path.commonpath((str(physical_path), project)) == project:
                raise ValueError("created shared directory is inside a project")
        try:
            path.lstat()
        except FileNotFoundError:
            pass
        else:
            raise ValueError("created directory target is already occupied")
        metadata = staged.lstat()
        if not stat.S_ISDIR(metadata.st_mode) or any(staged.iterdir()):
            raise ValueError("staged created directory is not an empty real directory")
        rows = body.get("created_directories", [])
        if any(row["path"] == str(path) or row["staged"] == str(staged) for row in rows):
            raise ValueError("created directory is already registered")
        body["created_directories"] = [*rows, {
            "path": str(path), "staged": str(staged),
            "parent": _setup_switch_link_parent_identity(path),
            "dev": metadata.st_dev, "ino": metadata.st_ino,
            "mode": stat.S_IMODE(metadata.st_mode),
        }]
    except (KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
        raise LoadError(f"setup switch created directory registration is invalid: {exc}") from exc
    _fsync_parent_directory(staged)
    _fsync_parent_directory(staged.parent)
    payload = _setup_switch_canonical_payload({
        "body": body,
        "sha256": hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest(),
    }) + b"\n"
    if len(payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
        raise LoadError("setup switch journal exceeds the bounded size limit")
    descriptor, name = tempfile.mkstemp(prefix=".setup-switch-journal.", dir=journal.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if (any(getattr(before, key) != getattr(now, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns"))
                or _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT) != opened):
            raise LoadError("setup switch journal changed before directory registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return journal


def _setup_switch_created_directory_states(body):
    """Prevalidate every new shared inode and child before any recovery write."""
    try:
        rows = body.get("created_directories", [])
        if (not isinstance(rows, list)
                or len({row["path"] for row in rows}) != len(rows)
                or len({row["staged"] for row in rows}) != len(rows)):
            raise ValueError("duplicate or invalid directory rows")
        owned_children = {
            Path(row["path"]) for row in body["links"]
            if row["before"] is None and row["after"] is not None
        } | {Path(row["path"]) for row in rows}
        states = []
        for row in rows:
            path, staged = Path(row["path"]), Path(row["staged"])
            if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                    or not staged.is_absolute() or os.path.normpath(str(staged)) != str(staged)
                    or staged.parent != path.parent
                    or not staged.name.startswith(f".{path.name}.setup-")
                    or row["parent"] != _setup_switch_link_parent_identity(path)
                    or any(type(row[key]) is not int for key in ("dev", "ino", "mode"))):
                raise ValueError("created directory names or parent changed")
            path.parent.resolve(strict=True).relative_to(HTTP_ROOT.resolve(strict=True))
            present = []
            for candidate in (path, staged):
                try:
                    metadata = candidate.lstat()
                except FileNotFoundError:
                    continue
                if (not stat.S_ISDIR(metadata.st_mode)
                        or (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
                        != (row["dev"], row["ino"], row["mode"])):
                    raise ValueError("created directory inode or mode changed")
                children = set(candidate.iterdir())
                if (candidate == staged and children) or children - owned_children:
                    raise ValueError("created directory contains unregistered children")
                present.append(candidate)
            if len(present) > 1:
                raise ValueError("created directory has conflicting stage and target")
            states.append((path, staged, present[0] if present else None, row))
        return states
    except (KeyError, TypeError, ValueError, OSError, RuntimeError) as exc:
        raise LoadError(f"setup switch created directory state is unknown: {exc}") from exc


def register_setup_switch_materialized_directory(
    journal: Path, source: Path, target: Path, *,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Persist the exact backup name for a Q-local real latest before rename.

    Registration alone changes no publication path.  The writer must use the
    returned, initially absent backup name and must not invent another one.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    journal = Path(journal)
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    if recover_setup_switch_journal(
        journal, deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        verify_only=True,
    ) != "prepared-p":
        raise LoadError("setup switch materialized registration lacks exact P state")
    try:
        before_name = journal.lstat()
        opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
        if opened is None or opened[1] != 0o600:
            raise ValueError("journal is absent or not private")
        payload, _mode = opened
        envelope = json.loads(payload)
        body = envelope["body"]
        if (not isinstance(body, dict) or body["schema_version"] != 2
                or body["phase"] != "prepared"
                or hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest()
                != envelope["sha256"]):
            raise ValueError("journal envelope is invalid")
        new = body["new_project"]
        new_project = Path(new["path"])
        if new != _setup_switch_directory_identity(new_project):
            raise ValueError("Q project identity changed")
        source = Path(source)
        target = Path(target)
        if (not source.is_absolute() or not target.is_absolute()
                or os.path.normpath(str(source)) != str(source)
                or os.path.normpath(str(target)) != str(target)
                or source.name != "latest" or source.parent != target.parent
                or source == target):
            raise ValueError("materialized latest names are not canonical siblings")
        source.parent.resolve(strict=True).relative_to(new_project)
        parent = _setup_switch_link_parent_identity(source)
        source_info, target_info = source.lstat(), target.lstat()
        if (not stat.S_ISDIR(source_info.st_mode)
                or not stat.S_ISDIR(target_info.st_mode)
                or source_info.st_dev != target_info.st_dev):
            raise ValueError("materialized latest and release must be real same-device directories")
        marker = target / ".published-complete"
        marker_info = marker.lstat()
        if not stat.S_ISREG(marker_info.st_mode) or marker_info.st_nlink != 1:
            raise ValueError("materialized latest release marker is unsafe")
        existing = next(
            (row for row in body.get("directories", []) if row["path"] == str(source)),
            None,
        )
        if existing is not None:
            expected = {
                "path": str(source), "parent": parent, "target": str(target),
                "source_dev": source_info.st_dev, "source_ino": source_info.st_ino,
                "target_dev": target_info.st_dev, "target_ino": target_info.st_ino,
            }
            if any(existing.get(key) != value for key, value in expected.items()):
                raise ValueError("materialized latest journal row changed")
            backup = Path(existing["backup"])
            if (backup.parent != source.parent
                    or not backup.name.startswith(".latest.setup-switch-wal-")
                    or os.path.lexists(backup)):
                raise ValueError("materialized latest backup is not in prewrite state")
            return backup
        backup = source.with_name(f".latest.setup-switch-wal-{secrets.token_hex(16)}")
        if os.path.lexists(backup):
            raise ValueError("materialized latest backup name is occupied")
        row = {
            "path": str(source), "parent": parent, "backup": str(backup),
            "target": str(target), "source_dev": source_info.st_dev,
            "source_ino": source_info.st_ino, "target_dev": target_info.st_dev,
            "target_ino": target_info.st_ino,
        }
        next_body = dict(body)
        next_body["directories"] = [*body.get("directories", []), row]
        next_payload = _setup_switch_canonical_payload({
            "body": next_body,
            "sha256": hashlib.sha256(_setup_switch_canonical_payload(next_body)).hexdigest(),
        }) + b"\n"
        if len(next_payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
            raise ValueError("journal exceeds the bounded size limit")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, LoadError) as exc:
        raise LoadError(f"setup switch materialized registration is invalid: {exc}") from exc
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".setup-switch-journal.", dir=journal.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(next_payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if any(getattr(before_name, name) != getattr(now, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")):
            raise LoadError("setup switch journal changed before directory registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return backup


def register_setup_switch_infra_log_tree(
    journal: Path, source: Path, destination: Path, *,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Durably authorize one real infra/logs migration before its receipt/write.

    The REQ19 writer retains its own receipt and backup.  The cross-project
    journal additionally binds those names to P so a fresh LOAD can restore
    the original directory before restoring P links after a killed SETUP.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    journal = Path(journal)
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    if recover_setup_switch_journal(
        journal, deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        verify_only=True,
    ) != "prepared-p":
        raise LoadError("setup switch infra registration lacks exact P state")
    try:
        before_name = journal.lstat()
        opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
        if opened is None or opened[1] != 0o600:
            raise ValueError("journal is absent or not private")
        envelope = json.loads(opened[0])
        body = envelope["body"]
        if (not isinstance(body, dict) or body["schema_version"] != 2
                or body["phase"] != "prepared"
                or hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest()
                != envelope["sha256"]):
            raise ValueError("journal envelope is invalid")
        q_project = Path(body["new_project"]["path"])
        source, destination = Path(source), Path(destination)
        expected_source = HTTP_ROOT.resolve(strict=True) / "infra/logs"
        expected_destination = q_project / "99-output-infra"
        if (source != expected_source or destination != expected_destination
                or body["new_project"] != _setup_switch_directory_identity(q_project)
                or not stat.S_ISDIR(source.lstat().st_mode)
                or not stat.S_ISDIR(destination.lstat().st_mode)):
            raise ValueError("real infra log source or Q destination is not canonical")
        source_parent = _setup_switch_link_parent_identity(source)
        destination_parent = _setup_switch_link_parent_identity(destination)
        source_info, destination_info = source.lstat(), destination.lstat()
        if source_info.st_dev != destination_info.st_dev:
            raise ValueError("real infra logs cannot be hardlinked across devices")
        backup = destination / ".logs-migration-source"
        receipt = HTTP_ROOT.resolve(strict=True) / "infra/.logs-migration.json"
        if os.path.lexists(backup) or os.path.lexists(receipt):
            raise ValueError("real infra logs have a pending receipt or backup")
        for entry in destination.iterdir():
            if (entry.name != ".gitkeep"
                    or not stat.S_ISREG(entry.lstat().st_mode)):
                raise ValueError("Q infra log destination contains unowned content")
        rows = body.get("infra_logs", [])
        if not isinstance(rows, list) or rows:
            raise ValueError("real infra log migration is already registered")
        row = {
            "source": str(source), "source_parent": source_parent,
            "source_dev": source_info.st_dev, "source_ino": source_info.st_ino,
            "destination": str(destination),
            "destination_parent": destination_parent,
            "destination_dev": destination_info.st_dev,
            "destination_ino": destination_info.st_ino,
            "backup": str(backup), "receipt": str(receipt),
        }
        next_body = dict(body, infra_logs=[row])
        next_payload = _setup_switch_canonical_payload({
            "body": next_body,
            "sha256": hashlib.sha256(_setup_switch_canonical_payload(next_body)).hexdigest(),
        }) + b"\n"
        if len(next_payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
            raise ValueError("journal exceeds the bounded size limit")
    except (OSError, ValueError, TypeError, KeyError, RuntimeError, LoadError) as exc:
        raise LoadError(f"setup switch infra registration is invalid: {exc}") from exc
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".setup-switch-journal.", dir=journal.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(next_payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if any(getattr(before_name, name) != getattr(now, name) for name in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns")):
            raise LoadError("setup switch journal changed before infra registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return backup


def _setup_switch_rename_directory_noreplace(source: Path, target: Path) -> None:
    """Restore a WAL-bound directory without overwriting an intervening name."""
    libc = ctypes.CDLL(None, use_errno=True)
    if sys.platform == "darwin":
        rename = getattr(libc, "renamex_np", None)
        if rename is None:
            raise LoadError("atomic no-replace directory rename is unavailable")
        rename.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(os.fsencode(source), os.fsencode(target), 0x00000004)
    elif sys.platform.startswith("linux"):
        rename = getattr(libc, "renameat2", None)
        if rename is None:
            raise LoadError("atomic no-replace directory rename is unavailable")
        rename.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                           ctypes.c_char_p, ctypes.c_uint)
        rename.restype = ctypes.c_int
        result = rename(-100, os.fsencode(source), -100, os.fsencode(target), 1)
    else:
        raise LoadError("atomic no-replace directory rename is unavailable")
    if result != 0:
        error = ctypes.get_errno()
        raise LoadError(f"materialized directory restore failed: {os.strerror(error)}")



def _setup_switch_infra_file_signature(path: Path) -> tuple[os.stat_result, dict[str, object]]:
    """Read a receipt-bound hardlink without following its final name."""
    named_before = path.lstat()
    if not stat.S_ISREG(named_before.st_mode):
        raise ValueError("infra log entry is not a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                         | getattr(os, "O_NONBLOCK", 0))
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("infra log entry is not a regular file")
        digest = hashlib.sha256()
        while chunk := os.read(descriptor, 1024 * 1024):
            digest.update(chunk)
        after, named = os.fstat(descriptor), path.lstat()
        identity = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                    "st_mtime_ns", "st_ctime_ns")
        if any(getattr(before, key) != getattr(named_before, key)
               or getattr(before, key) != getattr(after, key)
               or getattr(before, key) != getattr(named, key) for key in identity):
            raise ValueError("infra log entry changed while reading")
        return before, {"size": before.st_size, "sha256": digest.hexdigest()}
    finally:
        os.close(descriptor)


def _setup_switch_infra_receipt_identity(receipt: Path):
    """Bind receipt ownership, including same-inode write-and-restore changes."""
    try:
        metadata = receipt.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise LoadError("infra log receipt changed: not a single-link regular file")
    return tuple(getattr(metadata, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    ))


def _setup_switch_require_infra_receipt(receipt: Path, authority) -> None:
    """Recheck the preflight receipt (or its absence) before every recovery write."""
    parent, identity, opened = authority
    try:
        if (parent != _setup_switch_link_parent_identity(receipt)
                or identity != _setup_switch_infra_receipt_identity(receipt)):
            raise ValueError("identity or parent differs from preflight")
        current = _read_rollback_regular(
            receipt, limit=_ROLLBACK_PAYLOAD_LIMIT, missing_ok=True,
        )
        if (current != opened
                or identity != _setup_switch_infra_receipt_identity(receipt)
                or parent != _setup_switch_link_parent_identity(receipt)):
            raise ValueError("bytes, metadata or parent differs from preflight")
    except (OSError, RuntimeError, ValueError, LoadError) as exc:
        raise LoadError(f"infra log receipt changed: {exc}") from exc


def _setup_switch_infra_file_owner(metadata):
    # Retiring our Q hardlinks changes nlink/ctime on the surviving P inode.
    # The reader still checks those fields within each individual read.
    return tuple(getattr(metadata, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns",
    ))


def _setup_switch_infra_source_owner_from_stat(metadata, raw_target):
    if metadata is None:
        return None
    return (tuple(getattr(metadata, key) for key in (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )), raw_target)


def _setup_switch_infra_source_owner(path: Path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    raw_target = os.readlink(path) if stat.S_ISLNK(metadata.st_mode) else None
    return _setup_switch_infra_source_owner_from_stat(metadata, raw_target)


def _setup_switch_infra_directory_owner(path: Path):
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        raise LoadError(f"infra log directory changed: {path}")
    return metadata.st_dev, metadata.st_ino, metadata.st_mode


def _setup_switch_require_infra_copies(state, *, names=None, directory_names=None):
    """Check frozen P inodes and Q cleanup owners without following aliases."""
    source, backup, destination, _receipt, entries, directories = state[:6]
    authority = state[9]
    try:
        if (authority["source_parent"] != _setup_switch_link_parent_identity(source)
                or authority["destination_parent"] != _setup_switch_link_parent_identity(destination)
                or authority["destination"] != _setup_switch_infra_directory_owner(destination)):
            raise ValueError("root or parent identity differs from preflight")
        if authority["source_name"] != _setup_switch_infra_source_owner(source):
            raise ValueError("source name owner differs from preflight")
        original_tree = backup if os.path.lexists(backup) else source
        if authority["source"] != _setup_switch_infra_directory_owner(original_tree):
            raise ValueError("original directory identity differs from preflight")
        checked_names = tuple(entries) if names is None else tuple(names)
        checked_directories = set(directories if directory_names is None else directory_names)
        for name in (*checked_names, *tuple(checked_directories)):
            parent = os.path.dirname(name)
            while parent:
                checked_directories.add(parent)
                parent = os.path.dirname(parent)
        for name in checked_directories:
            if (authority["source_directories"][name]
                    != _setup_switch_infra_directory_owner(original_tree / name)
                    or authority["copy_directories"][name]
                    != _setup_switch_infra_directory_owner(destination / name)):
                raise ValueError("nested directory owner differs from preflight")
        for name in checked_names:
            original_info, signature = _setup_switch_infra_file_signature(original_tree / name)
            if (authority["source_files"][name] != _setup_switch_infra_file_owner(original_info)
                    or signature != entries[name]):
                raise ValueError("original log owner or bytes differ from preflight")
            target = destination / name
            expected = authority["copies"][name]
            if expected is None:
                if os.path.lexists(target):
                    raise ValueError("an absent Q copy name gained a new owner")
            else:
                target_info, target_signature = _setup_switch_infra_file_signature(target)
                if (expected != _setup_switch_infra_file_owner(target_info)
                        or target_signature != entries[name]):
                    raise ValueError("Q hardlink owner or bytes differ from preflight")
    except (OSError, RuntimeError, ValueError, KeyError, LoadError) as exc:
        raise LoadError(f"infra log copy changed: {exc}") from exc


def _setup_switch_prepare_infra_log_recovery(row: dict[str, object], q_project: Path):
    """Validate the entire receipt-bound P directory and Q copy before writing."""
    if not isinstance(row, dict):
        raise LoadError("setup switch infra log row is not an object")
    try:
        source, destination = Path(row["source"]), Path(row["destination"])
        backup, receipt = Path(row["backup"]), Path(row["receipt"])
        if (source != HTTP_ROOT.resolve(strict=True) / "infra/logs"
                or destination != q_project / "99-output-infra"
                or backup != destination / ".logs-migration-source"
                or receipt != HTTP_ROOT.resolve(strict=True) / "infra/.logs-migration.json"
                or row["source_parent"] != _setup_switch_link_parent_identity(source)
                or row["destination_parent"]
                != _setup_switch_link_parent_identity(destination)):
            raise ValueError("infra log WAL paths or parents changed")
        destination_info = destination.lstat()
        if (not stat.S_ISDIR(destination_info.st_mode)
                or (destination_info.st_dev, destination_info.st_ino)
                != (row["destination_dev"], row["destination_ino"])):
            raise ValueError("infra log Q destination identity changed")
        has_backup = os.path.lexists(backup)
        source_info = None
        if has_backup:
            backup_info = backup.lstat()
            if (not stat.S_ISDIR(backup_info.st_mode)
                    or (backup_info.st_dev, backup_info.st_ino)
                    != (row["source_dev"], row["source_ino"])):
                raise ValueError("infra log backup identity changed")
            if os.path.lexists(source):
                source_info = source.lstat()
                if (not stat.S_ISLNK(source_info.st_mode)
                        or os.readlink(source)
                        != os.path.relpath(destination, source.parent)):
                    raise ValueError("infra log name is not its Q pointer")
            original_tree = backup
            original_tree_info = backup_info
        else:
            source_info = source.lstat()
            if (not stat.S_ISDIR(source_info.st_mode)
                    or (source_info.st_dev, source_info.st_ino)
                    != (row["source_dev"], row["source_ino"])):
                raise ValueError("infra log source identity changed")
            original_tree = source
            original_tree_info = source_info
        receipt_parent = _setup_switch_link_parent_identity(receipt)
        receipt_identity = _setup_switch_infra_receipt_identity(receipt)
        opened = _read_rollback_regular(
            receipt, limit=_ROLLBACK_PAYLOAD_LIMIT, missing_ok=True,
        )
        receipt_authority = receipt_parent, receipt_identity, opened
        if (opened is None) != (receipt_identity is None):
            raise ValueError("infra log receipt changed while opening")
        _setup_switch_require_infra_receipt(receipt, receipt_authority)
        if opened is None:
            if has_backup:
                raise ValueError("infra log backup lacks its durable receipt")
            entries, directories = {}, ()
        else:
            if opened[1] != 0o600:
                raise ValueError("infra log receipt is not private")
            document = json.loads(opened[0])
            if (not isinstance(document, dict)
                    or document.get("schema_version") != 1
                    or document.get("phase", "pending") != "pending"
                    or document.get("source") != {
                        "path": str(source), "dev": row["source_dev"],
                        "ino": row["source_ino"],
                    }
                    or document.get("destination") != {"path": str(destination)}
                    or not isinstance(document.get("entries"), dict)
                    or not isinstance(document.get("directories"), list)):
                raise ValueError("infra log receipt does not match the WAL")
            entries = document["entries"]
            directories = tuple(document["directories"])
            if len(set(directories)) != len(directories):
                raise ValueError("infra log receipt repeats a directory")
        def safe_relative(value):
            return (isinstance(value, str) and bool(value)
                    and not os.path.isabs(value)
                    and os.path.normpath(value) == value
                    and all(part not in ("", ".", "..") for part in value.split(os.sep)))
        if (any(not safe_relative(name) or name == ".gitkeep" for name in entries)
                or any(not safe_relative(name) for name in directories)
                or set(entries).intersection(directories)):
            raise ValueError("infra log receipt has unsafe paths")
        for name in (*tuple(entries), *directories):
            parent = os.path.dirname(name)
            while parent:
                if parent not in directories:
                    raise ValueError("infra log receipt omits a parent directory")
                parent = os.path.dirname(parent)
        if opened is not None:
            observed_files, observed_directories = set(), set()
            for current, subdirs, files in os.walk(original_tree, followlinks=False):
                for name in (*subdirs, *files):
                    path = Path(current) / name
                    relative = os.path.relpath(path, original_tree)
                    metadata = path.lstat()
                    if stat.S_ISDIR(metadata.st_mode):
                        observed_directories.add(relative)
                    elif stat.S_ISREG(metadata.st_mode):
                        observed_files.add(relative)
                    else:
                        raise ValueError("infra log source contains a special path")
            if observed_files != set(entries) or observed_directories != set(directories):
                raise ValueError("infra log source inventory changed after receipt")
        source_directories, copy_directories = {}, {}
        source_files, copies = {}, {}
        for name in directories:
            original_dir = original_tree / name
            if not stat.S_ISDIR(original_dir.lstat().st_mode):
                raise ValueError("infra log receipt source directory changed")
            target_dir = destination / name
            if os.path.lexists(target_dir) and not stat.S_ISDIR(target_dir.lstat().st_mode):
                raise ValueError("infra log Q directory changed")
            source_directories[name] = _setup_switch_infra_directory_owner(original_dir)
            copy_directories[name] = _setup_switch_infra_directory_owner(target_dir)
        for name, expected in entries.items():
            if (not isinstance(expected, dict)
                    or not isinstance(expected.get("size"), int)
                    or expected["size"] < 0
                    or not isinstance(expected.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", expected["sha256"])):
                raise ValueError("infra log receipt signature is invalid")
            original_info, signature = _setup_switch_infra_file_signature(
                original_tree / name,
            )
            if signature != expected:
                raise ValueError("infra log original content changed")
            source_files[name] = _setup_switch_infra_file_owner(original_info)
            copies[name] = None
            target = destination / name
            if os.path.lexists(target):
                target_info, target_signature = _setup_switch_infra_file_signature(target)
                if ((original_info.st_dev, original_info.st_ino)
                        != (target_info.st_dev, target_info.st_ino)
                        or target_signature != expected):
                    raise ValueError("infra log Q hardlink changed")
                copies[name] = _setup_switch_infra_file_owner(target_info)
            elif has_backup and os.path.islink(source):
                raise ValueError("published infra log pointer has a missing Q entry")
        allowed = set(entries) | set(directories) | {".gitkeep"}
        for current, subdirs, files in os.walk(destination, followlinks=False):
            for name in (*tuple(subdirs), *files):
                path = Path(current) / name
                if path == backup:
                    subdirs.remove(name)
                    continue
                relative = os.path.relpath(path, destination)
                if relative not in allowed:
                    raise ValueError("infra log Q destination has unowned content")
                metadata = path.lstat()
                if relative == ".gitkeep":
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValueError("infra log Q .gitkeep changed type")
                elif relative in directories:
                    if not stat.S_ISDIR(metadata.st_mode):
                        raise ValueError("infra log Q directory changed type")
                elif not stat.S_ISREG(metadata.st_mode):
                    raise ValueError("infra log Q file changed type")
        _setup_switch_require_infra_receipt(receipt, receipt_authority)
        tree_authority = {
            "source": (original_tree_info.st_dev, original_tree_info.st_ino,
                       original_tree_info.st_mode),
            "destination": (destination_info.st_dev, destination_info.st_ino,
                            destination_info.st_mode),
            "source_parent": row["source_parent"],
            "source_name": _setup_switch_infra_source_owner_from_stat(
                source_info, os.path.relpath(destination, source.parent)
                if source_info is not None and stat.S_ISLNK(source_info.st_mode) else None,
            ),
            "destination_parent": row["destination_parent"],
            "source_directories": source_directories,
            "copy_directories": copy_directories,
            "source_files": source_files, "copies": copies,
        }
        state = (source, backup, destination, receipt, entries, directories,
                 has_backup, opened is not None, receipt_authority, tree_authority)
        _setup_switch_require_infra_copies(state)
        return state
    except (OSError, RuntimeError, TypeError, ValueError, KeyError, LoadError) as exc:
        raise LoadError(f"setup switch infra log state is unknown: {exc}") from exc


def _setup_switch_restore_infra_log_tree(state) -> None:
    (source, backup, destination, receipt, entries, directories,
     has_backup, has_receipt, receipt_authority, tree_authority) = state
    _setup_switch_require_infra_receipt(receipt, receipt_authority)
    _setup_switch_require_infra_copies(state)
    if has_backup:
        if os.path.islink(source):
            _setup_switch_require_infra_receipt(receipt, receipt_authority)
            _setup_switch_require_infra_copies(state, names=(), directory_names=())
            source.unlink()
            tree_authority["source_name"] = None
            _fsync_parent_directory(source.parent)
        _setup_switch_require_infra_receipt(receipt, receipt_authority)
        _setup_switch_require_infra_copies(state, names=(), directory_names=())
        _setup_switch_rename_directory_noreplace(backup, source)
        restored = source.lstat()
        if (restored.st_dev, restored.st_ino, restored.st_mode) != tree_authority["source"]:
            raise LoadError("infra log restored source identity changed")
        tree_authority["source_name"] = _setup_switch_infra_source_owner_from_stat(restored, None)
        _fsync_parent_directory(source.parent)
        _fsync_parent_directory(backup.parent)
    for name in sorted(entries):
        path = destination / name
        if os.path.lexists(path):
            _setup_switch_require_infra_receipt(receipt, receipt_authority)
            _setup_switch_require_infra_copies(state, names=(name,), directory_names=())
            path.unlink()
            tree_authority["copies"][name] = None
            _fsync_parent_directory(path.parent)
    for name in sorted(directories, key=lambda value: (-value.count(os.sep), value)):
        path = destination / name
        if os.path.lexists(path):
            _setup_switch_require_infra_receipt(receipt, receipt_authority)
            _setup_switch_require_infra_copies(state, names=(), directory_names=(name,))
            path.rmdir()
            tree_authority["copy_directories"][name] = None
            _fsync_parent_directory(path.parent)
    if has_receipt:
        _setup_switch_require_infra_receipt(receipt, receipt_authority)
        _setup_switch_require_infra_copies(state)
        receipt.unlink()
        _fsync_parent_directory(receipt.parent)


def _setup_switch_q_manifest_paths(body, candidate: bytes) -> set[Path]:
    """Validate a detached Q manifest against WAL-authorized shared names."""
    try:
        if not isinstance(candidate, bytes) or len(candidate) > _SETUP_MANIFEST_LIMIT:
            raise ValueError("Q manifest bytes are invalid")
        lines = candidate.decode("utf-8").splitlines()
        prefix = "# setup manifest — proj: "
        if not lines or not lines[0].startswith(prefix) or not candidate.endswith(b"\n"):
            raise ValueError("Q manifest header is invalid")
        project = Path(lines[0][len(prefix):])
        if (not project.is_absolute() or os.path.normpath(str(project)) != str(project)
                or project.resolve(strict=True) != Path(body["new_project"]["path"])):
            raise ValueError("Q manifest project identity is invalid")
        paths = [Path(value) for value in lines[1:]]
        rows = {Path(row["path"]): row for row in body["links"]}
        infra_paths = {Path(row["source"]) for row in body.get("infra_logs", [])}
        if not paths or len(set(paths)) != len(paths):
            raise ValueError("Q manifest inventory is invalid")
        for path in paths:
            if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                    or (path not in infra_paths and
                        (path not in rows or rows[path]["after"] is None))):
                raise ValueError(f"Q manifest contains an unregistered name: {path}")
        return set(paths)
    except (KeyError, TypeError, ValueError, UnicodeError, OSError, RuntimeError) as exc:
        raise LoadError(f"setup switch Q manifest is invalid: {exc}") from exc


def register_setup_switch_manifest(
    journal: Path, candidate: bytes, *, deployment_lock_descriptor: int | None,
    services_quiesced: bool, runtime_backend: ServiceRuntimeBackend | None,
) -> Path:
    """Fsync the exact Q manifest intent before replacing the P authority.

    This authorizes recovery, not acceptance of B or service activation.
    """
    journal = Path(journal)
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
    )
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    before = journal.lstat()
    opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
    recover_setup_switch_journal(
        journal, deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        verify_only=True, manifest_candidate=candidate,
    )
    envelope = json.loads(opened[0])
    body = dict(envelope["body"])
    intent = {
        "bytes": base64.b64encode(candidate).decode("ascii"),
        "sha256": hashlib.sha256(candidate).hexdigest(), "mode": 0o644,
        "parent": _setup_switch_link_parent_identity(MANIFEST),
    }
    if "q_manifest_intent" in body and body["q_manifest_intent"] != intent:
        raise LoadError("setup switch Q manifest intent cannot be changed")
    body["q_manifest_intent"] = intent
    payload = _setup_switch_canonical_payload({
        "body": body,
        "sha256": hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest(),
    }) + b"\n"
    if len(payload) > _SETUP_SWITCH_JOURNAL_LIMIT:
        raise LoadError("setup switch journal exceeds the bounded size limit")
    descriptor, name = tempfile.mkstemp(prefix=".setup-switch-journal.", dir=journal.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        now = journal.lstat()
        if (any(getattr(before, key) != getattr(now, key) for key in (
                "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
                "st_mtime_ns", "st_ctime_ns"))
                or _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT) != opened):
            raise LoadError("setup switch journal changed before manifest registration")
        os.replace(temporary, journal)
        _fsync_parent_directory(journal.parent)
    finally:
        if os.path.lexists(temporary):
            temporary.unlink()
    return journal


def recover_setup_switch_journal(
    journal: Path, *, deployment_lock_descriptor: int | None,
    services_quiesced: bool, runtime_backend: ServiceRuntimeBackend | None,
    verify_only: bool = False, manifest_candidate: bytes | None = None,
    inspect_only: bool = False,
    expected_old_state: ActiveSetupState | None = None,
    expected_new_project: Path | None = None,
    retain_journal: bool = False,
    _after_p_restore: Callable[[], None] | None = None,
) -> str:
    """Verify or restore P from a complete WAL and a known P/Q disk state.

    The read-only prewrite mode accepts only an untouched P state.  It never
    interprets an in-flight P/Q mixture as permission to begin another setup.
    Automatic failed SETUP recovery retains the original journal for incident
    review; a separate explicit recovery uses the default finalization mode.
    """
    _require_runtime_restore_guard(
        deployment_lock_descriptor=deployment_lock_descriptor,
        services_quiesced=services_quiesced,
        runtime_backend=runtime_backend,
    )
    if (expected_old_state is None) != (expected_new_project is None):
        raise LoadError("setup switch WAL context requires both P state and Q project")
    if type(retain_journal) is not bool or (retain_journal and (verify_only or inspect_only)):
        raise LoadError("journal retention requires an unambiguous recovery mode")
    if _after_p_restore is not None and (
            not callable(_after_p_restore) or verify_only or inspect_only
            or manifest_candidate is not None or retain_journal):
        raise LoadError("post-P recovery phase requires a full guarded restore")
    if type(inspect_only) is not bool or (inspect_only and (verify_only or manifest_candidate is not None)):
        raise LoadError("journal inspection must be read-only and unambiguous")
    if manifest_candidate is not None and not verify_only:
        raise LoadError("manifest candidate verification is read-only")
    journal = Path(journal)
    if journal != _setup_switch_journal_path():
        raise LoadError("setup switch journal path is not the configured authority")
    # Keep the original inode alive for this recovery. A second owner may
    # replace the authority name, even with identical bytes; an unrelated
    # replacement is neither permission to restore P nor ours to retire.
    identity_fields = (
        "st_dev", "st_ino", "st_mode", "st_nlink", "st_size",
        "st_mtime_ns", "st_ctime_ns",
    )
    descriptor = -1
    try:
        parent_identity = _setup_switch_link_parent_identity(journal)
        try:
            before = journal.lstat()
        except OSError as exc:
            raise LoadError(f"setup switch journal cannot be inspected safely: {exc}") from exc
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_size < 0 or before.st_size > _SETUP_SWITCH_JOURNAL_LIMIT):
            raise LoadError("setup switch journal is not a bounded single-link file")
        flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                 | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            descriptor = os.open(journal, flags)
            held = os.fstat(descriptor)
        except OSError as exc:
            raise LoadError(f"setup switch journal cannot be held safely: {exc}") from exc
        if any(getattr(before, field) != getattr(held, field) for field in identity_fields):
            raise LoadError("setup switch journal changed while opening")
        opened = _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT)
        if opened is None or opened[1] != 0o600:
            raise LoadError("setup switch journal mode is not private")

        def require_journal_unchanged() -> None:
            try:
                named = journal.lstat()
                still_held = os.fstat(descriptor)
                if (parent_identity != _setup_switch_link_parent_identity(journal)
                        or any(getattr(held, field) != getattr(named, field)
                               or getattr(held, field) != getattr(still_held, field)
                               for field in identity_fields)
                        or _read_rollback_regular(journal, limit=_SETUP_SWITCH_JOURNAL_LIMIT) != opened):
                    raise LoadError("authority identity or bytes differ")
                after = journal.lstat()
                if any(getattr(held, field) != getattr(after, field) for field in identity_fields):
                    raise LoadError("authority changed during revalidation")
            except (OSError, RuntimeError, ValueError, LoadError) as exc:
                raise LoadError(f"setup switch journal changed during recovery: {exc}") from exc

        require_journal_unchanged()
        return _recover_setup_switch_journal_snapshot(
            journal, opened=opened, require_journal_unchanged=require_journal_unchanged,
            verify_only=verify_only, manifest_candidate=manifest_candidate,
            inspect_only=inspect_only, expected_old_state=expected_old_state,
            expected_new_project=expected_new_project, retain_journal=retain_journal,
            after_p_restore=_after_p_restore,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _recover_setup_switch_journal_snapshot(
    journal: Path, *, opened: tuple[bytes, int],
    require_journal_unchanged: Callable[[], None],
    verify_only: bool, manifest_candidate: bytes | None,
    inspect_only: bool, expected_old_state: ActiveSetupState | None,
    expected_new_project: Path | None, retain_journal: bool,
    after_p_restore: Callable[[], None] | None = None,
) -> str:
    """Recover only from the immutable authority held by the guarded API."""
    payload, _mode = opened
    try:
        envelope = json.loads(payload)
        body = envelope["body"]
        if (not isinstance(body, dict) or not isinstance(envelope["sha256"], str)
                or hashlib.sha256(_setup_switch_canonical_payload(body)).hexdigest()
                != envelope["sha256"] or body["schema_version"] != 2
                or body["phase"] != "prepared"):
            raise ValueError("journal envelope is invalid")
        if not isinstance(body.get("allow_late_q_values", False), bool):
            raise ValueError("journal late Q registration policy is invalid")
        old = body["old_project"]
        new = body["new_project"]
        if (body["root"] != _setup_switch_directory_identity(HTTP_ROOT)
                or old != _setup_switch_directory_identity(Path(old["path"]))
                or new != _setup_switch_directory_identity(Path(new["path"]))
                or old == new):
            raise ValueError("journal directory identity changed")
        manifest_bytes = base64.b64decode(body["manifest"], validate=True)
        if hashlib.sha256(manifest_bytes).hexdigest() != body["manifest_sha256"]:
            raise ValueError("journal P manifest digest is invalid")
        state = _validate_setup_state_receipt(ActiveSetupState(
            project=Path(old["path"]), manifest=manifest_bytes,
            manifest_mode=body["manifest_mode"],
            links={Path(row["path"]): row["before"] for row in body["links"]
                   if row["before"] is not None},
        ))
        if expected_old_state is not None:
            expected = _validate_setup_state_receipt(expected_old_state)
            if (state != expected
                    or Path(new["path"]) != expected_new_project.resolve(strict=True)):
                raise LoadError("setup switch WAL differs from the parent rollback context")
        rows = body["links"]
        if (not isinstance(rows, list) or not rows
                or len({row["path"] for row in rows}) != len(rows)
                or set(state.links) != {Path(row["path"]) for row in rows
                                         if row["before"] is not None}):
            raise ValueError("journal link inventory is invalid")
    except (KeyError, TypeError, ValueError, UnicodeError, binascii.Error, LoadError) as exc:
        raise LoadError(f"setup switch journal is invalid: {exc}") from exc
    require_wal_unchanged = require_journal_unchanged

    def require_journal_unchanged():
        require_wal_unchanged()
        _require_setup_switch_q_parent_preimage(body)

    # A pending SETUP WAL is not authorization to roll P back after Q's
    # parent commit. Recheck this at every recovery mutation and retirement.
    require_journal_unchanged()
    current_manifest = _read_rollback_regular(MANIFEST, limit=_SETUP_MANIFEST_LIMIT)
    q_manifest = None
    if "q_manifest_intent" in body:
        try:
            intent = body["q_manifest_intent"]
            q_bytes = base64.b64decode(intent["bytes"], validate=True)
            if (hashlib.sha256(q_bytes).hexdigest() != intent["sha256"]
                    or intent["mode"] != 0o644
                    or intent["parent"] != _setup_switch_link_parent_identity(MANIFEST)):
                raise ValueError("Q manifest digest, mode or parent changed")
            _setup_switch_q_manifest_paths(body, q_bytes)
            q_manifest = (q_bytes, intent["mode"])
        except (KeyError, TypeError, ValueError, binascii.Error) as exc:
            raise LoadError(f"setup switch Q manifest intent is invalid: {exc}") from exc
    if (current_manifest != (state.manifest, state.manifest_mode)
            and (verify_only or q_manifest is None or current_manifest != q_manifest)):
        # Q manifest may have replaced P while the final journal phase was not
        # durable.  This is in-doubt, not proof that either project committed.
        raise LoadError("setup switch manifest is not exact P; recovery is in-doubt")
    root_path = Path(body["root"]["path"])
    q_project = Path(new["path"])
    q_local_states = _setup_switch_q_local_link_states(body)
    # A previous recovery may have removed an owned Q-only directory and died
    # before retiring the journal. Its child link rows remain valid absence
    # evidence only when the exact created-directory row and surviving outer
    # parent have already passed the full read-only preflight.
    created_directory_states = _setup_switch_created_directory_states(body)
    removed_created_parents = {
        path: directory_row
        for path, _staged, present, directory_row in created_directory_states
        if present is None
    }
    expected_rows = []
    for row in rows:
        try:
            path = Path(row["path"])
            before = row["before"]
            after = row["after"]
            if (not path.is_absolute() or os.path.normpath(str(path)) != str(path)
                    or before != state.links.get(path)
                    or (before is None and after is None)
                    or (after is not None and
                        (not isinstance(after, str) or not after
                         or os.path.isabs(after) or os.path.normpath(after) != after))):
                raise ValueError("invalid path or link value")
            removed_parent = removed_created_parents.get(path.parent)
            if removed_parent is not None:
                expected_parent = {
                    "path": str(Path(removed_parent["parent"]["path"]) / path.parent.name),
                    "dev": removed_parent["dev"], "ino": removed_parent["ino"],
                }
                if before is not None or row["parent"] != expected_parent:
                    raise ValueError("absent created directory is not the frozen Q-only parent")
                try:
                    path.lstat()
                except FileNotFoundError:
                    pass
                else:
                    raise ValueError("removed created directory child is not absent")
            else:
                path.parent.resolve(strict=True).relative_to(root_path)
                if row["parent"] != _setup_switch_link_parent_identity(path):
                    raise ValueError("journal link parent identity changed")
            if after is not None:
                _setup_switch_recovery_q_target(
                    Path(os.path.normpath(str(path.parent / after))), q_project, rows,
                )
            if os.path.lexists(path):
                metadata = path.lstat()
                if (not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1
                        or os.readlink(path) not in (before, after)):
                    raise ValueError("current link is not an approved P/Q value")
            expected_rows.append((path, before, after))
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            raise LoadError(f"setup switch disk state is unknown: {path}: {exc}") from exc
    expected_directories = []
    directory_rows = body.get("directories", [])
    if (not isinstance(directory_rows, list)
            or len({row.get("path") for row in directory_rows}) != len(directory_rows)):
        raise LoadError("setup switch materialized directory inventory is invalid")
    for row in directory_rows:
        try:
            source = Path(row["path"])
            backup = Path(row["backup"])
            target = Path(row["target"])
            if (not source.is_absolute() or os.path.normpath(str(source)) != str(source)
                    or source.name != "latest" or backup.parent != source.parent
                    or not backup.name.startswith(".latest.setup-switch-wal-")
                    or target.parent != source.parent or target == source
                    or row["parent"] != _setup_switch_link_parent_identity(source)):
                raise ValueError("directory row names or parent are invalid")
            source.parent.resolve(strict=True).relative_to(q_project)
            target_info = target.lstat()
            if (not stat.S_ISDIR(target_info.st_mode)
                    or (target_info.st_dev, target_info.st_ino)
                    != (row["target_dev"], row["target_ino"])):
                raise ValueError("materialized release identity changed")
            has_backup = os.path.lexists(backup)
            if has_backup:
                backup_info = backup.lstat()
                if (not stat.S_ISDIR(backup_info.st_mode)
                        or (backup_info.st_dev, backup_info.st_ino)
                        != (row["source_dev"], row["source_ino"])):
                    raise ValueError("materialized backup identity changed")
                if os.path.lexists(source):
                    source_info = source.lstat()
                    if (not stat.S_ISLNK(source_info.st_mode)
                            or os.readlink(source)
                            != os.path.relpath(target, source.parent)):
                        raise ValueError("materialized name is not its expected Q link")
            else:
                source_info = source.lstat()
                if (not stat.S_ISDIR(source_info.st_mode)
                        or (source_info.st_dev, source_info.st_ino)
                        != (row["source_dev"], row["source_ino"])):
                    raise ValueError("materialized source identity changed")
            expected_directories.append((source, backup, has_backup))
        except (OSError, RuntimeError, TypeError, ValueError, KeyError) as exc:
            raise LoadError(f"setup switch materialized state is unknown: {exc}") from exc
    infra_rows = body.get("infra_logs", [])
    if not isinstance(infra_rows, list) or len(infra_rows) > 1:
        raise LoadError("setup switch infra log inventory is invalid")
    infra_state = (
        _setup_switch_prepare_infra_log_recovery(infra_rows[0], q_project)
        if infra_rows else None
    )
    if inspect_only:
        require_journal_unchanged()
        return "prepared-known-disk-state"
    if verify_only:
        if manifest_candidate is not None:
            if any(os.readlink(path) != row["after"] for path, row in q_local_states):
                raise LoadError("setup switch Q-local latest precommit is not exact Q")
            if any(present != path for path, _staged, present, _row in created_directory_states):
                raise LoadError("setup switch Q manifest lacks an installed created directory")
            candidate_paths = _setup_switch_q_manifest_paths(body, manifest_candidate)
            for path, _before, after in expected_rows:
                if path in candidate_paths or os.path.lexists(path):
                    if after is None or not path.is_symlink() or os.readlink(path) != after:
                        raise LoadError("setup switch manifest prewrite state is not exact Q")
            if any(not path.is_symlink() for path in candidate_paths):
                raise LoadError("setup switch Q manifest name is absent")
            require_journal_unchanged()
            return "prepared-q-manifest"
        if any(os.readlink(path) != row["before"] for path, row in q_local_states):
            raise LoadError("setup switch Q-local latest prewrite is not exact Q preimage")
        if any(
            (not path.is_symlink() or os.readlink(path) != before)
            if before is not None else os.path.lexists(path)
            for path, before, _after in expected_rows
        ):
            raise LoadError("setup switch prewrite state is not exact P")
        if any(has_backup for _source, _backup, has_backup in expected_directories):
            raise LoadError("setup switch materialized prewrite state is not exact Q")
        if infra_state is not None and (infra_state[6] or infra_state[7]):
            raise LoadError("setup switch infra log prewrite state is not exact Q")
        if any(present is not None for _path, _staged, present, _row in created_directory_states):
            raise LoadError("setup switch created directory prewrite state is not exact P")
        require_journal_unchanged()
        return "prepared-p"
    require_journal_unchanged()
    if infra_state is not None:
        _setup_switch_restore_infra_log_tree(infra_state)
    for path, row in q_local_states:
        require_journal_unchanged()
        _setup_switch_q_local_link_states(body)
        if os.readlink(path) != row["before"]:
            _atomic_restore_setup_link(path, row["before"])
    for source, backup, has_backup in expected_directories:
        require_journal_unchanged()
        if has_backup:
            if os.path.islink(source):
                source.unlink()
                _fsync_parent_directory(source.parent)
            _setup_switch_rename_directory_noreplace(backup, source)
            _fsync_parent_directory(source.parent)
    for path, before, after in expected_rows:
        require_journal_unchanged()
        if before is not None:
            if not (path.is_symlink() and os.readlink(path) == before):
                _atomic_restore_setup_link(path, before)
        elif os.path.lexists(path):
            if not path.is_symlink() or os.readlink(path) != after:
                raise LoadError(f"setup switch Q-only link changed during recovery: {path}")
            path.unlink()
            _fsync_parent_directory(path.parent)
    for _path, _staged, present, row in sorted(
            created_directory_states, key=lambda state: len(state[0].parts), reverse=True):
        require_journal_unchanged()
        if present is not None:
            metadata = present.lstat()
            if (not stat.S_ISDIR(metadata.st_mode)
                    or (metadata.st_dev, metadata.st_ino, stat.S_IMODE(metadata.st_mode))
                    != (row["dev"], row["ino"], row["mode"])):
                raise LoadError("setup switch created directory changed during recovery")
            present.rmdir()
            _fsync_parent_directory(present.parent)
    if current_manifest != (state.manifest, state.manifest_mode):
        require_journal_unchanged()
        _atomic_restore_setup_manifest(state)
    verified = snapshot_active_setup_state(expected_project=state.project)
    if verified.manifest != state.manifest or verified.links != state.links:
        raise LoadError("setup switch P post-verify failed; journal retained")
    if any(os.readlink(path) != row["before"]
           for path, row in _setup_switch_q_local_link_states(body)):
        raise LoadError("setup switch Q-local latest post-verify failed; journal retained")
    require_journal_unchanged()
    if after_p_restore is not None:
        # Keep the original WAL descriptor, bytes and owner through A's runtime
        # restore and postverification. Exception or death must not erase the
        # only persistent P/Q recovery authority just because links are back.
        after_p_restore()
        require_journal_unchanged()
        if _recover_setup_switch_journal_snapshot(
                journal, opened=opened,
                require_journal_unchanged=require_wal_unchanged,
                verify_only=True, manifest_candidate=None, inspect_only=False,
                expected_old_state=expected_old_state,
                expected_new_project=expected_new_project, retain_journal=False,
        ) != "prepared-p":
            raise LoadError("post-runtime P recovery state is not exact; journal retained")
        require_journal_unchanged()
    # A failed SETUP must not erase its durable authorization/incident
    # evidence merely because P is recoverable. Explicit recovery keeps the
    # default finalization behavior; automatic child failure recovery does not.
    if not retain_journal:
        journal.unlink()
        _fsync_parent_directory(journal.parent)
    return "restored-p"


def restore_cross_project_rollback_context(
    context: CrossProjectRollbackContext, *, current_project: Path,
    deployment_lock_descriptor: int | None,
    services_quiesced: bool,
    runtime_backend: ServiceRuntimeBackend | None,
) -> None:
    """Restore all WAL-owned P/Q mutations first, then P's A runtime receipt.

    The detached P link snapshot cannot describe a half-written Q manifest,
    newly created shared directories, or retained real-directory backups.
    A pending WAL is held until both P and A runtime postverification finish;
    it must not be consumed before the later runtime phase can still fail.
    The older link-only restore cannot bypass it. This never activates services.
    """
    journal = _setup_switch_journal_path()
    def restore_runtime_phase() -> None:
        restore_runtime_rollback_receipt(
            context.project, context.runtime_receipt,
            expected_current=context.selector_target,
            deployment_lock_descriptor=deployment_lock_descriptor,
            services_quiesced=services_quiesced,
            runtime_backend=runtime_backend,
        )
        _require_runtime_restore_guard(
            deployment_lock_descriptor=deployment_lock_descriptor,
            services_quiesced=services_quiesced, runtime_backend=runtime_backend,
        )

    if os.path.lexists(journal):
        if context.project.resolve(strict=True) != context.setup_state.project.resolve(strict=True):
            raise LoadError("setup switch WAL context has inconsistent P projects")
        recover_setup_switch_journal(
            journal, deployment_lock_descriptor=deployment_lock_descriptor,
            services_quiesced=services_quiesced, runtime_backend=runtime_backend,
            expected_old_state=context.setup_state, expected_new_project=current_project,
            _after_p_restore=restore_runtime_phase,
        )
        return
    else:
        restore_active_setup_state(
            context.setup_state,
            current_project=current_project,
            deployment_lock_descriptor=deployment_lock_descriptor,
            services_quiesced=services_quiesced,
            runtime_backend=runtime_backend,
        )
    restore_runtime_phase()


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
    for name, record in frozen.items():
        _restore_receipt_file(
            ZTP_DIR / name, record, payload_groups["files"][name],
        )
    for extra in set(path.name for path in publickey_dir.glob("*.pub")) - set(key_records):
        path = publickey_dir / extra
        if path.is_dir() and not path.is_symlink():
            raise LoadError("rollback publickey target became a directory")
        path.unlink()
    for name, record in key_records.items():
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
    selected = manifest.get("switch_scope")
    if selected not in {"eth", "ib", "nvl"}:
        raise LoadError("零字节 DHCP host 仅允许在单一 switch scope 下保留")
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
    for source in empty_hosts:
        family = source.name.removeprefix("dhcpd_").removesuffix(".hosts")
        if family == selected or declarations[family] != 0:
            raise LoadError(
                f"DHCP 输出 {source.name} 大小为 0，但本轮拥有该 family "
                "或 manifest 声明了 host；请准备真实内容后再次执行 load"
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
    reported command failure is never permission to delete the only backups.
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
    restore_incomplete = False
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
            restore_incomplete = False
            raise
    finally:
        if build_workspace is not None:
            build_workspace.cleanup()
        if transaction_created and (restore_incomplete or (
                parent_candidate is not None and parent_candidate.committed
                and not parent_candidate.directory_synced)):
            # Neither a partial A restore nor uncertain visible B may erase
            # the original backup. Retention alone is not proof of complete
            # rollback, healthy activation or survival across a power failure.
            try:
                warn(
                    ("HOLD：DHCP 旧文件恢复未完成；" if restore_incomplete
                     else "HOLD：B 已可见但目录持久化未确认；")
                    + f"保留 DHCP 事务及 root-only A 备份：{transaction_dir}；"
                    "服务保持停止，须人工核验实际 A/B 状态，不自动回退或清理"
                )
            except BrokenPipeError:
                pass
        elif transaction_created:
            cleanup_failed = False
            for directory in (staged_dir, backup_dir):
                for name in mappings:
                    result = _run_subprocess(
                        sudo_command("rm", "-f", "--", str(directory / name.name)),
                        check=False,
                    )
                    cleanup_failed = cleanup_failed or result.returncode != 0
            for directory in (backup_dir, staged_dir, transaction_dir):
                result = _run_subprocess(
                    sudo_command("rmdir", "--", str(directory)), check=False,
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
        for source in dhcp_file_mappings(dhcp_source):
            item = output_hashes.get(source.name)
            expected_hash = item.get("sha256") if isinstance(item, dict) else None
            if expected_hash != _sha256_path(source):
                raise LoadError(f"DHCP release 输出 hash 漂移：{source.name}")
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
    parent = {
        "schema_version": 2,
        "release_id": release_id,
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "validation": "passed",
        **release_basis,
        # Transaction metadata, not a change to the established release-ID basis.
        # Preserve the selected alias itself so retargeting is rechecked too.
        "input_paths": {
            name: (path.parent.resolve() / path.name).relative_to(project.resolve()).as_posix()
            for name, path in input_files.items()
        },
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
            source.resolve(strict=True).relative_to(project.resolve())
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
        path.unlink(missing_ok=True)


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
                [sys.executable, "d-hostname2mac.py", "-y", *scope_args,
                 *switch_args, *effective_options,
                 str(publish)],
                cwd=ZTP_DIR / "config/cumulus",
            )

    if deployment_scope != "air" and device_types & {"ib", "nvl"}:
        template_dir = ZTP_DIR / "config/nvos/template"
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "ib", "-y",
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
                [sys.executable, "d-hostname2mac.py", "-y", *scope_args,
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
    """Atomically publish exact Native listeners and roll back failed syntax."""
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
    http_available = bool(
        plan.endpoint_ips
        or (inputs.settings.http_enabled and inputs.settings.http_address)
    )
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
    for url in urls:
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
                    "sudo ./infra/infra-setup.sh --recover-monitor-authority"
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
    inputs: ProjectInputs, images: dict[str, Path], dry_run: bool = False, *,
    dhcp_runtime_plan: DhcpRuntimePlan | None = None,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    backend = runtime_backend or service_runtime_backend()
    if backend.name == "supervisor":
        plan = dhcp_runtime_plan or plan_local_dhcp_runtime(inputs)
        http_required, dhcp_required = supervisor_service_availability(
            inputs, plan, dry_run,
        )
        if http_required:
            verify_control_auth(runtime_backend=backend, dry_run=dry_run)
            verify_published_files(inputs, images, dry_run=dry_run)
            verify_apache_publication_boundary(dry_run=dry_run)
            run(sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
        if dhcp_required:
            validate_dhcp_output_sources(dhcp_file_mappings())
            run(
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
    if not inputs.settings.ztp_enabled:
        info("global 中 ZTP status=disabled，不启动服务")
        return
    if not validate_management_host(inputs.settings, dry_run):
        raise LoadError("本机服务启动条件不满足")
    verify_control_auth(runtime_backend=backend, dry_run=dry_run)
    verify_published_files(inputs, images, dry_run=dry_run)
    verify_apache_publication_boundary(dry_run=dry_run)
    if inputs.settings.dhcp_enabled:
        validate_dhcp_output_sources(dhcp_file_mappings())
        run(
            sudo_command("dhcpd", "-t", "-cf", "/etc/dhcp/dhcpd.conf"),
            dry_run=dry_run,
        )
    run(sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
    ok(
        "启动前检查通过：公钥、Apache 配置和 HTTP 发布文件均有效"
        + ("；DHCP 配置有效" if inputs.settings.dhcp_enabled else "；DHCP 已禁用")
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
    states: dict[str, ServiceRuntimeState] = {}
    for service in services:
        active = _run_subprocess(
            [systemctl, "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        enabled = _run_subprocess(
            [systemctl, "is-enabled", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode == 0
        states[service] = ServiceRuntimeState(enabled=enabled, active=active)
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
    ensure_ztp_url_network_ready(inputs, dry_run=dry_run)
    if not inputs.settings.dhcp_enabled:
        if not inputs.settings.http_enabled:
            raise LoadError("DHCP 与 HTTP 均已禁用，没有可启动的原生服务")
        if dry_run:
            run(sudo_command("systemctl", "enable", "--now", "apache2"), dry_run=True)
            info("dry-run：DHCP 已禁用，保持 isc-dhcp-server 停止")
            verify_http_publication(inputs, images, True)
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
    placeholder_sections = find_placeholder_password_sections(
        global_data, switch_scope=switch_scope,
    )
    if placeholder_sections:
        raise _placeholder_password_error(
            project, placeholder_sections, host_role=host_role,
        )
    validation_errors = []
    device_types: frozenset[str] = frozenset()
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
        validate_subnet_file(subnet_file, settings)
    except LoadError as exc:
        validation_errors.append(str(exc))
    # P2P selection may migrate a legacy workbook.  An invalid subnet must
    # stop before that or any later image/receipt preparation is attempted.
    if validation_errors:
        raise LoadError("项目输入检查失败：\n  - " + "\n  - ".join(validation_errors))
    try:
        device_types = load_device_types(
            devices_file, settings.schema_version, switch_scope=switch_scope,
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
    parser.add_argument("--p2p-file", help="明确选择项目根目录或 p2p/ 下的非空普通 XLSX（name.xlsx 或 p2p/name.xlsx）")
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
    cross_project_rollback: CrossProjectRollbackContext | None = None
    deployment_lock_descriptor: int | None = None
    parent_candidate: PreparedParentRelease | None = None
    report_candidate = None
    prefix_publication_snapshot: ZtpPrefixPublicationSnapshot | None = None
    dhcp_runtime_plan: DhcpRuntimePlan | None = None
    runtime_backend_instance: ServiceRuntimeBackend | None = None
    active_before: Path | None = None
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
            failure_phase = "未结清 setup WAL 前置闸门"
            require_no_pending_setup_switch_journal()
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
            active_before = active_project() if local_services_supported else None
            if (active_before is not None
                    and active_before.resolve(strict=True) != project.resolve(strict=True)):
                (
                    previous_selector_target,
                    cross_project_rollback,
                ) = prepare_cross_project_rollback_context(project)
            else:
                previous_selector_target = ensure_previous_generation_frozen(project)
            if (local_services_supported and previous_selector_target
                    and cross_project_rollback is None):
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
            quiesce_services(
                args.dry_run,
                dhcp_runtime_plan=dhcp_runtime_plan,
                runtime_backend=runtime_backend_instance,
                native_monitor_already_quiesced=native_monitor_quiesced,
                host_role=host_role,
            )
            runtime_restore_safe = True
        elif local_services_supported:
            require_artifact_builder_services_inactive(
                args.dry_run, runtime_backend=runtime_backend_instance,
                host_role=host_role,
            )
            runtime_restore_safe = True
        failure_phase = "活动项目 setup 检查/切换"
        # setup is the first post-quiesce operation allowed to rewrite managed
        # links.  Mark before entry because a child failure may be partial.
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
            prepare_switch_wal=(
                local_services_supported and not args.dry_run
                and active_before is not None and active_before != project
            ),
            runtime_backend=runtime_backend_instance,
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
            prepare_infra(
                inputs,
                args.dry_run,
                skip_doca=args.skip_doca,
                download_doca=args.download_doca,
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
            )
            should_start = args.start_services or (
                not args.dry_run and confirm_service_start()
            )
            if should_start:
                start_services(
                    inputs, images, args.dry_run,
                    dhcp_runtime_plan=dhcp_runtime_plan,
                    runtime_backend=runtime_backend_instance,
                )
            else:
                info("Apache/DHCP 未启动。确认输出后可重新执行并加 --start-services。")

        if local_services_supported:
            section("ZTP 状态后台监控")
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
                )
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
        if (cross_project_rollback is not None and not release_committed
                and runtime_mutation_started):
            try:
                restore_cross_project_rollback_context(
                    cross_project_rollback,
                    current_project=project,
                    deployment_lock_descriptor=deployment_lock_descriptor,
                    services_quiesced=runtime_restore_safe,
                    runtime_backend=runtime_backend_instance,
                )
            except (LoadError, OSError, ValueError) as rollback_exc:
                cleanup_errors.append(f"active project runtime rollback failed: {rollback_exc}")
        elif (runtime_rollback_receipt is not None and not release_committed
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
                shutil.rmtree(dhcp_candidate_dir)
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
            configure_local_pre_push_proof_gate()
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
