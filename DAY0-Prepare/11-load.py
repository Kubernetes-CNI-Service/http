#!/usr/bin/env python3
"""Validate, activate and prepare one DAY0 deployment project end to end.

The script deliberately separates reversible preparation from the final service
start. Apache and DHCP start with ``--start-services`` or unless the operator
declines the default-yes service prompt. A second default-yes bounded prompt
starts the detached ZTP status monitor after the load flow succeeds.
"""

from __future__ import annotations

import argparse
import base64
import csv
from dataclasses import dataclass, replace
from datetime import datetime
import getpass
import hashlib
import hmac
import importlib.util
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
    deployment_lock,
    inherited_lock_subprocess_kwargs,
    release_lock_descriptor,
)
from ztp_service_runtime import (
    DhcpRuntimePlan,
    RuntimeContractError,
    ServiceRuntimeBackend,
    monitor_pid_lock,
    plan_dhcp_runtime,
    runtime_backend_from_environment,
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
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
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
    air_topology_policy: Path | None = None
    mini_devices_file: Path | None = None
    mini_source_file: Path | None = None
    deployment_scope: str = "all"
    switch_scope: str = "all"
    source_identities: dict[str, str] | None = None


def section(title: str) -> None:
    print(f"\n── {title} " + "─" * max(2, 58 - len(title)))


def ok(message: str) -> None:
    print(f"[OK] {message}")


def info(message: str) -> None:
    print(f"[INFO] {message}")


def warn(message: str) -> None:
    print(f"[WARN] {message}")


def _run_local_test_runner(arguments: list[str], label: str) -> None:
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
    if completed.returncode != 0:
        raise LoadError(f"{label}失败（exit={completed.returncode}）")


def run_local_full_test_gate() -> None:
    """Run the canonical full suite and issue an exact local attestation."""
    _run_local_test_runner(["--all"], "本机正式 load 前全量测试")
    verify_local_full_test_attestation()


def verify_local_full_test_attestation() -> None:
    """Require the exact full-suite attestation without running tests."""
    _run_local_test_runner(
        ["--check", "--require-full"], "本机 load 全量测试证明复核",
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
) -> None:
    display = " ".join(shlex_quote(item) for item in command)
    if dry_run:
        print(f"[DRY] ({cwd or Path.cwd()}) {display}")
        return
    print(f"[RUN] ({cwd or Path.cwd()}) {display}")
    result = _run_subprocess(
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
                selected_kind = (
                    selected_scope == "all"
                    or kind in SWITCH_SCOPE_TYPES[selected_scope]
                )
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
    if not payload or len(payload) > MANAGEMENT_KEY_MAX_BYTES:
        raise LoadError(f"{label} 为空或过大")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n") or b"\r" in payload:
        raise LoadError(f"{label} 必须是单行 canonical Ed25519 public key")
    line = payload[:-1]
    if b"\n" in line or any(byte < 0x20 or byte > 0x7e for byte in line):
        raise LoadError(f"{label} 必须是单行 canonical Ed25519 public key")
    fields = line.split(b" ", 2)
    if len(fields) < 2 or fields[0] != b"ssh-ed25519" or not fields[1]:
        raise LoadError(f"{label} 必须是 ssh-ed25519 public key")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise LoadError(f"{label} base64 格式无效") from exc
    expected_prefix = len(b"ssh-ed25519").to_bytes(4, "big") + b"ssh-ed25519"
    if (
        not blob.startswith(expected_prefix)
        or len(blob) != len(expected_prefix) + 4 + 32
        or int.from_bytes(blob[len(expected_prefix):len(expected_prefix) + 4], "big") != 32
    ):
        raise LoadError(f"{label} Ed25519 blob 结构无效")
    return b"ssh-ed25519", fields[1]


def _parse_held_project_public_identity(
    payload: bytes, label: str,
) -> tuple[bytes, bytes]:
    if not payload or len(payload) > MANAGEMENT_KEY_MAX_BYTES:
        raise LoadError(f"{label} 为空或过大")
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n") or b"\r" in payload:
        raise LoadError(f"{label} 必须是单行 canonical SSH public key")
    line = payload[:-1]
    if b"\n" in line or any(byte < 0x20 or byte > 0x7e for byte in line):
        raise LoadError(f"{label} 含有不安全控制字符")
    fields = line.split(b" ", 2)
    if len(fields) < 2 or not re.fullmatch(
        rb"(?:ssh-(?:ed25519|rsa)|ecdsa-sha2-nistp(?:256|384|521)|"
        rb"sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)",
        fields[0],
    ):
        raise LoadError(f"{label} SSH public key type 无效")
    try:
        blob = base64.b64decode(fields[1], validate=True)
    except (ValueError, TypeError) as exc:
        raise LoadError(f"{label} base64 格式无效") from exc
    offset = 0

    def ssh_string() -> bytes:
        nonlocal offset
        if offset + 4 > len(blob):
            raise LoadError(f"{label} SSH public key blob truncated")
        size = int.from_bytes(blob[offset:offset + 4], "big")
        offset += 4
        if size <= 0 or offset + size > len(blob):
            raise LoadError(f"{label} SSH public key blob field 无效")
        value = blob[offset:offset + size]
        offset += size
        return value

    if ssh_string() != fields[0]:
        raise LoadError(f"{label} textual type 与 SSH blob type 不匹配")
    if fields[0] == b"ssh-ed25519":
        if len(ssh_string()) != 32:
            raise LoadError(f"{label} Ed25519 key length 无效")
    elif fields[0] == b"ssh-rsa":
        exponent = ssh_string()
        modulus = ssh_string()
        if not exponent or not modulus:
            raise LoadError(f"{label} RSA key fields 无效")
    elif fields[0].startswith(b"ecdsa-sha2-"):
        curve = ssh_string()
        point = ssh_string()
        if fields[0] != b"ecdsa-sha2-" + curve or not point:
            raise LoadError(f"{label} ECDSA key fields 无效")
    elif fields[0] == b"sk-ssh-ed25519@openssh.com":
        if len(ssh_string()) != 32 or not ssh_string():
            raise LoadError(f"{label} security-key fields 无效")
    elif fields[0] == b"sk-ecdsa-sha2-nistp256@openssh.com":
        if ssh_string() != b"nistp256" or not ssh_string() or not ssh_string():
            raise LoadError(f"{label} security-key fields 无效")
    if offset != len(blob):
        raise LoadError(f"{label} SSH public key blob 含 trailing data")
    return fields[0], fields[1]


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


def _public_key_identity(path: Path) -> str:
    """Return the key type/blob pair, excluding the non-identity comment."""
    fields = path.read_text(encoding="utf-8").splitlines()[0].split()
    return " ".join(fields[:2])


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


def _generate_native_management_key(ssh_dir: Path) -> None:
    private_key = ssh_dir / MANAGEMENT_PRIVATE_KEY_NAME
    public_key = ssh_dir / MANAGEMENT_PUBLIC_KEY_NAME
    created_directory = False
    try:
        os.lstat(ssh_dir)
    except FileNotFoundError:
        try:
            ssh_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
            created_directory = True
        except OSError as exc:
            raise LoadError(f"无法创建管理服务器 SSH 目录：{exc}") from exc
    directory = _open_management_directory(
        ssh_dir, label="管理服务器 SSH 目录", allowed_modes=(0o700,),
    )
    directory.close()
    if not MANAGEMENT_KEYGEN.is_file():
        raise LoadError("固定 /usr/bin/ssh-keygen 不存在，无法生成管理服务器 key")
    try:
        result = _run_bounded_management_command(
            [
                os.fspath(MANAGEMENT_KEYGEN), "-q", "-t", "ed25519", "-N", "",
                "-f", os.fspath(private_key), "-C", "root@management-server",
            ],
        )
        if result.returncode != 0:
            raise LoadError("自动生成管理服务器 SSH key 失败")
        os.chmod(private_key, 0o600, follow_symlinks=False)
        os.chmod(public_key, 0o644, follow_symlinks=False)
    except BaseException:
        for path in (private_key, public_key):
            try:
                metadata = os.lstat(path)
            except OSError:
                continue
            if stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                try:
                    path.unlink()
                except OSError:
                    pass
        if created_directory:
            try:
                ssh_dir.rmdir()
            except OSError:
                pass
        raise


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
    if not static:
        raise LoadError("项目必须至少包含一个非空 *.pub（例如模板中的电脑公钥）")
    for item in static:
        validate_pubkey(item)
    planned_management = sorted(
        project / name for name in managed_names if (project / name).is_file()
    )
    if not planned_management:
        planned_management = sorted(empty)
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
    valid = static + planned_management
    if len(valid) < 2:
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
        if placeholder_identity is not None:
            if placeholder_identity != pair.identity:
                raise LoadError("项目管理服务器公钥与 prepared service key 不匹配 mismatch")
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
            or before.st_mode & 0o022
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
    if not dry_run:
        IMAGE_DIR.mkdir(parents=True, exist_ok=True)
    expected_names = {
        candidate
        for filename in expected.values()
        for candidate in _image_filename_candidates(filename)
    }
    project_bins = sorted(project.glob("*.bin"))
    # The complete project template intentionally carries zero-byte .bin files
    # for every supported image as preparation reminders.  They are metadata,
    # not candidate payloads, so only a non-empty unexpected image is a version
    # conflict.  Exact expected placeholders are resolved from the shared store.
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
                raise LoadError(
                    message + f"；项目占位文件为空，且 {IMAGE_DIR} 中没有合法镜像"
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
    for shared_image, project_image in copy_pairs.items():
        if not quiet:
            print(f"[IMAGE] {project_image} → {shared_image}")
        if not dry_run:
            shutil.copy2(project_image, shared_image)
    for kind, filename in expected.items():
        _selected, project_has_payload = resolution_cache[filename]
        if not project_has_payload:
            if not quiet:
                info(f"项目镜像为空/缺失，复用共享镜像：image/{resolved[kind].name}")
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
    command = [
        sys.executable, str(SETUP_SCRIPT), "-y", "--confirm-project-switch",
    ]
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
    except RuntimeContractError as exc:
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
) -> tuple[str, ...]:
    """Return the managed units that are currently active, without mutation."""
    if not supports_local_ztp_services():
        return ()
    backend = runtime_backend or service_runtime_backend()
    if backend.name == "supervisor":
        return tuple(
            service for service in SUPERVISOR_QUIESCE_SERVICES
            if _runtime_service_active(backend, service)
        )
    systemctl = shutil.which("systemctl")
    if not systemctl:
        return ()
    active = []
    for service in ("isc-dhcp-server", "apache2"):
        result = _run_subprocess(
            [systemctl, "is-active", "--quiet", service],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0:
            active.append(service)
    return tuple(active)


def require_artifact_builder_services_inactive(
    dry_run: bool = False, *,
    runtime_backend: ServiceRuntimeBackend | None = None,
) -> None:
    """Never stop unrelated live services for a configuration-only Linux run."""
    if dry_run:
        return
    active = active_managed_services(runtime_backend)
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
) -> DhcpRuntimePlan | None:
    """Stop services before changing project links; failed loads remain safely stopped."""
    if not supports_local_ztp_services():
        info(f"{runtime_os()} 不管理 Apache/ISC DHCP，跳过旧服务状态检查")
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
    active = list(active_managed_services(backend))
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
            raise
    finally:
        if transaction_created:
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

    inventory = _augment_air_json_inventory(
        _release_inventory(inputs.devices_file),
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
    dhcp_path = ZTP_DIR / "config/isc-dhcp-server/dhcp-release-manifest.json"
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
    input_hashes = {name: _sha256_path(path) for name, path in input_files.items()}
    release_basis = {
        "project": project.name,
        "deployment_scope": inputs.deployment_scope,
        "switch_scope": inputs.switch_scope,
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


def generate_configs(
    device_types: frozenset[str], *, install_dhcp: bool, dry_run: bool = False,
    schema_version: int = GLOBAL_SCHEMA_VERSION,
    eth_version: str | None = None,
    air_topology_policy: Path | None = None,
    mini_air: bool = False,
    mini_devices_file: Path | None = None,
    deployment_scope: str = "all",
    switch_scope: str = "all",
    deployment_lock_descriptor: int | None = None,
    source_identities: dict[str, str] | None = None,
) -> None:
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
    run(
        [
            sys.executable, "c1-generate_dhcp.py", "-y",
            *scope_args, *switch_args,
        ],
        cwd=ZTP_DIR / "config/isc-dhcp-server",
        dry_run=dry_run,
        **inherited_lock,
    )
    device_types = _device_types_after_dhcp(
        device_types, dry_run=dry_run, schema_version=schema_version,
        deployment_scope=deployment_scope,
        switch_scope=selected_switch,
    )

    if device_types & {"eth", "eth_spx", "spx", "air"}:
        template_dir = ZTP_DIR / "config/cumulus/template"
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "eth", "-y",
             *scope_args, *switch_args],
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
                [sys.executable, "d-hostname2mac.py", "-y", *scope_args,
                 *switch_args,
                 str(publish)],
                cwd=ZTP_DIR / "config/cumulus",
            )

    if deployment_scope != "air" and device_types & {"ib", "nvl"}:
        template_dir = ZTP_DIR / "config/nvos/template"
        run(
            [sys.executable, "90-c2-generate_configs.py", "--branch", "ib", "-y",
             *scope_args, *switch_args],
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
                [sys.executable, "d-hostname2mac.py", "-y", *scope_args,
                 *switch_args,
                 *map(str, kinds)],
                cwd=ZTP_DIR / "config/nvos",
            )

    if install_dhcp:
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


def print_ztp_monitor_access(service_ips: tuple[str, ...]) -> None:
    """Show operators where the live ZTP status can be inspected."""
    status_csv = ZTP_DIR / "status" / "latest" / "devices.csv"
    info(f"ZTP 状态 CSV：{status_csv}")
    for address in dict.fromkeys(service_ips):
        info(f"ZTP 状态页面：http://{address}/monitor/monitor.html")


def _canonical_apache_listener_addresses(
    service_ips: tuple[str, ...],
) -> tuple[str, ...]:
    addresses = []
    for raw in service_ips:
        raw_text = str(raw)
        try:
            parsed = ipaddress.IPv4Address(raw_text)
        except ipaddress.AddressValueError as exc:
            raise LoadError(f"Apache service IPv4 无效：{raw!r}") from exc
        canonical = str(parsed)
        if (
            raw_text != canonical
            or parsed.is_unspecified
            or parsed.is_multicast
            or int(parsed) == 0xFFFFFFFF
        ):
            raise LoadError(f"Apache service IPv4 无效：{raw!r}")
        if canonical in addresses:
            raise LoadError(f"Apache service IPv4 重复：{canonical}")
        addresses.append(canonical)
    if not addresses:
        raise LoadError("Apache exact listener 缺少 service IPv4")
    return tuple(addresses)


def render_native_apache_listener_config(
    service_ips: tuple[str, ...],
) -> str:
    """Render Native Apache listeners bound only to canonical service IPv4s."""
    addresses = _canonical_apache_listener_addresses(service_ips)
    lines = [
        "# Generated by DAY0-Prepare/11-load.py; do not edit.",
        "# Exact service-IP listeners only; wildcard binds are forbidden.",
    ]
    for address in addresses:
        lines.append(f"Listen {address}:80")
    for address in addresses:
        lines.extend((
            "",
            f"<VirtualHost {address}:80>",
            f"    ServerName {address}",
            "    DocumentRoot /var/www/html",
            "    ErrorLog /var/log/apache2/error.log",
            "    CustomLog /var/log/apache2/access.log combined",
            "</VirtualHost>",
        ))
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
    destination: Path = NATIVE_APACHE_LISTENER_CONF,
    command_runner=run,
    dry_run: bool = False,
) -> None:
    """Atomically publish exact Native listeners and roll back failed syntax."""
    rendered = render_native_apache_listener_config(service_ips).encode("utf-8")
    destination = Path(destination)
    if dry_run:
        info(
            "dry-run：将原子发布 Apache exact listener："
            + ", ".join(_canonical_apache_listener_addresses(service_ips))
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
        print_ztp_monitor_access(service_ips)
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
    print_ztp_monitor_access(service_ips)


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
    http_available = bool(plan.endpoint_ips)
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
        http_required = bool(plan.endpoint_ips)
        dhcp_required = bool(plan.listener_names)
        if http_required:
            verify_control_auth(runtime_backend=backend, dry_run=dry_run)
            verify_published_files(inputs, images, dry_run=dry_run)
            verify_apache_publication_boundary(dry_run=dry_run)
            run(sudo_command("apache2ctl", "configtest"), dry_run=dry_run)
        if dhcp_required:
            for source in dhcp_file_mappings():
                _nonempty_file(source, f"DHCP 输出 {source.name}")
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
        http_required = bool(plan.endpoint_ips)
        dhcp_required = bool(plan.listener_names)
        # This endpoint check can prompt the operator, so it must finish before
        # the first Supervisor mutation.  DHCP-only plans have no URL endpoint
        # and must not be forced through an Apache-specific gate.
        if http_required:
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
) -> tuple[ProjectInputs, dict[str, Path]]:
    global_file = project / "01-global.yaml"
    devices_file = project / "02-devices_config.csv"
    subnet_file = project / "02-dhcp-subnet_config.csv"
    settings = load_global(global_file)
    validation_errors = []
    device_types: frozenset[str] = frozenset()
    p2p_file = project / (args.p2p_file or "p2p.xlsx")
    air_topology_policy = None
    mini_devices_file = None
    mini_source_file = None
    preview_images: dict[str, Path] = {}
    deployment_scope = str(getattr(args, "deployment_scope", "all") or "all")
    switch_scope = str(getattr(args, "switch_scope", "all") or "all")
    try:
        settings = apply_subnet_service_ips(settings, subnet_file)
    except LoadError as exc:
        validation_errors.append(str(exc))
    try:
        device_types = load_device_types(
            devices_file, settings.schema_version, switch_scope=switch_scope,
        )
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
        inject_management_key=supports_local_ztp_services(),
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
    parser.add_argument("--p2p-file", help="明确选择项目根目录或 p2p/ 下的 P2P XLSX")
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


def main(argv: list[str] | None = None) -> int:
    requested_argv = list(sys.argv[1:] if argv is None else argv)
    args = parse_args(argv)
    release_link_snapshot: dict[Path, Optional[str]] = {}
    release_committed = False
    deployment_lock_descriptor: int | None = None
    parent_candidate: PreparedParentRelease | None = None
    prefix_publication_snapshot: ZtpPrefixPublicationSnapshot | None = None
    dhcp_runtime_plan: DhcpRuntimePlan | None = None
    runtime_backend_instance: ServiceRuntimeBackend | None = None
    http_service_available = False
    dhcp_service_available = False
    services_must_remain_stopped = False
    native_monitor_quiesced = False
    allow_management_key_generation=False
    should_monitor = False
    monitor_scope: str | None = None
    failure_phase = "启动前参数检查"
    try:
        host_os = runtime_os()
        deployment_scope = validate_deployment_scope_options(args)
        switch_scope = validate_switch_scope_options(args, deployment_scope)
        args.deployment_scope = deployment_scope
        args.switch_scope = switch_scope
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
        local_services_supported = supports_local_ztp_services(host_os)
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
            http_service_available = legacy_service_available
            dhcp_service_available = legacy_service_available
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
            )
        elif local_services_supported:
            require_artifact_builder_services_inactive(
                args.dry_run, runtime_backend=runtime_backend_instance,
            )
        failure_phase = "活动项目 setup 检查/切换"
        activate_project(
            project, inputs.p2p_file,
            # Configuration-only platforms cannot inject the management-host
            # key and therefore cannot satisfy the Linux deployment gate.
            strict=local_services_supported and not args.no_upgrade,
            dry_run=args.dry_run,
            deployment_lock_descriptor=deployment_lock_descriptor,
        )

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
                "install_dhcp": dhcp_service_available,
                "dry_run": args.dry_run,
                "schema_version": inputs.settings.schema_version,
                "eth_version": inputs.settings.versions.get("eth"),
                "air_topology_policy": inputs.air_topology_policy,
                "deployment_scope": deployment_scope,
                "switch_scope": switch_scope,
            }
            # Keep the established full-topology call contract byte-for-byte
            # compatible for embedders which wrap generate_configs().
            if getattr(args, "mini", False):
                generation_options["mini_air"] = True
                mini_source, _mini_canonical = project_mini_air_devices(
                    project, args.mini,
                )
                generation_options["mini_devices_file"] = mini_source
                generation_options["source_identities"] = inputs.source_identities
            generate_configs(
                inputs.device_types,
                deployment_lock_descriptor=deployment_lock_descriptor,
                **generation_options,
            )
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
        parent_release = validate_and_publish_release(
            project, inputs, dry_run=args.dry_run, publish=False,
        )
        if parent_release is not None:
            # Materialize and fsync the parent before touching /etc/dhcp.  The
            # remaining commit is one os.replace performed while DHCP backups
            # and the global deployment lock are still held.
            parent_candidate = prepare_current_release(project, parent_release)
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
                    inputs.settings.service_ips, dry_run=args.dry_run,
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
        ok(f"load 流程完成：{project}")
        return 0
    except BaseException as exc:
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
        discard_prepared_release(parent_candidate)
        release_deployment_lock(deployment_lock_descriptor)


def cli(argv: list[str] | None = None) -> int:
    """Own the workstation test gate while keeping Linux production load lean."""
    requested_argv = list(sys.argv[1:] if argv is None else argv)
    try:
        args = parse_args(requested_argv)
        deployment_scope = validate_deployment_scope_options(args)
        validate_switch_scope_options(args, deployment_scope)
        local_formal_load = (
            runtime_os().casefold() == "darwin" and not args.dry_run
        )
        if local_formal_load:
            run_local_full_test_gate()
        result = main(requested_argv)
        if result == 0 and local_formal_load:
            verify_local_full_test_attestation()
        return result
    except (LoadError, OSError, ValueError, RuntimeError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(cli())
