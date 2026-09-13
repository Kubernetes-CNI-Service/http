#!/usr/bin/env python3
"""Fail-closed runtime activation for the host-network ZTP container.

The container never creates, renames, addresses, or otherwise configures a
host interface.  It observes a stable pair of Linux ``ip -j`` snapshots and
delegates all DHCP listener selection to ``tools/ztp_service_runtime.py``.
"""

from __future__ import annotations

import argparse
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import fcntl
import grp
import hashlib
import hmac
import importlib
from importlib import metadata as importlib_metadata
import importlib.util
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
from typing import Iterable, Mapping, NamedTuple, Optional, Sequence, Tuple


HERE = Path(__file__).resolve().parent
sys.path.insert(0, os.fspath(HERE))
TOOLS_DIRECTORY = HERE.parents[1] / "tools"
sys.path.insert(0, os.fspath(TOOLS_DIRECTORY))
import hostlock  # noqa: E402
from project_contract import path_disposition  # noqa: E402


DEFAULT_HTTP_ROOT = Path("/var/www/html")
DEFAULT_STATE_ROOT = Path("/var/lib/http-ztp")
DEFAULT_LOG_ROOT = Path("/var/log/http-ztp")
DEFAULT_DHCP_CONFIG = Path("/etc/dhcp/dhcpd.conf")
DEFAULT_DHCP_LEASES = Path("/var/lib/dhcp/dhcpd.leases")
DEFAULT_APACHE_LISTENERS = Path(
    "/etc/apache2/conf-enabled/http-ztp-listeners.conf"
)
CONTROL_AUTH_HELPER = Path("/opt/http-ztp/control-auth.py")
CONTROL_AUTH_STATUS_HELPER = Path(
    "/usr/local/lib/http-ztp/control-auth.py"
)
CONTROL_AUTH_IMAGE_SOURCE_HELPER = Path(
    "/opt/http-ztp/source-tree/tools/control-auth.py"
)
MONITOR_AUTHORITY_ROOT = Path("/var/lib/http-ztp-monitor-auth")
CONTROL_AUTH_HELPER_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
CONTROL_AUTH_HELPER_SIZE_LIMIT = 256 * 1024
CONTROL_AUTH_IMAGE_DIRECTORY_CONTRACTS = (
    (Path("/opt/http-ztp"), 0o700),
    (Path("/opt/http-ztp/source-tree"), 0o755),
    (Path("/opt/http-ztp/source-tree/tools"), 0o755),
    (Path("/usr"), 0o755),
    (Path("/usr/local"), 0o755),
    (Path("/usr/local/lib"), 0o755),
    (Path("/usr/local/lib/http-ztp"), 0o755),
)
CONTROL_AUTH_OUTPUT_LIMIT = 4096
DEFAULT_RELEASE_NAME = "99-output-ztp/current-release.json"
RUNTIME_PLAN_NAME = "runtime-plan.json"
ACTIVATION_MARKER_NAME = "activation.json"
PRECOMMIT_MARKER_NAME = "precommit-activation.json"
MARKER_SCHEMA = 2
PLAN_SCHEMA = 2
UINT32_MAX = (1 << 32) - 1
MAX_FINITE_ADDRESS_LIFETIME = UINT32_MAX - 1
SAFE_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
MANAGED_SERVICES = (
    "apache2", "dhcpd", "ztp-monitor", "switch-collection", "manual-ztp",
)
WORKER_CONTROL_DEFAULTS = (
    (Path("ztp/status/ztp-monitor.control"), b"running\n"),
    (Path("monitor/status/switch-collection.request"), b"idle\n"),
    (Path("monitor/status/manual-ztp.request.json"), b'{"requests":[]}\n'),
)
CONTROL_CGI = (
    (Path("monitor/ztp-monitor-control.cgi"), "ztp-monitor-control"),
    (Path("monitor/switch-collection-control.cgi"), "switch-collection-control"),
    (Path("monitor/manual-ztp-control.cgi"), "manual-ztp-control"),
)
PUBLISHED_RUNTIME_FILES = (
    Path("ztp/ztp-bootstrap_oob.sh"),
    Path("ztp/ztp-bootstrap_oobofoob.sh"),
    Path("ztp/ztp.json"),
)
PUBLISHED_RUNTIME_LINKS = (
    (Path("monitor/01-global.yaml"),
     "../DAY0-Prepare/{project}/01-global.yaml", Path("01-global.yaml")),
    (Path("monitor/02-devices_config.csv"),
     "../DAY0-Prepare/{project}/02-devices_config.csv", Path("02-devices_config.csv")),
    (Path("monitor/99-output-p2p"),
     "../DAY0-Prepare/{project}/99-output-p2p", Path("99-output-p2p")),
    (Path("monitor/ethernet"),
     "../DAY0-Prepare/{project}/99-output-monitor/ethernet",
     Path("99-output-monitor/ethernet")),
    (Path("monitor/infiniband"),
     "../DAY0-Prepare/{project}/99-output-monitor/infiniband",
     Path("99-output-monitor/infiniband")),
    (Path("monitor/nvlink"),
     "../DAY0-Prepare/{project}/99-output-monitor/nvlink",
     Path("99-output-monitor/nvlink")),
    (Path("monitor/ztp-status"), "../ztp/status", Path("99-output-ztp")),
    (Path("ztp/status"),
     "../DAY0-Prepare/{project}/99-output-ztp", Path("99-output-ztp")),
    (Path("ethernet/eth.csv"),
     "../DAY0-Prepare/{project}/02-devices_config.csv", Path("02-devices_config.csv")),
    (Path("ethernet/monitor/eth.csv"), "../eth.csv", Path("02-devices_config.csv")),
    (Path("infiniband/ib.csv"),
     "../DAY0-Prepare/{project}/02-devices_config.csv", Path("02-devices_config.csv")),
    (Path("infiniband/monitor/ib.csv"), "../ib.csv", Path("02-devices_config.csv")),
    (Path("nvlink/nvsw.csv"),
     "../DAY0-Prepare/{project}/02-devices_config.csv", Path("02-devices_config.csv")),
    (Path("nvlink/monitor/nvsw.csv"), "../nvsw.csv", Path("02-devices_config.csv")),
    (Path("ethernet/monitor/eth-info"),
     "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/eth-info",
     Path("99-output-monitor/ethernet/eth-info")),
    (Path("ethernet/monitor/spx-link"),
     "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/spx-link",
     Path("99-output-monitor/ethernet/spx-link")),
    (Path("ethernet/monitor/cronjob.log"),
     "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/cronjob.log",
     Path("99-output-monitor/ethernet/cronjob.log")),
    (Path("infiniband/monitor/ib-info"),
     "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/ib-info",
     Path("99-output-monitor/infiniband/ib-info")),
    (Path("infiniband/monitor/ib-link"),
     "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/ib-link",
     Path("99-output-monitor/infiniband/ib-link")),
    (Path("infiniband/monitor/cronjob.log"),
     "../../DAY0-Prepare/{project}/99-output-monitor/infiniband/cronjob.log",
     Path("99-output-monitor/infiniband/cronjob.log")),
    (Path("nvlink/monitor/nvsw-info"),
     "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/nvsw-info",
     Path("99-output-monitor/nvlink/nvsw-info")),
    (Path("nvlink/monitor/nvsw-link"),
     "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/nvsw-link",
     Path("99-output-monitor/nvlink/nvsw-link")),
    (Path("nvlink/monitor/cronjob.log"),
     "../../DAY0-Prepare/{project}/99-output-monitor/nvlink/cronjob.log",
     Path("99-output-monitor/nvlink/cronjob.log")),
    (Path("tools/lldp-analyze-tool/99-output-p2p"),
     "../../DAY0-Prepare/{project}/99-output-p2p", Path("99-output-p2p")),
    (Path("tools/lldp-analyze-tool/99-output-monitor"),
     "../../DAY0-Prepare/{project}/99-output-monitor", Path("99-output-monitor")),
)
PUBLISHED_P2P_INPUT_LINK = Path("ztp/config/cumulus/template/P2P/p2p.xlsx")
PUBLISHED_P2P_AIR_LINK = Path("ztp/config/isc-dhcp-server/p2p-air.json")
# The receipt is intentionally directory-derived rather than a hand-maintained
# entrypoint list.  Several lifecycle generators discover Python modules,
# Jinja templates and default*.yaml files by glob; exact membership therefore
# matters just as much as the hash of today's known files.
IMAGE_SOURCE_SCAN_ROOTS = (
    "infra", "monitor", "ethernet", "infiniband", "nvlink", "ztp", "tools",
)
IMAGE_SOURCE_SUFFIXES = frozenset({
    ".py", ".sh", ".cgi", ".conf", ".yaml", ".yml", ".json", ".j2",
    ".dot", ".nv", ".service", ".timer", ".socket", ".target", ".path",
    ".csv", ".log", ".txt", ".pub", ".xlsx", ".example",
})
IMAGE_SOURCE_EXACT_NAMES = frozenset({
    "Dockerfile", "Dockerfile.dockerignore",
})
IMAGE_SOURCE_EXCLUDED_PREFIXES = (
    "infra/logs/",
    "infiniband/bringup/",
    "monitor/status/",
    "ztp/backup/",
    "ztp/config/cumulus/template/.claude/",
    "ztp/config/publickey/",
    "ztp/image/",
    "ztp/optimize/2026-12-vb-gb300-sample/",
    "tools/ib-tool-Jie/",
    "tools/ibdiagnet-analyze-tool/",
)
IMAGE_SOURCE_EXCLUDED_PATHS = frozenset({
    "infra/01-global.yaml",
    "infra/02-devices_config.csv",
    "infra/docker/infra-runtime.conf",
    "infra/docker/deployment-source-manifest.json",
    "monitor/01-global.yaml",
    "monitor/02-devices_config.csv",
    "monitor/generate-monitor.log",
    "ethernet/eth.csv",
    "ethernet/p2p.xlsx",
    "ethernet/monitor/eth.csv",
    "ethernet/monitor/cronjob.log",
    "infiniband/ib.csv",
    "infiniband/p2p.xlsx",
    "infiniband/monitor/ib.csv",
    "infiniband/monitor/cronjob.log",
    "infiniband/bringup/xdr-upgrade/ib.csv",
    "infiniband/bringup/xdr-initial-setup/ib.csv",
    "infiniband/bringup/xdr-initial-setup/p2p.xlsx",
    "nvlink/nvsw.csv",
    "nvlink/p2p.xlsx",
    "nvlink/monitor/nvsw.csv",
    "nvlink/monitor/cronjob.log",
    "ztp/ztp-bootstrap_oob.sh",
    "ztp/ztp-bootstrap_oobofoob.sh",
    "ztp/ztp.json",
    "ztp/config/isc-dhcp-server/01-global.yaml",
    "ztp/config/isc-dhcp-server/02-devices_config.csv",
    "ztp/config/isc-dhcp-server/02-subnet_config.csv",
    "ztp/config/isc-dhcp-server/dhcp-release-manifest.json",
    "ztp/config/isc-dhcp-server/dhcpd.conf",
    "ztp/config/isc-dhcp-server/p2p-air.json",
    "ztp/config/publickey/laptop.pub",
    "ztp/backup/02-devices_config.csv",
    "ztp/config/cumulus/template/01-global.yaml",
    "ztp/config/cumulus/template/02-devices_config.csv",
    "ztp/config/cumulus/template/91-devices.yaml",
    "ztp/config/cumulus/template/P2P/p2p.xlsx",
    "ztp/config/nvos/template/01-global.yaml",
    "ztp/config/nvos/template/02-devices_config.csv",
    "ztp/config/nvos/template/P2P/p2p.xlsx",
})
MUTABLE_IMAGE_SOURCE_PATTERNS = (
    re.compile(r"^ztp/config/(?:cumulus|nvos)/default[^/]*[.]yaml$"),
)
DEFAULT_IMAGE_SOURCE_MANIFEST = Path("/opt/http-ztp/image-source.sha256")
DEFAULT_IMAGE_SOURCE_TREE = Path("/opt/http-ztp/source-tree")
IMAGE_SOURCE_SCHEMA = 1
IMAGE_RUNTIME_CONTRACT = "3"
RUNTIME_CONTRACT_RELATIVE = "infra/docker/runtime-contract.json"
CONTAINER_TOPLEVEL_LOCK_NAME = "requirements-container-top-level.lock"
CONTAINER_VENV = Path("/opt/http-ztp/venv")
CONTAINER_VENV_PYTHON = CONTAINER_VENV / "bin/python"
CONTAINER_SYSTEM_SITE = Path("/usr/lib/python3/dist-packages")
CONTAINER_TOPLEVEL_REQUIREMENTS = {
    "Jinja2": "3.1.6",
    "PyYAML": "6.0.3",
    "pandas": "2.3.3",
    "openpyxl": "3.1.5",
    "XlsxWriter": "3.2.9",
}
CONTAINER_TOPLEVEL_IMPORTS = {
    "Jinja2": "jinja2",
    "PyYAML": "yaml",
    "pandas": "pandas",
    "openpyxl": "openpyxl",
    "XlsxWriter": "xlsxwriter",
}
CONTAINER_TRANSITIVE_IMPORTS = (
    "dateutil",
    "et_xmlfile",
    "markupsafe",
    "numpy",
    "pytz",
)
# These files execute from, or are installed into, the immutable image.  They
# must remain byte-identical.  Project inputs, ordinary generators and workers
# execute from the separately verified live release and may advance without
# rebuilding the infrastructure image while contract 3 remains listed as
# compatible by that release.  The discovered default*.yaml set is added to
# this boundary separately because entrypoint restores it from the image.
IMAGE_COUPLED_SOURCE_PATHS = frozenset({
    CONTAINER_TOPLEVEL_LOCK_NAME,
    "infra/docker/activate.py",
    "infra/docker/entrypoint.py",
    "infra/docker/healthcheck.py",
    "infra/docker/hostctl.py",
    "infra/docker/hostlock.py",
    "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/supervisord.conf",
    "infra/docker/apache-ztp.conf",
    "infra/docker/logrotate-http-ztp.conf",
    "tools/ztp_service_runtime.py",
    "tools/control-auth.py",
})


class ActivationError(RuntimeError):
    """The container cannot safely prepare or activate the requested runtime."""


def _origin_within(origin: object, root: Path) -> bool:
    if not isinstance(origin, str) or not origin.startswith("/"):
        return False
    try:
        canonical_root = root.resolve(strict=True)
        canonical_origin = Path(origin).resolve(strict=True)
        canonical_origin.relative_to(canonical_root)
        metadata = canonical_origin.stat()
    except (OSError, RuntimeError, ValueError):
        return False
    return stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1


def validate_python_runtime() -> None:
    """Require the exact TOPLEVEL-5 venv and its apt-provided import closure."""
    if Path(sys.executable) != CONTAINER_VENV_PYTHON:
        raise ActivationError(
            f"container Python must run from venv {CONTAINER_VENV_PYTHON}"
        )
    for distribution, expected in CONTAINER_TOPLEVEL_REQUIREMENTS.items():
        try:
            actual = importlib_metadata.version(distribution)
        except importlib_metadata.PackageNotFoundError as exc:
            raise ActivationError(
                f"missing TOPLEVEL-5 distribution: {distribution}"
            ) from exc
        if actual != expected:
            raise ActivationError(
                f"TOPLEVEL-5 {distribution} must be {expected}, got {actual}"
            )

    ordered_modules = (
        tuple(CONTAINER_TOPLEVEL_IMPORTS.values())
        + CONTAINER_TRANSITIVE_IMPORTS
    )
    for module in ordered_modules:
        try:
            spec = importlib.util.find_spec(module)
        except (ImportError, AttributeError, ValueError) as exc:
            raise ActivationError(f"cannot inspect Python import {module}: {exc}") from exc
        if spec is None:
            raise ActivationError(f"missing Python import closure module: {module}")
        expected_root = (
            CONTAINER_VENV
            if module in CONTAINER_TOPLEVEL_IMPORTS.values()
            else CONTAINER_SYSTEM_SITE
        )
        if not _origin_within(getattr(spec, "origin", None), expected_root):
            raise ActivationError(
                f"Python import path for {module} is outside {expected_root}"
            )
        try:
            importlib.import_module(module)
        except ImportError as exc:
            raise ActivationError(
                f"cannot import Python closure module {module}: {exc}"
            ) from exc


class MonitorAuthorityError(ActivationError):
    """A shared-helper machine classification blocked Monitor startup."""

    def __init__(self, classification: str, message: str) -> None:
        if classification not in {
            "recovery-in-progress",
            "recovery-committed-cleanup-pending",
        }:
            raise ValueError("invalid Monitor authority machine classification")
        super().__init__(message)
        self.classification = classification


def _fixed_path(environment: Mapping[str, str], name: str, expected: Path) -> Path:
    raw = str(environment.get(name) or os.fspath(expected)).strip()
    candidate = Path(raw)
    if candidate != expected:
        raise ActivationError(f"{name} must be {expected}, got {candidate}")
    return candidate


def parse_name_list(raw: str, label: str) -> Tuple[str, ...]:
    values = []
    for value in re.split(r"[\s,]+", str(raw or "").strip()):
        if not value:
            continue
        if not SAFE_NAME.fullmatch(value):
            raise ActivationError(f"unsafe {label}: {value!r}")
        if value in values:
            raise ActivationError(f"duplicate {label}: {value}")
        values.append(value)
    return tuple(values)


@dataclass(frozen=True)
class Settings:
    project_name: str
    scope: str
    http_root: Path = DEFAULT_HTTP_ROOT
    state_root: Path = DEFAULT_STATE_ROOT
    log_root: Path = DEFAULT_LOG_ROOT
    dhcp_config: Path = DEFAULT_DHCP_CONFIG
    dhcp_leases: Path = DEFAULT_DHCP_LEASES
    apache_listeners: Path = DEFAULT_APACHE_LISTENERS
    allowlist: Tuple[str, ...] = ()
    relay_ingress: Tuple[str, ...] = ()
    monitor_interval: int = 30
    switch_scope: str = ""
    mini: bool = False

    def __post_init__(self) -> None:
        scope = str(self.scope or "").strip().casefold()
        if scope not in {"air", "prod"}:
            raise ActivationError("HTTP_ZTP_SCOPE must be air or prod")
        switch_scope = str(
            self.switch_scope or ("eth" if scope == "air" else "all")
        ).strip().casefold()
        if switch_scope not in {"all", "eth", "ib", "nvl"}:
            raise ActivationError(
                "HTTP_ZTP_SWITCH_SCOPE must be all, eth, ib, or nvl"
            )
        if scope == "air" and switch_scope != "eth":
            raise ActivationError(
                "AIR deployment requires HTTP_ZTP_SWITCH_SCOPE=eth"
            )
        if not isinstance(self.mini, bool):
            raise ActivationError("HTTP_ZTP_MINI must be enabled or disabled")
        if self.mini and (scope != "air" or switch_scope != "eth"):
            raise ActivationError(
                "mini selection requires AIR deployment and switch scope eth"
            )
        object.__setattr__(self, "scope", scope)
        object.__setattr__(self, "switch_scope", switch_scope)

    @classmethod
    def from_environment(cls, environment: Mapping[str, str]) -> "Settings":
        project = str(environment.get("HTTP_ZTP_PROJECT") or "").strip()
        if not SAFE_PROJECT.fullmatch(project):
            raise ActivationError(
                "HTTP_ZTP_PROJECT must be one safe DAY0-Prepare directory name"
            )
        scope = str(environment.get("HTTP_ZTP_SCOPE") or "").strip().casefold()
        if scope not in {"air", "prod"}:
            raise ActivationError("HTTP_ZTP_SCOPE must be air or prod")
        raw_switch_scope = str(
            environment.get("HTTP_ZTP_SWITCH_SCOPE") or ""
        ).strip().casefold()
        switch_scope = raw_switch_scope or (
            "eth" if scope == "air" else "all"
        )
        raw_mini = str(
            environment.get("HTTP_ZTP_MINI") or "disabled"
        ).strip().casefold()
        if raw_mini not in {"enabled", "disabled"}:
            raise ActivationError("HTTP_ZTP_MINI must be enabled or disabled")
        mini = raw_mini == "enabled"
        raw_interval = str(
            environment.get("HTTP_ZTP_MONITOR_INTERVAL") or "30"
        ).strip()
        try:
            interval = int(raw_interval)
        except ValueError as exc:
            raise ActivationError(
                "HTTP_ZTP_MONITOR_INTERVAL must be an integer"
            ) from exc
        if interval < 5 or interval > 86400:
            raise ActivationError(
                "HTTP_ZTP_MONITOR_INTERVAL must be between 5 and 86400"
            )
        return cls(
            project_name=project,
            scope=scope,
            http_root=_fixed_path(
                environment, "HTTP_ZTP_ROOT", DEFAULT_HTTP_ROOT,
            ),
            state_root=_fixed_path(
                environment, "HTTP_ZTP_STATE_ROOT", DEFAULT_STATE_ROOT,
            ),
            log_root=_fixed_path(
                environment, "HTTP_ZTP_LOG_ROOT", DEFAULT_LOG_ROOT,
            ),
            dhcp_config=_fixed_path(
                environment, "HTTP_ZTP_DHCP_CONFIG", DEFAULT_DHCP_CONFIG,
            ),
            dhcp_leases=_fixed_path(
                environment, "HTTP_ZTP_DHCP_LEASES", DEFAULT_DHCP_LEASES,
            ),
            apache_listeners=_fixed_path(
                environment,
                "HTTP_ZTP_APACHE_LISTENERS",
                DEFAULT_APACHE_LISTENERS,
            ),
            allowlist=parse_name_list(
                str(environment.get("HTTP_ZTP_DHCP_INTERFACE_ALLOWLIST") or ""),
                "DHCP interface allowlist entry",
            ),
            relay_ingress=parse_name_list(
                str(environment.get("HTTP_ZTP_DHCP_RELAY_INGRESS") or ""),
                "DHCP relay ingress entry",
            ),
            monitor_interval=interval,
            switch_scope=switch_scope,
            mini=mini,
        )

    @property
    def project_dir(self) -> Path:
        return self.http_root / "DAY0-Prepare" / self.project_name

    @property
    def subnet_csv(self) -> Path:
        return self.project_dir / "02-dhcp-subnet_config.csv"

    @property
    def release_manifest(self) -> Path:
        return self.project_dir / DEFAULT_RELEASE_NAME

    @property
    def runtime_plan(self) -> Path:
        return self.state_root / RUNTIME_PLAN_NAME

    @property
    def activation_marker(self) -> Path:
        return self.state_root / ACTIVATION_MARKER_NAME

    @property
    def precommit_marker(self) -> Path:
        return self.state_root / PRECOMMIT_MARKER_NAME

    @property
    def rebuild_required(self) -> Path:
        return self.state_root / "rebuild-required.json"

    @property
    def quarantine_marker(self) -> Path:
        return self.state_root / "quarantine.json"

    @property
    def guardian_fault(self) -> Path:
        return self.state_root / "guardian-fault.json"


class WorkerSpec(NamedTuple):
    argv: Tuple[str, ...]
    pid_file: Path


def _run_json(command: Sequence[str], runner=subprocess.run):
    result = runner(
        list(command), capture_output=True, text=True, check=False,
    )
    if int(getattr(result, "returncode", 0)) != 0:
        stderr = str(getattr(result, "stderr", "") or "").strip()
        raise ActivationError(
            f"network snapshot command failed: {' '.join(command)}"
            + (f": {stderr}" if stderr else "")
        )
    try:
        payload = json.loads(str(getattr(result, "stdout", "") or ""))
    except json.JSONDecodeError as exc:
        raise ActivationError(
            f"network snapshot is invalid JSON: {' '.join(command)}: {exc}"
        ) from exc
    if not isinstance(payload, list):
        raise ActivationError("network snapshot must be a JSON array")
    return payload


def require_control_auth(
    *, runner=subprocess.run, emit_factory_warning: bool = False,
) -> dict[str, bool]:
    """Require the installed Monitor-control helper and exact valid state.

    Both helper entry points are exercised deliberately.  Automatic lifecycle
    callers are machine-silent by default; only an explicit human preparation
    surface may opt into forwarding a bounded warning.  ``status`` gives
    callers a small machine contract without reading credential bytes.
    """
    validate_command = [os.fspath(CONTROL_AUTH_HELPER), "validate"]
    try:
        validated = runner(
            validate_command,
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ActivationError(
            f"Monitor control credential validation could not run: {exc}"
        ) from exc
    validate_stdout = str(getattr(validated, "stdout", "") or "")
    validate_stderr = str(getattr(validated, "stderr", "") or "")
    if (
        len(validate_stdout.encode("utf-8", errors="replace"))
        > CONTROL_AUTH_OUTPUT_LIMIT
        or len(validate_stderr.encode("utf-8", errors="replace"))
        > CONTROL_AUTH_OUTPUT_LIMIT
        or "\x00" in validate_stdout
        or "\x00" in validate_stderr
    ):
        raise ActivationError("Monitor control credential validation output is unsafe")
    if int(getattr(validated, "returncode", 1)) != 0 or validate_stdout:
        raise ActivationError("Monitor control credential validation failed")
    if validate_stderr and emit_factory_warning:
        print(validate_stderr.rstrip("\n"), file=sys.stderr)

    status_command = [os.fspath(CONTROL_AUTH_HELPER), "status"]
    try:
        completed = runner(
            status_command,
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ActivationError(
            f"Monitor control credential status could not run: {exc}"
        ) from exc
    stdout = str(getattr(completed, "stdout", "") or "")
    stderr = str(getattr(completed, "stderr", "") or "")
    if (
        len(stdout.encode("utf-8", errors="replace")) > CONTROL_AUTH_OUTPUT_LIMIT
        or len(stderr.encode("utf-8", errors="replace")) > CONTROL_AUTH_OUTPUT_LIMIT
        or "\x00" in stdout
        or "\x00" in stderr
    ):
        raise ActivationError("Monitor control credential status output is unsafe")
    if int(getattr(completed, "returncode", 1)) != 0 or stderr:
        raise ActivationError("Monitor control credential status failed")
    try:
        payload = json.loads(stdout)
    except (TypeError, json.JSONDecodeError) as exc:
        raise ActivationError(
            "Monitor control credential status is invalid"
        ) from exc
    if (
        not isinstance(payload, dict)
        or set(payload) != {"valid", "factory_records_active"}
        or type(payload.get("valid")) is not bool
        or type(payload.get("factory_records_active")) is not bool
        or payload["valid"] is not True
    ):
        raise ActivationError("Monitor control credential status is invalid")
    return {
        "valid": payload["valid"],
        "factory_records_active": payload["factory_records_active"],
    }


def require_monitor_authority(*, runner=None) -> None:
    """Read-only attestation of the fixed cache anchor before Apache can run."""
    runner = runner or subprocess.run
    command = [os.fspath(CONTROL_AUTH_HELPER), "monitor-authority-attest"]
    try:
        result = runner(
            command,
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ActivationError(
            f"Monitor cache authority attestation could not run: {exc}"
        ) from exc
    stdout = str(getattr(result, "stdout", "") or "")
    stderr = str(getattr(result, "stderr", "") or "")
    unsafe_output = (
        len(stdout.encode("utf-8", errors="replace")) > CONTROL_AUTH_OUTPUT_LIMIT
        or len(stderr.encode("utf-8", errors="replace")) > CONTROL_AUTH_OUTPUT_LIMIT
        or "\x00" in stdout
        or "\x00" in stderr
    )
    returncode = int(getattr(result, "returncode", 1))
    if not unsafe_output and returncode == 0 and not stdout and not stderr:
        return
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
            and stdout == _canonical_json(payload) + "\n"
        ):
            classification = str(payload["classification"])
            command = "sudo ./infra/docker/deploy.sh recover-monitor-authority"
            if classification == "recovery-committed-cleanup-pending":
                raise MonitorAuthorityError(
                    classification,
                    "classification=recovery-committed-cleanup-pending; previous "
                    "Monitor authority recovery COMPLETED and the repaired authority "
                    "itself is not in question; rerun the explicit recovery only to "
                    f"reattest and finish marker cleanup: {command}",
                )
            raise MonitorAuthorityError(
                classification,
                "classification=recovery-in-progress; Monitor authority recovery "
                "has not been committed; keep the container stopped and rerun "
                f"exactly: {command}",
            )
    if unsafe_output or returncode != 0 or stdout or stderr:
        raise ActivationError("Monitor cache authority attestation failed")


def _canonical_json(value: object) -> str:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    )


def _link_stability_projection(snapshot: object) -> list:
    """Return a copy suitable only for comparing link observation stability."""
    if not isinstance(snapshot, list):
        raise ActivationError("link stability snapshot must be a JSON array")
    projected = copy.deepcopy(snapshot)
    for position, record in enumerate(projected):
        if not isinstance(record, dict):
            raise ActivationError(
                f"link stability snapshot[{position}] must be an object"
            )
        if "linkinfo" not in record:
            continue
        linkinfo = record["linkinfo"]
        if not isinstance(linkinfo, dict):
            raise ActivationError(
                f"link stability snapshot[{position}].linkinfo must be an object"
            )
        if linkinfo.get("info_kind") != "bridge":
            continue
        if "info_data" not in linkinfo:
            continue
        info_data = linkinfo["info_data"]
        if not isinstance(info_data, dict):
            raise ActivationError(
                "bridge link stability info_data must be an object"
            )
        if "gc_timer" not in info_data:
            continue
        timer = info_data["gc_timer"]
        timer_is_finite = False
        if not isinstance(timer, bool) and isinstance(timer, (int, float)):
            try:
                timer_is_finite = math.isfinite(timer)
            except (OverflowError, TypeError):
                timer_is_finite = False
        if not timer_is_finite or timer < 0:
            raise ActivationError(
                "bridge link stability gc_timer must be a finite "
                "non-negative number"
            )
        info_data["gc_timer"] = "<dynamic-bridge-gc-timer>"
    return projected


def _finite_address_lifetime(value: object, field: str) -> Optional[int]:
    """Classify one Linux u32 address lifetime without weakening boundaries."""
    if value == "forever":
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise ActivationError(
            f"address stability {field} lifetime must be zero, a bounded "
            "positive integer, the uint32 forever value, or 'forever'"
        )
    if value == UINT32_MAX:
        return None
    if value < 0 or value > UINT32_MAX:
        raise ActivationError(
            f"address stability {field} lifetime is outside the uint32 range"
        )
    if value == 0:
        return None
    if value > MAX_FINITE_ADDRESS_LIFETIME:
        raise ActivationError(
            f"address stability {field} finite lifetime is out of range"
        )
    return value


def _address_stability_projection(snapshot: object) -> list:
    """Return a copy that classifies only safe finite lease countdowns."""
    if not isinstance(snapshot, list):
        raise ActivationError("address stability snapshot must be a JSON array")
    projected = copy.deepcopy(snapshot)
    for position, record in enumerate(projected):
        if not isinstance(record, dict):
            raise ActivationError(
                f"address stability snapshot[{position}] must be an object"
            )
        if "addr_info" not in record:
            continue
        addr_info = record["addr_info"]
        if not isinstance(addr_info, list):
            raise ActivationError(
                f"address stability snapshot[{position}].addr_info must be an array"
            )
        for address_position, address in enumerate(addr_info):
            if not isinstance(address, dict):
                raise ActivationError(
                    "address stability snapshot"
                    f"[{position}].addr_info[{address_position}] must be an object"
                )
            for field in ("valid_life_time", "preferred_life_time"):
                if field not in address:
                    continue
                lifetime = _finite_address_lifetime(address[field], field)
                if lifetime is not None:
                    address[field] = "<positive-finite-lifetime>"
    return projected


def _validate_address_lifetime_countdown(first: list, second: list) -> None:
    """Reject lease renewal while permitting only stable or decreasing timers."""
    for record_position, (first_record, second_record) in enumerate(
        zip(first, second)
    ):
        first_info = first_record.get("addr_info")
        if first_info is None:
            continue
        second_info = second_record["addr_info"]
        for address_position, (first_address, second_address) in enumerate(
            zip(first_info, second_info)
        ):
            for field in ("valid_life_time", "preferred_life_time"):
                if field not in first_address:
                    continue
                first_lifetime = _finite_address_lifetime(
                    first_address[field], field,
                )
                second_lifetime = _finite_address_lifetime(
                    second_address[field], field,
                )
                if (
                    first_lifetime is not None
                    and second_lifetime is not None
                    and second_lifetime > first_lifetime
                ):
                    raise ActivationError(
                        "IPv4 addresses changed while taking runtime snapshot: "
                        f"{field} increased at address snapshot"
                        f"[{record_position}].addr_info[{address_position}]"
                    )


def _route_stability_projection(snapshot: object) -> list:
    """Return an exact-copy projection after validating route record shape."""
    if not isinstance(snapshot, list):
        raise ActivationError("route stability snapshot must be a JSON array")
    projected = copy.deepcopy(snapshot)
    for position, record in enumerate(projected):
        if not isinstance(record, dict):
            raise ActivationError(
                f"route stability snapshot[{position}] must be an object"
            )
    return projected


def capture_stable_network_snapshot(runner=subprocess.run):
    """Read link/address/route state twice and reject a moving observation."""
    first_links = _run_json(("ip", "-d", "-j", "link", "show"), runner)
    first_addresses = _run_json(("ip", "-j", "-4", "address", "show"), runner)
    first_routes = _run_json(
        ("ip", "-j", "-4", "route", "show", "table", "all"), runner,
    )
    second_links = _run_json(("ip", "-d", "-j", "link", "show"), runner)
    second_addresses = _run_json(("ip", "-j", "-4", "address", "show"), runner)
    second_routes = _run_json(
        ("ip", "-j", "-4", "route", "show", "table", "all"), runner,
    )
    if _canonical_json(_link_stability_projection(first_links)) != _canonical_json(
        _link_stability_projection(second_links)
    ):
        raise ActivationError("network links changed while taking runtime snapshot")
    first_address_projection = _address_stability_projection(first_addresses)
    second_address_projection = _address_stability_projection(second_addresses)
    if _canonical_json(first_address_projection) != _canonical_json(
        second_address_projection
    ):
        raise ActivationError("IPv4 addresses changed while taking runtime snapshot")
    _validate_address_lifetime_countdown(first_addresses, second_addresses)
    if _canonical_json(_route_stability_projection(first_routes)) != _canonical_json(
        _route_stability_projection(second_routes)
    ):
        raise ActivationError("IPv4 routes changed while taking runtime snapshot")
    return first_links, first_addresses


def _load_runtime_module(http_root: Path):
    path = http_root / "tools/ztp_service_runtime.py"
    if not path.is_file():
        raise ActivationError(f"missing shared ZTP runtime module: {path}")
    name = "http_ztp_service_runtime"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise ActivationError(f"cannot import shared ZTP runtime module: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def validate_project_mount(settings: Settings) -> None:
    day0_path = settings.http_root / "DAY0-Prepare"
    project_path = day0_path / settings.project_name
    try:
        day0_metadata = day0_path.lstat()
        project_metadata = project_path.lstat()
    except OSError as exc:
        raise ActivationError(f"project mount is incomplete: {exc}") from exc
    if not stat.S_ISDIR(day0_metadata.st_mode):
        raise ActivationError(
            f"DAY0-Prepare must be a real directory, not a symlink: {day0_path}"
        )
    if not stat.S_ISDIR(project_metadata.st_mode):
        raise ActivationError(
            f"project must be a real directory, not a symlink: {project_path}"
        )
    try:
        day0 = day0_path.resolve(strict=True)
        project = project_path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActivationError(f"project mount is incomplete: {exc}") from exc
    if project != day0 / settings.project_name or project.parent != day0:
        raise ActivationError(
            f"project must be a direct child of {day0}: {project}"
        )
    for name in (
        "01-global.yaml", "02-devices_config.csv",
        "02-dhcp-subnet_config.csv",
    ):
        path = project_path / name
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ActivationError(
                f"project {name} must be one real regular file: {exc}"
            ) from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or resolved.parent != project
        ):
            raise ActivationError(
                f"project {name} must be one real regular file inside {project}"
            )


def build_runtime_plan(settings: Settings, runner=subprocess.run):
    validate_project_mount(settings)
    links, addresses = capture_stable_network_snapshot(runner)
    runtime = _load_runtime_module(settings.http_root)
    try:
        selected = runtime.plan_dhcp_runtime(
            settings.subnet_csv,
            link_snapshot=links,
            address_snapshot=addresses,
            allowlist=settings.allowlist,
            relay_ingress=settings.relay_ingress,
        )
    except Exception as exc:
        if isinstance(exc, ActivationError):
            raise
        raise ActivationError(str(exc)) from exc
    return selected, links, addresses, runtime


def sha256_path(path: Path) -> str:
    try:
        payload = path.read_bytes()
    except OSError as exc:
        raise ActivationError(f"cannot read activation input {path}: {exc}") from exc
    if not payload:
        raise ActivationError(f"activation input is empty: {path}")
    return hashlib.sha256(payload).hexdigest()


def _source_record(source_root: Path, relative_name: str) -> dict:
    """Describe one fixed runtime dependency without following an unsafe link."""
    relative = Path(relative_name)
    if (
        relative.is_absolute()
        or not relative.parts
        or ".." in relative.parts
        or relative.as_posix() != relative_name
    ):
        raise ActivationError(f"unsafe image source path: {relative_name!r}")
    try:
        root = source_root.resolve(strict=True)
        path = source_root / relative
        metadata = path.lstat()
    except OSError as exc:
        raise ActivationError(
            f"mounted runtime source is missing; rebuild image: {relative_name}: {exc}"
        ) from exc
    if metadata.st_nlink != 1:
        raise ActivationError(
            f"mounted runtime source has unsafe hard links; rebuild image: {relative_name}"
        )
    if relative_name == CONTAINER_TOPLEVEL_LOCK_NAME and (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_size == 0
        or metadata.st_size > 64 * 1024
    ):
        raise ActivationError(
            "top-level container lock must be a nonempty, bounded regular file; "
            f"rebuild image: {relative_name}"
        )
    target = None
    if stat.S_ISLNK(metadata.st_mode):
        try:
            target = os.readlink(path)
        except OSError as exc:
            raise ActivationError(
                f"cannot read runtime source symlink; rebuild image: {relative_name}: {exc}"
            ) from exc
        if not target or Path(target).is_absolute():
            raise ActivationError(
                f"runtime source symlink target is unsafe; rebuild image: {relative_name}"
            )
        source_type = "symlink"
    elif stat.S_ISREG(metadata.st_mode):
        source_type = "file"
    else:
        raise ActivationError(
            f"mounted runtime source type is unsafe; rebuild image: {relative_name}"
        )
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
        resolved_status = resolved.stat()
    except (OSError, RuntimeError, ValueError) as exc:
        raise ActivationError(
            f"runtime source escapes repository; rebuild image: {relative_name}: {exc}"
        ) from exc
    if not stat.S_ISREG(resolved_status.st_mode) or resolved_status.st_nlink != 1:
        raise ActivationError(
            f"resolved runtime source is unsafe; rebuild image: {relative_name}"
        )
    return {
        "path": relative_name,
        "type": source_type,
        "target": target,
        # Empty placeholder files in DAY0-Prepare/template are intentional
        # lifecycle inputs, unlike activation inputs where empty is invalid.
        "sha256": hashlib.sha256(resolved.read_bytes()).hexdigest(),
    }


def _source_path_selected(relative_name: str) -> bool:
    if path_disposition(relative_name) != "production":
        return False
    if relative_name in IMAGE_SOURCE_EXCLUDED_PATHS:
        return False
    if any(relative_name.startswith(prefix) for prefix in IMAGE_SOURCE_EXCLUDED_PREFIXES):
        return False
    path = Path(relative_name)
    if any(part in {"__pycache__", ".git", ".DS_Store"} for part in path.parts):
        return False
    if (
        len(path.parts) >= 3
        and path.parts[:2] == ("ztp", "optimize")
        and path.parts[2].endswith("-sample")
    ):
        return False
    if (
        relative_name.startswith("DAY0-Prepare/template/")
        and (
            path.name.casefold().startswith("readme")
            or path.suffix.casefold() in {".md", ".markdown"}
        )
    ):
        return False
    return path.name in IMAGE_SOURCE_EXACT_NAMES or path.suffix in IMAGE_SOURCE_SUFFIXES


def image_source_paths(source_root: Path) -> Tuple[str, ...]:
    """Select the exact deployable production/static source membership."""
    try:
        root = source_root.resolve(strict=True)
    except OSError as exc:
        raise ActivationError(f"cannot inspect image source root: {exc}") from exc
    selected = {CONTAINER_TOPLEVEL_LOCK_NAME}
    scan_roots = [root / name for name in IMAGE_SOURCE_SCAN_ROOTS]
    day0 = root / "DAY0-Prepare"
    if day0.is_dir():
        scan_roots.append(day0)
    for scan_root in scan_roots:
        if not scan_root.is_dir():
            raise ActivationError(
                f"image source tree is incomplete; rebuild image: {scan_root.relative_to(root)}"
            )
        for directory, dirnames, filenames in os.walk(scan_root, followlinks=False):
            directory_path = Path(directory)
            relative_directory = directory_path.relative_to(root)
            dirnames[:] = sorted(
                name for name in dirnames
                if name not in {"__pycache__", ".git"}
                and path_disposition(
                    (relative_directory / name).as_posix()
                ) == "production"
                and not (
                    relative_directory == Path("DAY0-Prepare")
                    and name != "template"
                )
                and not any(
                    (relative_directory / name).as_posix().startswith(prefix.rstrip("/"))
                    for prefix in IMAGE_SOURCE_EXCLUDED_PREFIXES
                )
            )
            for name in sorted(filenames):
                relative = (relative_directory / name).as_posix()
                if _source_path_selected(relative):
                    selected.add(relative)
                elif relative.startswith("DAY0-Prepare/template/"):
                    # The setup lifecycle recursively copies every template
                    # file, including intentionally empty image/key/XLSX
                    # placeholders; bind every member regardless of suffix.
                    lowered = name.casefold()
                    if not (
                        lowered.startswith("readme")
                        or lowered.endswith((".md", ".markdown"))
                    ):
                        selected.add(relative)
    if not selected:
        raise ActivationError("image source selection is empty; rebuild image")
    return tuple(sorted(selected))


def image_source_identity(source_root: Path) -> list:
    return [_source_record(source_root, name) for name in image_source_paths(source_root)]


def write_image_source_manifest(source_root: Path, manifest: Path) -> dict:
    payload = {
        "schema_version": IMAGE_SOURCE_SCHEMA,
        "files": image_source_identity(source_root),
    }
    _atomic_write(
        manifest,
        json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
        0o644,
    )
    return payload


def _read_image_source_manifest(manifest: Path) -> dict:
    try:
        payload = json.loads(
            _bounded_regular_bytes(
                manifest, "deployment source manifest", 16 * 1024 * 1024,
            ).decode("ascii")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(
            f"container image source manifest is unreadable; rebuild image: {exc}"
        ) from exc
    if (
        not isinstance(payload, dict)
        or payload.get("schema_version") != IMAGE_SOURCE_SCHEMA
        or set(payload) != {"schema_version", "files"}
        or not isinstance(payload.get("files"), list)
    ):
        raise ActivationError("container image source manifest is invalid; rebuild image")
    recorded = {}
    for record in payload["files"]:
        raw_path = record.get("path") if isinstance(record, dict) else None
        relative = Path(raw_path) if isinstance(raw_path, str) else None
        if (
            not isinstance(record, dict)
            or set(record) != {"path", "type", "target", "sha256"}
            or relative is None
            or relative.is_absolute()
            or not relative.parts
            or ".." in relative.parts
            or relative.as_posix() != raw_path
            or record["path"] in recorded
            or record.get("type") not in {"file", "symlink"}
            or (
                record.get("type") == "file"
                and record.get("target") is not None
            )
            or (
                record.get("type") == "symlink"
                and not isinstance(record.get("target"), str)
            )
            or not re.fullmatch(r"[0-9a-f]{64}", str(record.get("sha256") or ""))
        ):
            raise ActivationError(
                "container image source manifest has an invalid record; rebuild image"
            )
        recorded[record["path"]] = record
    return payload


def _runtime_contract(source_root: Path) -> dict:
    path = source_root / RUNTIME_CONTRACT_RELATIVE
    try:
        payload = json.loads(
            _bounded_regular_bytes(
                path, "Docker runtime compatibility contract", 64 * 1024,
            ).decode("ascii")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(
            f"Docker runtime compatibility contract is unreadable: {exc}"
        ) from exc
    contracts = payload.get("compatible_image_contracts") \
        if isinstance(payload, dict) else None
    contracts_are_valid = (
        isinstance(contracts, list)
        and bool(contracts)
        and all(
            isinstance(item, str)
            and re.fullmatch(r"[1-9][0-9]{0,7}", item) is not None
            for item in contracts
        )
    )
    if (
        not isinstance(payload, dict)
        or set(payload) != {"schema_version", "compatible_image_contracts"}
        or payload.get("schema_version") != 1
        or not contracts_are_valid
        or len(contracts) != len(set(contracts))
    ):
        raise ActivationError("Docker runtime compatibility contract is invalid")
    if IMAGE_RUNTIME_CONTRACT not in contracts:
        raise ActivationError(
            "live source is not compatible with Docker image contract "
            + IMAGE_RUNTIME_CONTRACT
        )
    return payload


def _image_compatibility_paths(image_records: Mapping[str, dict],
                               live_records: Mapping[str, dict]) -> set[str]:
    image_mutable = {
        path for path in image_records
        if any(pattern.fullmatch(path) for pattern in MUTABLE_IMAGE_SOURCE_PATTERNS)
    }
    live_mutable = {
        path for path in live_records
        if any(pattern.fullmatch(path) for pattern in MUTABLE_IMAGE_SOURCE_PATTERNS)
    }
    if image_mutable != live_mutable:
        raise ActivationError(
            "image-coupled mutable source membership changed; build a compatible image"
        )
    return set(IMAGE_COUPLED_SOURCE_PATHS) | image_mutable


def verify_compatible_live_source(
    source_root: Path, image_manifest: Path, *, allow_mutable_drift: bool = False,
) -> list:
    """Verify one live release, then enforce only the image-coupled subset."""
    live_manifest = source_root / "infra/docker/deployment-source-manifest.json"
    try:
        live = verify_image_source_manifest(
            source_root, live_manifest,
            allow_mutable_drift=allow_mutable_drift,
        )
    except ActivationError as exc:
        raise ActivationError(
            f"deployment source manifest does not match live source authority: {exc}"
        ) from exc
    image_payload = _read_image_source_manifest(image_manifest)
    image_records = {record["path"]: record for record in image_payload["files"]}
    live_records = {record["path"]: record for record in live}
    if RUNTIME_CONTRACT_RELATIVE not in image_records \
            or RUNTIME_CONTRACT_RELATIVE not in live_records:
        raise ActivationError(
            "Docker runtime compatibility contract is absent from source authority"
        )
    _runtime_contract(source_root)
    for relative_name in sorted(
        _image_compatibility_paths(image_records, live_records)
    ):
        image_record = image_records.get(relative_name)
        live_record = live_records.get(relative_name)
        if image_record is None or live_record is None:
            raise ActivationError(
                f"image-coupled source is missing: {relative_name}; "
                "build a compatible image"
            )
        if image_record != live_record:
            raise ActivationError(
                f"image-coupled source differs: {relative_name}; "
                "build a compatible image"
            )
    return live


def verify_image_source_manifest(
    source_root: Path, manifest: Path, *,
    allow_mutable_drift: bool = False,
) -> list:
    """Verify one tree against a separately supplied authority manifest."""
    payload = _read_image_source_manifest(manifest)
    recorded = {record["path"]: record for record in payload["files"]}
    actual = image_source_identity(source_root)
    actual_paths = {record["path"] for record in actual}
    if actual_paths != set(recorded):
        added = sorted(actual_paths - set(recorded))
        removed = sorted(set(recorded) - actual_paths)
        detail = []
        if added:
            detail.append("added=" + ",".join(added[:5]))
        if removed:
            detail.append("missing=" + ",".join(removed[:5]))
        raise ActivationError(
            "container image source membership drift; rebuild image"
            + (": " + "; ".join(detail) if detail else "")
        )
    for record in actual:
        expected = recorded[record["path"]]
        for field in ("type", "target", "sha256"):
            if (
                field == "sha256" and allow_mutable_drift
                and any(
                    pattern.fullmatch(record["path"])
                    for pattern in MUTABLE_IMAGE_SOURCE_PATTERNS
                )
            ):
                continue
            if record[field] != expected[field]:
                raise ActivationError(
                    f"container image source {field} drift for {record['path']}; "
                    "run sudo ./infra/docker/deploy.sh deploy to rebuild"
                )
    return actual


def validate_image_source_contract(
    settings: Settings, *, manifest: Path = DEFAULT_IMAGE_SOURCE_MANIFEST,
    allow_mutable_drift: bool = False,
) -> list:
    """Verify live authority and its compatibility with immutable image infra."""
    return verify_compatible_live_source(
        settings.http_root, manifest,
        allow_mutable_drift=allow_mutable_drift,
    )


def restore_mutable_image_sources(
    settings: Settings, *, manifest: Path = DEFAULT_IMAGE_SOURCE_MANIFEST,
    source_root: Path = DEFAULT_IMAGE_SOURCE_TREE,
) -> None:
    """Restore generator-mutated defaults from the immutable image copy."""
    payload = _read_image_source_manifest(manifest)
    recorded = {record["path"]: record for record in payload["files"]}
    for relative_name in sorted(recorded):
        if not any(
            pattern.fullmatch(relative_name)
            for pattern in MUTABLE_IMAGE_SOURCE_PATTERNS
        ):
            continue
        pristine = _source_record(source_root, relative_name)
        if pristine != recorded[relative_name] or pristine["type"] != "file":
            raise ActivationError(
                f"immutable generator default is invalid: {relative_name}"
            )
        destination = settings.http_root / relative_name
        try:
            metadata = destination.lstat()
        except OSError as exc:
            raise ActivationError(
                f"cannot restore generator default {relative_name}: {exc}"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationError(
                f"generator default is not one regular file: {relative_name}"
            )
        _atomic_write_bytes(destination, (source_root / relative_name).read_bytes(), 0o644)


def render_apache_listener_config(endpoint_ips: Iterable[str]) -> str:
    addresses = []
    for raw in endpoint_ips:
        raw_text = str(raw)
        try:
            parsed = ipaddress.IPv4Address(raw_text)
        except ipaddress.AddressValueError as exc:
            raise ActivationError(f"invalid Apache service IPv4: {raw!r}") from exc
        address = str(parsed)
        if (
            raw_text != address
            or parsed.is_unspecified
            or parsed.is_multicast
            or int(parsed) == 0xFFFFFFFF
        ):
            raise ActivationError(f"invalid Apache service IPv4: {raw!r}")
        if address in addresses:
            raise ActivationError(f"duplicate Apache service IPv4: {address}")
        addresses.append(address)
    lines = [
        "# Generated by /opt/http-ztp/activate.py; do not edit.",
        "# Exact host-network listeners only; wildcard binds are forbidden.",
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


def _atomic_write(path: Path, payload: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _snapshot_hash(snapshot: object) -> str:
    return hashlib.sha256(_canonical_json(snapshot).encode("ascii")).hexdigest()


def selected_interface_fingerprints(selected, links: object, addresses: object) -> list:
    """Bind only selected listeners to stable Linux identity and addressing."""
    if not isinstance(links, (list, tuple)) or not isinstance(addresses, (list, tuple)):
        raise ActivationError("network fingerprint snapshots must be arrays")
    names = tuple(selected.listener_names)
    indexes = tuple(selected.listener_ifindexes)
    if len(names) != len(indexes) or len(set(indexes)) != len(indexes):
        raise ActivationError("selected listener names/ifindexes are inconsistent")
    link_by_index = {}
    for record in links:
        if not isinstance(record, Mapping):
            raise ActivationError("link fingerprint record must be an object")
        try:
            ifindex = int(record.get("ifindex"))
        except (TypeError, ValueError) as exc:
            raise ActivationError("link fingerprint has invalid ifindex") from exc
        if ifindex in link_by_index:
            raise ActivationError(f"duplicate link fingerprint ifindex {ifindex}")
        link_by_index[ifindex] = record
    addresses_by_index = {}
    for record in addresses:
        if not isinstance(record, Mapping):
            raise ActivationError("address fingerprint record must be an object")
        try:
            ifindex = int(record.get("ifindex"))
        except (TypeError, ValueError) as exc:
            raise ActivationError("address fingerprint has invalid ifindex") from exc
        values = []
        raw_info = record.get("addr_info") or ()
        if not isinstance(raw_info, (list, tuple)):
            raise ActivationError("address fingerprint addr_info must be an array")
        for item in raw_info:
            if not isinstance(item, Mapping) or item.get("family") != "inet":
                continue
            try:
                value = str(ipaddress.IPv4Interface(
                    f"{item.get('local')}/{item.get('prefixlen')}"
                ))
            except ValueError as exc:
                raise ActivationError("address fingerprint has invalid IPv4 prefix") from exc
            if value not in values:
                values.append(value)
        addresses_by_index[ifindex] = sorted(values)
    result = []
    for expected_name, ifindex in zip(names, indexes):
        record = link_by_index.get(ifindex)
        if record is None or record.get("ifname") != expected_name:
            raise ActivationError(
                f"selected listener identity is absent: {expected_name}/{ifindex}"
            )
        mac = str(record.get("address") or "").strip().casefold()
        link_type = str(record.get("link_type") or "").strip().casefold()
        if not mac or not link_type:
            raise ActivationError(
                f"selected listener lacks MAC/link type: {expected_name}/{ifindex}"
            )
        raw_linkinfo = record.get("linkinfo") or {}
        if not isinstance(raw_linkinfo, Mapping):
            raise ActivationError(f"selected listener has invalid linkinfo: {expected_name}")
        link_kind = raw_linkinfo.get("info_kind")
        link_kind = str(link_kind).strip().casefold() if link_kind is not None else None
        raw_info_data = raw_linkinfo.get("info_data") or {}
        if not isinstance(raw_info_data, Mapping):
            raise ActivationError(f"selected listener has invalid link info data: {expected_name}")
        vlan_id = raw_info_data.get("id") if link_kind == "vlan" else None
        if vlan_id is not None:
            try:
                vlan_id = int(vlan_id)
            except (TypeError, ValueError) as exc:
                raise ActivationError(f"selected VLAN has invalid ID: {expected_name}") from exc
            if vlan_id < 1 or vlan_id > 4094:
                raise ActivationError(f"selected VLAN has invalid ID: {expected_name}")
        parent_ifindex = record.get("link_index")
        parent_ifname = None
        parent_mac = None
        if parent_ifindex is not None:
            try:
                parent_ifindex = int(parent_ifindex)
            except (TypeError, ValueError) as exc:
                raise ActivationError(f"selected listener has invalid parent: {expected_name}") from exc
            parent = link_by_index.get(parent_ifindex)
            if parent is None:
                raise ActivationError(f"selected listener parent is absent: {expected_name}")
            parent_ifname = str(parent.get("ifname") or "")
            parent_mac = str(parent.get("address") or "").strip().casefold()
            if not parent_ifname or not parent_mac:
                raise ActivationError(f"selected listener parent is incomplete: {expected_name}")
        result.append({
            "ifindex": ifindex,
            "ifname": expected_name,
            "mac": mac,
            "link_type": link_type,
            "link_kind": link_kind,
            "vlan_id": vlan_id,
            "parent_ifindex": parent_ifindex,
            "parent_ifname": parent_ifname,
            "parent_mac": parent_mac,
            "ipv4_addresses": addresses_by_index.get(ifindex, []),
        })
    return result


def runtime_plan_payload(
    settings: Settings, selected, links: object, addresses: object,
) -> dict:
    return {
        "schema_version": PLAN_SCHEMA,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "project": settings.project_name,
        "scope": settings.scope,
        "switch_scope": settings.switch_scope,
        "mini": settings.mini,
        "subnet_csv": os.fspath(settings.subnet_csv),
        "subnet_sha256": sha256_path(settings.subnet_csv),
        "listener_names": list(selected.listener_names),
        "listener_ifindexes": list(selected.listener_ifindexes),
        "direct_shared_networks": list(selected.direct_shared_networks),
        "relay_shared_networks": list(selected.relay_shared_networks),
        "dhcp_only_shared_networks": list(
            getattr(selected, "dhcp_only_shared_networks", ())
        ),
        "endpoint_ips": list(selected.endpoint_ips),
        "listener_fingerprints": selected_interface_fingerprints(
            selected, links, addresses,
        ),
        "link_snapshot_sha256": _snapshot_hash(links),
        "address_snapshot_sha256": _snapshot_hash(addresses),
    }


def ensure_runtime_directories(settings: Settings) -> None:
    for path, mode in (
        (settings.state_root, 0o700),
        (settings.log_root, 0o750),
        (settings.log_root / "apache2", 0o750),
        (settings.dhcp_leases.parent, 0o755),
        (settings.http_root / "monitor/status", 0o775),
        (Path("/run/http-ztp"), 0o700),
        (Path("/run/http-ztp/askpass"), 0o700),
        (Path("/run/apache2"), 0o755),
        # Ubuntu publishes /var/lock as a symlink to /run/lock. Docker mounts
        # a fresh tmpfs at /run, so restore the canonical sticky lock root
        # before descending through the distribution-owned compatibility link.
        (Path("/run/lock"), 0o1777),
        (Path("/var/lock/apache2"), 0o755),
        (Path("/var/spool/rsyslog"), 0o755),
        (Path("/root/.ssh"), 0o700),
    ):
        path.mkdir(parents=True, exist_ok=True)
        os.chmod(path, mode)
    if not settings.dhcp_leases.exists():
        descriptor = os.open(
            settings.dhcp_leases,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o640,
        )
        os.close(descriptor)


def _www_data_gid() -> int:
    try:
        return int(grp.getgrnam("www-data").gr_gid)
    except KeyError as exc:
        raise ActivationError("required runtime group does not exist: www-data") from exc


def _worker_control_parents(settings: Settings) -> dict[Path, Path]:
    """Validate the two exact directories that own worker control state.

    ``ztp/status`` is deliberately not created by the container bootstrap.  It
    is a setup-owned publication link selecting the current project's
    ``99-output-ztp`` directory, so post-load initialization must prove that
    exact link before following it.  ``monitor/status`` is container-owned and
    must remain a canonical real directory in the mounted HTTP tree.
    """
    try:
        root = settings.http_root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActivationError(f"HTTP root is unavailable for worker controls: {exc}") from exc

    monitor_status = settings.http_root / "monitor/status"
    expected_monitor_status = root / "monitor/status"
    try:
        monitor_metadata = monitor_status.lstat()
        monitor_resolved = monitor_status.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActivationError(f"monitor status directory is unsafe: {exc}") from exc
    if (
        not stat.S_ISDIR(monitor_metadata.st_mode)
        or monitor_resolved != expected_monitor_status
    ):
        raise ActivationError(
            "monitor status directory must be one canonical real directory"
        )

    ztp_status = settings.http_root / "ztp/status"
    expected_raw_target = (
        f"../DAY0-Prepare/{settings.project_name}/99-output-ztp"
    )
    project_output = (
        settings.http_root
        / "DAY0-Prepare" / settings.project_name / "99-output-ztp"
    )
    expected_project_output = (
        root / "DAY0-Prepare" / settings.project_name / "99-output-ztp"
    )
    try:
        link_metadata = ztp_status.lstat()
        raw_target = os.readlink(ztp_status)
        output_metadata = project_output.lstat()
        output_resolved = project_output.resolve(strict=True)
        link_resolved = ztp_status.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ActivationError(
            f"setup-owned ztp status link is missing or unsafe: {exc}"
        ) from exc
    if (
        not stat.S_ISLNK(link_metadata.st_mode)
        or link_metadata.st_nlink != 1
        or raw_target != expected_raw_target
        or not stat.S_ISDIR(output_metadata.st_mode)
        or output_resolved != expected_project_output
        or link_resolved != expected_project_output
    ):
        raise ActivationError(
            "setup-owned ztp status link is non-canonical or does not select "
            "the current project"
        )
    return {
        Path("ztp/status"): expected_project_output,
        Path("monitor/status"): expected_monitor_status,
    }


def initialize_worker_control_files(
    settings: Settings, *, owner_uid: int = 0, owner_gid: Optional[int] = None,
) -> None:
    """Reset all three CGI/worker controls after a successful no-start load.

    The complete target set is inspected before any existing state is changed.
    This prevents a symlink, FIFO, device or hard-link substitution in one
    target from causing a partial reset of the others.  Workers and Apache are
    still stopped while hostctl calls this function under the deployment lock.
    """
    if owner_uid < 0:
        raise ActivationError("worker control owner UID must be non-negative")
    if owner_gid is None:
        owner_gid = _www_data_gid()
    if owner_gid < 0:
        raise ActivationError("worker control owner GID must be non-negative")

    canonical_parents = _worker_control_parents(settings)
    targets = []
    for relative, payload in WORKER_CONTROL_DEFAULTS:
        parent_relative = relative.parent
        canonical_parent = canonical_parents.get(parent_relative)
        if canonical_parent is None:
            raise ActivationError(f"unknown worker control parent: {parent_relative}")
        # Access the leaf through the already validated canonical real parent,
        # not through the setup-owned publication symlink itself.
        path = canonical_parent / relative.name
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            metadata = None
        except OSError as exc:
            raise ActivationError(f"cannot inspect worker control/request {path}: {exc}") from exc
        if metadata is not None and (
            not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
        ):
            raise ActivationError(
                f"worker control/request must be one regular single-link file: {path}"
            )
        targets.append((path, payload, metadata, canonical_parent))

    opened = []
    created = []
    try:
        for path, payload, expected, canonical_parent in targets:
            flags = (
                os.O_RDWR | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            descriptor = None
            try:
                if expected is None:
                    flags |= os.O_CREAT | os.O_EXCL
                    descriptor = os.open(path, flags, 0o664)
                    created_status = os.fstat(descriptor)
                    created.append(
                        (path, created_status.st_dev, created_status.st_ino)
                    )
                else:
                    descriptor = os.open(path, flags)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                current = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or (
                        expected is not None
                        and (current.st_dev, current.st_ino)
                        != (expected.st_dev, expected.st_ino)
                    )
                ):
                    raise ActivationError(
                        f"worker control/request changed or is not one regular "
                        f"single-link file: {path}"
                    )
                opened.append((path, payload, descriptor, canonical_parent))
            except BaseException:
                if descriptor is not None:
                    os.close(descriptor)
                raise

        for path, payload, descriptor, _canonical_parent in opened:
            os.fchown(descriptor, owner_uid, owner_gid)
            os.fchmod(descriptor, 0o664)
            os.lseek(descriptor, 0, os.SEEK_SET)
            os.ftruncate(descriptor, 0)
            remaining = memoryview(payload)
            while remaining:
                written = os.write(descriptor, remaining)
                if written <= 0:
                    raise OSError(f"short write initializing {path}")
                remaining = remaining[written:]
            os.fsync(descriptor)

        for directory in sorted({item[3] for item in opened}):
            descriptor = os.open(
                directory,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0),
            )
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    except ActivationError:
        raise
    except OSError as exc:
        raise ActivationError(
            f"cannot initialize worker control/request files: {exc}"
        ) from exc
    finally:
        for _path, _payload, descriptor, _canonical_parent in reversed(opened):
            try:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            except OSError:
                pass
            os.close(descriptor)
        # If opening the complete target set failed, remove only files created
        # by this attempt and only while their original descriptor identity is
        # still present.  Existing files have not yet been truncated here.
        if len(opened) != len(targets):
            for path, device, inode in reversed(created):
                try:
                    current = path.lstat()
                    if (
                        stat.S_ISREG(current.st_mode)
                        and current.st_nlink == 1
                        and (current.st_dev, current.st_ino)
                        == (device, inode)
                    ):
                        path.unlink()
                except OSError:
                    pass


def _bounded_regular_bytes(path: Path, label: str, maximum_size: int) -> bytes:
    try:
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size > maximum_size
        ):
            raise ActivationError(f"{label} must be one bounded regular file")
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
    except ActivationError:
        raise
    except OSError as exc:
        raise ActivationError(f"cannot open {label}: {exc}") from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or metadata.st_nlink != 1
            or opened.st_nlink != 1
            or (metadata.st_dev, metadata.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_size > maximum_size
        ):
            raise ActivationError(f"{label} must be one bounded regular file")
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ActivationError(f"{label} was truncated while reading")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ActivationError(f"{label} grew while reading")
        after = os.fstat(descriptor)
        if (
            after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
        ) != (
            opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
        ):
            raise ActivationError(f"{label} changed while reading")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _verify_control_auth_image_directory(
    path: Path,
    expected_mode: int,
    *,
    required_uid: int,
    required_gid: int,
) -> None:
    """Prove one immutable helper parent without following its last component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ActivationError(
            "control auth image helper directory authority is unavailable"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        after = path.lstat()
    except OSError as exc:
        raise ActivationError(
            "control auth image helper directory authority cannot be verified"
        ) from exc
    finally:
        os.close(descriptor)
    identity = lambda value: (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_nlink,
        value.st_uid,
        value.st_gid,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )
    if (
        not stat.S_ISDIR(before.st_mode)
        or not stat.S_ISDIR(opened.st_mode)
        or not stat.S_ISDIR(after.st_mode)
        or identity(before) != identity(opened)
        or identity(opened) != identity(after)
        or any(
            metadata.st_uid != required_uid
            or metadata.st_gid != required_gid
            or stat.S_IMODE(metadata.st_mode) != expected_mode
            for metadata in (before, opened, after)
        )
    ):
        raise ActivationError(
            "control auth image helper directory owner or mode is invalid"
        )


def _control_auth_image_helper_bytes(
    path: Path,
    *,
    required_uid: int,
    required_gid: int,
) -> bytes:
    """Read one stable root-owned installed helper through a no-follow FD."""
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        before = path.lstat()
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ActivationError(
            "control auth image helper must be one real regular file"
        ) from exc
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or not stat.S_ISREG(opened.st_mode)
            or before.st_nlink != 1
            or opened.st_nlink != 1
            or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
            or opened.st_uid != required_uid
            or opened.st_gid != required_gid
            or stat.S_IMODE(opened.st_mode) != 0o755
            or opened.st_size <= 0
            or opened.st_size > CONTROL_AUTH_HELPER_SIZE_LIMIT
        ):
            raise ActivationError(
                "control auth image helper owner, mode, link count, or size is invalid"
            )
        chunks = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise ActivationError(
                    "control auth image helper changed while being read"
                )
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ActivationError("control auth image helper grew while being read")
        held_after = os.fstat(descriptor)
        rebound = path.lstat()
        stable_fields = lambda value: (
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_nlink,
            value.st_uid,
            value.st_gid,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )
        if (
            stable_fields(opened) != stable_fields(held_after)
            or stable_fields(held_after) != stable_fields(rebound)
        ):
            raise ActivationError(
                "control auth image helper binding changed during verification"
            )
        return b"".join(chunks)
    except OSError as exc:
        raise ActivationError(
            "control auth image helper cannot be read or rebound"
        ) from exc
    finally:
        os.close(descriptor)


def verify_control_auth_image_copies(
    *,
    source_helper: Path = CONTROL_AUTH_IMAGE_SOURCE_HELPER,
    lifecycle_helper: Path = CONTROL_AUTH_HELPER,
    status_helper: Path = CONTROL_AUTH_STATUS_HELPER,
    directory_contracts: Sequence[tuple[Path, int]] = (
        CONTROL_AUTH_IMAGE_DIRECTORY_CONTRACTS
    ),
    manifest: Path = DEFAULT_IMAGE_SOURCE_MANIFEST,
    expected_sha256: str = CONTROL_AUTH_HELPER_SHA256,
    required_uid: int = 0,
    required_gid: int = 0,
) -> dict[str, object]:
    """Bind source, root lifecycle and CGI-status helper bytes to one image."""
    if re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is None:
        raise ActivationError("control auth image helper digest authority is invalid")
    payload = _read_image_source_manifest(manifest)
    records = {record["path"]: record for record in payload["files"]}
    if records.get("tools/control-auth.py") != {
        "path": "tools/control-auth.py",
        "type": "file",
        "target": None,
        "sha256": expected_sha256,
    }:
        raise ActivationError(
            "control auth image helper manifest authority does not match"
        )

    for directory, mode in directory_contracts:
        _verify_control_auth_image_directory(
            Path(directory), mode,
            required_uid=required_uid, required_gid=required_gid,
        )
    helpers = (Path(source_helper), Path(lifecycle_helper), Path(status_helper))
    contents = tuple(
        _control_auth_image_helper_bytes(
            helper, required_uid=required_uid, required_gid=required_gid,
        )
        for helper in helpers
    )
    if any(
        not hmac.compare_digest(
            hashlib.sha256(content).hexdigest(), expected_sha256,
        )
        for content in contents
    ) or not all(
        hmac.compare_digest(contents[0], content) for content in contents[1:]
    ):
        raise ActivationError(
            "control auth image helper digest or byte identity does not match"
        )
    for directory, mode in directory_contracts:
        _verify_control_auth_image_directory(
            Path(directory), mode,
            required_uid=required_uid, required_gid=required_gid,
        )
    return {"verified": True, "copies": 3}


def _container_os_release(
    path: Path = Path("/etc/os-release"),
) -> Mapping[str, str]:
    """Read only the fixed OS identity fields needed by the image contract."""

    try:
        alias_before = path.lstat()
    except OSError as exc:
        raise ActivationError(f"cannot open container OS release: {exc}") from exc
    if stat.S_ISREG(alias_before.st_mode):
        raw = _bounded_regular_bytes(path, "container OS release", 64 * 1024)
    elif stat.S_ISLNK(alias_before.st_mode):
        if (
            path.name != "os-release"
            or path.parent.name != "etc"
            or alias_before.st_nlink != 1
        ):
            raise ActivationError(
                "container OS release must use the canonical safe alias"
            )
        try:
            raw_target = os.readlink(path)
        except OSError as exc:
            raise ActivationError(
                f"cannot inspect container OS release alias: {exc}"
            ) from exc
        if raw_target != "../usr/lib/os-release":
            raise ActivationError(
                "container OS release must use the canonical safe alias"
            )
        canonical = path.parent.parent / "usr/lib/os-release"
        try:
            resolved = path.resolve(strict=True)
            canonical_resolved = canonical.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ActivationError(
                f"container OS release canonical alias is invalid: {exc}"
            ) from exc
        if resolved != canonical_resolved:
            raise ActivationError(
                "container OS release canonical alias resolved unexpectedly"
            )
        raw = _bounded_regular_bytes(
            canonical, "container OS release canonical target", 64 * 1024,
        )
        try:
            alias_after = path.lstat()
            target_after = os.readlink(path)
            resolved_after = path.resolve(strict=True)
            canonical_after = canonical.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ActivationError(
                f"container OS release canonical alias changed: {exc}"
            ) from exc
        before_identity = (
            alias_before.st_dev, alias_before.st_ino, alias_before.st_mode,
            alias_before.st_nlink, alias_before.st_size, alias_before.st_mtime_ns,
        )
        after_identity = (
            alias_after.st_dev, alias_after.st_ino, alias_after.st_mode,
            alias_after.st_nlink, alias_after.st_size, alias_after.st_mtime_ns,
        )
        if (
            before_identity != after_identity
            or target_after != raw_target
            or resolved_after != canonical_after
            or canonical_after != canonical_resolved
        ):
            raise ActivationError("container OS release canonical alias changed")
    else:
        raise ActivationError(
            "container OS release must be a bounded regular file or canonical safe alias"
        )
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise ActivationError("container OS release is not UTF-8") from exc
    values = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        if key not in {"ID", "VERSION_ID"}:
            continue
        value = value.strip()
        if len(value) >= 2 and value[:1] == value[-1:] and value[:1] in {"'", '"'}:
            value = value[1:-1]
        if not re.fullmatch(r"[A-Za-z0-9._-]+", value):
            raise ActivationError("container OS release identity is invalid")
        values[key] = value
    return values


def verify_deployment_image(
    source_root: Path,
    image_manifest: Path = DEFAULT_IMAGE_SOURCE_MANIFEST,
    *,
    os_release: Path = Path("/etc/os-release"),
) -> list:
    """Verify an imported image against Ubuntu and the locked live source."""

    release = _container_os_release(os_release)
    if release.get("ID") != "ubuntu" or release.get("VERSION_ID") != "24.04":
        raise ActivationError("preloaded image must contain Ubuntu 24.04")
    return verify_compatible_live_source(source_root, image_manifest)


def ensure_docker_deployment_owner(
    settings: Settings, *,
    image_manifest: Path = DEFAULT_IMAGE_SOURCE_MANIFEST,
) -> None:
    """Persist the Docker backend even while its named container is absent."""
    path = settings.state_root / "deployment-owner.json"
    manifest = settings.http_root / "infra/docker/deployment-source-manifest.json"
    verify_compatible_live_source(settings.http_root, image_manifest)
    live_manifest_bytes = _bounded_regular_bytes(
        manifest, "deployment source manifest", 16 * 1024 * 1024,
    )
    manifest_sha256 = hashlib.sha256(live_manifest_bytes).hexdigest()
    expected = {
        "schema_version": 2,
        "runtime": "docker",
        "http_root": os.fspath(settings.http_root),
        "source_manifest_sha256": manifest_sha256,
    }
    if os.path.lexists(path):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ActivationError(f"cannot inspect Docker owner marker: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationError("Docker owner marker must be one regular file")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(path, flags)
            try:
                current = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(current.st_mode)
                    or current.st_nlink != 1
                    or (current.st_dev, current.st_ino)
                    != (metadata.st_dev, metadata.st_ino)
                    or current.st_size > 4096
                ):
                    raise ActivationError("Docker owner marker changed during validation")
                payload = os.read(descriptor, 4097)
            finally:
                os.close(descriptor)
            actual = json.loads(payload.decode("utf-8"))
        except ActivationError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise ActivationError(f"Docker owner marker is unreadable: {exc}") from exc
        legacy = {
            "schema_version": 1, "runtime": "docker",
            "http_root": os.fspath(settings.http_root),
        }
        if actual not in (legacy, expected):
            raise ActivationError("Docker owner marker does not match this deployment")
        if actual == expected:
            return
    _atomic_write(
        path, json.dumps(expected, ensure_ascii=False, sort_keys=True) + "\n", 0o600,
    )


def observe_runtime(settings: Settings, runner=subprocess.run):
    """Build the current plan and rendered config without changing any file."""
    selected, links, addresses, runtime = build_runtime_plan(settings, runner)
    apache = render_apache_listener_config(selected.endpoint_ips)
    payload = runtime_plan_payload(settings, selected, links, addresses)
    payload["apache_listener_sha256"] = hashlib.sha256(
        apache.encode("utf-8")
    ).hexdigest()
    return selected, runtime, payload, apache


def prepare_runtime(settings: Settings, runner=subprocess.run):
    """Explicitly publish a freshly observed plan and exact Apache listeners."""
    ensure_runtime_directories(settings)
    selected, runtime, payload, apache = observe_runtime(settings, runner)
    _atomic_write(settings.apache_listeners, apache, 0o644)
    _atomic_write(
        settings.runtime_plan,
        json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    return selected, runtime, payload


def expected_services(selected) -> Tuple[str, ...]:
    services = []
    if selected.endpoint_ips:
        services.append("apache2")
    if selected.listener_names:
        services.append("dhcpd")
    if selected.endpoint_ips and selected.listener_names:
        services.extend(("ztp-monitor", "switch-collection", "manual-ztp"))
    return tuple(services)


def _safe_cgi_source(settings: Settings, relative: Path) -> Path:
    source = settings.http_root / relative
    try:
        metadata = source.lstat()
    except OSError as exc:
        raise ActivationError(f"missing control CGI source {source}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationError(f"control CGI source must be one regular file: {source}")
    try:
        source.resolve(strict=True).relative_to(settings.http_root.resolve(strict=True))
    except (OSError, ValueError) as exc:
        raise ActivationError(f"control CGI escapes HTTP root: {source}") from exc
    return source


def _atomic_write_bytes(path: Path, payload: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def install_control_cgi(
    settings: Settings, *, cgi_root: Path = Path("/usr/lib/cgi-bin"),
) -> None:
    """Install exact CGI bytes from the locked repository mount."""
    for relative, destination_name in CONTROL_CGI:
        source = _safe_cgi_source(settings, relative)
        payload = source.read_bytes()
        if not payload:
            raise ActivationError(f"control CGI source is empty: {source}")
        _atomic_write_bytes(cgi_root / destination_name, payload, 0o755)


def validate_control_cgi(
    settings: Settings, *, cgi_root: Path = Path("/usr/lib/cgi-bin"),
) -> None:
    for relative, destination_name in CONTROL_CGI:
        source = _safe_cgi_source(settings, relative)
        destination = cgi_root / destination_name
        try:
            metadata = destination.lstat()
            actual = destination.read_bytes()
        except OSError as exc:
            raise ActivationError(f"control CGI is missing: {destination}: {exc}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationError(f"control CGI target is not one regular file: {destination}")
        if hashlib.sha256(actual).digest() != hashlib.sha256(source.read_bytes()).digest():
            raise ActivationError(f"control CGI hash mismatch: {destination}")
        if metadata.st_mode & 0o111 == 0:
            raise ActivationError(f"control CGI is not executable: {destination}")


def worker_spec(name: str, settings: Settings) -> WorkerSpec:
    python = "/usr/bin/python3"
    if name == "ztp-monitor":
        status = settings.http_root / "ztp/status"
        return WorkerSpec((
            python, "-u",
            os.fspath(settings.http_root / "DAY0-Prepare/12-ztp-monitor.py"),
            os.fspath(settings.project_dir),
            "--watch", str(settings.monitor_interval),
            "--generate-html",
            "--known-hosts", os.fspath(status / "ztp-known-hosts"),
            "--dhcp-leases", os.fspath(settings.dhcp_leases),
            "--scope", settings.scope,
        ), status / "ztp-monitor.pid")
    if name == "switch-collection":
        return WorkerSpec((
            python, "-u",
            os.fspath(settings.http_root / "monitor/switch-collection-worker.py"),
            "--scope", settings.scope,
        ), settings.http_root / "monitor/status/switch-collection.pid")
    if name == "manual-ztp":
        return WorkerSpec((
            python, "-u",
            os.fspath(settings.http_root / "monitor/manual-ztp-worker.py"),
            "--scope", settings.scope,
        ), settings.http_root / "monitor/status/manual-ztp.pid")
    raise ActivationError(f"unknown worker: {name}")


def clear_stale_worker_pid_files(settings: Settings) -> None:
    """Remove only the three Supervisor-owned persistent worker PID files.

    The HTTP tree survives container replacement.  A PID from the previous
    PID namespace must never be accepted by a control CGI in the new one.
    Validate the entire exact target set before unlinking anything so a
    symlink or special-file substitution fails closed without partial cleanup.
    """
    paths = tuple(
        worker_spec(name, settings).pid_file
        for name in ("ztp-monitor", "switch-collection", "manual-ztp")
    )
    identities = []
    root = settings.http_root.resolve(strict=True)
    for path in paths:
        try:
            metadata = path.lstat()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise ActivationError(f"cannot inspect stale worker PID file {path}: {exc}") from exc
        try:
            path.parent.resolve(strict=True).relative_to(root)
        except (OSError, ValueError) as exc:
            raise ActivationError(f"worker PID directory escapes HTTP root: {path}") from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationError(
                f"worker PID target must be one regular file: {path}"
            )
        identities.append((path, metadata.st_dev, metadata.st_ino))
    for path, device, inode in identities:
        try:
            current = path.lstat()
        except OSError as exc:
            raise ActivationError(f"stale worker PID file changed: {path}: {exc}") from exc
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_nlink != 1
            or current.st_dev != device
            or current.st_ino != inode
        ):
            raise ActivationError(f"stale worker PID file changed: {path}")
        path.unlink()
    for directory in sorted({path.parent for path, _dev, _ino in identities}):
        descriptor = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def _activation_files(
    settings: Settings,
    subnet_csv: Optional[Path],
    dhcp_config: Optional[Path],
    release_manifest: Optional[Path],
):
    return (
        subnet_csv or settings.subnet_csv,
        dhcp_config or settings.dhcp_config,
        release_manifest or settings.release_manifest,
    )


def _load_json_object(path: Path, label: str) -> dict:
    try:
        payload = json.loads(
            _bounded_regular_bytes(path, label, 16 * 1024 * 1024).decode("utf-8")
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"cannot read {label} {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise ActivationError(f"{label} must be a JSON object: {path}")
    return payload


def _hash_matches(path: Path, expected: object, label: str) -> None:
    value = str(expected or "").strip().casefold()
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ActivationError(f"{label} has invalid SHA-256")
    actual = sha256_path(path)
    if actual != value:
        raise ActivationError(
            f"{label} hash drift: {path}: actual={actual}, expected={value}"
        )


def _canonical_regular_within(path: Path, root: Path, label: str) -> Path:
    """Require a single-link regular leaf with no alias in its path."""
    canonical_root = root.resolve(strict=True)
    try:
        relative = path.relative_to(root)
    except ValueError:
        try:
            relative = path.relative_to(canonical_root)
        except ValueError as exc:
            raise ActivationError(f"{label} is outside its authority") from exc
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
        resolved.relative_to(canonical_root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise ActivationError(f"{label} is missing or escapes its authority: {exc}") from exc
    expected = canonical_root / relative
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or resolved != expected
    ):
        raise ActivationError(
            f"{label} must be one canonical real regular file within {canonical_root}"
        )
    return resolved


def _matching_p2p_input(project: Path, expected: object) -> Path:
    value = str(expected or "").strip().casefold()
    canonical_project = project.resolve(strict=True)
    candidates = [project / "p2p.xlsx"]
    candidates.extend(sorted(project.glob("*.xlsx")))
    p2p_dir = project / "p2p"
    if p2p_dir.is_dir():
        candidates.extend(sorted(p2p_dir.glob("*.xlsx")))
    seen = set()
    for candidate in candidates:
        try:
            metadata = candidate.lstat()
            lexical_parent = candidate.parent.resolve(strict=True)
            if lexical_parent not in {
                canonical_project, canonical_project / "p2p",
            }:
                continue
            if stat.S_ISLNK(metadata.st_mode):
                if candidate != project / "p2p.xlsx" or metadata.st_nlink != 1:
                    continue
                target = os.readlink(candidate)
                if Path(target).is_absolute():
                    continue
                target_path = Path(
                    os.path.abspath(os.path.join(lexical_parent, target))
                )
                if target != os.path.relpath(target_path, lexical_parent):
                    continue
                if target_path.parent not in {
                    canonical_project, canonical_project / "p2p",
                }:
                    continue
                identity = _canonical_regular_within(
                    target_path, canonical_project,
                    "parent release P2P input target",
                )
            elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
                identity = candidate.resolve(strict=True)
                identity.relative_to(canonical_project)
                if identity != canonical_project / candidate.relative_to(project):
                    continue
            else:
                continue
        except (ActivationError, OSError, RuntimeError, ValueError):
            continue
        if identity in seen:
            continue
        seen.add(identity)
        if sha256_path(identity) == value:
            return identity
    raise ActivationError("parent release P2P input no longer matches any project XLSX")


def validate_parent_release(settings: Settings, release_manifest: Path) -> dict:
    """Bind an activation marker to current inputs and child release manifests."""
    validate_project_mount(settings)
    parent = _load_json_object(release_manifest, "parent current release")
    parent_scope = str(parent.get("deployment_scope") or "")
    if parent_scope != settings.scope:
        raise ActivationError(
            "parent release deployment scope does not match container runtime: "
            f"{parent_scope!r} != {settings.scope!r}"
        )
    parent_switch_scope = str(parent.get("switch_scope") or "")
    if parent_switch_scope != settings.switch_scope:
        raise ActivationError(
            "parent release switch scope does not match container runtime: "
            f"{parent_switch_scope!r} != {settings.switch_scope!r}"
        )
    inputs = parent.get("inputs")
    if not isinstance(inputs, dict):
        raise ActivationError("parent current release has no inputs hash object")
    allowed_inputs = {
        "global", "devices", "subnet", "p2p", "air_topology_policy",
        "mini_air_devices",
    }
    if not {"global", "devices", "subnet", "p2p"}.issubset(inputs):
        raise ActivationError("parent current release is missing required input hashes")
    has_mini_input = "mini_air_devices" in inputs
    if has_mini_input != settings.mini:
        raise ActivationError(
            "parent release mini selection does not match container runtime"
        )
    unknown = sorted(set(inputs) - allowed_inputs)
    if unknown:
        raise ActivationError(
            "parent current release has unsupported inputs: " + ", ".join(unknown)
        )
    project = settings.project_dir
    canonical_project = project.resolve(strict=True)
    fixed = {
        "global": project / "01-global.yaml",
        "devices": project / "02-devices_config.csv",
        "subnet": project / "02-dhcp-subnet_config.csv",
        "air_topology_policy": project / "03-air-topology-policy.json",
        "mini_air_devices": project / "04-air-mini-devices.txt",
    }
    for key, expected in inputs.items():
        if key == "p2p":
            _matching_p2p_input(project, expected)
        else:
            _canonical_regular_within(
                fixed[key], project, f"parent release input {key}",
            )
            _hash_matches(fixed[key], expected, f"parent release input {key}")

    components = parent.get("components")
    if not isinstance(components, dict):
        raise ActivationError("parent current release has no components object")
    component_identity = {}
    for name, raw_component in components.items():
        if name not in {"cumulus", "nvos", "dhcp"} or not isinstance(raw_component, dict):
            raise ActivationError(f"parent release has invalid component: {name}")
        if name == "dhcp":
            dhcp_directory = settings.http_root / "ztp/config/isc-dhcp-server"
            try:
                dhcp_directory_metadata = dhcp_directory.lstat()
                expected_dhcp_directory = (
                    settings.http_root.resolve(strict=True)
                    / "ztp/config/isc-dhcp-server"
                )
                canonical_dhcp_directory = dhcp_directory.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ActivationError(f"parent release dhcp directory is unsafe: {exc}") from exc
            if (
                not stat.S_ISDIR(dhcp_directory_metadata.st_mode)
                or canonical_dhcp_directory != expected_dhcp_directory
            ):
                raise ActivationError(
                    "parent release dhcp directory must be canonical in HTTP root"
                )
            manifest_path = dhcp_directory / "dhcp-release-manifest.json"
            expected_manifest = (
                canonical_project / "99-output-dhcp/dhcp-release-manifest.json"
            )
            try:
                public_metadata = manifest_path.lstat()
                if (
                    not stat.S_ISLNK(public_metadata.st_mode)
                    or public_metadata.st_nlink != 1
                ):
                    raise ActivationError(
                        "parent release dhcp manifest publication must be one symlink"
                    )
                public_target = os.readlink(manifest_path)
                expected_target = os.path.relpath(
                    expected_manifest, canonical_dhcp_directory,
                )
                if public_target != expected_target:
                    raise ActivationError(
                        "parent release dhcp manifest target is non-canonical or "
                        "does not select current project"
                    )
                _canonical_regular_within(
                    expected_manifest,
                    canonical_project / "99-output-dhcp",
                    "parent release dhcp manifest target",
                )
                if manifest_path.resolve(strict=True) != expected_manifest:
                    raise ActivationError(
                        "parent release dhcp manifest does not select current project"
                    )
            except ActivationError:
                raise
            except (OSError, RuntimeError) as exc:
                raise ActivationError(
                    f"parent release dhcp manifest publication is unsafe: {exc}"
                ) from exc
        else:
            raw_directory = str(raw_component.get("release_dir") or "")
            relative = Path(raw_directory)
            if relative.is_absolute() or ".." in relative.parts or not raw_directory:
                raise ActivationError(f"parent release {name} directory is unsafe")
            manifest_path = settings.project_dir / relative / "release-manifest.json"
            marker_path = settings.project_dir / relative / ".published-complete"
            release_directory = manifest_path.parent
            try:
                directory_metadata = release_directory.lstat()
                canonical_release = release_directory.resolve(strict=True)
                canonical_release.relative_to(canonical_project)
            except (OSError, RuntimeError, ValueError) as exc:
                raise ActivationError(
                    f"parent release {name} directory is unsafe: {exc}"
                ) from exc
            if (
                not stat.S_ISDIR(directory_metadata.st_mode)
                or canonical_release != canonical_project / relative
            ):
                raise ActivationError(
                    f"parent release {name} directory must be canonical in current project"
                )
            _canonical_regular_within(
                marker_path, release_directory,
                f"parent release {name} publication marker",
            )
            _canonical_regular_within(
                manifest_path, release_directory,
                f"parent release {name} manifest",
            )
            _hash_matches(
                marker_path,
                raw_component.get("published_marker_sha256"),
                f"parent release {name} publication marker",
            )
            public_latest = settings.http_root / f"ztp/config/{name}/latest_yaml"
            try:
                public_target = public_latest.resolve(strict=True)
                release_target = manifest_path.parent.resolve(strict=True)
            except (OSError, RuntimeError) as exc:
                raise ActivationError(
                    f"public {name} latest_yaml cannot be resolved: {exc}"
                ) from exc
            if public_target != release_target:
                raise ActivationError(
                    f"public {name} latest_yaml does not match parent release: "
                    f"{public_target} != {release_target}"
                )
        _hash_matches(
            manifest_path,
            raw_component.get("manifest_sha256"),
            f"parent release {name} manifest",
        )
        component_identity[name] = {
            "release_id": str(raw_component.get("release_id") or ""),
            "manifest_sha256": str(raw_component.get("manifest_sha256") or ""),
        }
    return {
        "parent_release_sha256": sha256_path(release_manifest),
        "parent_inputs": dict(sorted((str(k), str(v)) for k, v in inputs.items())),
        "parent_components": component_identity,
    }


def published_runtime_identity(settings: Settings) -> dict:
    """Hash the small files Apache serves outside versioned YAML releases."""
    root = settings.http_root.resolve(strict=True)
    identity = {}
    for relative in PUBLISHED_RUNTIME_FILES:
        path = settings.http_root / relative
        try:
            metadata = path.lstat()
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActivationError(
                f"published runtime file is missing or unsafe: {path}: {exc}"
            ) from exc
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ActivationError(
                f"published runtime artifact must be one real regular file: {path}"
            )
        identity[relative.as_posix()] = sha256_path(path)

    candidates = []
    public_keys = settings.http_root / "ztp/config/publickey"
    if os.path.lexists(public_keys):
        try:
            public_key_metadata = public_keys.lstat()
            expected_public_keys = root / "ztp/config/publickey"
            if (
                not stat.S_ISDIR(public_key_metadata.st_mode)
                or public_keys.resolve(strict=True) != expected_public_keys
            ):
                raise ActivationError(
                    "published public-key directory must be one canonical real directory"
                )
        except ActivationError:
            raise
        except (OSError, RuntimeError) as exc:
            raise ActivationError(
                f"published public-key directory is unsafe: {exc}"
            ) from exc
        candidates.extend(
            path.relative_to(settings.http_root)
            for path in sorted(public_keys.glob("*.pub"))
        )
    project = None
    for relative in candidates:
        path = settings.http_root / relative
        try:
            if project is None:
                validate_project_mount(settings)
                project = settings.project_dir.resolve(strict=True)
            metadata = path.lstat()
            if not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActivationError(
                    f"published public key must be one canonical symlink: {path}"
                )
            target = os.readlink(path)
            expected_target = (
                f"../../../DAY0-Prepare/{settings.project_name}/{path.name}"
            )
            if target != expected_target:
                raise ActivationError(
                    f"published public key target is non-canonical: "
                    f"{relative} -> {target!r} (expected {expected_target!r})"
                )
            expected = project / path.name
            expected_metadata = expected.lstat()
            if (
                not stat.S_ISREG(expected_metadata.st_mode)
                or expected_metadata.st_nlink != 1
                or expected.resolve(strict=True) != expected
            ):
                raise ActivationError(
                    f"project public key must be one real regular file: {expected}"
                )
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
            if resolved != expected:
                raise ActivationError(
                    f"published public key does not select current project: {path}"
                )
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActivationError(
                f"published runtime file escapes HTTP root: {path}: {exc}"
            ) from exc
        identity[relative.as_posix()] = {
            "target": target,
            "resolved": resolved.relative_to(root).as_posix(),
            "sha256": sha256_path(expected),
        }
    return dict(sorted(identity.items()))


def published_link_identity(settings: Settings) -> dict:
    """Bind project inventory/output publication links to this exact project."""
    root = settings.http_root.resolve(strict=True)
    validate_project_mount(settings)
    project = settings.project_dir.resolve(strict=True)
    identity = {}

    def project_terminal(relative: Path, *, regular: Optional[bool] = None) -> Path:
        expected = project / relative
        try:
            metadata = expected.lstat()
            resolved = expected.resolve(strict=True)
            resolved.relative_to(project)
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActivationError(
                f"published project target is missing or escapes current project: "
                f"{expected}: {exc}"
            ) from exc
        # A project-owned publication target must not be an inner alias.  This
        # prevents a canonical outer link from laundering a sibling-project or
        # external target through project/01-global.yaml (or an output dir).
        if resolved != expected:
            raise ActivationError(
                f"published project target is not canonical in current project: "
                f"{expected} -> {resolved}"
            )
        if regular is True:
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActivationError(
                    f"published project target must be one real regular file: {expected}"
                )
        elif regular is False:
            if not stat.S_ISDIR(metadata.st_mode):
                raise ActivationError(
                    f"published project target must be one real directory: {expected}"
                )
        elif not (
            stat.S_ISDIR(metadata.st_mode)
            or (stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1)
        ):
            raise ActivationError(
                f"published project target has an unsafe type: {expected}"
            )
        return expected

    def bind_link(path: Path, expected_target: str, expected: Path) -> None:
        relative = path.relative_to(settings.http_root)
        if not os.path.lexists(path):
            raise ActivationError(f"published project link is missing: {path}")
        try:
            metadata = path.lstat()
            if not stat.S_ISLNK(metadata.st_mode) or metadata.st_nlink != 1:
                raise ActivationError(
                    f"published project path must be one symlink: {path}"
                )
            target = os.readlink(path)
            if target != expected_target:
                raise ActivationError(
                    f"published project link target is unsafe/non-canonical: "
                    f"{relative} -> {target!r} (expected {expected_target!r})"
                )
            resolved = path.resolve(strict=True)
            resolved.relative_to(root)
        except ActivationError:
            raise
        except (OSError, RuntimeError, ValueError) as exc:
            raise ActivationError(
                f"published project link is unsafe: {path}: {exc}"
            ) from exc
        if resolved != expected:
            raise ActivationError(
                f"published project link does not select current project: "
                f"{relative} -> {resolved} (expected {expected})"
            )
        identity[relative.as_posix()] = {
            "target": target,
            "resolved": resolved.relative_to(root).as_posix(),
        }

    for relative, target_template, project_relative in PUBLISHED_RUNTIME_LINKS:
        path = settings.http_root / relative
        expected = project_terminal(project_relative)
        bind_link(
            path,
            target_template.format(project=settings.project_name),
            expected,
        )

    # The selected P2P workbook name is project data, so its canonical raw
    # target cannot be a static format string.  It may live directly below the
    # project or in its real `p2p/` directory, but nowhere else.
    p2p_link = settings.http_root / PUBLISHED_P2P_INPUT_LINK
    if not os.path.lexists(p2p_link):
        raise ActivationError(f"published project link is missing: {p2p_link}")
    try:
        p2p_metadata = p2p_link.lstat()
        if not stat.S_ISLNK(p2p_metadata.st_mode) or p2p_metadata.st_nlink != 1:
            raise ActivationError(
                f"published project path must be one symlink: {p2p_link}"
            )
        p2p_target = os.readlink(p2p_link)
        if Path(p2p_target).is_absolute():
            raise ActivationError("published P2P target must be relative")
        canonical_link_parent = p2p_link.parent.resolve(strict=True)
        lexical = Path(os.path.abspath(os.path.join(canonical_link_parent, p2p_target)))
        lexical.relative_to(project)
        if lexical.parent not in {project, project / "p2p"}:
            raise ActivationError(
                "published P2P workbook must be in the current project root or p2p/"
            )
        if lexical.suffix.casefold() != ".xlsx":
            raise ActivationError("published P2P workbook must have an .xlsx suffix")
        expected_raw = os.path.relpath(lexical, canonical_link_parent)
        if p2p_target != expected_raw:
            raise ActivationError(
                f"published P2P link target is non-canonical: {p2p_target!r}"
            )
        if lexical.parent == project / "p2p":
            p2p_dir_metadata = lexical.parent.lstat()
            if (
                not stat.S_ISDIR(p2p_dir_metadata.st_mode)
                or lexical.parent.resolve(strict=True) != lexical.parent
            ):
                raise ActivationError("project p2p/ must be one real directory")
        lexical_metadata = lexical.lstat()
        alias_target = None
        if stat.S_ISLNK(lexical_metadata.st_mode):
            # The repository's canonical project/p2p.xlsx is itself one
            # setup-managed alias to the human-named workbook.  Permit exactly
            # this one extra hop and bind its raw target as well.
            if lexical != project / "p2p.xlsx" or lexical_metadata.st_nlink != 1:
                raise ActivationError(
                    "only current-project p2p.xlsx may be a P2P workbook alias"
                )
            alias_target = os.readlink(lexical)
            if Path(alias_target).is_absolute():
                raise ActivationError("project p2p.xlsx alias must be relative")
            alias_lexical = Path(
                os.path.abspath(os.path.join(lexical.parent, alias_target))
            )
            alias_lexical.relative_to(project)
            if alias_lexical.parent not in {project, project / "p2p"}:
                raise ActivationError(
                    "project p2p.xlsx alias must remain in current project"
                )
            if alias_target != os.path.relpath(alias_lexical, lexical.parent):
                raise ActivationError("project p2p.xlsx alias is non-canonical")
            p2p_source = project_terminal(
                alias_lexical.relative_to(project), regular=True,
            )
        else:
            p2p_source = project_terminal(
                lexical.relative_to(project), regular=True,
            )
        if p2p_link.resolve(strict=True) != p2p_source:
            raise ActivationError("published P2P workbook alias chain is inconsistent")
    except ActivationError:
        raise
    except (OSError, RuntimeError, ValueError) as exc:
        raise ActivationError(f"published P2P workbook is unsafe: {exc}") from exc
    # bind_link normally requires the lexical project endpoint itself to be
    # terminal.  The explicitly validated project/p2p.xlsx hop above is the
    # sole exception.
    p2p_resolved = p2p_link.resolve(strict=True)
    identity[PUBLISHED_P2P_INPUT_LINK.as_posix()] = {
        "target": p2p_target,
        "project_alias_target": alias_target,
        "resolved": p2p_resolved.relative_to(root).as_posix(),
        "sha256": sha256_path(p2p_source),
    }

    air_relative = Path("99-output-p2p") / f"{p2p_source.stem}-air.json"
    air_target = project_terminal(air_relative, regular=True)
    air_link = settings.http_root / PUBLISHED_P2P_AIR_LINK
    bind_link(
        air_link,
        os.path.relpath(air_target, air_link.parent.resolve(strict=True)),
        air_target,
    )
    identity[PUBLISHED_P2P_AIR_LINK.as_posix()]["sha256"] = sha256_path(
        air_target,
    )
    return dict(sorted(identity.items()))


def build_activation_marker(
    settings: Settings,
    selected,
    *,
    subnet_csv: Optional[Path] = None,
    dhcp_config: Optional[Path] = None,
    release_manifest: Optional[Path] = None,
) -> dict:
    subnet, dhcp, release = _activation_files(
        settings, subnet_csv, dhcp_config, release_manifest,
    )
    release_identity = validate_parent_release(settings, release)
    published_links = published_link_identity(settings)
    p2p_publication = published_links[PUBLISHED_P2P_INPUT_LINK.as_posix()]
    if p2p_publication.get("sha256") != release_identity["parent_inputs"].get("p2p"):
        raise ActivationError(
            "published P2P workbook does not match parent release input"
        )
    return {
        "schema_version": MARKER_SCHEMA,
        "activated_at": datetime.now(timezone.utc).isoformat(),
        "project": settings.project_name,
        "scope": settings.scope,
        "switch_scope": settings.switch_scope,
        "mini": settings.mini,
        "subnet_sha256": sha256_path(subnet),
        "dhcp_config_sha256": sha256_path(dhcp),
        "release_manifest_sha256": sha256_path(release),
        "services": list(expected_services(selected)),
        "published_runtime": published_runtime_identity(settings),
        "published_links": published_links,
        "runtime_source": validate_image_source_contract(settings),
        **release_identity,
    }


def validate_activation_marker(
    marker: object,
    settings: Settings,
    selected,
    *,
    subnet_csv: Optional[Path] = None,
    dhcp_config: Optional[Path] = None,
    release_manifest: Optional[Path] = None,
):
    if not isinstance(marker, dict):
        return False, "activation marker is not an object"
    try:
        expected = build_activation_marker(
            settings,
            selected,
            subnet_csv=subnet_csv,
            dhcp_config=dhcp_config,
            release_manifest=release_manifest,
        )
    except ActivationError as exc:
        return False, str(exc)
    for key in (
        "schema_version", "project", "scope", "switch_scope", "mini",
        "subnet_sha256",
        "dhcp_config_sha256", "release_manifest_sha256", "services",
        "parent_release_sha256", "parent_inputs", "parent_components",
        "published_runtime", "published_links", "runtime_source",
    ):
        if marker.get(key) != expected[key]:
            return False, f"activation marker {key} does not match current runtime"
    return True, "active runtime matches current inputs"


def _read_optional_state_json(path: Path, label: str):
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ActivationError(f"cannot inspect {label}: {exc}") from exc
    raw_bytes = _bounded_regular_bytes(path, label, 4 * 1024 * 1024)
    try:
        marker = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ActivationError(f"{label} is invalid JSON: {exc}") from exc
    if not isinstance(marker, dict):
        raise ActivationError(f"{label} must be a JSON object")
    return marker


def read_activation_marker(settings: Settings):
    return _read_optional_state_json(
        settings.activation_marker, "activation marker",
    )


def read_runtime_plan(settings: Settings):
    return _read_optional_state_json(settings.runtime_plan, "runtime plan")


def validate_network_reload_plan(saved: object, current: object) -> bool:
    """Validate a network-only re-plan and report listener identity drift.

    A reload may update the observation timestamp, raw snapshot hashes, and
    the selected listener identity.  Every project, release-input, endpoint,
    DHCP-network, Apache-listener, and future plan field remains exact.  The
    return value is true only when the selected listener identity changed.
    """
    if not isinstance(saved, dict) or not isinstance(current, dict):
        raise ActivationError("network reload plans must be JSON objects")
    required = (
        "schema_version", "project", "scope", "switch_scope", "mini",
        "subnet_csv", "subnet_sha256", "listener_names",
        "listener_ifindexes", "direct_shared_networks",
        "relay_shared_networks", "dhcp_only_shared_networks", "endpoint_ips",
        "listener_fingerprints", "link_snapshot_sha256",
        "address_snapshot_sha256", "apache_listener_sha256",
    )
    for key in required:
        if key not in saved or key not in current:
            raise ActivationError(f"network reload plan is missing {key}")

    binding_keys = (
        "listener_names", "listener_ifindexes", "listener_fingerprints",
    )
    volatile_keys = {
        "generated_at", "link_snapshot_sha256", "address_snapshot_sha256",
        *binding_keys,
    }
    for key in sorted(set(saved) | set(current)):
        if key not in volatile_keys and saved.get(key) != current.get(key):
            raise ActivationError(
                f"network reload refused because {key} changed"
            )

    for plan_label, plan in (("saved", saved), ("current", current)):
        for label in binding_keys:
            if not isinstance(plan[label], list):
                raise ActivationError(
                    f"network reload {plan_label} plan {label} must be a list"
                )
        if not (
            len(plan["listener_names"])
            == len(plan["listener_ifindexes"])
            == len(plan["listener_fingerprints"])
        ):
            raise ActivationError(
                f"network reload {plan_label} listener identity is incomplete"
            )
        if any(
            not isinstance(fingerprint, dict)
            for fingerprint in plan["listener_fingerprints"]
        ):
            raise ActivationError(
                f"network reload {plan_label} listener fingerprints are invalid"
            )
    names_changed = saved["listener_names"] != current["listener_names"]
    identity_changed = any(saved[key] != current[key] for key in binding_keys)
    if identity_changed and not names_changed:
        raise ActivationError(
            "network reload refused because listener identity changed but "
            "the listener name did not change"
        )
    return names_changed


def _precommit_path(settings: Settings) -> Path:
    explicit = getattr(settings, "precommit_marker", None)
    if explicit is not None:
        return explicit
    activation = getattr(settings, "activation_marker", None)
    if activation is None:
        raise ActivationError("settings do not define a precommit marker path")
    return activation.parent / PRECOMMIT_MARKER_NAME


def read_precommit_activation(settings: Settings):
    return _read_optional_state_json(
        _precommit_path(settings), "precommit activation marker",
    )


def _supervisor_states() -> dict:
    result = subprocess.run(
        ("supervisorctl", "status"), capture_output=True, text=True, check=False,
    )
    if result.returncode not in {0, 3}:
        raise ActivationError(
            "cannot read Supervisor status: "
            + str(result.stderr or result.stdout).strip()
        )
    states = {}
    for line in result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            states[fields[0]] = fields[1]
    return states


def commit_activation(settings: Settings, selected) -> dict:
    marker = build_activation_marker(settings, selected)
    states = _supervisor_states()
    for service in marker["services"]:
        if states.get(service) != "RUNNING":
            raise ActivationError(
                f"refuse activation while {service} is {states.get(service, 'MISSING')}"
            )
    _atomic_write(
        settings.activation_marker,
        json.dumps(marker, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    clear_precommit_activation(settings)
    return marker


def _clear_state_file(path: Path, label: str) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise ActivationError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationError(f"{label} must be one regular file")
    try:
        path.unlink()
    except OSError as exc:
        raise ActivationError(f"cannot clear {label}: {exc}") from exc
    directory = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def clear_precommit_activation(settings: Settings) -> None:
    _clear_state_file(_precommit_path(settings), "precommit activation marker")


def clear_activation(settings: Settings) -> None:
    errors = []
    for path, label in (
        (settings.activation_marker, "activation marker"),
        (_precommit_path(settings), "precommit activation marker"),
    ):
        try:
            _clear_state_file(path, label)
        except ActivationError as exc:
            errors.append(str(exc))
    if errors:
        raise ActivationError("cannot clear service start authority: " + "; ".join(errors))


def publish_precommit_activation(settings: Settings, selected) -> dict:
    marker = build_activation_marker(settings, selected)
    marker["start_authority"] = "precommit"
    _atomic_write(
        _precommit_path(settings),
        json.dumps(marker, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        0o600,
    )
    return marker


def require_service_start_authority(
    name: str, settings: Settings, selected,
) -> dict:
    marker = read_activation_marker(settings)
    if marker is not None:
        valid, reason = validate_activation_marker(marker, settings, selected)
        if not valid:
            raise ActivationError(f"active service start authority is stale: {reason}")
    else:
        marker = read_precommit_activation(settings)
        if marker is None:
            raise ActivationError("managed service start authority is absent")
        if marker.get("start_authority") != "precommit":
            raise ActivationError("precommit service start authority is invalid")
        valid, reason = validate_activation_marker(marker, settings, selected)
        if not valid:
            raise ActivationError(f"precommit service start authority is stale: {reason}")
    services = marker.get("services")
    if not isinstance(services, list) or name not in services:
        raise ActivationError(f"managed service {name} is not authorized by current plan")
    return marker


def clear_rebuild_required(settings: Settings) -> None:
    """Remove only the validated persistent image-rebuild gate."""
    path = settings.rebuild_required
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationError("rebuild-required marker must be one regular file")
    try:
        path.unlink()
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as exc:
        raise ActivationError(f"cannot clear rebuild-required marker: {exc}") from exc


def state_marker_present(path: Path, label: str) -> bool:
    """Return marker presence without following an unsafe filesystem object."""
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ActivationError(f"cannot inspect {label}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ActivationError(f"{label} must be one regular file")
    return True


def _check_command(command: Sequence[str], label: str) -> None:
    result = subprocess.run(list(command), check=False)
    if result.returncode != 0:
        raise ActivationError(f"{label} failed with exit code {result.returncode}")


def _write_worker_pid(path: Path, *, runtime_backend) -> None:
    with runtime_backend.monitor_pid_lock(path):
        runtime_backend.write_monitor_pid_record_locked(path, os.getpid())
        try:
            os.chown(path, 0, 33)  # root:www-data on Ubuntu
        except OSError as exc:
            raise ActivationError(
                f"cannot set worker PID ownership: {path}: {exc}"
            ) from exc


def exec_managed_service(name: str, settings: Settings) -> None:
    require_monitor_authority()
    selected, runtime, payload, expected_apache = observe_runtime(settings)
    require_service_start_authority(name, settings, selected)
    if name == "apache2":
        if not selected.endpoint_ips:
            raise ActivationError("refuse Apache start without a ZTP service endpoint")
        try:
            actual = settings.apache_listeners.read_text(encoding="utf-8")
        except OSError as exc:
            raise ActivationError(f"cannot read Apache listener config: {exc}") from exc
        if actual != expected_apache:
            raise ActivationError("Apache listener config is stale")
        _check_command(("/usr/sbin/apache2ctl", "configtest"), "Apache configtest")
        os.execv(
            "/usr/sbin/apache2ctl",
            ("/usr/sbin/apache2ctl", "-D", "FOREGROUND"),
        )
    if name == "dhcpd":
        try:
            saved = json.loads(settings.runtime_plan.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ActivationError(f"cannot read saved runtime plan: {exc}") from exc
        for key in (
            "project", "scope", "subnet_sha256", "listener_names",
            "listener_ifindexes", "direct_shared_networks",
            "relay_shared_networks", "dhcp_only_shared_networks", "endpoint_ips",
            "listener_fingerprints",
        ):
            if saved.get(key) != payload.get(key):
                raise ActivationError(f"saved DHCP runtime plan is stale: {key}")
        if not settings.dhcp_config.is_file():
            raise ActivationError(f"missing DHCP configuration: {settings.dhcp_config}")
        _check_command(
            ("/usr/sbin/dhcpd", "-4", "-t", "-cf", os.fspath(settings.dhcp_config)),
            "DHCP configtest",
        )
        # Config validation may take time.  Re-observe immediately before exec
        # so an ifindex/name/prefix change cannot turn an approved listener
        # name into a different logical interface.
        links, addresses = capture_stable_network_snapshot()
        selected = runtime.revalidate_dhcp_runtime_plan(
            selected,
            settings.subnet_csv,
            link_snapshot=links,
            address_snapshot=addresses,
            allowlist=settings.allowlist,
            relay_ingress=settings.relay_ingress,
        )
        revalidated_fingerprints = selected_interface_fingerprints(
            selected, links, addresses,
        )
        if saved.get("listener_fingerprints") != revalidated_fingerprints:
            raise ActivationError(
                "saved DHCP runtime plan is stale: listener_fingerprints"
            )
        argv = runtime.build_dhcpd_argv(
            selected.listener_names,
            config=os.fspath(settings.dhcp_config),
            leases=os.fspath(settings.dhcp_leases),
        )
        os.execv(argv[0], argv)
    if name in {"ztp-monitor", "switch-collection", "manual-ztp"}:
        spec = worker_spec(name, settings)
        for executable in (Path(spec.argv[0]), Path(spec.argv[2])):
            if not executable.is_file():
                raise ActivationError(f"missing worker executable: {executable}")
        _write_worker_pid(spec.pid_file, runtime_backend=runtime)
        os.chdir(settings.http_root)
        os.execv(spec.argv[0], spec.argv)
    raise ActivationError(f"unknown managed service: {name}")


def _print_json(value: object) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument(
        "action",
        choices=(
            "plan", "status", "exec-service", "build-source-manifest",
            "verify-source-manifest", "verify-control-auth-image",
            "verify-deployment-image", "verify-python-runtime",
        ),
    )
    result.add_argument("service", nargs="?")
    result.add_argument("--source-root", type=Path, default=DEFAULT_IMAGE_SOURCE_TREE)
    result.add_argument("--manifest", type=Path, default=DEFAULT_IMAGE_SOURCE_MANIFEST)
    return result


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.action == "verify-python-runtime":
            if args.service is not None:
                raise ActivationError("verify-python-runtime takes no arguments")
            validate_python_runtime()
            _print_json({"verified": True, "contract": "TOPLEVEL-5"})
            return 0
        if args.action == "build-source-manifest":
            if args.service is not None:
                raise ActivationError("build-source-manifest takes only named options")
            _print_json(write_image_source_manifest(args.source_root, args.manifest))
            return 0
        if args.action == "verify-source-manifest":
            if args.service is not None:
                raise ActivationError("verify-source-manifest takes only named options")
            verified = verify_image_source_manifest(args.source_root, args.manifest)
            _print_json({"verified": True, "files": len(verified)})
            return 0
        if args.action == "verify-control-auth-image":
            if args.service is not None:
                raise ActivationError(
                    "verify-control-auth-image takes only named options"
                )
            _print_json(verify_control_auth_image_copies(manifest=args.manifest))
            return 0
        if args.action == "verify-deployment-image":
            if args.service is not None:
                raise ActivationError("verify-deployment-image takes only named options")
            verify_control_auth_image_copies(manifest=args.manifest)
            verified = verify_deployment_image(args.source_root, args.manifest)
            _print_json({
                "verified": True,
                "files": len(verified),
                "os": "ubuntu",
                "version": "24.04",
            })
            return 0
        settings = Settings.from_environment(os.environ)
        verify_control_auth_image_copies()
        # Writers are stopped before any supported sync/upload mutation.  A
        # Supervisor child is itself started while hostctl owns that same
        # transaction lock, so taking it again here would self-deadlock.
        # Revalidate the image receipt immediately before any dynamic exec.
        validate_image_source_contract(settings)
        if args.action == "exec-service":
            require_control_auth(emit_factory_warning=False)
            if not args.service:
                raise ActivationError("exec-service requires a service name")
            if args.service not in MANAGED_SERVICES:
                raise ActivationError(f"unknown managed service: {args.service}")
            exec_managed_service(args.service, settings)
            return 0
        if args.service is not None:
            raise ActivationError(f"{args.action} does not take a service name")
        # plan/status are intentionally instantaneous, unlocked diagnostics.
        # They must never create the workspace lock or persist a runtime plan.
        selected, _runtime, payload, _apache = observe_runtime(settings)
        if args.action == "plan":
            _print_json(payload)
            return 0
        control_auth = require_control_auth(emit_factory_warning=False)
        marker = read_activation_marker(settings)
        if marker is None:
            _print_json({
                "active": False,
                "reason": "activation marker is absent",
                "control_auth": control_auth,
            })
            return 3
        valid, reason = validate_activation_marker(marker, settings, selected)
        _print_json({
            "active": valid,
            "reason": reason,
            "marker": marker,
            "control_auth": control_auth,
        })
        return 0 if valid else 2
    except (ActivationError, hostlock.HostLockError, OSError, ValueError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
