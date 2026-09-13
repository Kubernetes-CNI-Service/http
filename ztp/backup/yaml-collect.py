#!/usr/bin/env python3
"""
读取当前目录下 *devices_config*.csv 文件，SSH 进每台设备备份 startup.yaml、收集 MAC 和序列号。

连接策略：每台设备依次尝试 eth0_ip → 同网段 SVI → eth1_ip → hostname，首个可达地址用于连接。
每台设备只备份一份 yaml 文件。

CSV type 列支持：eth / eth_spx / spx / air（Cumulus）、ib、nvl。

用法：
  python3 yaml-collect.py       # 自动判定当前可达环境；采集时会提示输入密码
  python3 yaml-collect.py -y    # 自动确认提示，密码仍需手动输入
  python3 yaml-collect.py --air # 只备份统一清单中 type=air 的设备

输出目录：<timestamp>-prod-backup/ 或 <timestamp>-air-backup/
  eth/<hostname>.yaml       type=eth/eth_spx/air 的 Cumulus 配置
  spx/<hostname>.yaml       type=spx 的 Cumulus 配置
  ib/<hostname>.yaml        nvos ib 设备配置
  nvl/<hostname>.yaml       nvos nvlink 设备配置
  backup.log                操作日志
  devices_config.csv        收集到的设备信息（devices_config 格式，template 列替换为 sn）
  collection.json           环境、输入清单、采集器和带时区采集时间

"""

import csv
import atexit
import base64
from contextlib import contextmanager
import getpass
import hashlib
import json
import ipaddress
import os
import re
import select
import secrets
import selectors
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from threading import Lock

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
ZTP_DIR = os.path.dirname(SCRIPT_DIR)
if ZTP_DIR not in sys.path:
    sys.path.insert(0, ZTP_DIR)
from environment_probe import detect_environment
from dynamic_air_inventory import dynamic_air_devices, static_air_lease_fallbacks

DEFAULT_ETH_USER = "cumulus"
DEFAULT_IB_USER  = "admin"
DEFAULT_NVL_USER = "admin"

ETH_YAML_PATH = "/etc/nvue.d/startup.yaml"
IB_YAML_PATH  = "/etc/sonic/nvue.d/startup.yaml"
NVL_YAML_PATH = "/etc/sonic/nvue.d/startup.yaml"

SN_CMD = "nv show platform inventory 2>/dev/null | awk '/^SWITCH/ {print $4}'"

SSH_OPTS = [
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
    "-o", "ServerAliveInterval=10",
]

_AUTO_YES = False
_ENVIRONMENT = "prod"
_ASKPASS_PATH = None
_ASKPASS_DIR = None
_ASKPASS_PATH_IDENTITY = None
_ASKPASS_DIR_IDENTITY = None
_AUTH_MODES = {}
_AUTH_LOCK = Lock()
_SSH_BINARY = None
_SSH_BINARY_IDENTITY = None
_SSH_KEYSCAN_BINARY = None
_SSH_KEYSCAN_BINARY_IDENTITY = None
_KNOWN_HOSTS_COMMAND_EVIDENCE = None
_SAFE_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")
_EXPECTED_DEVICE_CORE_PREFIX = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac",
)

# ── 交互 ──────────────────────────────────────────────────────────────────────

def _confirm(prompt, default="y"):
    if _AUTO_YES:
        print(prompt + f" {default}（-y 模式自动确认）")
        return default == "y"
    print(prompt + f"（10 秒后自动 {default}）", end=" ", flush=True)
    ready, _, _ = select.select([sys.stdin], [], [], 10)
    if ready:
        ans = sys.stdin.readline().strip().lower()
        return ans not in ("n", "no") if default == "y" else ans in ("y", "yes")
    print(default)
    return default == "y"

def _ask_password(label):
    try:
        pw = getpass.getpass(
            f"{label} SSH/sudo 共用密码"
            "（仅在 SSH 公钥登录且免密 sudo 均可用时才直接回车）："
        )
    except (EOFError, KeyboardInterrupt):
        print()
        return ""
    return pw

# ── CSV 读取 ──────────────────────────────────────────────────────────────────

def _na(val):
    return not val or val.strip().upper() == "NA"


def normalize_mac(value):
    return re.sub(r"[^0-9a-f]", "", str(value or "").casefold())

def _fallback_fmt(hostname):
    """无 type 列时的兜底判断：主机名前缀 ib → ib，nv/nvl → nvl，否则 → eth。"""
    hn = hostname.strip().lower()
    if hn.startswith("ib"):
        return "ib"
    if hn.startswith("nv"):
        return "nvl"
    return "eth"


def _backup_category(fmt):
    """Map CSV device type to the stable backup directory contract."""
    return "eth" if fmt in {"eth", "eth_spx", "air"} else fmt

def load_devices_csv(path):
    """
    返回设备列表，每条含所有字段用于后续输出 CSV。

    设备类型判断优先级：
      1. 表头含 type 列 → 读每行的 type 值（eth / ib）
      2. 无 type 列 → 用表头兜底（lo_ip 存在 → eth，否则 ib）

    统一列结构（cols 0-9）：
      hostname, template, eth0_ip, eth0_pfx, eth0_gw, eth0_mac,
      eth1_ip,  eth1_pfx, eth1_gw, eth1_mac
    type 列可放在表头任意位置。
    """
    devices = []
    seen_hostnames = {}
    with open(path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        header = next(reader, [])
        h_lower = [c.strip().lower() for c in header]
        if tuple(h_lower[:len(_EXPECTED_DEVICE_CORE_PREFIX)]) != _EXPECTED_DEVICE_CORE_PREFIX:
            raise ValueError(
                "devices_config.csv 前 7 列顺序必须为："
                + ",".join(_EXPECTED_DEVICE_CORE_PREFIX)
            )
        type_col = h_lower.index("type") if "type" in h_lower else None
        svi_cols = [i for i, name in enumerate(h_lower) if name == "svi_ip"]
        eth1_col = h_lower.index("eth1_ip") if "eth1_ip" in h_lower else None
        if eth1_col is not None and tuple(h_lower[eth1_col:eth1_col + 4]) != (
                "eth1_ip", "netmask", "eth1_gw", "eth1_mac"):
            raise ValueError(
                "devices_config.csv 中 eth1_ip 后必须依次为 "
                "netmask,eth1_gw,eth1_mac"
            )

        for lineno, raw in enumerate(reader, start=2):
            row = [c.strip() for c in raw]
            if not any(row):
                continue
            if len(row) < 7:
                raise ValueError(
                    f"{os.path.basename(path)} 第 {lineno} 行列数不足（{len(row)} < 7）"
                )
            def _col(i):
                return "" if len(row) <= i or _na(row[i]) else row[i].strip()

            hostname = _col(0)
            eth0_ip  = _col(3)
            eth1_ip  = _col(eth1_col) if eth1_col is not None else ""
            alternate_ssh_ips = []
            try:
                eth0_network = ipaddress.ip_interface(
                    f"{eth0_ip}/{_col(4)}"
                ).network
            except ValueError:
                eth0_network = None
            if eth0_network is not None:
                for index in svi_cols:
                    candidate = _col(index)
                    if not candidate:
                        continue
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if address in eth0_network and str(address) != eth0_ip:
                        alternate_ssh_ips.append(str(address))

            # 三者都空则跳过
            if not hostname and not eth0_ip and not eth1_ip:
                continue

            # hostname 缺失时用 IP 作为标识符
            if not hostname:
                hostname = eth0_ip or eth1_ip
            if not _SAFE_HOSTNAME_RE.fullmatch(hostname):
                raise ValueError(
                    f"{os.path.basename(path)} 第 {lineno} 行 hostname 含不安全字符："
                    f"{hostname!r}"
                )
            hostname_key = hostname.casefold()
            if hostname_key in seen_hostnames:
                raise ValueError(
                    f"{os.path.basename(path)} 第 {lineno} 行 hostname 与第 "
                    f"{seen_hostnames[hostname_key]} 行重复：{hostname!r}"
                )
            seen_hostnames[hostname_key] = lineno

            # 判断设备类型
            if type_col is not None and len(row) > type_col:
                fmt = row[type_col].strip().lower()
                if fmt == "server":
                    continue
                if fmt not in ("eth", "eth_spx", "spx", "air", "ib", "nvl"):
                    raise ValueError(
                        f"{os.path.basename(path)} 第 {lineno} 行 type={fmt!r} 无效"
                    )
            else:
                fmt = _fallback_fmt(hostname)

            devices.append({
                "hostname": hostname,
                "fmt":      fmt,
                "eth0_ip":  eth0_ip,
                "eth0_pfx": _col(4),
                "eth0_gw":  _col(5),
                "eth0_mac": _col(6),
                "eth1_ip":  eth1_ip,
                "eth1_pfx": _col(eth1_col + 1) if eth1_col is not None else "",
                "eth1_gw":  _col(eth1_col + 2) if eth1_col is not None else "",
                "eth1_mac": _col(eth1_col + 3) if eth1_col is not None else "",
                "has_eth1": bool(eth1_ip),
                "alternate_ssh_ips": list(dict.fromkeys(alternate_ssh_ips)),
            })
    # AIR rows contain identity/address data but intentionally omit generated
    # SVI configuration.  Pair by the shared eth0 IP and inherit the Production
    # row's same-subnet transport alternatives.
    prod_alternates = {
        dev["eth0_ip"]: dev["alternate_ssh_ips"]
        for dev in devices
        if dev["fmt"] in {"eth", "eth_spx", "spx"}
        and dev["eth0_ip"] and dev["alternate_ssh_ips"]
    }
    for dev in devices:
        if dev["fmt"] == "air" and not dev["alternate_ssh_ips"]:
            dev["alternate_ssh_ips"] = list(prod_alternates.get(dev["eth0_ip"], ()))
    return devices


def load_dynamic_air_backup_devices(
    inventory_path,
    leases_path="/var/lib/dhcp/dhcpd.leases",
):
    """Adapt resolved AIR-only DHCP identities to the backup device shape."""
    resolved = []
    warnings = []
    for runtime in dynamic_air_devices(
        Path(inventory_path).resolve(), leases=Path(leases_path),
    ):
        hostname = str(runtime.get("hostname") or "")
        ip = str(runtime.get("ip") or "")
        issue = str(runtime.get("issue") or "")
        if not ip:
            warnings.append(
                f"{hostname} ({runtime.get('mac') or 'MAC unknown'}) "
                + (issue or f"没有 active DHCP lease（{leases_path}）")
            )
            continue
        resolved.append({
            "hostname": hostname,
            "fmt": "air",
            "eth0_ip": ip,
            "eth0_pfx": "",
            "eth0_gw": "",
            "eth0_mac": str(runtime.get("mac") or ""),
            "eth1_ip": "",
            "eth1_pfx": "",
            "eth1_gw": "",
            "eth1_mac": "",
            "has_eth1": False,
            "alternate_ssh_ips": [],
            "dynamic_dhcp": True,
            "address_source": str(runtime.get("address_source") or "dhcp-lease"),
        })
    return resolved, warnings


def apply_static_air_lease_fallbacks(
    devices, inventory_path, leases_path="/var/lib/dhcp/dhcpd.leases",
):
    """Add a promoted AIR device's old lease as a MAC-verified transport."""
    by_name = {
        dev["hostname"].casefold(): dev for dev in devices if dev["fmt"] == "air"
    }
    by_mac = {
        normalize_mac(dev.get("eth0_mac")): dev for dev in devices
        if dev["fmt"] == "air" and normalize_mac(dev.get("eth0_mac"))
    }
    for transition in static_air_lease_fallbacks(
        Path(inventory_path).resolve(), leases=Path(leases_path),
    ):
        dev = (
            by_name.get(str(transition.get("hostname") or "").casefold())
            or by_mac.get(str(transition.get("mac_plain") or ""))
        )
        lease_ip = str(transition.get("ip") or "").strip()
        if dev is None or not lease_ip:
            continue
        dev["transition_ssh_ips"] = [lease_ip]
        dev["alternate_ssh_ips"] = list(dict.fromkeys([
            *dev.get("alternate_ssh_ips", []), lease_ip,
        ]))

# ── SSH 工具 ──────────────────────────────────────────────────────────────────

def _cleanup_askpass():
    global _ASKPASS_PATH, _ASKPASS_DIR
    global _ASKPASS_PATH_IDENTITY, _ASKPASS_DIR_IDENTITY
    with _AUTH_LOCK:
        if _ASKPASS_PATH and _ASKPASS_PATH_IDENTITY:
            try:
                metadata = os.lstat(_ASKPASS_PATH)
            except FileNotFoundError:
                metadata = None
            if metadata is not None and (
                metadata.st_dev, metadata.st_ino
            ) == _ASKPASS_PATH_IDENTITY and stat.S_ISREG(metadata.st_mode):
                os.unlink(_ASKPASS_PATH)
        if _ASKPASS_DIR and _ASKPASS_DIR_IDENTITY:
            try:
                metadata = os.lstat(_ASKPASS_DIR)
            except FileNotFoundError:
                metadata = None
            if metadata is not None and (
                metadata.st_dev, metadata.st_ino
            ) == _ASKPASS_DIR_IDENTITY and stat.S_ISDIR(metadata.st_mode):
                try:
                    os.rmdir(_ASKPASS_DIR)
                except OSError:
                    pass
        _ASKPASS_PATH = None
        _ASKPASS_DIR = None
        _ASKPASS_PATH_IDENTITY = None
        _ASKPASS_DIR_IDENTITY = None


def _validated_exec_root():
    configured = os.environ.get("HTTP_ZTP_ASKPASS_TMPDIR")
    if not configured:
        if os.environ.get("HTTP_ZTP_RUNTIME_BACKEND") == "supervisor":
            raise RuntimeError(
                "Supervisor 缺少 HTTP_ZTP_ASKPASS_TMPDIR，拒绝密码认证"
            )
        return None
    root = Path(configured)
    if not root.is_absolute():
        raise ValueError("HTTP_ZTP_ASKPASS_TMPDIR 必须是规范绝对路径")
    try:
        canonical = root.resolve(strict=True)
        metadata = os.lstat(root)
    except OSError as exc:
        raise ValueError("HTTP_ZTP_ASKPASS_TMPDIR 不可用") from exc
    if canonical != root or not stat.S_ISDIR(metadata.st_mode):
        raise ValueError("HTTP_ZTP_ASKPASS_TMPDIR 必须是真实目录，不能是符号链接")
    if stat.S_IMODE(metadata.st_mode) != 0o700:
        raise ValueError("HTTP_ZTP_ASKPASS_TMPDIR 权限必须精确为 0700")
    if metadata.st_uid != os.geteuid():
        raise ValueError("HTTP_ZTP_ASKPASS_TMPDIR 必须由当前有效用户拥有")
    return root


def _ensure_askpass():
    """创建不含密码内容的临时 SSH_ASKPASS helper。"""
    global _ASKPASS_PATH, _ASKPASS_DIR
    global _ASKPASS_PATH_IDENTITY, _ASKPASS_DIR_IDENTITY
    with _AUTH_LOCK:
        if _ASKPASS_PATH:
            try:
                current = os.lstat(_ASKPASS_PATH)
            except FileNotFoundError:
                current = None
            if current is not None and (
                (current.st_dev, current.st_ino) == _ASKPASS_PATH_IDENTITY
                and stat.S_ISREG(current.st_mode)
                and current.st_nlink == 1
                and current.st_uid == os.geteuid()
                and stat.S_IMODE(current.st_mode) == 0o700
            ):
                return _ASKPASS_PATH
            _ASKPASS_PATH = None
            _ASKPASS_DIR = None
            _ASKPASS_PATH_IDENTITY = None
            _ASKPASS_DIR_IDENTITY = None
        root = _validated_exec_root()
        private = tempfile.mkdtemp(
            prefix="ztp-backup-askpass-",
            dir=None if root is None else str(root),
        )
        os.chmod(private, 0o700)
        directory_metadata = os.lstat(private)
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or directory_metadata.st_uid != os.geteuid()
        ):
            os.rmdir(private)
            raise RuntimeError("SSH_ASKPASS 私有目录身份验证失败")
        path = os.path.join(private, "askpass.py")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
        fd = os.open(path, flags, 0o700)
        try:
            helper = b'''#!/usr/bin/env python3
import os
import stat
import sys

try:
    path = os.environ["ZTP_BACKUP_PASSWORD_FIFO"]
    expected = (
        int(os.environ["ZTP_BACKUP_FIFO_DEV"]),
        int(os.environ["ZTP_BACKUP_FIFO_INO"]),
    )
    before = os.lstat(path)
    if (
        not stat.S_ISFIFO(before.st_mode)
        or stat.S_IMODE(before.st_mode) != 0o600
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or (before.st_dev, before.st_ino) != expected
    ):
        raise RuntimeError("password FIFO identity changed")
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISFIFO(opened.st_mode)
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_uid != os.geteuid()
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != expected
        ):
            raise RuntimeError("password FIFO opened identity changed")
        payload = b""
        while b"\\n" not in payload and len(payload) <= 1025:
            try:
                chunk = os.read(descriptor, 1025 - len(payload))
            except BlockingIOError:
                continue
            if not chunk:
                break
            payload += chunk
    finally:
        os.close(descriptor)
    if not payload.endswith(b"\\n") or payload.count(b"\\n") != 1:
        raise RuntimeError("invalid password FIFO payload")
    sys.stdout.buffer.write(payload)
except Exception:
    raise SystemExit(1)
'''
            view = memoryview(helper)
            while view:
                view = view[os.write(fd, view):]
        finally:
            os.close(fd)
        os.chmod(path, 0o700)
        helper_metadata = os.lstat(path)
        if (
            not stat.S_ISREG(helper_metadata.st_mode)
            or stat.S_IMODE(helper_metadata.st_mode) != 0o700
            or helper_metadata.st_uid != os.geteuid()
            or helper_metadata.st_nlink != 1
        ):
            os.unlink(path)
            os.rmdir(private)
            raise RuntimeError("SSH_ASKPASS helper 身份验证失败")
        _ASKPASS_DIR = private
        _ASKPASS_DIR_IDENTITY = (
            directory_metadata.st_dev, directory_metadata.st_ino,
        )
        _ASKPASS_PATH = path
        _ASKPASS_PATH_IDENTITY = (
            helper_metadata.st_dev, helper_metadata.st_ino,
        )
        atexit.register(_cleanup_askpass)
        return path


MAX_SSH_OUTPUT_BYTES = 64 * 1024


def _bounded_ssh_text(value):
    payload = (value or "").encode("utf-8", errors="replace")
    if len(payload) <= MAX_SSH_OUTPUT_BYTES:
        return value or "", False
    marker = b"\n[output truncated]\n"
    kept = payload[:MAX_SSH_OUTPUT_BYTES - len(marker)] + marker
    return kept.decode("utf-8", errors="replace"), True


def _kill_ssh_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except (OSError, ProcessLookupError):
            pass


def _drain_ssh_process(process, stdin_text, timeout):
    """Retain at most MAX_SSH_OUTPUT_BYTES per stream while enforcing a wall."""
    if process.stdin is not None:
        try:
            if stdin_text is not None:
                payload = stdin_text.encode("utf-8")
                view = memoryview(payload)
                while view:
                    view = view[os.write(process.stdin.fileno(), view):]
        except BrokenPipeError:
            pass
        finally:
            process.stdin.close()

    streams = {process.stdout: bytearray(), process.stderr: bytearray()}
    selector = selectors.DefaultSelector()
    overflow = False
    timed_out = False
    deadline = time.monotonic() + timeout
    try:
        for stream in streams:
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            events = selector.select(min(0.1, remaining))
            for key, _mask in events:
                stream = key.fileobj
                try:
                    chunk = os.read(stream.fileno(), 8192)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(stream)
                    continue
                retained = streams[stream]
                available = MAX_SSH_OUTPUT_BYTES - len(retained)
                if available > 0:
                    retained.extend(chunk[:available])
                if len(chunk) > available:
                    overflow = True
            if overflow:
                break
    finally:
        selector.close()
    return bytes(streams[process.stdout]), bytes(streams[process.stderr]), (
        "overflow" if overflow else "timeout" if timed_out else None
    )


def _run_bounded_process(argv, timeout, env=None, stdin_text=None):
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL if stdin_text is None else subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=False,
        env=env,
        start_new_session=True,
        close_fds=True,
        pass_fds=(),
    )
    try:
        stdout_bytes, stderr_bytes, stop_reason = _drain_ssh_process(
            process, stdin_text, timeout,
        )
        if stop_reason is not None:
            _kill_ssh_group(process)
        try:
            process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            _kill_ssh_group(process)
            process.wait(timeout=1)
        else:
            # A successful leader can close its captured streams and exit while
            # leaving local helper descendants in the new process group.
            _kill_ssh_group(process)
        stdout = stdout_bytes.decode("utf-8", errors="ignore")
        stderr = stderr_bytes.decode("utf-8", errors="ignore")
        if stop_reason == "overflow":
            returncode = 125
            marker = b"\n[output exceeded 65536-byte limit]"
            stdout = (
                stdout_bytes[:MAX_SSH_OUTPUT_BYTES - len(marker)] + marker
            ).decode("utf-8", errors="ignore")
            stderr = (
                stderr_bytes[:MAX_SSH_OUTPUT_BYTES - len(marker)] + marker
            ).decode("utf-8", errors="ignore")
        elif stop_reason == "timeout":
            returncode = 124
            if not stderr:
                stderr = f"timeout after {timeout}s"
        else:
            returncode = process.returncode
        return subprocess.CompletedProcess(argv, returncode, stdout, stderr)
    except BaseException:
        _kill_ssh_group(process)
        try:
            process.wait(timeout=1)
        except (OSError, subprocess.TimeoutExpired):
            _kill_ssh_group(process)
            try:
                process.wait(timeout=1)
            except (OSError, subprocess.TimeoutExpired):
                pass
        raise
    finally:
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()


def _bound_executable(name, path_value, identity_value, environment=None):
    if path_value is None:
        search_path = (environment or os.environ).get("PATH")
        located = shutil.which(name, path=search_path)
        if not located:
            raise RuntimeError(f"找不到所需 executable: {name}")
        path = Path(located).resolve(strict=True)
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode) or not os.access(path, os.X_OK):
            raise RuntimeError(f"{name} executable 不安全或不可执行")
        return str(path), (metadata.st_dev, metadata.st_ino)
    metadata = os.lstat(path_value)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_dev, metadata.st_ino) != identity_value
        or Path(path_value).resolve(strict=True) != Path(path_value)
        or not os.access(path_value, os.X_OK)
    ):
        raise RuntimeError(f"已绑定的 {name} executable 身份发生变化")
    return path_value, identity_value


def _ssh_binary(environment=None):
    global _SSH_BINARY, _SSH_BINARY_IDENTITY
    _SSH_BINARY, _SSH_BINARY_IDENTITY = _bound_executable(
        "ssh", _SSH_BINARY, _SSH_BINARY_IDENTITY, environment,
    )
    return _SSH_BINARY


def _ssh_keyscan_binary(environment=None):
    global _SSH_KEYSCAN_BINARY, _SSH_KEYSCAN_BINARY_IDENTITY
    _SSH_KEYSCAN_BINARY, _SSH_KEYSCAN_BINARY_IDENTITY = _bound_executable(
        "ssh-keyscan", _SSH_KEYSCAN_BINARY, _SSH_KEYSCAN_BINARY_IDENTITY,
        environment,
    )
    return _SSH_KEYSCAN_BINARY


def _require_known_hosts_command_support():
    global _KNOWN_HOSTS_COMMAND_EVIDENCE
    if _KNOWN_HOSTS_COMMAND_EVIDENCE is not None:
        _ssh_binary()
        return _KNOWN_HOSTS_COMMAND_EVIDENCE
    binary = _ssh_binary()
    version_result = _run_bounded_process([binary, "-V"], 5)
    probe_result = _run_bounded_process(
        [
            binary, "-G", "-F", "/dev/null", "-o",
            "KnownHostsCommand=/usr/bin/printf %%s\\n example.invalid",
            "example.invalid",
        ],
        5,
    )
    version = (version_result.stderr or version_result.stdout).strip().splitlines()
    evidence = version[0] if version else "OpenSSH version unknown"
    if (
        version_result.returncode != 0
        or probe_result.returncode != 0
        or "bad configuration option" in probe_result.stderr.casefold()
    ):
        raise RuntimeError(
            "SSH client 不支持 KnownHostsCommand；需要 OpenSSH 8.5 或更高版本；"
            f"检测版本：{evidence}"
        )
    _KNOWN_HOSTS_COMMAND_EVIDENCE = evidence
    return evidence


def _trusted_known_hosts_command_helper():
    helper = Path("/usr/bin/printf")
    current = helper
    while True:
        metadata = os.lstat(current)
        if current == helper:
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) & 0o111 == 0
                or not os.access(current, os.X_OK)
            ):
                raise ValueError("KnownHostsCommand helper 必须是可执行 regular file")
        elif not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("KnownHostsCommand helper 祖先必须是真实目录")
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(
                "KnownHostsCommand helper 及祖先必须 root-owned 且组/其他不可写"
            )
        if current.resolve(strict=True) != current:
            raise ValueError("KnownHostsCommand helper 及祖先不能是符号链接")
        if current == current.parent:
            break
        current = current.parent
    return str(helper)


def _run_ssh(user, ip, cmd, timeout, extra_opts, env=None, stdin_text=None):
    argv = [_ssh_binary(env), "-C"] + SSH_OPTS + extra_opts + [f"{user}@{ip}", cmd]
    return _run_bounded_process(argv, timeout, env=env, stdin_text=stdin_text)


@contextmanager
def _password_ssh_env(password):
    payload = password.encode("utf-8") + b"\n"
    if len(payload) > MAX_PASSWORD_BYTES + 1:
        raise ValueError("密码超过 1024 bytes")
    if any(marker in password for marker in ("\x00", "\r", "\n")):
        raise ValueError("密码不能包含 NUL 或换行")
    helper = _ensure_askpass()
    private = Path(helper).parent
    fifo = None
    descriptor = -1
    identity = None
    try:
        for _attempt in range(100):
            candidate = private / ("password-" + secrets.token_hex(16) + ".fifo")
            try:
                os.mkfifo(candidate, 0o600)
                fifo = candidate
                break
            except FileExistsError:
                continue
        if fifo is None:
            raise RuntimeError("无法分配唯一密码 FIFO")
        initial = os.lstat(fifo)
        flags = os.O_RDWR | os.O_NONBLOCK | os.O_CLOEXEC | os.O_NOFOLLOW
        descriptor = os.open(fifo, flags)
        os.fchmod(descriptor, 0o600)
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISFIFO(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (initial.st_dev, initial.st_ino)
        ):
            raise RuntimeError("密码 FIFO 身份验证失败")
        identity = (opened.st_dev, opened.st_ino)
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        env = os.environ.copy()
        env.update({
            "SSH_ASKPASS": helper,
            "SSH_ASKPASS_REQUIRE": "force",
            "DISPLAY": env.get("DISPLAY") or "ztp-backup:0",
            "ZTP_BACKUP_PASSWORD_FIFO": str(fifo),
            "ZTP_BACKUP_FIFO_DEV": str(opened.st_dev),
            "ZTP_BACKUP_FIFO_INO": str(opened.st_ino),
        })
        env.pop("ZTP_BACKUP_PASSWORD", None)
        yield env
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if fifo is not None:
            try:
                current = os.lstat(fifo)
            except FileNotFoundError:
                current = None
            if current is not None and (
                (current.st_dev, current.st_ino) == identity
                and stat.S_ISFIFO(current.st_mode)
                and current.st_nlink == 1
                and current.st_uid == os.geteuid()
                and stat.S_IMODE(current.st_mode) == 0o600
            ):
                os.unlink(fifo)


_KEY_AUTH_OPTS = [
    "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
]
_PASSWORD_AUTH_BASE_OPTS = [
    "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
    "-o", "PasswordAuthentication=yes",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
    "-o", "KbdInteractiveAuthentication=yes",
    "-o", "NumberOfPasswordPrompts=1",
]


def _pin_name(scope, target):
    identity = json.dumps(
        {"scope": scope, "target": target},
        ensure_ascii=True, sort_keys=True, separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(identity).hexdigest() + ".known_hosts"


def _validate_known_hosts_directory(path):
    try:
        metadata = os.lstat(path)
    except FileNotFoundError:
        try:
            os.mkdir(path, 0o700)
            os.chmod(path, 0o700)
        except FileExistsError:
            pass
        metadata = os.lstat(path)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or Path(path).resolve(strict=True) != Path(path)
    ):
        raise ValueError(".ssh-known-hosts 必须是当前用户拥有的真实 0700 目录")
    return metadata


_SUPPORTED_HOST_KEY_TYPES = {
    "ssh-ed25519", "ssh-rsa",
    "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521",
    "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
}


def _read_pin_records(path, target, dir_fd=None):
    lookup = Path(path).name if dir_fd is not None else path
    try:
        if dir_fd is None:
            metadata = os.lstat(lookup)
        else:
            metadata = os.stat(lookup, dir_fd=dir_fd, follow_symlinks=False)
    except FileNotFoundError:
        return []
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_size > 64 * 1024
    ):
        raise ValueError("目标 SSH pin 必须是当前用户拥有的 single-link 0600 regular file")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    if dir_fd is None:
        descriptor = os.open(lookup, flags)
    else:
        descriptor = os.open(lookup, flags, dir_fd=dir_fd)
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (metadata.st_dev, metadata.st_ino):
            raise ValueError("目标 SSH pin 在读取期间发生变化")
        payload = b""
        while len(payload) <= 64 * 1024:
            chunk = os.read(descriptor, min(8192, 64 * 1024 + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
    finally:
        os.close(descriptor)
    if len(payload) > 64 * 1024:
        raise ValueError("目标 SSH pin 超过 64 KiB")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("目标 SSH pin 不是有效 UTF-8") from exc
    records = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        fields = stripped.split()
        if (
            len(fields) < 3
            or target not in fields[0].split(",")
            or fields[1] not in _SUPPORTED_HOST_KEY_TYPES
        ):
            raise ValueError("目标 SSH pin 含不可解析或其他目标记录")
        _record_fingerprint(stripped)
        records.append(stripped)
    if not records:
        raise ValueError("目标 SSH pin 没有目标记录")
    return records


def _known_hosts_authority(project_output, scope, target):
    project = Path(project_output).resolve(strict=True)
    if not project.is_dir():
        raise ValueError("backup project output 不是真实目录")
    directory = project / ".ssh-known-hosts"
    _validate_known_hosts_directory(directory)
    pin = directory / _pin_name(scope, target)
    records = _read_pin_records(pin, target)
    return pin, records


@contextmanager
def _held_known_hosts_authority(project_output, scope, target):
    project = Path(project_output).resolve(strict=True)
    if not project.is_dir():
        raise ValueError("backup project output 不是真实目录")
    directory = project / ".ssh-known-hosts"
    metadata = _validate_known_hosts_directory(directory)
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_DIRECTORY
    descriptor = os.open(directory, flags)
    try:
        opened = os.fstat(descriptor)
        identity = (opened.st_dev, opened.st_ino)
        if (
            identity != (metadata.st_dev, metadata.st_ino)
            or not stat.S_ISDIR(opened.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise ValueError(".ssh-known-hosts 在打开期间发生变化")
        name = _pin_name(scope, target)
        yield {
            "directory": directory,
            "directory_fd": descriptor,
            "directory_identity": identity,
            "pin": directory / name,
            "pin_name": name,
            "records": _read_pin_records(name, target, dir_fd=descriptor),
            "created_identity": None,
        }
    finally:
        os.close(descriptor)


def _validate_held_authority_parent(authority):
    metadata = _validate_known_hosts_directory(authority["directory"])
    if (metadata.st_dev, metadata.st_ino) != authority["directory_identity"]:
        raise ValueError(".ssh-known-hosts project-scoped authority 身份发生变化")
    opened = os.fstat(authority["directory_fd"])
    if (opened.st_dev, opened.st_ino) != authority["directory_identity"]:
        raise ValueError("held .ssh-known-hosts directory 身份发生变化")


def _persist_first_use_pin(directory_fd, name, record, target):
    # Validate the independent keyscan record before making any authority file.
    if len(record.splitlines()) != 1:
        raise ValueError("首次 SSH pin 必须是单一 public-key record")
    fields = record.split()
    if len(fields) < 3 or target not in fields[0].split(","):
        raise ValueError("首次 SSH pin 目标不匹配")
    _record_fingerprint(record)
    payload = (record + "\n").encode("utf-8")
    flags = (
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
    )
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=directory_fd)
    except FileExistsError:
        existing = _read_pin_records(name, target, dir_fd=directory_fd)
        if existing != [record]:
            raise ValueError("并发创建的 SSH pin 与扫描结果不一致")
        return None
    created_identity = None
    try:
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        created_identity = (metadata.st_dev, metadata.st_ino)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("新 SSH pin 身份不安全")
        view = memoryview(payload)
        while view:
            view = view[os.write(descriptor, view):]
        os.fsync(descriptor)
    except BaseException:
        try:
            current = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
            if created_identity == (current.st_dev, current.st_ino):
                os.unlink(name, dir_fd=directory_fd)
                os.fsync(directory_fd)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    os.fsync(directory_fd)
    return created_identity


def _remove_created_pin(authority):
    identity = authority.get("created_identity")
    if identity is None:
        return
    try:
        metadata = os.stat(
            authority["pin_name"], dir_fd=authority["directory_fd"],
            follow_symlinks=False,
        )
        if (
            (metadata.st_dev, metadata.st_ino) == identity
            and stat.S_ISREG(metadata.st_mode)
            and metadata.st_nlink == 1
        ):
            os.unlink(authority["pin_name"], dir_fd=authority["directory_fd"])
            os.fsync(authority["directory_fd"])
    except OSError:
        pass


def _record_fingerprint(record):
    fields = record.split()
    if len(fields) < 3:
        raise ValueError("SSH public-key record 不完整")
    try:
        raw = base64.b64decode(fields[2].encode("ascii"), validate=True)
    except (UnicodeEncodeError, ValueError) as exc:
        raise ValueError("SSH public-key record base64 无效") from exc
    offset = 0

    def read_ssh_string(label, maximum=64 * 1024):
        nonlocal offset
        if offset + 4 > len(raw):
            raise ValueError(f"SSH public-key {label} length 缺失")
        size = int.from_bytes(raw[offset:offset + 4], "big")
        offset += 4
        if size > maximum or offset + size > len(raw):
            raise ValueError(f"SSH public-key {label} length 无效")
        value = raw[offset:offset + size]
        offset += size
        return value

    algorithm_bytes = read_ssh_string("algorithm", 128)
    try:
        wire_algorithm = algorithm_bytes.decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("SSH public-key wire algorithm 不是 ASCII") from exc
    if (
        fields[1] not in _SUPPORTED_HOST_KEY_TYPES
        or wire_algorithm != fields[1]
    ):
        raise ValueError("SSH public-key label 与 wire algorithm 不一致")

    def require_mpint(label):
        value = read_ssh_string(label)
        if not value or value[0] & 0x80 or all(byte == 0 for byte in value):
            raise ValueError(f"SSH RSA {label} mpint 无效")
        if len(value) > 1 and value[0] == 0 and not value[1] & 0x80:
            raise ValueError(f"SSH RSA {label} mpint 非规范")

    if wire_algorithm == "ssh-ed25519":
        if len(read_ssh_string("ed25519 key", 32)) != 32:
            raise ValueError("SSH ed25519 key 必须精确为 32 bytes")
    elif wire_algorithm == "ssh-rsa":
        require_mpint("exponent")
        require_mpint("modulus")
    elif wire_algorithm.startswith("ecdsa-sha2-"):
        curve = wire_algorithm.removeprefix("ecdsa-sha2-").encode("ascii")
        if read_ssh_string("ECDSA curve", 32) != curve:
            raise ValueError("SSH ECDSA curve 与 algorithm 不一致")
        point_sizes = {b"nistp256": 65, b"nistp384": 97, b"nistp521": 133}
        point = read_ssh_string("ECDSA point", 133)
        if len(point) != point_sizes.get(curve) or not point.startswith(b"\x04"):
            raise ValueError("SSH ECDSA public point 无效")
    elif wire_algorithm == "sk-ssh-ed25519@openssh.com":
        if len(read_ssh_string("SK ed25519 key", 32)) != 32:
            raise ValueError("SSH SK ed25519 key 必须精确为 32 bytes")
        if not read_ssh_string("SK application"):
            raise ValueError("SSH SK application 不能为空")
    elif wire_algorithm == "sk-ecdsa-sha2-nistp256@openssh.com":
        if read_ssh_string("SK ECDSA curve", 32) != b"nistp256":
            raise ValueError("SSH SK ECDSA curve 无效")
        point = read_ssh_string("SK ECDSA point", 65)
        if len(point) != 65 or not point.startswith(b"\x04"):
            raise ValueError("SSH SK ECDSA public point 无效")
        if not read_ssh_string("SK application"):
            raise ValueError("SSH SK application 不能为空")
    if offset != len(raw):
        raise ValueError("SSH public-key wire record 含 trailing bytes")
    digest = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
    return "SHA256:" + digest.rstrip("=")


def _keyscan_type(host_key_type):
    if host_key_type == "ssh-ed25519":
        return "ed25519"
    if host_key_type == "ssh-rsa":
        return "rsa"
    if host_key_type.startswith("ecdsa-sha2-"):
        return "ecdsa"
    if host_key_type == "sk-ssh-ed25519@openssh.com":
        return "ed25519-sk"
    if host_key_type == "sk-ecdsa-sha2-nistp256@openssh.com":
        return "ecdsa-sk"
    raise ValueError("现有 SSH pin 使用不支持的 public-key 算法")


def _scan_offered_host_key(target, timeout, secret=None, key_type=None):
    scan_timeout = max(1, min(10, int(timeout)))
    requested_type = _keyscan_type(key_type) if key_type else "ed25519,ecdsa,rsa"
    environment = {
        key: value for key, value in os.environ.items()
        if key not in {
            "SSH_ASKPASS", "SSH_ASKPASS_REQUIRE", "ZTP_BACKUP_PASSWORD",
            "ZTP_BACKUP_PASSWORD_FIFO", "ZTP_BACKUP_FIFO_DEV",
            "ZTP_BACKUP_FIFO_INO",
        } and (not secret or secret not in value)
    }
    completed = _run_bounded_process(
        [
            _ssh_keyscan_binary(environment), "-T", str(scan_timeout), "-t",
            requested_type, target,
        ],
        scan_timeout, env=environment,
    )
    if completed.returncode != 0:
        raise RuntimeError("无法取得对端 SSH public key")
    records = [
        line.strip() for line in completed.stdout.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    valid = []
    for record in records:
        fields = record.split()
        if (
            len(fields) < 3
            or target not in fields[0].split(",")
            or fields[1] not in _SUPPORTED_HOST_KEY_TYPES
            or (key_type is not None and fields[1] != key_type)
        ):
            continue
        try:
            _record_fingerprint(record)
        except ValueError:
            continue
        valid.append(record)
    distinct = list(dict.fromkeys(valid))
    if not distinct:
        raise ValueError("对端没有返回目标的有效 SSH public key")
    if len(distinct) != 1:
        raise ValueError("对端返回冲突的 SSH public key")
    return distinct[0]


def _known_hosts_command_options(record):
    fields = record.split()
    if len(fields) < 3:
        raise ValueError("KnownHostsCommand record 不完整")
    helper = _trusted_known_hosts_command_helper()
    command = f"{helper} '%%s\\n' {shlex.quote(record)}"
    return [
        "-o", "StrictHostKeyChecking=yes",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", f"KnownHostsCommand={command}",
        "-o", f"HostKeyAlgorithms={fields[1]}",
        "-o", "CheckHostIP=no",
        "-o", "UpdateHostKeys=no",
    ]


def _changed_key_error(target, authority, pinned_records, timeout, password):
    if not pinned_records:
        raise RuntimeError("changed-key refusal 缺少现有 pin")
    _validate_held_authority_parent(authority)
    before_records = _read_pin_records(
        authority["pin_name"], target, dir_fd=authority["directory_fd"],
    )
    if before_records != pinned_records:
        raise ValueError("changed-key pin 在证据采集前发生变化")
    pinned_key_type = pinned_records[0].split()[1]
    offered = _scan_offered_host_key(
        target, timeout, password, key_type=pinned_key_type,
    )
    _validate_held_authority_parent(authority)
    after_records = _read_pin_records(
        authority["pin_name"], target, dir_fd=authority["directory_fd"],
    )
    if after_records != pinned_records:
        raise ValueError("changed-key pin 在证据采集期间发生变化")
    pinned_fingerprint = _record_fingerprint(pinned_records[0])
    offered_fingerprint = _record_fingerprint(offered)
    return (
        f"SSH host key changed for target={target}\n"
        f"pinned_fingerprint={pinned_fingerprint}\n"
        f"offered_fingerprint={offered_fingerprint}\n"
        f"rm -- {shlex.quote(str(authority['pin']))}"
    )


def _is_changed_key_error(stderr):
    lowered = (stderr or "").casefold()
    return (
        "remote host identification has changed" in lowered
        or "host key verification failed" in lowered
    )


def _password_ssh_attempt(
    user, password, target, command, timeout, project_output, scope,
    stdin_text=None,
):
    # Trust/capability checks intentionally precede keyscan and password setup.
    _trusted_known_hosts_command_helper()
    _require_known_hosts_command_support()
    with _held_known_hosts_authority(
        project_output, scope, target,
    ) as authority:
        records = authority["records"]
        if not records:
            offered = _scan_offered_host_key(
                target, timeout, password, key_type="ssh-ed25519",
            )
            authority["created_identity"] = _persist_first_use_pin(
                authority["directory_fd"], authority["pin_name"],
                offered, target,
            )
            records = _read_pin_records(
                authority["pin_name"], target,
                dir_fd=authority["directory_fd"],
            )
            authority["records"] = records
        if not records:
            raise ValueError("password SSH 缺少持久 host-key pin")
        options = _PASSWORD_AUTH_BASE_OPTS + _known_hosts_command_options(records[0])
        input_options = {} if stdin_text is None else {"stdin_text": stdin_text}
        with _password_ssh_env(password) as password_env:
            result = _run_ssh(
                user, target, command, timeout, options,
                env=password_env, **input_options,
            )
        try:
            _validate_held_authority_parent(authority)
            current_records = _read_pin_records(
                authority["pin_name"], target,
                dir_fd=authority["directory_fd"],
            )
            if current_records != records:
                raise ValueError("SSH pin 在 password operation 期间发生变化")
        except BaseException:
            _remove_created_pin(authority)
            raise
        safe_error = None
        if result.returncode != 0 and _is_changed_key_error(result.stderr):
            safe_error = _changed_key_error(
                target, authority, records, timeout, password,
            )
        return result, safe_error, authority["pin"]


def _ssh(
    user, password, ip, cmd, timeout=30, stdin_text=None, project_output=None,
    scope=None,
):
    """
    先用无副作用的 ``true`` 确定认证方式，再执行远端命令。

    远端命令自身退出非零（例如 sudo 密码错误）不能被当成 SSH 公钥认证
    失败，否则脚本会错误切换到密码登录，并用 ``Permission denied`` 掩盖
    原始命令错误。
    """
    selected_scope = scope or _ENVIRONMENT
    project_identity = (
        str(Path(project_output).resolve(strict=True))
        if project_output is not None else ""
    )
    key = (project_identity, selected_scope, user, ip)
    with _AUTH_LOCK:
        mode = _AUTH_MODES.get(key)

    pin = None
    if mode is None:
        probe = _run_ssh(user, ip, "true", timeout, _KEY_AUTH_OPTS)
        if probe.returncode == 0:
            mode = "key"
        elif password:
            if project_output is None:
                raise ValueError("密码 SSH 需要 project-scoped known-host authority")
            probe, safe_error, pin = _password_ssh_attempt(
                user, password, ip, "true", timeout,
                project_output, selected_scope,
            )
            if probe.returncode == 0:
                mode = "password"
            else:
                if safe_error is not None:
                    return probe.stdout, safe_error, probe.returncode
                return probe.stdout, probe.stderr.strip(), probe.returncode
        else:
            return probe.stdout, probe.stderr.strip(), probe.returncode

        with _AUTH_LOCK:
            _AUTH_MODES[key] = (mode, pin)
    else:
        mode, pin = mode

    input_options = (
        {} if stdin_text is None else {"stdin_text": stdin_text}
    )
    if mode == "key":
        result = _run_ssh(
            user, ip, cmd, timeout, _KEY_AUTH_OPTS, **input_options,
        )
    else:
        result, safe_error, pin = _password_ssh_attempt(
            user, password, ip, cmd, timeout,
            project_output, selected_scope, stdin_text=stdin_text,
        )
        if safe_error is not None:
            return result.stdout, safe_error, result.returncode
    return result.stdout, result.stderr.strip(), result.returncode

def _compact_error(message, limit=180):
    """把 SSH/sudo 多行错误压缩成适合单行设备汇总的文本。"""
    text = " ".join((message or "").split())
    if len(text) > limit:
        return text[: limit - 3] + "..."
    return text

# ── 单台设备收集 ──────────────────────────────────────────────────────────────

def collect_device(dev, out_dir, eth_pass, ib_pass, nvl_pass):
    hostname = dev["hostname"]
    fmt      = dev["fmt"]
    if fmt == "ib":
        user, password, yaml_remote = DEFAULT_IB_USER,  ib_pass,  IB_YAML_PATH
    elif fmt == "nvl":
        user, password, yaml_remote = DEFAULT_NVL_USER, nvl_pass, NVL_YAML_PATH
    else:
        user, password, yaml_remote = DEFAULT_ETH_USER, eth_pass, ETH_YAML_PATH
    output_type = _backup_category(fmt)
    sub_dir = os.path.join(out_dir, output_type)
    project_output = Path(out_dir).resolve(strict=True).parent

    log    = [f"######## Collect info of {hostname}"]
    result = None

    # IP is transport only.  Prefer inventory IPs; hostname DNS may resolve to
    # the wrong environment when Production and AIR reuse addressing.
    connect_target = None
    transition_ips = set(dev.get("transition_ssh_ips") or [])
    candidates = [
        (address, "eth0 dynamic lease (transition)")
        for address in transition_ips
    ]
    candidates.append((dev["eth0_ip"], "eth0_ip"))
    candidates.extend(
        (address, "same-subnet SVI")
        for address in dev.get("alternate_ssh_ips", ())
        if address not in transition_ips
    )
    candidates.extend([
        (dev["eth1_ip"], "eth1_ip"),
        (hostname, "hostname"),
    ])
    expected_hostname = hostname.strip().split(".", 1)[0]
    for target, label in candidates:
        if not target:
            continue
        actual_hostname, actual_err, actual_rc = _ssh(
            user, password, target, "hostname -s 2>/dev/null",
            project_output=project_output, scope=_ENVIRONMENT,
        )
        actual_hostname = actual_hostname.strip().split(".", 1)[0]
        if actual_rc != 0:
            detail = _compact_error(actual_err) or f"exit={actual_rc}"
            if (actual_err or "").startswith("SSH host key changed for target="):
                changed_lines = actual_err.splitlines()
                log.append("[ERROR] " + " ".join(changed_lines[:2]))
                log.extend(changed_lines[2:])
                return log, result
            log.append(f"Not able to use {target} ({label}): {detail}")
            continue
        transitional = target in transition_ips
        if (actual_hostname.lower() != expected_hostname.lower()
                and not dev.get("dynamic_dhcp") and not transitional):
            detail = actual_hostname or "hostname 为空"
            log.append(
                f"[ERROR] 设备身份不匹配：通过 {target} 期望 {expected_hostname}，"
                f"实际 {detail}；为防止 AIR/Production 数据串写，跳过"
            )
            log.append(f"######## End of info collection for {hostname}")
            return log, result
        if dev.get("dynamic_dhcp") or transitional:
            actual_mac, mac_err, mac_rc = _ssh(
                user, password, target,
                "cat /sys/class/net/eth0/address 2>/dev/null",
                project_output=project_output, scope=_ENVIRONMENT,
            )
            if (mac_rc != 0 or normalize_mac(actual_mac) != normalize_mac(dev["eth0_mac"])):
                detail = _compact_error(mac_err) or actual_mac.strip() or "MAC 读取失败"
                log.append(
                    f"[ERROR] 动态地址身份不匹配：通过 {target} 期望 eth0 MAC "
                    f"{dev['eth0_mac']}，实际 {detail}；跳过"
                )
                log.append(f"######## End of info collection for {hostname}")
                return log, result
        connect_target = target
        log.append(f"Able to use {target} ({label}) over SSH")
        break

    if connect_target is None:
        log.append(f"[ERROR] {hostname} 所有地址均不可达，跳过")
        log.append(f"######## End of info collection for {hostname}")
        return log, result

    # ── startup.yaml ─────────────────────────────────────────────────────────
    yaml_ok = False
    yaml_error = ""
    if password:
        yaml_cmd = f"sudo -S -p '' -- cat {shlex.quote(yaml_remote)}"
        yaml_stdin = password + "\n"
    else:
        yaml_cmd = f"sudo -n cat {shlex.quote(yaml_remote)}"
        yaml_stdin = None
    yaml_out, yaml_err, yaml_rc = _ssh(
        user, password, connect_target, yaml_cmd, stdin_text=yaml_stdin,
        project_output=project_output, scope=_ENVIRONMENT,
    )
    if yaml_rc != 0 or not yaml_out.strip():
        yaml_error = yaml_err or f"远端命令退出码 {yaml_rc}，且没有返回 YAML 内容"
        if not password and (
            "password is required" in yaml_error.lower()
            or "a terminal is required" in yaml_error.lower()
            or "sudo" in yaml_error.lower()
        ):
            yaml_error += "；SSH 公钥可用，但 sudo 需要密码，请重新运行并输入 SSH/sudo 共用密码"
        log.append(f"[WARN] 无法获取 startup.yaml：{yaml_error}")
    else:
        out_file = os.path.join(sub_dir, f"{hostname}.yaml")
        with open(out_file, "w", encoding="utf-8") as f:
            f.write(yaml_out)
        log.append(f"Backup startup.yaml of {hostname}")
        yaml_ok = True

    # ── 从设备收集网络信息 ────────────────────────────────────────────────────
    def _read(cmd):
        out, _, _ = _ssh(
            user, password, connect_target, cmd,
            project_output=project_output, scope=_ENVIRONMENT,
        )
        return out.strip()

    eth0_mac = _read("cat /sys/class/net/eth0/address 2>/dev/null")
    eth1_mac = _read("cat /sys/class/net/eth1/address 2>/dev/null")

    # eth0 IP / 前缀 / 网关：设备读取优先，回退到 CSV
    dev_eth0_ip  = _read(
        "ip -4 addr show eth0 2>/dev/null"
        " | awk '/inet / {split($2,a,\"/\"); print a[1]; exit}'"
    )
    dev_eth0_pfx = _read(
        "ip -4 addr show eth0 2>/dev/null"
        " | awk '/inet / {split($2,a,\"/\"); print a[2]; exit}'"
    )
    dev_eth0_gw  = _read(
        "ip route show default 2>/dev/null | awk 'NR==1 {print $3}'"
    )

    # eth1 IP / 前缀 / 网关：设备读取优先，回退到 CSV
    dev_eth1_ip  = _read(
        "ip -4 addr show eth1 2>/dev/null"
        " | awk '/inet / {split($2,a,\"/\"); print a[1]; exit}'"
    )
    dev_eth1_pfx = _read(
        "ip -4 addr show eth1 2>/dev/null"
        " | awk '/inet / {split($2,a,\"/\"); print a[2]; exit}'"
    )
    dev_eth1_gw  = _read(
        "ip route show default dev eth1 2>/dev/null | awk 'NR==1 {print $3}'"
    )

    eth0_ip  = dev_eth0_ip  or dev["eth0_ip"]
    eth0_pfx = dev_eth0_pfx or dev["eth0_pfx"]
    eth0_gw  = dev_eth0_gw  or dev["eth0_gw"]
    eth1_ip  = dev_eth1_ip  or dev["eth1_ip"]
    eth1_pfx = dev_eth1_pfx or dev["eth1_pfx"]
    eth1_gw  = dev_eth1_gw  or dev["eth1_gw"]

    log.append(
        f"Collect eth0 of {hostname}: ip={eth0_ip} prefix={eth0_pfx}"
        f" gw={eth0_gw} mac={eth0_mac}"
    )
    if eth1_ip or eth1_mac:
        log.append(
            f"Collect eth1 of {hostname}: ip={eth1_ip} prefix={eth1_pfx}"
            f" gw={eth1_gw} mac={eth1_mac}"
        )

    # ── 序列号 ────────────────────────────────────────────────────────────────
    sn = _read(SN_CMD)
    log.append(f"Collect SN of {hostname}: {sn or '(empty)'}")

    log.append(f"######## End of info collection for {hostname}")
    result = {
        "hostname": hostname,
        "fmt":      fmt,
        "sn":       sn,
        "eth0_ip":  eth0_ip,
        "eth0_pfx": eth0_pfx,
        "eth0_gw":  eth0_gw,
        "eth0_mac": eth0_mac,
        "eth1_ip":  eth1_ip,
        "eth1_pfx": eth1_pfx,
        "eth1_gw":  eth1_gw,
        "eth1_mac": eth1_mac,
        "has_eth1": bool(eth1_ip or eth1_mac),
        "yaml_ok":  yaml_ok,
        "yaml_error": yaml_error,
    }
    return log, result

# ── 主流程 ────────────────────────────────────────────────────────────────────

MAX_PASSWORD_BYTES = 1024


def _read_password_fd(descriptor):
    """Read one web-supplied shared password from an inherited anonymous FD."""
    chunks = []
    total = 0
    try:
        while True:
            chunk = os.read(descriptor, min(4096, MAX_PASSWORD_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAX_PASSWORD_BYTES:
                raise ValueError("密码超过 1024 bytes")
    except OSError as exc:
        raise ValueError(f"无法读取密码描述符：{exc}") from exc
    finally:
        try:
            os.close(descriptor)
        except OSError:
            pass
    payload = b"".join(chunks)
    if any(marker in payload for marker in (b"\x00", b"\r", b"\n")):
        raise ValueError("密码不能包含 NUL 或换行")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("密码不是有效 UTF-8") from exc


def _resolve_backup_passwords(eth_count, ib_count, nvl_count, shared_password):
    """Resolve per-platform passwords without prompting in the Web worker path."""
    if shared_password is not None:
        return (shared_password,) * 3
    eth_password = (
        _ask_password(f"ETH 交换机（{DEFAULT_ETH_USER}）") if eth_count else ""
    )
    ib_password = (
        _ask_password(f"IB  交换机（{DEFAULT_IB_USER}）") if ib_count else ""
    )
    nvl_password = (
        _ask_password(f"NVL 交换机（{DEFAULT_NVL_USER}）") if nvl_count else ""
    )
    return eth_password or "", ib_password or "", nvl_password or ""

def _parse_args(argv):
    """Parse the intentionally small CLI without accepting silent typos."""
    auto_yes = False
    environment = "auto"
    environment_option = ""
    password_fd = None

    def select_environment(value, option):
        nonlocal environment, environment_option
        if environment_option and environment != value:
            raise ValueError(f"{option} 与 {environment_option} 冲突")
        environment = value
        environment_option = option
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "-y":
            auto_yes = True
        elif arg == "--air":
            select_environment("air", "--air")
        elif arg == "--prod":
            select_environment("prod", "--prod")
        elif arg == "--type":
            index += 1
            if index >= len(argv):
                raise ValueError("--type 需要 auto/prod/air")
            value = argv[index].lower()
            if value not in {"auto", "prod", "air"}:
                raise ValueError("--type 只支持 auto/prod/air")
            select_environment(value, f"--type {value}")
        elif arg.startswith("--type="):
            value = arg.split("=", 1)[1].lower()
            if value not in {"auto", "prod", "air"}:
                raise ValueError("--type 只支持 auto/prod/air")
            select_environment(value, f"--type={value}")
        elif arg == "--password-fd":
            index += 1
            if index >= len(argv):
                raise ValueError("--password-fd 需要文件描述符")
            value = argv[index]
            if not value.isascii() or not value.isdigit() or int(value) < 3:
                raise ValueError("--password-fd 必须是大于等于 3 的十进制文件描述符")
            if password_fd is not None:
                raise ValueError("--password-fd 只能指定一次")
            password_fd = int(value)
        elif arg in ("-h", "--help"):
            return auto_yes, environment, True, password_fd
        else:
            raise ValueError(f"不支持的参数：{arg}")
        index += 1
    return auto_yes, environment, False, password_fd


def _inventory_paths(script_dir, environment):
    """Select exactly one environment; never collect Production and AIR twice."""
    name = "02-devices_config.csv"
    path = os.path.join(script_dir, name)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    return [path]


def main():
    global _AUTO_YES, _ENVIRONMENT
    try:
        _AUTO_YES, requested_environment, show_help, password_fd = _parse_args(
            sys.argv[1:]
        )
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        print("使用 --help 查看用法")
        sys.exit(2)

    if show_help:
        if password_fd is not None:
            try:
                os.close(password_fd)
            except OSError:
                pass
        print("""usage: yaml-collect.py [-y] [--air | --prod | --type auto|prod|air]

读取 setup 链接的 devices_config.csv，优先使用 SSH 公钥，必要时提示输入各类型
设备的共享密码，并把配置备份到带 prod/air 来源标记的时间戳目录。

默认从同 IP 设备的实际 hostname/eth0 MAC 自动判断当前可达环境；--type
prod/air 可显式限定，--air/--prod 分别是 --type air/prod 的短写。输出始终标记为
<timestamp>-prod-backup 或 <timestamp>-air-backup。""")
        return

    shared_password = None
    if password_fd is not None:
        try:
            shared_password = _read_password_fd(password_fd)
        except ValueError as exc:
            print(f"[ERROR] 无法读取 Web YAML Backup 密码：{exc}")
            sys.exit(2)

    prod_csv = os.path.join(SCRIPT_DIR, "02-devices_config.csv")
    if requested_environment == "auto":
        try:
            _ENVIRONMENT, probe_details = detect_environment(prod_csv)
        except (OSError, ValueError, RuntimeError, subprocess.TimeoutExpired) as exc:
            print(f"[ERROR] 无法自动判断当前可达环境：{exc}")
            print("        请检查 SSH 公钥，或用 --type prod / --type air 明确指定")
            sys.exit(1)
        print(f"[OK] 自动识别当前可达环境：{_ENVIRONMENT.upper()}")
        for item in probe_details:
            print(f"  probe {item}")
    else:
        _ENVIRONMENT = requested_environment
        print(f"[INFO] 用户限定环境：{_ENVIRONMENT.upper()}；逐台设备仍校验实际 hostname")

    try:
        csv_files = _inventory_paths(SCRIPT_DIR, _ENVIRONMENT)
    except FileNotFoundError as exc:
        print(f"[ERROR] 找不到 {_ENVIRONMENT.upper()} 设备清单：{exc}")
        sys.exit(1)

    all_devices = []
    for path in csv_files:
        try:
            devs = load_devices_csv(path)
        except (OSError, ValueError, csv.Error) as exc:
            print(f"[ERROR] 设备清单无法安全读取：{exc}")
            sys.exit(1)
        if _ENVIRONMENT == "air":
            devs = [dev for dev in devs if dev["fmt"] == "air"]
            apply_static_air_lease_fallbacks(
                devs,
                path,
                os.environ.get("DHCP_LEASES_FILE", "/var/lib/dhcp/dhcpd.leases"),
            )
            runtime, runtime_warnings = load_dynamic_air_backup_devices(
                path,
                os.environ.get("DHCP_LEASES_FILE", "/var/lib/dhcp/dhcpd.leases"),
            )
            devs.extend(runtime)
            for warning in runtime_warnings:
                print(f"  [WARN] AIR 动态设备 {warning}；本轮跳过")
        else:
            devs = [dev for dev in devs if dev["fmt"] != "air"]
        eth_n = sum(1 for d in devs if d["fmt"] == "eth")
        eth_spx_n = sum(1 for d in devs if d["fmt"] == "eth_spx")
        spx_n = sum(1 for d in devs if d["fmt"] == "spx")
        air_n = sum(1 for d in devs if d["fmt"] == "air")
        ib_n  = sum(1 for d in devs if d["fmt"] == "ib")
        nvl_n = sum(1 for d in devs if d["fmt"] == "nvl")
        print(f"读取：{os.path.basename(path)}  eth {eth_n} 条，eth_spx {eth_spx_n} 条，spx {spx_n} 条，air {air_n} 条，ib {ib_n} 条，nvl {nvl_n} 条")
        all_devices.extend(devs)

    # 同 hostname 去重，保留第一次出现
    seen, unique = set(), []
    for d in all_devices:
        key = d["hostname"].lower()
        if key not in seen:
            seen.add(key)
            unique.append(d)
    all_devices = unique

    eth_n = sum(1 for d in all_devices if d["fmt"] == "eth")
    eth_spx_n = sum(1 for d in all_devices if d["fmt"] == "eth_spx")
    spx_n = sum(1 for d in all_devices if d["fmt"] == "spx")
    air_n = sum(1 for d in all_devices if d["fmt"] == "air")
    ib_n  = sum(1 for d in all_devices if d["fmt"] == "ib")
    nvl_n = sum(1 for d in all_devices if d["fmt"] == "nvl")
    print(f"\n共 {len(all_devices)} 台设备（eth: {eth_n}，eth_spx: {eth_spx_n}，spx: {spx_n}，air: {air_n}，ib: {ib_n}，nvl: {nvl_n}）\n")

    # ── 提示输入密码 ──────────────────────────────────────────────────────────
    eth_pass, ib_pass, nvl_pass = _resolve_backup_passwords(
        eth_n + eth_spx_n + spx_n + air_n,
        ib_n,
        nvl_n,
        shared_password,
    )

    if not _confirm("\n[Y/n] 开始收集？"):
        print("已取消")
        sys.exit(0)

    ts      = datetime.now().strftime("%Y%m%d_%H%M")
    suffix = f"-{_ENVIRONMENT}-backup"
    out_dir = os.path.join(SCRIPT_DIR, "yaml-backup", f"{ts}{suffix}")
    os.makedirs(os.path.join(out_dir, "eth"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "spx"), exist_ok=True)
    os.makedirs(os.path.join(out_dir, "ib"),  exist_ok=True)
    os.makedirs(os.path.join(out_dir, "nvl"), exist_ok=True)
    with open(os.path.join(out_dir, "collection.json"), "w", encoding="utf-8") as handle:
        json.dump({
            "schema_version": 1,
            "environment": _ENVIRONMENT,
            "inventory": os.path.basename(csv_files[0]),
            "collector": os.path.basename(__file__),
            "collected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
            "planned_device_count": len(all_devices),
        }, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    log_lock  = Lock()
    all_log   = ["##### Start backup #######"]
    info_rows = []
    failed_devices = []
    print()

    def worker(dev):
        log, result = collect_device(dev, out_dir, eth_pass, ib_pass, nvl_pass)
        with log_lock:
            all_log.extend(log)
        return dev, result, log

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(worker, dev): dev for dev in all_devices}
        for future in as_completed(futures):
            dev, result, device_log = future.result()
            if result:
                sn_str   = f"  sn={result['sn']}" if result["sn"] else ""
                mac_str  = f"  eth0_mac={result['eth0_mac']}"
                if result["eth1_mac"]:
                    mac_str += f"  eth1_mac={result['eth1_mac']}"
                yaml_tag = ""
                if not result["yaml_ok"]:
                    yaml_reason = _compact_error(result.get("yaml_error")) or "原因未知"
                    yaml_tag = f"  [YAML备份失败: {yaml_reason}]"
                    failed_devices.append({
                        "hostname": result["hostname"],
                        "operation": "yaml_backup",
                        "reason": yaml_reason,
                    })
                status = "[OK]  " if result["yaml_ok"] else "[WARN]"
                print(f"{status} {result['hostname']}{sn_str}{mac_str}{yaml_tag}")
                info_rows.append(result)
            else:
                for line in device_log:
                    if (
                        line.startswith("[ERROR] SSH host key changed")
                        or line.startswith("offered_fingerprint=")
                        or line.startswith("rm -- ")
                    ):
                        print(line)
                print(f"[FAIL] {dev['hostname']} （所有地址不可达）")
                reason = (
                    _compact_error(" | ".join(device_log[-3:]))
                    or "所有候选地址不可达"
                )
                failed_devices.append({
                    "hostname": dev["hostname"],
                    "operation": "connect",
                    "reason": reason,
                })

    all_log.append("##### Finish backup #######")

    # ── 写 backup.log ─────────────────────────────────────────────────────────
    log_file = os.path.join(out_dir, "backup.log")
    with open(log_file, "w", encoding="utf-8") as f:
        f.write("\n".join(all_log) + "\n")
    print(f"\n日志：{log_file}")

    # ── 写 devices_config.csv（template 列替换为 sn）─────────────────────────
    csv_file = os.path.join(out_dir, "devices_config.csv")
    with open(csv_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["hostname", "type", "sn",
                         "eth0_ip", "eth0_pfx", "eth0_gw", "eth0_mac",
                         "eth1_ip", "eth1_pfx", "eth1_gw", "eth1_mac"])
        order = {d["hostname"].lower(): i for i, d in enumerate(all_devices)}
        for r in sorted(info_rows, key=lambda x: order.get(x["hostname"].lower(), 9999)):
            writer.writerow([
                r["hostname"], r["fmt"], r["sn"],
                r["eth0_ip"], r["eth0_pfx"], r["eth0_gw"], r["eth0_mac"],
                r["eth1_ip"], r["eth1_pfx"], r["eth1_gw"], r["eth1_mac"],
            ])
    yaml_ok_n  = sum(1 for r in info_rows if r["yaml_ok"])
    yaml_fail_n = len(info_rows) - yaml_ok_n
    reach_fail_n = len(all_devices) - len(info_rows)
    print(f"设备信息收集成功：{len(info_rows)} 台，不可达：{reach_fail_n} 台")
    print(f"YAML 备份成功：{yaml_ok_n} 台，备份失败：{yaml_fail_n} 台")
    if yaml_fail_n and not any((eth_pass, ib_pass, nvl_pass)):
        print(
            "[HINT] 本次未输入密码；若 SSH 公钥登录正常但设备没有免密 sudo，"
            "请重新运行并输入对应设备类型的 SSH/sudo 共用密码。"
        )
    print(f"设备信息：{csv_file}")

    # ── 全部收集完成后，读取两个 CSV 文件进行比对 ────────────────────────────
    compare_csv_files(csv_files, csv_file, out_dir, expected_devices=all_devices)

    failed_devices.sort(key=lambda item: item["hostname"].casefold())
    state = "success"
    if failed_devices:
        state = "partial" if yaml_ok_n else "failed"
    task_result = {
        "schema_version": 1,
        "task": "yaml_backup",
        "state": state,
        "planned": len(all_devices),
        "succeeded": yaml_ok_n,
        "failed_count": len(failed_devices),
        "failed_devices": failed_devices,
    }
    print(
        "[HTTP_ZTP_TASK_RESULT] "
        + json.dumps(task_result, ensure_ascii=False, separators=(",", ":"))
    )
    if state == "failed":
        raise SystemExit(1)


# ── 对比函数 ──────────────────────────────────────────────────────────────────

# (col_key in collected CSV, src_key in source dict, display label)
_COMPARE_FIELDS = [
    ("eth0_ip",  "eth0_ip",  "ETH0 IP"),
    ("eth0_pfx", "eth0_pfx", "ETH0 prefix"),
    ("eth0_gw",  "eth0_gw",  "ETH0 GW"),
    ("eth0_mac", "eth0_mac", "ETH0 MAC"),
    ("eth1_ip",  "eth1_ip",  "ETH1 IP"),
    ("eth1_pfx", "eth1_pfx", "ETH1 prefix"),
    ("eth1_gw",  "eth1_gw",  "ETH1 GW"),
    ("eth1_mac", "eth1_mac", "ETH1 MAC"),
]

def compare_csv_files(src_csv_paths, collected_csv_path, out_dir, expected_devices=None):
    """
    读取两个 CSV 文件进行比对：
      src_csv_paths      : 提供的源 CSV 文件路径列表（输入）
      collected_csv_path : 本次收集写出的 devices_config.csv（输出）
    源 CSV 中为空的字段跳过对比。
    """
    print("\n" + "─" * 60)
    print("对比：提供的 CSV  vs  收集到的 CSV")
    print("─" * 60)

    # 读取源 CSV（使用已有的 load_devices_csv，按 hostname 建索引）
    src_map = {}
    if expected_devices is not None:
        for dev in expected_devices:
            src_map[dev["hostname"].lower()] = dev
    else:
        for p in src_csv_paths:
            for dev in load_devices_csv(p):
                src_map[dev["hostname"].lower()] = dev

    # 读取收集到的 CSV（列名唯一，可用 DictReader）
    col_map = {}
    with open(collected_csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            hn = (row.get("hostname") or "").strip()
            if hn:
                col_map[hn.lower()] = {k: (v or "").strip() for k, v in row.items()}

    diff_lines = [
        f"# 对比报告",
        f"# 源文件   : {', '.join(os.path.basename(p) for p in src_csv_paths)}",
        f"# 收集文件 : {os.path.basename(collected_csv_path)}",
        "",
    ]
    diffs = 0
    ok    = 0

    # ── 1. 已收集设备：逐字段对比 ────────────────────────────────────────────
    for hn_lower, col in sorted(col_map.items()):
        hostname = col.get("hostname", hn_lower)
        src = src_map.get(hn_lower)
        if src is None:
            msg = f"[WARN] {hostname}：在源 CSV 中未找到对应记录"
            print(msg); diff_lines.append(msg)
            diffs += 1
            continue

        host_diffs = []
        for col_key, src_key, label in _COMPARE_FIELDS:
            cv = col.get(col_key, "")
            sv = (src.get(src_key) or "").strip()
            if not sv:
                continue  # 源 CSV 未填该字段，跳过
            if "mac" in col_key:
                cv = cv.replace(":", "").replace("-", "").lower()
                sv = sv.replace(":", "").replace("-", "").lower()
            if cv != sv:
                host_diffs.append(f"  {label:14s}  收集={cv!r:22s}  源CSV={sv!r}")

        if host_diffs:
            header = f"[DIFF] {hostname}"
            print(header); diff_lines.append(header)
            for d in host_diffs:
                print(d); diff_lines.append(d)
            diffs += 1
        else:
            line = f"[OK]   {hostname}"
            print(line); diff_lines.append(line)
            ok += 1

    # ── 2. 源 CSV 有但未成功收集（不可达）的设备 ─────────────────────────────
    missing = [d["hostname"] for d in src_map.values()
               if d["hostname"].lower() not in col_map]
    if missing:
        diff_lines.append("")
        diff_lines.append("# 源 CSV 中存在但未成功收集（不可达）：")
        for hn in sorted(missing):
            msg = f"[MISS] {hn}"
            print(msg); diff_lines.append(msg)
        diffs += len(missing)

    # ── 汇总 ─────────────────────────────────────────────────────────────────
    print("─" * 60)
    summary = f"结果：{ok} 台一致，{diffs} 台存在差异或未收集"
    print(summary)
    diff_lines.extend(["", summary])

    diff_file = os.path.join(out_dir, "diff.log")
    with open(diff_file, "w", encoding="utf-8") as f:
        f.write("\n".join(diff_lines) + "\n")
    print(f"差异报告：{diff_file}")


if __name__ == "__main__":
    main()
