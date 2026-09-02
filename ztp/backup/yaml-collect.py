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
import getpass
import json
import ipaddress
import os
import re
import select
import shlex
import subprocess
import sys
import tempfile
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
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "LogLevel=ERROR",
    "-o", "ConnectTimeout=5",
    "-o", "ServerAliveInterval=10",
]

_AUTO_YES = False
_ENVIRONMENT = "prod"
_ASKPASS_PATH = None
_AUTH_MODES = {}
_AUTH_LOCK = Lock()
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
    global _ASKPASS_PATH
    if _ASKPASS_PATH and os.path.exists(_ASKPASS_PATH):
        os.remove(_ASKPASS_PATH)
    _ASKPASS_PATH = None


def _ensure_askpass():
    """创建不含密码内容的临时 SSH_ASKPASS helper。"""
    global _ASKPASS_PATH
    with _AUTH_LOCK:
        if _ASKPASS_PATH:
            return _ASKPASS_PATH
        fd, path = tempfile.mkstemp(prefix="ztp-backup-askpass-", suffix=".sh")
        try:
            os.write(fd, b'#!/bin/sh\nprintf "%s\\n" "$ZTP_BACKUP_PASSWORD"\n')
        finally:
            os.close(fd)
        os.chmod(path, 0o700)
        _ASKPASS_PATH = path
        atexit.register(_cleanup_askpass)
        return path


def _run_ssh(user, ip, cmd, timeout, extra_opts, env=None):
    return subprocess.run(
        ["ssh", "-C"] + SSH_OPTS + extra_opts + [f"{user}@{ip}", cmd],
        stdin=subprocess.DEVNULL, capture_output=True, text=True,
        timeout=timeout, env=env,
    )


def _password_ssh_env(password):
    env = os.environ.copy()
    env.update({
        "SSH_ASKPASS": _ensure_askpass(),
        "SSH_ASKPASS_REQUIRE": "force",
        "DISPLAY": env.get("DISPLAY") or "ztp-backup:0",
        "ZTP_BACKUP_PASSWORD": password,
    })
    return env


_KEY_AUTH_OPTS = [
    "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
]
_PASSWORD_AUTH_OPTS = [
    "-o", "BatchMode=no", "-o", "PubkeyAuthentication=no",
    "-o", "PreferredAuthentications=password,keyboard-interactive",
]


def _ssh(user, password, ip, cmd, timeout=30):
    """
    先用无副作用的 ``true`` 确定认证方式，再执行远端命令。

    远端命令自身退出非零（例如 sudo 密码错误）不能被当成 SSH 公钥认证
    失败，否则脚本会错误切换到密码登录，并用 ``Permission denied`` 掩盖
    原始命令错误。
    """
    key = (user, ip)
    with _AUTH_LOCK:
        mode = _AUTH_MODES.get(key)

    password_env = None
    if mode is None:
        probe = _run_ssh(user, ip, "true", timeout, _KEY_AUTH_OPTS)
        if probe.returncode == 0:
            mode = "key"
        elif password:
            password_env = _password_ssh_env(password)
            probe = _run_ssh(
                user, ip, "true", timeout, _PASSWORD_AUTH_OPTS,
                env=password_env,
            )
            if probe.returncode == 0:
                mode = "password"
            else:
                return probe.stdout, probe.stderr.strip(), probe.returncode
        else:
            return probe.stdout, probe.stderr.strip(), probe.returncode

        with _AUTH_LOCK:
            _AUTH_MODES[key] = mode

    if mode == "key":
        result = _run_ssh(user, ip, cmd, timeout, _KEY_AUTH_OPTS)
    else:
        if password_env is None:
            password_env = _password_ssh_env(password)
        result = _run_ssh(
            user, ip, cmd, timeout, _PASSWORD_AUTH_OPTS,
            env=password_env,
        )
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
            user, password, target, "hostname -s 2>/dev/null"
        )
        actual_hostname = actual_hostname.strip().split(".", 1)[0]
        if actual_rc != 0:
            detail = _compact_error(actual_err) or f"exit={actual_rc}"
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
        yaml_cmd = f"printf '%s\\n' {shlex.quote(password)} | sudo -S -p '' cat {shlex.quote(yaml_remote)}"
    else:
        yaml_cmd = f"sudo -n cat {shlex.quote(yaml_remote)}"
    yaml_out, yaml_err, yaml_rc = _ssh(user, password, connect_target, yaml_cmd)
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
        out, _, _ = _ssh(user, password, connect_target, cmd)
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

def _parse_args(argv):
    """Parse the intentionally small CLI without accepting silent typos."""
    auto_yes = False
    environment = "auto"
    environment_option = ""

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
        elif arg in ("-h", "--help"):
            return auto_yes, environment, True
        else:
            raise ValueError(f"不支持的参数：{arg}")
        index += 1
    return auto_yes, environment, False


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
        _AUTO_YES, requested_environment, show_help = _parse_args(sys.argv[1:])
    except ValueError as exc:
        print(f"[ERROR] {exc}")
        print("使用 --help 查看用法")
        sys.exit(2)

    if show_help:
        print("""usage: yaml-collect.py [-y] [--air | --prod | --type auto|prod|air]

读取 setup 链接的 devices_config.csv，优先使用 SSH 公钥，必要时提示输入各类型
设备的共享密码，并把配置备份到带 prod/air 来源标记的时间戳目录。

默认从同 IP 设备的实际 hostname/eth0 MAC 自动判断当前可达环境；--type
prod/air 可显式限定，--air/--prod 分别是 --type air/prod 的短写。输出始终标记为
<timestamp>-prod-backup 或 <timestamp>-air-backup。""")
        return

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
    eth_pass = ib_pass = nvl_pass = None
    if eth_n + eth_spx_n + spx_n + air_n > 0:
        eth_pass = _ask_password(f"ETH 交换机（{DEFAULT_ETH_USER}）")
    if ib_n > 0:
        ib_pass  = _ask_password(f"IB  交换机（{DEFAULT_IB_USER}）")
    if nvl_n > 0:
        nvl_pass = _ask_password(f"NVL 交换机（{DEFAULT_NVL_USER}）")
    eth_pass = eth_pass or ""
    ib_pass  = ib_pass  or ""
    nvl_pass = nvl_pass or ""

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
    print()

    def worker(dev):
        log, result = collect_device(dev, out_dir, eth_pass, ib_pass, nvl_pass)
        with log_lock:
            all_log.extend(log)
        return dev, result

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(worker, dev): dev for dev in all_devices}
        for future in as_completed(futures):
            dev, result = future.result()
            if result:
                sn_str   = f"  sn={result['sn']}" if result["sn"] else ""
                mac_str  = f"  eth0_mac={result['eth0_mac']}"
                if result["eth1_mac"]:
                    mac_str += f"  eth1_mac={result['eth1_mac']}"
                yaml_tag = ""
                if not result["yaml_ok"]:
                    yaml_reason = _compact_error(result.get("yaml_error")) or "原因未知"
                    yaml_tag = f"  [YAML备份失败: {yaml_reason}]"
                status = "[OK]  " if result["yaml_ok"] else "[WARN]"
                print(f"{status} {result['hostname']}{sn_str}{mac_str}{yaml_tag}")
                info_rows.append(result)
            else:
                print(f"[FAIL] {dev['hostname']} （所有地址不可达）")

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
