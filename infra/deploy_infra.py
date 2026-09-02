#!/usr/bin/env python3
"""Prepare infra shell scripts and deploy them to CSV devices of type=server."""

from __future__ import annotations

import argparse
from concurrent.futures import as_completed, ThreadPoolExecutor
import csv
from datetime import datetime, timezone
import getpass
import hashlib
import ipaddress
import os
from pathlib import Path
import re
import select
import shlex
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Iterable
import urllib.error
import urllib.request

import yaml


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_GLOBAL = SCRIPT_DIR / "01-global.yaml"
DEFAULT_DEVICES = SCRIPT_DIR / "02-devices_config.csv"
DEFAULT_SETUP = SCRIPT_DIR / "infra-setup.sh"
DEFAULT_TEARDOWN = SCRIPT_DIR / "infra-teardown.sh"
MANAGED_BEGIN = "# BEGIN managed by deploy_infra.py"
MANAGED_END = "# END managed by deploy_infra.py"
NA_VALUES = {"", "na", "n/a", "none", "null", "-"}


class DeployError(RuntimeError):
    pass


class TeeStream:
    def __init__(self, terminal: object, log_stream: object):
        self.terminal = terminal
        self.log_stream = log_stream

    def write(self, data: str) -> int:
        written = self.terminal.write(data)
        self.log_stream.write(data)
        return written

    def flush(self) -> None:
        self.terminal.flush()
        self.log_stream.flush()

    def isatty(self) -> bool:
        return bool(self.terminal.isatty())

    def fileno(self) -> int:
        return self.terminal.fileno()

    @property
    def encoding(self) -> str:
        return getattr(self.terminal, "encoding", "utf-8")


def run_with_log(prefix: str, callback: object) -> int:
    log_dir = SCRIPT_DIR / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    log_path = log_dir / f"{prefix}-{timestamp}-{os.getpid()}.log"
    original_stdout, original_stderr = sys.stdout, sys.stderr
    with log_path.open("a", encoding="utf-8") as log_stream:
        sys.stdout = TeeStream(original_stdout, log_stream)
        sys.stderr = TeeStream(original_stderr, log_stream)
        try:
            print(f"[LOG] 执行日志：{log_path}")
            return callback()
        finally:
            sys.stdout.flush()
            sys.stderr.flush()
            sys.stdout, sys.stderr = original_stdout, original_stderr


def _clean(value: object) -> str:
    return "" if value is None else str(value).strip()


def _required_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list):
        raise DeployError(f"{label} 必须是非空列表")
    result = [_clean(item) for item in value if _clean(item)]
    if not result:
        raise DeployError(f"{label} 不能为空")
    if any(any(ch.isspace() for ch in item) for item in result):
        raise DeployError(f"{label} 的单个值不能包含空白字符")
    return result


def load_common(global_file: Path) -> tuple[list[str], list[str], str]:
    try:
        data = yaml.safe_load(global_file.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DeployError(f"global 文件不存在：{global_file}") from exc
    except yaml.YAMLError as exc:
        raise DeployError(f"global YAML 格式错误：{exc}") from exc

    try:
        system = data["common"]["switch"]["system"]
        dns = _required_list(system["dns"]["server"], "common.switch.system.dns.server")
        ntp = _required_list(system["ntp"]["server"], "common.switch.system.ntp.server")
        timezone = _clean(system["date-time"]["timezone"])
    except (KeyError, TypeError) as exc:
        raise DeployError(f"global 缺少 common.switch.system 的 DNS/NTP/timezone 字段：{exc}") from exc
    if not timezone or any(ch.isspace() for ch in timezone):
        raise DeployError("common.switch.system.date-time.timezone 无效")
    return dns, ntp, timezone


def _interface_ipv4(interface: str) -> str | None:
    commands = [
        ["ip", "-4", "-o", "addr", "show", "dev", interface],
        ["ipconfig", "getifaddr", interface],
        ["ifconfig", interface],
    ]
    patterns = [
        re.compile(r"\binet\s+(\d+\.\d+\.\d+\.\d+)(?:/\d+)?"),
        re.compile(r"^\s*(\d+\.\d+\.\d+\.\d+)\s*$", re.MULTILINE),
    ]
    for command in commands:
        if not shutil.which(command[0]):
            continue
        result = subprocess.run(command, text=True, capture_output=True)
        if result.returncode != 0:
            continue
        for pattern in patterns:
            match = pattern.search(result.stdout)
            if match:
                address = str(ipaddress.IPv4Address(match.group(1)))
                if not address.startswith("127."):
                    return address
    return None


def detect_route_source_ipv4(target: str) -> str:
    """Return the local IPv4 source selected by the route to target."""
    target = str(ipaddress.IPv4Address(target))
    if shutil.which("ip"):
        result = subprocess.run(
            ["ip", "-4", "route", "get", target], text=True, capture_output=True
        )
        if result.returncode == 0:
            match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)\b", result.stdout)
            if match:
                return str(ipaddress.IPv4Address(match.group(1)))

    if shutil.which("route"):
        result = subprocess.run(["route", "-n", "get", target], text=True, capture_output=True)
        if result.returncode == 0:
            match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.MULTILINE)
            if match:
                address = _interface_ipv4(match.group(1))
                if address:
                    return address

    raise DeployError(
        f"无法根据到设备 {target} 的路由确定本机源 IPv4；请检查路由，"
        "或使用 --http-server-ip 显式指定"
    )


def determine_http_source_ip(
    servers: list[dict[str, str]], explicit_ip: str | None = None
) -> str:
    if explicit_ip:
        try:
            return str(ipaddress.IPv4Address(explicit_ip))
        except ipaddress.AddressValueError as exc:
            raise DeployError(f"--http-server-ip 不是有效 IPv4：{explicit_ip}") from exc
    if not servers:
        raise DeployError("没有有效的 type=server 目标，无法通过设备路由确定 HTTP Server 地址")

    routes: list[tuple[str, str, str]] = []
    for server in servers:
        source = detect_route_source_ipv4(server["address"])
        routes.append((server["hostname"], server["address"], source))
        print(f"[INFO] 路由 {server['hostname']} ({server['address']}) → 本机源地址 {source}")

    unique_sources = {source for _hostname, _address, source in routes}
    if len(unique_sources) != 1:
        details = "; ".join(
            f"{hostname}({address})={source}" for hostname, address, source in routes
        )
        raise DeployError(
            "目标设备使用了不同的本机出接口源地址，单一 setup 脚本无法安全复用：" + details
        )
    return unique_sources.pop()


def local_http_url(http_ip: str) -> str:
    return f"http://{ipaddress.IPv4Address(http_ip)}/apps"


def http_service_works(http_ip: str, timeout: float = 3.0) -> bool:
    base = local_http_url(http_ip)
    repository_paths = (
        "ubuntu-22.04/amd64", "ubuntu-22.04/arm64",
        "ubuntu-24.04/amd64", "ubuntu-24.04/arm64",
    )
    for repository in repository_paths:
        request = urllib.request.Request(
            f"{base}/{repository}/Packages.gz", method="HEAD"
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                if 200 <= response.status < 400:
                    return True
        except (OSError, urllib.error.URLError, urllib.error.HTTPError, ValueError):
            continue
    return False


def render_managed_block(
    http_ip: str, dns: Iterable[str], ntp: Iterable[str], timezone: str,
    local_http_enabled: bool = True,
) -> str:
    # Preserve the future publication URL even before Packages.gz exists.  A
    # first --mgmt run needs this address to verify the repository it creates;
    # clients still obey local_http_enabled and will not use an unavailable URL.
    http_server = local_http_url(http_ip)
    dns_values = " ".join(shlex.quote(item) for item in dns)
    ntp_values = " ".join(shlex.quote(item) for item in ntp)
    return "\n".join(
        [
            MANAGED_BEGIN,
            f"http_server={shlex.quote(http_server)}",
            f"local_http_enabled={'true' if local_http_enabled else 'false'}",
            f"dns_servers=({dns_values})",
            f"ntp_servers=({ntp_values})",
            f"time_zone={shlex.quote(timezone)}",
            MANAGED_END,
        ]
    )


def update_runtime_config(runtime_config: Path, managed_block: str,
                          dry_run: bool = False) -> bool:
    updated = managed_block.rstrip() + "\n"
    original = runtime_config.read_text(encoding="utf-8") if runtime_config.is_file() else ""
    if updated == original:
        print(f"[OK] infra 主机运行参数已经是最新：{runtime_config}")
        return False
    if dry_run:
        print(f"[DRY] 将更新 infra 主机运行参数：{runtime_config}")
        print(managed_block)
        return True

    temp_name = ""
    try:
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=runtime_config.parent,
            prefix=".infra-runtime.", delete=False
        ) as temp_file:
            temp_file.write(updated)
            temp_name = temp_file.name
        os.chmod(temp_name, 0o600)
        syntax = subprocess.run(["bash", "-n", temp_name], text=True, capture_output=True)
        if syntax.returncode != 0:
            raise DeployError(f"infra-runtime.conf 语法检查失败：{syntax.stderr.strip()}")
        os.replace(temp_name, runtime_config)
    finally:
        if temp_name and os.path.exists(temp_name):
            os.unlink(temp_name)
    print(f"[OK] 已根据 global common 更新主机运行参数：{runtime_config}")
    return True


def load_servers(devices_file: Path, only_hosts: set[str] | None = None) -> list[dict[str, str]]:
    try:
        stream = devices_file.open(newline="", encoding="utf-8-sig")
    except FileNotFoundError as exc:
        raise DeployError(f"devices CSV 不存在：{devices_file}") from exc
    with stream:
        reader = csv.DictReader(stream)
        required = {"hostname", "type", "eth0_ip"}
        missing = required.difference(reader.fieldnames or [])
        if missing:
            raise DeployError(f"devices CSV 缺少字段：{', '.join(sorted(missing))}")
        servers: list[dict[str, str]] = []
        seen: set[str] = set()
        for line_no, row in enumerate(reader, 2):
            if _clean(row.get("type")).lower() != "server":
                continue
            hostname = _clean(row.get("hostname"))
            raw_address = _clean(row.get("eth0_ip"))
            if raw_address.lower() in NA_VALUES:
                print(f"[WARN] 第 {line_no} 行 server {hostname or '<无hostname>'} 没有 eth0_ip，跳过")
                continue
            try:
                parsed_address = ipaddress.ip_interface(raw_address).ip
            except ValueError:
                try:
                    parsed_address = ipaddress.ip_address(raw_address)
                except ValueError:
                    print(f"[WARN] 第 {line_no} 行 server 的 eth0_ip 无效：{raw_address}，跳过")
                    continue
            if not isinstance(parsed_address, ipaddress.IPv4Address):
                print(f"[WARN] 第 {line_no} 行 server 目前只支持 IPv4 SSH 地址：{raw_address}，跳过")
                continue
            address = str(parsed_address)
            if only_hosts and address not in only_hosts and hostname not in only_hosts:
                continue
            if address in seen:
                print(f"[WARN] 重复 server 地址 {address}，只部署一次")
                continue
            seen.add(address)
            servers.append({"hostname": hostname or address, "address": address})
    return servers


def _validate_username(username: str) -> str:
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", username):
        raise DeployError(f"SSH 用户名不安全或无效：{username!r}")
    return username


def _identity_args(identity: Path | None) -> list[str]:
    return ["-i", str(identity)] if identity else []


def _ssh_options(batch_mode: bool = False) -> list[str]:
    result = [
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=15",
        "-o", "ServerAliveCountMax=3",
    ]
    if batch_mode:
        result += ["-o", "BatchMode=yes", "-o", "PasswordAuthentication=no"]
    return result


def key_login_works(host: str, username: str, identity: Path | None) -> bool:
    target = f"{_validate_username(username)}@{host}"
    command = ["ssh", *_identity_args(identity), *_ssh_options(True), target, "true"]
    return subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def find_public_key(identity: Path | None) -> tuple[Path | None, Path | None]:
    if identity:
        identity = identity.expanduser().resolve()
        if identity.suffix == ".pub":
            private = identity.with_suffix("")
            return identity, private if private.is_file() else None
        public = Path(str(identity) + ".pub")
        return (public if public.is_file() else None), identity
    for private in (Path.home() / ".ssh/id_ed25519", Path.home() / ".ssh/id_rsa"):
        public = Path(str(private) + ".pub")
        if private.is_file() and public.is_file():
            return public, private
    return None, None


def ensure_public_key(identity: Path | None) -> tuple[Path, Path | None]:
    public, private = find_public_key(identity)
    if public:
        return public, private
    if not sys.stdin.isatty():
        raise DeployError("没有可部署的本地 SSH 公钥；请先创建密钥或用 --identity 指定")
    default_private = Path.home() / ".ssh/id_ed25519"
    answer = input(f"没有找到本地 SSH key，是否创建 {default_private}？[Y/n] ").strip().lower()
    if answer in {"n", "no"}:
        raise DeployError("没有 SSH 公钥，无法部署免密登录")
    default_private.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    subprocess.run(
        ["ssh-keygen", "-t", "ed25519", "-f", str(default_private), "-N", "", "-C", "http-infra-deploy"],
        check=True,
    )
    return Path(str(default_private) + ".pub"), default_private


def copy_public_key_with_password(
    host: str, username: str, public_key: Path, password: str
) -> bool:
    sshpass = shutil.which("sshpass")
    ssh_copy_id = shutil.which("ssh-copy-id")
    if not sshpass or not ssh_copy_id:
        missing = "sshpass" if not sshpass else "ssh-copy-id"
        raise DeployError(f"系统没有 {missing}，无法安全复用 SSH 密码部署公钥")

    read_fd, write_fd = os.pipe()
    try:
        os.write(write_fd, (password + "\n").encode("utf-8"))
        os.close(write_fd)
        write_fd = -1
        command = [
            sshpass, "-d", str(read_fd), ssh_copy_id, "-i", str(public_key),
            "-o", "StrictHostKeyChecking=accept-new", f"{username}@{host}",
        ]
        return subprocess.run(command, pass_fds=(read_fd,)).returncode == 0
    finally:
        os.close(read_fd)
        if write_fd >= 0:
            os.close(write_fd)


def establish_key_login(
    host: str, username: str, identity: Path | None,
    shared_ssh_password: str | None = None,
    username_confirmed: bool = False,
) -> tuple[str, Path | None, str | None]:
    requested_identity = identity
    if identity and identity.suffix == ".pub":
        _public, private = find_public_key(identity)
        identity = private
    username = _validate_username(username)
    if key_login_works(host, username, identity):
        print(f"[OK] {username}@{host} 免密登录可用")
        return username, identity, shared_ssh_password

    if not sys.stdin.isatty():
        raise DeployError(f"{username}@{host} 免密登录失败，非交互终端无法输入登录信息")
    if not username_confirmed:
        entered = input(f"{host} 免密登录失败，请输入 SSH 用户名 [{username}]：").strip()
        if entered:
            username = _validate_username(entered)
            if key_login_works(host, username, identity):
                print(f"[OK] {username}@{host} 免密登录可用")
                return username, identity, shared_ssh_password

    public_key, private_key = ensure_public_key(requested_identity)
    if shared_ssh_password is None:
        shared_ssh_password = getpass.getpass(
            f"SSH 登录密码 for {username}（将复用于其他 client）："
        )
        if not shared_ssh_password:
            raise DeployError("SSH 登录密码不能为空")
    print(f"[ACTION] 正在为 {username}@{host} 部署公钥 {public_key}")
    if not copy_public_key_with_password(
        host, username, public_key, shared_ssh_password
    ):
        raise DeployError(f"{username}@{host} 密码登录或公钥部署失败")
    identity = private_key or identity
    if not key_login_works(host, username, identity):
        raise DeployError(f"公钥已尝试部署，但 {username}@{host} 免密验证仍失败")
    print(f"[OK] {username}@{host} 公钥部署并验证成功")
    return username, identity, shared_ssh_password


def prepare_server_access(
    server: dict[str, str], username: str, identity: Path | None,
    shared_ssh_password: str | None = None,
    username_confirmed: bool = False,
) -> tuple[str, Path | None, bool, str | None]:
    host = server["address"]
    username, identity, shared_ssh_password = establish_key_login(
        host, username, identity, shared_ssh_password, username_confirmed
    )
    needs_sudo_password = False
    if username != "root":
        target = f"{username}@{host}"
        command = [
            "ssh", *_identity_args(identity), *_ssh_options(True), target, "sudo -n true"
        ]
        check = subprocess.run(command, text=True, capture_output=True)
        if check.returncode != 0:
            if not sys.stdin.isatty():
                raise DeployError(
                    f"{target} 没有免密 sudo，非交互终端无法安全输入 sudo 密码"
                )
            needs_sudo_password = True
            print(
                f"[INFO] {target} 需要 sudo 密码；验证共用密码后仍将加入并行队列"
            )
    mode = "共用密码 sudo" if needs_sudo_password else "免密 sudo/root"
    print(f"[OK] {server['hostname']} SSH 前置检查通过（{mode}）")
    return username, identity, needs_sudo_password, shared_ssh_password


def sudo_password_works(
    host: str, username: str, identity: Path | None, password: str
) -> bool:
    target = f"{_validate_username(username)}@{host}"
    command = [
        "ssh", *_identity_args(identity), *_ssh_options(True), target,
        "sudo -S -k -p '' -v && sudo -k",
    ]
    result = subprocess.run(
        command,
        input=password + "\n",
        text=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return result.returncode == 0


def confirm_teardown_targets(
    servers: list[dict[str, str]], timeout: int = 15
) -> bool:
    """Show the destructive target set and accept yes by default or timeout."""
    print("\n[WARN] 即将在以下 server 上执行 teardown（回滚配置并卸载本工具记录的软件包）：")
    for index, server in enumerate(servers, 1):
        print(f"    {index}. {server['hostname']} ({server['address']})")
    prompt = f"是否继续？[Y/n]（默认允许，{timeout} 秒后自动执行）："
    if not sys.stdin.isatty():
        print(prompt)
        print("[INFO] 非交互终端，按默认选项继续执行 teardown。")
        return True

    print(prompt, end="", flush=True)
    ready, _writable, _exceptional = select.select([sys.stdin], [], [], timeout)
    if not ready:
        print()
        print(f"[INFO] {timeout} 秒内未收到输入，按默认选项继续执行 teardown。")
        return True
    answer = sys.stdin.readline().strip().lower()
    if answer in {"", "y", "yes"}:
        return True
    if answer in {"n", "no"}:
        return False
    print(f"[WARN] 无法识别输入 {answer!r}，按默认选项继续执行 teardown。")
    return True


def deploy_server(
    server: dict[str, str], username: str, identity: Path | None,
    setup_script: Path, teardown_script: Path, runtime_config: Path, client_log: Path,
    sudo_password: str | None = None,
    action: str = "setup",
) -> None:
    host = server["address"]
    label = server["hostname"]
    target = f"{username}@{host}"
    ssh_base = ["ssh", *_identity_args(identity), *_ssh_options(True)]
    scp_base = ["scp", *_identity_args(identity), *_ssh_options(True)]
    client_log.parent.mkdir(parents=True, exist_ok=True)
    with client_log.open("a", encoding="utf-8") as log_stream:
        def logged_run(command: list[str], input_text: str | None = None) -> None:
            subprocess.run(
                command, check=True, text=True, stdout=log_stream,
                stderr=subprocess.STDOUT, input=input_text,
            )

        log_stream.write(
            f"[{datetime.now(timezone.utc).isoformat()}] deploy started: {label} ({host})\n"
        )
        home_result = subprocess.run(
            [*ssh_base, target, "printf '%s' \"$HOME\""],
            check=True, text=True, capture_output=True,
        )
        if home_result.stderr:
            log_stream.write(home_result.stderr)
        remote_home = home_result.stdout.strip()
        if not re.fullmatch(r"/[A-Za-z0-9_./-]+", remote_home):
            raise DeployError(f"无法确定 {target} 的安全家目录：{remote_home!r}")
        remote_dir = f"{remote_home}/http-infra"
        release_name = f"{int(time.time())}-{os.getpid()}"
        release_dir = f"{remote_dir}/releases/{release_name}"
        setup_stage = f"{release_dir}/infra-setup.sh"
        teardown_stage = f"{release_dir}/infra-teardown.sh"
        runtime_stage = f"{release_dir}/infra-runtime.conf"
        if action == "setup":
            setup_hash = hashlib.sha256(setup_script.read_bytes()).hexdigest()
            teardown_hash = hashlib.sha256(teardown_script.read_bytes()).hexdigest()
            runtime_hash = hashlib.sha256(runtime_config.read_bytes()).hexdigest()
            logged_run([*ssh_base, target, f"install -d -m 0755 -- {shlex.quote(release_dir)}"])
            logged_run([*scp_base, str(setup_script), f"{target}:{setup_stage}"])
            logged_run([*scp_base, str(teardown_script), f"{target}:{teardown_stage}"])
            logged_run([*scp_base, str(runtime_config), f"{target}:{runtime_stage}"])
            current_stage = f"{remote_dir}/.current-{os.getpid()}"
            current_link = f"{remote_dir}/current"
            setup_link = f"{remote_dir}/infra-setup.sh"
            teardown_link = f"{remote_dir}/infra-teardown.sh"
            setup_check = shlex.quote(f"{setup_hash}  {setup_stage}")
            teardown_check = shlex.quote(f"{teardown_hash}  {teardown_stage}")
            runtime_check = shlex.quote(f"{runtime_hash}  {runtime_stage}")
            activate_command = (
                f"bash -n {shlex.quote(setup_stage)} && bash -n {shlex.quote(teardown_stage)} && "
                f"bash -n {shlex.quote(runtime_stage)} && "
                f"printf '%s\\n' {setup_check} {teardown_check} {runtime_check} | sha256sum -c - && "
                f"chmod 0755 -- {shlex.quote(setup_stage)} {shlex.quote(teardown_stage)} && "
                f"chmod 0600 -- {shlex.quote(runtime_stage)} && "
                f"ln -sfn -- current/infra-setup.sh {shlex.quote(setup_link)} && "
                f"ln -sfn -- current/infra-teardown.sh {shlex.quote(teardown_link)} && "
                f"ln -sfn -- {shlex.quote('releases/' + release_name)} {shlex.quote(current_stage)} && "
                f"mv -Tf -- {shlex.quote(current_stage)} {shlex.quote(current_link)}"
            )
            logged_run([*ssh_base, target, activate_command])
            action_script = "./current/infra-setup.sh"
            action_args = " --client --non-interactive --enable-bluefield-nic"
            action_log_pattern = "infra-setup-*.log"
        elif action == "teardown":
            teardown_hash = hashlib.sha256(teardown_script.read_bytes()).hexdigest()
            logged_run([*ssh_base, target, f"install -d -m 0755 -- {shlex.quote(release_dir)}"])
            logged_run([*scp_base, str(teardown_script), f"{target}:{teardown_stage}"])
            teardown_check = shlex.quote(f"{teardown_hash}  {teardown_stage}")
            teardown_link = f"{remote_dir}/infra-teardown.sh"
            teardown_link_stage = f"{remote_dir}/.infra-teardown-{os.getpid()}"
            activate_command = (
                f"bash -n {shlex.quote(teardown_stage)} && "
                f"printf '%s\\n' {teardown_check} | sha256sum -c - && "
                f"chmod 0755 -- {shlex.quote(teardown_stage)} && "
                f"ln -sfn -- {shlex.quote('releases/' + release_name + '/infra-teardown.sh')} "
                f"{shlex.quote(teardown_link_stage)} && "
                f"mv -Tf -- {shlex.quote(teardown_link_stage)} {shlex.quote(teardown_link)}"
            )
            logged_run([*ssh_base, target, activate_command])
            action_script = "./infra-teardown.sh"
            action_args = " --non-interactive --yes"
            action_log_pattern = "infra-teardown-*.log"
        else:
            raise DeployError(f"未知部署动作：{action}")
        if username == "root":
            action_command = f"bash {action_script}{action_args}"
        elif sudo_password is not None:
            action_command = f"sudo -S -k -p '' bash {action_script}{action_args}"
        else:
            action_command = f"sudo -n bash {action_script}{action_args}"
        remote_command = (
            f"cd {shlex.quote(remote_dir)} || exit 1; "
            f"{action_command}; rc=$?; "
            "if [ \"$rc\" -ne 0 ]; then "
            f"echo '--- latest remote infra-{action} log (last 80 lines) ---'; "
            f"latest=$(ls -1t logs/{action_log_pattern} 2>/dev/null | head -1); "
            "if [ -n \"$latest\" ]; then tail -n 80 -- \"$latest\"; "
            f"else echo 'remote infra-{action} log not found'; fi; "
            "fi; exit \"$rc\""
        )
        logged_run(
            [*ssh_base, target, remote_command],
            sudo_password + "\n" if sudo_password is not None else None,
        )
        log_stream.write(
            f"[{datetime.now(timezone.utc).isoformat()}] {action} completed: {label} ({host})\n"
        )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--global-file", type=Path, default=DEFAULT_GLOBAL)
    parser.add_argument("--devices-file", type=Path, default=DEFAULT_DEVICES)
    parser.add_argument(
        "--setup-script", type=Path, default=DEFAULT_SETUP,
        help="要上传的 setup 脚本路径；不决定执行动作",
    )
    parser.add_argument(
        "--teardown-script", type=Path, default=DEFAULT_TEARDOWN,
        help="要上传的 teardown 脚本路径；要执行它还必须指定 --teardown",
    )
    parser.add_argument(
        "--teardown", action="store_true",
        help="在选定 client 上执行 teardown；默认执行 setup",
    )
    parser.add_argument(
        "--http-server-ip", "--bond0-ip", dest="http_server_ip",
        help="特殊环境显式指定 HTTP Server IPv4；--bond0-ip 作为兼容别名保留",
    )
    parser.add_argument("--user", default=getpass.getuser(), help="首次尝试免密登录的 SSH 用户")
    parser.add_argument("--identity", type=Path, help="SSH 私钥或公钥路径")
    parser.add_argument("--host", action="append", dest="hosts", help="只部署指定 hostname/IP，可重复")
    execution_mode = parser.add_mutually_exclusive_group()
    execution_mode.add_argument(
        "--prepare-only", action="store_true", help="只更新并检查 shell 脚本，不连接设备"
    )
    execution_mode.add_argument(
        "--dry-run", action="store_true", help="显示更新与部署计划，不修改或连接"
    )
    parser.add_argument(
        "--max-workers", type=int, default=8,
        help="client 并行部署数，默认 8",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        action = "teardown" if args.teardown else "setup"
        teardown_path_explicit = any(
            item == "--teardown-script" or item.startswith("--teardown-script=")
            for item in sys.argv[1:]
        )
        if teardown_path_explicit and not args.teardown:
            print(
                "[WARN] --teardown-script 只指定上传文件，不执行 teardown；"
                "本次动作仍为 setup。要执行回滚请同时指定 --teardown。",
                file=sys.stderr,
            )
        if args.max_workers < 1:
            raise DeployError("--max-workers 必须大于 0")
        servers = load_servers(args.devices_file.resolve(), set(args.hosts) if args.hosts else None)
        if args.hosts:
            matched = {item for server in servers for item in (server["hostname"], server["address"])}
            unmatched = sorted(set(args.hosts).difference(matched))
            if unmatched:
                raise DeployError(f"--host 未匹配到有效的 type=server：{', '.join(unmatched)}")
        local_http_enabled = False
        http_ip: str | None = None
        if action == "setup":
            if not servers and not args.http_server_ip:
                print(
                    "[WARN] devices CSV 中没有有效的 type=server 设备，"
                    "无法通过目标路由更新 HTTP Server，未修改脚本"
                )
                return 0
            dns, ntp, timezone_name = load_common(args.global_file.resolve())
            http_ip = determine_http_source_ip(servers, args.http_server_ip)
            local_http_enabled = http_service_works(http_ip)
            if local_http_enabled:
                print(
                    f"[OK] 本机存在兼容的版本化 APT 仓库："
                    f"{local_http_url(http_ip)}/ubuntu-<version>/<arch>/Packages.gz"
                )
            else:
                print(
                    f"[WARN] 本机 {local_http_url(http_ip)} 不可用，"
                    "生成的 setup 将跳过本地下载并直接使用 Internet"
                )
            managed_block = render_managed_block(
                http_ip, dns, ntp, timezone_name, local_http_enabled=local_http_enabled
            )
            update_runtime_config(
                args.setup_script.resolve().with_name("infra-runtime.conf"),
                managed_block, args.dry_run,
            )
            scripts_to_validate = (args.setup_script.resolve(), args.teardown_script.resolve())
        else:
            scripts_to_validate = (args.teardown_script.resolve(),)

        for script in scripts_to_validate:
            syntax = subprocess.run(["bash", "-n", str(script)], text=True, capture_output=True)
            if syntax.returncode != 0:
                raise DeployError(f"shell 语法检查失败 {script}：{syntax.stderr.strip()}")
        if action == "teardown":
            print(f"[OK] teardown 脚本验证通过：{args.teardown_script.resolve()}")
        if args.prepare_only:
            print("[OK] prepare-only 完成，未连接任何设备")
            return 0

        if not servers:
            print("[WARN] devices CSV 中没有可部署的 type=server 设备，未执行远程操作")
            return 0
        if action == "setup" and local_http_enabled and http_ip is not None:
            print(f"[INFO] HTTP Server: {local_http_url(http_ip)}")
        elif action == "setup":
            print("[INFO] HTTP Server: disabled; package downloads use Internet directly")
        print(f"[INFO] 待部署 server：{len(servers)} 台")
        print(f"[INFO] 执行动作：{action}")

        if args.dry_run:
            for server in servers:
                mode = "root" if args.user == "root" else "sudo（免密或统一收集共用密码）"
                print(
                    f"[DRY] {server['hostname']} ({server['address']}): "
                    f"检查 SSH/{mode}，上传脚本并执行 "
                    + (
                        "infra-teardown.sh --non-interactive --yes"
                        if action == "teardown" else
                        "infra-setup.sh --client --non-interactive --enable-bluefield-nic"
                    )
                )
            print(f"[DRY] 最大并行数：{min(args.max_workers, len(servers))}")
            return 0

        if action == "teardown" and not confirm_teardown_targets(servers, timeout=15):
            print("[INFO] 用户取消 teardown，未连接或修改任何 server。")
            return 0

        failures: list[str] = []
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        client_log_dir = SCRIPT_DIR / "logs" / "clients" / run_id
        client_log_dir.mkdir(parents=True, exist_ok=True)
        print(f"[INFO] client 独立日志目录：{client_log_dir}")

        accesses: list[tuple[dict[str, str], str, Path | None, Path, bool]] = []
        preferred_username = args.user
        preferred_identity = args.identity
        preferred_username_confirmed = False
        shared_ssh_password: str | None = None
        for server in servers:
            safe_name = re.sub(
                r"[^A-Za-z0-9_.-]+", "_", f"{server['hostname']}-{server['address']}"
            )
            client_log = client_log_dir / f"{safe_name}.log"
            try:
                username, identity, needs_sudo_password, shared_ssh_password = prepare_server_access(
                    server, preferred_username, preferred_identity, shared_ssh_password,
                    preferred_username_confirmed,
                )
                preferred_username = username
                preferred_identity = identity
                preferred_username_confirmed = True
                accesses.append((server, username, identity, client_log, needs_sudo_password))
            except (DeployError, subprocess.CalledProcessError, OSError) as exc:
                message = f"{server['hostname']} ({server['address']}): {exc}"
                client_log.write_text(f"AUTH/PREFLIGHT ERROR: {message}\n", encoding="utf-8")
                failures.append(message)
                print(f"[ERROR] {failures[-1]}", file=sys.stderr)

        password_accesses = [item for item in accesses if item[4]]
        sudo_password: str | None = None
        if password_accesses:
            password_valid = False
            if shared_ssh_password is not None:
                invalid = [
                    f"{server['hostname']} ({server['address']})"
                    for server, username, identity, _client_log, _needs_password in password_accesses
                    if not sudo_password_works(
                        server["address"], username, identity, shared_ssh_password
                    )
                ]
                if not invalid:
                    sudo_password = shared_ssh_password
                    password_valid = True
                    print(
                        f"[OK] SSH 共用密码同时通过 {len(password_accesses)} 台 client 的 sudo 验证；"
                        "无需再次输入"
                    )
                else:
                    print(
                        f"[INFO] SSH 共用密码不能用于全部 client 的 sudo：{', '.join(invalid)}",
                        file=sys.stderr,
                    )

            if not password_valid:
                for attempt in range(1, 4):
                    candidate = getpass.getpass(
                        f"{len(password_accesses)} 台 client 需要另一个 sudo 共用密码；"
                        f"请输入密码（第 {attempt}/3 次）："
                    )
                    if not candidate:
                        print("[WARN] sudo 密码不能为空", file=sys.stderr)
                        continue
                    invalid = []
                    for server, username, identity, _client_log, _needs_password in password_accesses:
                        if not sudo_password_works(
                            server["address"], username, identity, candidate
                        ):
                            invalid.append(f"{server['hostname']} ({server['address']})")
                    if not invalid:
                        sudo_password = candidate
                        password_valid = True
                        print(
                            f"[OK] 共用 sudo 密码已在 {len(password_accesses)} 台 client 上验证通过"
                        )
                        break
                    print(
                        f"[WARN] sudo 密码验证失败：{', '.join(invalid)}",
                        file=sys.stderr,
                    )
            if not password_valid:
                for server, _username, _identity, client_log, _needs_password in password_accesses:
                    message = (
                        f"{server['hostname']} ({server['address']}): "
                        "共用 sudo 密码连续 3 次未在所有目标上验证通过"
                    )
                    client_log.write_text(f"AUTH/PREFLIGHT ERROR: {message}\n", encoding="utf-8")
                    failures.append(message)
                accesses = [item for item in accesses if not item[4]]
                sudo_password = None
        shared_ssh_password = None

        workers = min(args.max_workers, len(accesses)) if accesses else 0
        if workers:
            print(f"[INFO] 开始并行部署：{len(accesses)} 台，最大并行数 {workers}")
            with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="infra-deploy") as executor:
                future_map = {}
                for server, username, identity, client_log, needs_password in accesses:
                    print(
                        f"[START] {server['hostname']} ({server['address']}) → {client_log}"
                    )
                    future = executor.submit(
                        deploy_server, server, username, identity, args.setup_script.resolve(),
                        args.teardown_script.resolve(),
                        args.setup_script.resolve().with_name("infra-runtime.conf"), client_log,
                        sudo_password if needs_password else None,
                        action,
                    )
                    future_map[future] = (server, client_log)
                for future in as_completed(future_map):
                    server, client_log = future_map[future]
                    try:
                        future.result()
                        print(
                            f"[OK] {server['hostname']} ({server['address']}) "
                            f"{action} 执行完成；"
                            f"日志：{client_log}"
                        )
                    except (DeployError, subprocess.CalledProcessError, OSError) as exc:
                        message = f"{server['hostname']} ({server['address']}): {exc}"
                        with client_log.open("a", encoding="utf-8") as log_stream:
                            log_stream.write(
                                f"[{datetime.now(timezone.utc).isoformat()}] FINAL ERROR: {message}\n"
                            )
                            if isinstance(exc, subprocess.CalledProcessError) and exc.stderr:
                                log_stream.write(str(exc.stderr))
                                if not str(exc.stderr).endswith("\n"):
                                    log_stream.write("\n")
                        failures.append(message)
                        print(f"[ERROR] {message}；详情：{client_log}", file=sys.stderr)
                        try:
                            detail_lines = client_log.read_text(
                                encoding="utf-8", errors="replace"
                            ).splitlines()[-24:]
                        except OSError:
                            detail_lines = []
                        if detail_lines:
                            print("[DETAIL] client 日志末尾：", file=sys.stderr)
                            for line in detail_lines:
                                print(f"    {line}", file=sys.stderr)
        sudo_password = None
        if failures:
            print("\n部署失败清单：", file=sys.stderr)
            for failure in failures:
                print(f"  - {failure}", file=sys.stderr)
            return 1
        return 0
    except (DeployError, OSError, subprocess.CalledProcessError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Help is a read-only operation; do not create an execution log for it.
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        raise SystemExit(main())
    raise SystemExit(run_with_log("deploy_infra", main))
