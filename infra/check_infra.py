#!/usr/bin/env python3
"""Collect infra execution logs and health status from CSV server devices."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import subprocess
import sys

from deploy_infra import (
    DEFAULT_DEVICES,
    DeployError,
    _identity_args,
    _ssh_options,
    _validate_username,
    find_public_key,
    key_login_works,
    load_servers,
    run_with_log,
    sudo_password_works,
)


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_OUTPUT = SCRIPT_DIR / "collected"
SUPPORTED_UBUNTU_VERSIONS = {"22.04", "24.04"}
LOG_NAME = re.compile(r"(?:logs/)?infra-(?:setup|teardown)-\d{8}_\d{6}(?:-\d+)?\.log")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--devices-file", type=Path, default=DEFAULT_DEVICES)
    parser.add_argument("--user", default=getpass.getuser(), help="SSH 用户")
    parser.add_argument("--identity", type=Path, help="SSH 私钥或公钥路径")
    parser.add_argument("--host", action="append", dest="hosts", help="只检查指定 hostname/IP")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument(
        "--clients-only", action="store_true",
        help="只检查 CSV client，不检查运行 check_infra.py 的 mgmt 本机",
    )
    return parser.parse_args()


def normalize_identity(identity: Path | None) -> Path | None:
    if not identity:
        return None
    if identity.suffix == ".pub":
        _public, private = find_public_key(identity)
        if not private:
            raise DeployError(f"SSH 公钥没有对应私钥：{identity}")
        return private
    return identity.expanduser().resolve()


def prepare_check_access(
    server: dict[str, str], username: str, identity: Path | None
) -> tuple[str, bool]:
    host = server["address"]
    username = _validate_username(username)
    if not key_login_works(host, username, identity):
        if not sys.stdin.isatty():
            raise DeployError(
                f"{username}@{host} SSH 免密登录失败，非交互终端无法询问其他用户名"
            )
        for attempt in range(1, 4):
            entered = input(
                f"{host} 使用 {username} 免密登录失败，请输入已配置公钥的 SSH 用户名"
                f"（第 {attempt}/3 次）："
            ).strip()
            if not entered:
                print("[WARN] SSH 用户名不能为空", file=sys.stderr)
                continue
            try:
                username = _validate_username(entered)
            except DeployError as exc:
                print(f"[WARN] {exc}", file=sys.stderr)
                continue
            if key_login_works(host, username, identity):
                break
            print(f"[WARN] {username}@{host} 免密登录失败", file=sys.stderr)
        else:
            raise DeployError(
                f"{host} 连续 3 次 SSH 用户名验证失败；检查脚本不会修改远端 key"
            )

    target = f"{username}@{host}"
    sudo_check = subprocess.run(
        ["ssh", *_identity_args(identity), *_ssh_options(True), target, "sudo -n true"],
        text=True, capture_output=True,
    )
    needs_sudo_password = username != "root" and sudo_check.returncode != 0
    mode = "共用密码 sudo" if needs_sudo_password else "免密 sudo/root"
    print(f"[OK] {server['hostname']} 使用 {target}（{mode}）")
    return username, needs_sudo_password


def parse_key_values(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        if re.fullmatch(r"[A-Za-z0-9_.-]+", key):
            result[key] = value.strip()
    return result


def remote_probe_script() -> str:
    return r'''set -u
base="${INFRA_BASE:-$HOME/http-infra}"
if [ -r "$base/infra-status" ]; then
  while IFS= read -r line; do printf 'public.%s\n' "$line"; done < "$base/infra-status"
  status_http_server=$(awk -F= '$1 == "http_server" { print substr($0, index($0,"=")+1); exit }' "$base/infra-status")
else
  printf 'public.status=not_run\n'
  status_http_server=""
fi
if [ -n "$status_http_server" ]; then
  if command -v wget >/dev/null 2>&1; then
    if wget -q --spider "${status_http_server}/Packages.gz" 2>/dev/null; then reachable=true; else reachable=false; fi
  elif command -v curl >/dev/null 2>&1; then
    if curl -fsSIL --max-time 5 "${status_http_server}/Packages.gz" >/dev/null 2>&1; then reachable=true; else reachable=false; fi
  else
    reachable=unknown
  fi
else
  reachable=not_configured
fi
printf 'repository.reachable=%s\n' "$reachable"
. /etc/os-release
printf 'system.os_id=%s\n' "${ID:-unknown}"
printf 'system.os_version=%s\n' "${VERSION_ID:-unknown}"
printf 'system.hostname=%s\n' "$(hostname -f 2>/dev/null || hostname)"
for service in systemd-resolved systemd-timesyncd lldpd apache2 isc-dhcp-server; do
  if systemctl is-active --quiet "$service" 2>/dev/null; then value=active; else value=inactive; fi
  printf 'service.%s=%s\n' "$service" "$value"
done
if sudo -n true 2>/dev/null; then
  printf 'privileged.available=true\n'
  if sudo -n test -r /var/lib/http-infra/run-info; then
    sudo -n awk -F= '{ printf "run_info.%s=%s\n", $1, substr($0, index($0,"=")+1) }' /var/lib/http-infra/run-info
  fi
  if sudo -n test -r /var/lib/http-infra/installed-packages; then
    recorded=$(sudo -n awk -F '\t' 'NF && !seen[$1]++ { count++ } END { print count+0 }' /var/lib/http-infra/installed-packages)
    package_names=$(sudo -n awk -F '\t' 'NF && !seen[$1]++ { if (names != "") names=names ", "; names=names $1 } END { print names }' /var/lib/http-infra/installed-packages)
    missing=$(sudo -n awk -F '\t' 'NF { print $1 }' /var/lib/http-infra/installed-packages | while IFS= read -r pkg; do dpkg -s "$pkg" >/dev/null 2>&1 || printf '%s ' "$pkg"; done)
    printf 'packages.recorded=%s\n' "$recorded"
    printf 'packages.names=%s\n' "$package_names"
    printf 'packages.missing=%s\n' "$missing"
  else
    printf 'packages.recorded=0\n'
    printf 'packages.names=\n'
    printf 'packages.missing=\n'
  fi
else
  printf 'privileged.available=false\n'
fi
for log_root in "$base" "$base/logs"; do
  find "$log_root" -maxdepth 1 -type f \( -name 'infra-setup-*.log' -o -name 'infra-teardown-*.log' \) -print 2>/dev/null \
    | while IFS= read -r path; do
        case "$path" in
          "$base/logs/"*) printf 'log.file=logs/%s\n' "$(basename "$path")" ;;
          *) printf 'log.file=%s\n' "$(basename "$path")" ;;
        esac
      done
done
'''


def classify(values: dict[str, str]) -> tuple[str, list[str]]:
    issues: list[str] = []
    severity = "OK"
    status = values.get("public.status", "not_run")
    action = values.get("public.last_action", "unknown")
    exit_code = values.get("public.exit_code", "")

    if status == "failed" or (exit_code and exit_code != "0"):
        severity = "ERROR"
        issues.append(f"{action} 执行失败，exit_code={exit_code or 'unknown'}")
    elif status in {"started", "not_run"}:
        severity = "WARN"
        issues.append("没有完成状态，脚本可能未运行或曾被中断")
    elif status == "aborted":
        severity = "WARN"
        issues.append("最后一次 teardown 被用户取消")
    elif status != "completed":
        severity = "WARN"
        issues.append(f"未知状态：{status}")

    if (
        values.get("system.os_id") != "ubuntu"
        or values.get("system.os_version") not in SUPPORTED_UBUNTU_VERSIONS
    ):
        severity = "ERROR"
        issues.append(
            f"系统不是受支持的 Ubuntu 22.04/24.04：{values.get('system.os_id', '?')} "
            f"{values.get('system.os_version', '?')}"
        )
    if action == "setup" and values.get("run_info.status") not in {None, "completed"}:
        severity = "ERROR"
        issues.append(f"root run-info 状态异常：{values.get('run_info.status')}")
    missing = values.get("packages.missing", "").strip()
    if action == "setup" and missing:
        severity = "ERROR"
        issues.append(f"清单中的包未安装：{missing}")
    if values.get("privileged.available") == "false":
        if severity == "OK":
            severity = "WARN"
        issues.append("无免密 sudo，仅完成普通用户范围检查")
    if action == "teardown" and values.get("public.recorded_packages") not in {None, "0"}:
        severity = "ERROR"
        issues.append("teardown 后仍有软件包状态记录")
    return severity, issues


def format_recorded_packages(values: dict[str, str]) -> str:
    recorded = values.get("packages.recorded", "unknown").strip() or "unknown"
    names = values.get("packages.names", "").strip()
    if names:
        return f"{recorded} ({names})"
    if recorded == "0":
        return "0 (none)"
    if recorded != "unknown":
        return f"{recorded} (names unavailable)"
    return "unknown"


def print_result_details(
    severity: str, issues: list[str], values: dict[str, str], log_count: int
) -> None:
    """Print the useful collected status instead of hiding it in report files."""
    fields = [
        ("Hostname", values.get("system.hostname", "unknown")),
        (
            "OS",
            " ".join(
                part for part in (
                    values.get("system.os_id", "unknown"),
                    values.get("system.os_version", "unknown"),
                ) if part
            ),
        ),
        ("Last action", values.get("public.last_action", "unknown")),
        ("Script status", values.get("public.status", "not_run")),
        ("Exit code", values.get("public.exit_code", "unknown")),
        ("HTTP server", values.get("public.http_server", values.get("run_info.http_server", "unknown"))),
        (
            "Local APT",
            values.get("public.local_http_enabled", values.get("run_info.local_http_enabled", "unknown")),
        ),
        ("APT reachable now", values.get("repository.reachable", "unknown")),
        ("Privileged check", values.get("privileged.available", "unknown")),
        ("Recorded packages", format_recorded_packages(values)),
        ("Missing packages", values.get("packages.missing", "").strip() or "none"),
        ("Collected logs", str(log_count)),
    ]
    for label, value in fields:
        print(f"    {label:<18}: {value}")

    services = sorted(
        (key.removeprefix("service."), value)
        for key, value in values.items() if key.startswith("service.")
    )
    if services:
        print("    Services           : " + ", ".join(f"{name}={state}" for name, state in services))
    if issues:
        print("    Issues:")
        for issue in issues:
            print(f"      - {issue}")
    print(f"[{severity}] {'; '.join(issues) if issues else '检查通过'}；已收集日志 {log_count} 个")


def collect_server(
    server: dict[str, str], username: str, identity: Path | None, output_dir: Path,
    sudo_password: str | None = None,
) -> dict[str, object]:
    host, label = server["address"], server["hostname"]
    result: dict[str, object] = {"hostname": label, "address": host, "logs": [], "issues": []}
    print(f"\n── 检查 {label} ({host}) ─────────────────────────────────")
    if not key_login_works(host, username, identity):
        result.update(severity="ERROR", issues=["SSH 免密登录失败"], values={})
        print("[ERROR] SSH 免密登录失败；检查脚本不会提示密码或修改远端 key")
        return result

    target = f"{username}@{host}"
    ssh_base = ["ssh", *_identity_args(identity), *_ssh_options(True)]
    scp_base = ["scp", "-q", *_identity_args(identity), *_ssh_options(True)]
    home = subprocess.run(
        [*ssh_base, target, "printf '%s' \"$HOME\""], check=True, text=True, capture_output=True
    ).stdout.strip()
    if not re.fullmatch(r"/[A-Za-z0-9_./-]+", home):
        raise DeployError(f"无法确定 {target} 的安全家目录：{home!r}")

    probe_script = remote_probe_script()
    if sudo_password is None:
        probe_command = [*ssh_base, target, "bash -s"]
        probe_input = probe_script
    else:
        # Run the complete read-only probe as root.  A sudo timestamp created
        # by a separate non-TTY SSH command is not reliably reusable, even
        # though password validation succeeded during preflight.
        remote_base = f"{home}/http-infra"
        privileged_probe = (
            f"sudo -S -k -p '' INFRA_BASE={shlex.quote(remote_base)} "
            f"bash -c {shlex.quote(probe_script)}; rc=$?; "
            "sudo -k >/dev/null 2>&1 || true; exit \"$rc\""
        )
        probe_command = [
            *ssh_base, target, f"bash -c {shlex.quote(privileged_probe)}"
        ]
        # stdin contains only the password.  The probe itself is a quoted
        # command argument, so sudo cannot consume any probe bytes as password.
        probe_input = sudo_password + "\n"
    probe = subprocess.run(
        probe_command, input=probe_input, check=True, text=True, capture_output=True,
    )
    values = parse_key_values(probe.stdout)
    severity, issues = classify(values)
    host_dir = output_dir / re.sub(r"[^A-Za-z0-9_.-]+", "_", label)
    host_dir.mkdir(parents=True, exist_ok=True)
    (host_dir / "status.txt").write_text(probe.stdout, encoding="utf-8")

    log_names = [line.split("=", 1)[1] for line in probe.stdout.splitlines() if line.startswith("log.file=")]
    copied: list[str] = []
    for name in sorted(set(log_names)):
        if not LOG_NAME.fullmatch(name):
            issues.append(f"跳过不安全的日志文件名：{name}")
            severity = "ERROR"
            continue
        remote_path = f"{home}/http-infra/{name}"
        destination = host_dir / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run([*scp_base, f"{target}:{remote_path}", str(destination)], check=True)
        copied.append(name)

    result.update(severity=severity, issues=issues, values=values, logs=copied)
    print_result_details(severity, issues, values, len(copied))
    return result


def collect_local(output_dir: Path) -> dict[str, object]:
    print("\n── 检查 mgmt 本机 ─────────────────────────────────────")
    environment = os.environ.copy()
    environment["INFRA_BASE"] = str(SCRIPT_DIR)
    probe = subprocess.run(
        ["bash", "-s"], input=remote_probe_script(), cwd=SCRIPT_DIR,
        env=environment, check=True, text=True, capture_output=True,
    )
    values = parse_key_values(probe.stdout)
    severity, issues = classify(values)
    hostname = values.get("system.hostname", "mgmt-local")
    host_dir = output_dir / re.sub(r"[^A-Za-z0-9_.-]+", "_", f"mgmt-{hostname}")
    host_dir.mkdir(parents=True, exist_ok=True)
    (host_dir / "status.txt").write_text(probe.stdout, encoding="utf-8")

    copied: list[str] = []
    # Backward compatibility: releases before 2026-08-11 wrote Shell logs beside the scripts.
    for source in sorted(SCRIPT_DIR.glob("infra-setup-*.log")):
        shutil.copy2(source, host_dir / source.name)
        copied.append(source.name)
    for source in sorted(SCRIPT_DIR.glob("infra-teardown-*.log")):
        shutil.copy2(source, host_dir / source.name)
        copied.append(source.name)
    runtime_log_dir = SCRIPT_DIR / "logs"
    if runtime_log_dir.is_dir():
        for source in sorted(runtime_log_dir.rglob("*.log")):
            relative = source.relative_to(runtime_log_dir)
            destination = host_dir / "logs" / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)
            copied.append(str(Path("logs") / relative))

    print_result_details(severity, issues, values, len(copied))
    return {
        "hostname": f"mgmt:{hostname}", "address": "local", "severity": severity,
        "issues": issues, "values": values, "logs": copied,
    }


def write_reports(output_dir: Path, results: list[dict[str, object]]) -> None:
    counts = {level: sum(item.get("severity") == level for item in results) for level in ("OK", "WARN", "ERROR")}
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": counts,
        "devices": results,
    }
    (output_dir / "summary.json").write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    lines = [
        "# Infra 检查汇总", "", f"生成时间：{payload['generated_at']}", "",
        f"OK: {counts['OK']} / WARN: {counts['WARN']} / ERROR: {counts['ERROR']}", "",
        "| 设备 | 地址 | 状态 | 最后动作 | 脚本状态 | Recorded packages | 问题 | 日志数 |",
        "|---|---|---|---|---|---|---|---:|",
    ]
    for item in results:
        values = item.get("values", {})
        assert isinstance(values, dict)
        issues = item.get("issues", [])
        assert isinstance(issues, list)
        lines.append(
            f"| {item['hostname']} | {item['address']} | {item['severity']} | "
            f"{values.get('public.last_action', '-')} | {values.get('public.status', '-')} | "
            f"{format_recorded_packages(values)} | "
            f"{'；'.join(str(issue) for issue in issues) or '-'} | {len(item.get('logs', []))} |"
        )
    (output_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n── 检查汇总 ────────────────────────────────────────────")
    print(
        f"    Total: {len(results)}  OK: {counts['OK']}  "
        f"WARN: {counts['WARN']}  ERROR: {counts['ERROR']}"
    )
    for item in results:
        issues = item.get("issues", [])
        issue_text = "; ".join(str(issue) for issue in issues) if issues else "检查通过"
        print(
            f"    [{item.get('severity', 'ERROR')}] {item.get('hostname', 'unknown')} "
            f"({item.get('address', 'unknown')}): {issue_text}"
        )


def main() -> int:
    args = parse_args()
    try:
        username = _validate_username(args.user)
        identity = normalize_identity(args.identity)
        servers = load_servers(args.devices_file.resolve(), set(args.hosts) if args.hosts else None)
        if args.hosts:
            matched = {item for server in servers for item in (server["hostname"], server["address"])}
            unmatched = sorted(set(args.hosts).difference(matched))
            if unmatched:
                raise DeployError(f"--host 未匹配到有效的 type=server：{', '.join(unmatched)}")
        if not servers and args.clients_only:
            print("[WARN] devices CSV 中没有可检查的 type=server 设备")
            return 0

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        output_dir = args.output_dir.resolve() / timestamp
        output_dir.mkdir(parents=True, exist_ok=False)
        results: list[dict[str, object]] = []
        if not args.clients_only:
            try:
                results.append(collect_local(output_dir))
            except (DeployError, OSError, subprocess.CalledProcessError) as exc:
                print(f"[ERROR] mgmt 本机：{exc}", file=sys.stderr)
                results.append({
                    "hostname": "mgmt:local", "address": "local", "severity": "ERROR",
                    "issues": [str(exc)], "values": {}, "logs": [],
                })
        accesses: list[tuple[dict[str, str], str, bool]] = []
        preferred_username = username
        for server in servers:
            print(
                f"\n── SSH 前置检查 {server['hostname']} ({server['address']}) "
                "────────────────────────"
            )
            try:
                server_username, needs_sudo_password = prepare_check_access(
                    server, preferred_username, identity
                )
                preferred_username = server_username
                accesses.append((server, server_username, needs_sudo_password))
            except (DeployError, OSError, subprocess.CalledProcessError) as exc:
                print(f"[ERROR] {server['hostname']}：{exc}", file=sys.stderr)
                results.append({
                    "hostname": server["hostname"], "address": server["address"],
                    "severity": "ERROR", "issues": [str(exc)], "values": {}, "logs": [],
                })

        password_accesses = [item for item in accesses if item[2]]
        sudo_password: str | None = None
        if password_accesses and sys.stdin.isatty():
            for attempt in range(1, 4):
                candidate = getpass.getpass(
                    f"{len(password_accesses)} 台 client 需要 sudo 密码；"
                    f"请输入共用密码（第 {attempt}/3 次）："
                )
                if not candidate:
                    print("[WARN] sudo 密码不能为空", file=sys.stderr)
                    continue
                invalid = [
                    f"{server['hostname']} ({server['address']})"
                    for server, server_username, _needs_password in password_accesses
                    if not sudo_password_works(
                        server["address"], server_username, identity, candidate
                    )
                ]
                if not invalid:
                    sudo_password = candidate
                    print(
                        f"[OK] 共用 sudo 密码已在 {len(password_accesses)} 台 client 上验证通过"
                    )
                    break
                print(
                    f"[WARN] sudo 密码验证失败：{', '.join(invalid)}",
                    file=sys.stderr,
                )
            if sudo_password is None:
                print(
                    "[WARN] 未获得所有 client 通用的有效 sudo 密码；"
                    "这些设备只执行普通用户范围检查",
                    file=sys.stderr,
                )
        elif password_accesses:
            print(
                "[WARN] 非交互终端无法读取 sudo 密码；需要密码的设备只执行普通用户范围检查",
                file=sys.stderr,
            )

        for server, server_username, needs_sudo_password in accesses:
            try:
                results.append(
                    collect_server(
                        server, server_username, identity, output_dir,
                        sudo_password if needs_sudo_password else None,
                    )
                )
            except (DeployError, OSError, subprocess.CalledProcessError) as exc:
                print(f"[ERROR] {server['hostname']}：{exc}", file=sys.stderr)
                results.append({
                    "hostname": server["hostname"], "address": server["address"],
                    "severity": "ERROR", "issues": [str(exc)], "values": {}, "logs": [],
                })
        sudo_password = None
        write_reports(output_dir, results)
        print(f"\n[INFO] 汇总报告：{output_dir / 'report.md'}")
        print(f"[INFO] 结构化结果：{output_dir / 'summary.json'}")
        return 1 if any(item.get("severity") == "ERROR" for item in results) else 0
    except (DeployError, OSError) as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    # Help is a read-only operation; do not create an execution log for it.
    if any(arg in {"-h", "--help"} for arg in sys.argv[1:]):
        raise SystemExit(main())
    raise SystemExit(run_with_log("check_infra", main))
