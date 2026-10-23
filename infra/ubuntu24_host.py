"""Ubuntu 24.04 host configuration shared by server types (server_ufm now, server_mgmt later).

Every *_script() returns a POSIX shell script that runs on the target host as root and prints
KEY=VALUE lines; the matching parser turns that output back into facts the caller verifies.
Nothing here opens connections, holds credentials or knows about a specific server role.
"""

from __future__ import annotations

import base64
import ipaddress
import os
import re
import shlex
from pathlib import Path


class HostConfigError(ValueError):
    """Invalid host intent or unverifiable host output; the message is operator-facing."""


IFNAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]{0,14}$")
TIMEZONE_RE = re.compile(r"^[A-Za-z0-9_+-]+(?:/[A-Za-z0-9_+-]+)*$")
PUBLIC_KEY_RE = re.compile(
    r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com|"
    r"sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}(?: [ -~]{0,200})?$")
LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
NETPLAN_TARGET = "/etc/netplan/01-netcfg.yaml"
NETPLAN_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.yaml$")
IPMI_PASSWORD_PROMPT = r"^[^\n]*password for user \d+\s*:\s*$"
IPMI_LAN_PASSWORD_PROMPT = r"^Password:\s*$"   # `ipmitool -a`; an SSH login prompt starts with user@host
IPMI_ADMIN_ACCESS = {"Link Authentication": "enabled", "IPMI Messaging": "enabled",
                     "Privilege Level": "ADMINISTRATOR", "Enable Status": "enabled"}


def yaml_module():
    try:
        import yaml
    except ImportError as exc:
        raise HostConfigError("需要 PyYAML（python3 -m pip install pyyaml）") from exc
    return yaml


def valid_hostname(value: str) -> bool:
    hostname = str(value or "").strip().rstrip(".")
    return bool(hostname) and len(hostname) <= 253 and all(
        LABEL_RE.fullmatch(part) for part in hostname.split("."))


def parse_kv(text: str) -> dict:
    result = {}
    for line in text.splitlines():
        key, sep, value = line.partition("=")
        if sep and re.fullmatch(r"[a-z_]+", key):
            result.setdefault(key, value.strip())
    return result


# ------------------------------------------------------------- global inputs

def infra_settings(document: object) -> tuple:
    """(dns, ntp, timezone, errors, warnings) from common.switch.system, the source infra uses too."""
    dns, ntp, errors, warnings, timezone = [], [], [], [], ""
    system = {}
    if isinstance(document, dict):
        system = ((document.get("common") or {}).get("switch") or {}).get("system") or {}
    if not isinstance(system, dict):
        return dns, ntp, timezone, ["common.switch.system 必须是映射"], warnings
    # As deploy_infra.load_common: an absent key is skipped, a present but empty/invalid one is an error.
    for key, target in (("dns", dns), ("ntp", ntp)):
        if key not in system:
            warnings.append(f"common.switch.system.{key} 未配置；跳过 {key.upper()}")
            continue
        section = system[key]
        servers = section.get("server") if isinstance(section, dict) else None
        if not isinstance(servers, list) or not servers:
            errors.append(f"common.switch.system.{key}.server 必须是非空列表")
            continue
        for value in servers:
            if not isinstance(value, str) or not value.strip():
                errors.append(f"common.switch.system.{key}.server 中的 {value!r} 必须是非空字符串")
                continue
            value = value.strip()
            try:
                ipaddress.ip_address(value)
            except ValueError:
                if key == "dns" or not valid_hostname(value):
                    errors.append(f"common.switch.system.{key}.server 中的 {value!r} 无效")
                    continue
            target.append(value)
    if "date-time" in system:
        date_time = system["date-time"]
        zone = date_time.get("timezone") if isinstance(date_time, dict) else None
        if not isinstance(zone, str) or not TIMEZONE_RE.fullmatch(zone.strip()):
            errors.append(f"common.switch.system.date-time.timezone 无效: {zone!r}")
        else:
            timezone = zone.strip()
    else:
        warnings.append("common.switch.system.date-time 未配置；跳过时区")
    return dns, ntp, timezone, errors, warnings


def read_public_keys(key_dir: Path) -> tuple:
    """(file names, key lines, errors, warnings); plain keys only, no options or forced commands."""
    names, lines, errors, warnings = [], [], [], []
    if not key_dir.is_dir():
        return names, lines, errors, [f"没有 {key_dir.name}/ 目录；不会写入部署服务器公钥"]
    for path in sorted(key_dir.glob("*.pub")):
        try:
            entries = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        except (OSError, UnicodeError) as exc:
            errors.append(f"无法读取公钥 {path.name}: {exc}")
            continue
        if not entries:
            warnings.append(f"公钥文件 {path.name} 是空文件，已忽略")
            continue
        if any(not PUBLIC_KEY_RE.fullmatch(entry) for entry in entries):
            errors.append(f"公钥 {path.name} 格式无效（只接受不带选项的 ssh 公钥行）")
            continue
        names.append(path.name)
        lines.extend(entry for entry in entries if entry not in lines)
    if not names:
        warnings.append(f"{key_dir.name}/ 下没有可用的 .pub 公钥；不会写入部署服务器公钥")
    return names, lines, errors, warnings


# ------------------------------------------------------- hostname / time / keys

def would(name: str, condition: str) -> str:
    """Check-only output: `would_<name>=yes|no` for a shell test that is true when a write is needed."""
    return f'if {condition}; then echo "would_{name}=yes"; else echo "would_{name}=no"; fi\n'


def hostname_script(fqdn: str, backup_dir, *, check_only: bool = False, hosts_file: bool = False) -> str:
    """Set the static hostname and make it resolve locally (127.0.1.1), as infra/infra-setup.py does.

    backup_dir=None skips the module's own copy of /etc/hosts (callers with their own rollback).
    check_only=True reads the same state and prints would_hostname/would_hosts instead of writing.
    hosts_file=True decides on /etc/hosts itself instead of the full resolver chain: right after a
    rename systemd-resolved synthesises the name (so getent says yes and nothing is written), and
    with unreachable DNS servers getent can block for a minute. It prints in_hosts and hosts_added
    and never calls getent; the default keeps the resolver-based `resolves` contract.
    """
    if not valid_hostname(fqdn):
        raise HostConfigError(f"hostname 无效: {fqdn!r}")
    short = fqdn.split(".", 1)[0]
    name = shlex.quote(fqdn)
    names = name if short == fqdn else f"{name} {shlex.quote(short)}"
    backup = ""
    if backup_dir is not None:
        quoted = shlex.quote(backup_dir)
        backup = f"  mkdir -p {quoted}\n  [ -e {quoted}/hosts ] || cp -a /etc/hosts {quoted}/hosts\n"
    if hosts_file:
        missing = ("! awk -v n=" + name + " '!/^[[:space:]]*#/ { for (i = 2; i <= NF; i++) if ($i == n) f = 1 }"
                   " END { exit !f }' /etc/hosts 2>/dev/null")
        report = f'if {missing}; then echo "in_hosts=no"; else echo "in_hosts=yes"; fi\n'
    else:
        missing = f"! getent hosts {name} >/dev/null 2>&1"
        report = f'printf "resolves=%s\\n" "$(getent hosts {name} >/dev/null 2>&1 && echo yes || echo no)"\n'
    if check_only:
        changes = would("hostname", f'[ "$before" != {name} ]') + would("hosts", missing)
    else:
        changes = (f'if [ "$before" != {name} ]; then hostnamectl set-hostname {name}; fi\n'
                   f"if {missing}; then\n"
                   + backup +
                   f"  printf '127.0.1.1\\t%s\\n' \"{names}\" >> /etc/hosts\n"
                   + ('  echo "hosts_added=yes"\n' if hosts_file else "") +
                   "fi\n")
    return ("set -eu\n"
            'before=$(hostname)\nprintf "before=%s\\n" "$before"\n'
            + changes + report +
            'printf "after=%s\\n" "$(hostname)"\n')


def hosts_entries_script(entries: list, backup_dir, *, check_only: bool = False) -> str:
    """Make sure /etc/hosts has one `address    fqdn  short` line per entry; add only what is missing.

    An entry is present when an uncommented line starts with its address and names its FQDN. Nothing
    else in the file is changed (owner 2026-10-22: the UFM pair by their HA link address, as in
    ufm-manual.log). Prints entry_a, entry_b, ...=present|missing (letters: parse_kv keys have no
    digits) and would_hosts=yes|no; when writing, also hosts_ok=yes|no after reading the file back.
    backup_dir=None skips the copy of /etc/hosts.
    """
    if len(entries) > 26:
        raise HostConfigError("/etc/hosts 条目过多")
    tests, lines = [], []
    for number, (address, fqdn, short) in enumerate(entries):
        index = chr(ord("a") + number)
        try:
            ipaddress.ip_address(address)
        except ValueError as exc:
            raise HostConfigError(f"/etc/hosts 地址无效: {address!r}") from exc
        if not valid_hostname(fqdn) or not valid_hostname(short):
            raise HostConfigError(f"/etc/hosts 主机名无效: {fqdn!r} {short!r}")
        present = (f"awk -v a={shlex.quote(address)} -v n={shlex.quote(fqdn)} "
                   "'!/^[[:space:]]*#/ && $1 == a { for (i = 2; i <= NF; i++) if ($i == n) f = 1 }"
                   " END { exit !f }' /etc/hosts")
        tests.append((index, present))
        lines.append((index, present, f"{address}    {fqdn}  {short}"))
    report = "".join(f'if {test}; then echo "entry_{index}=present"; else echo "entry_{index}=missing"; '
                     f"missing=yes; fi\n" for index, test in tests)
    script = "set -eu\nmissing=no\n" + report + 'printf "would_hosts=%s\\n" "$missing"\n'
    if check_only:
        return script
    backup = ""
    if backup_dir is not None:
        quoted = shlex.quote(backup_dir)
        backup = f"  mkdir -p {quoted}\n  [ -e {quoted}/hosts ] || cp -a /etc/hosts {quoted}/hosts\n"
    script += ('if [ "$missing" = yes ]; then\n' + backup
               + '  if [ -n "$(tail -c 1 /etc/hosts)" ]; then printf "\\n" >> /etc/hosts; fi\n'
               + "".join(f"  if ! {test}; then printf '%s\\n' {shlex.quote(line)} >> /etc/hosts; fi\n"
                         for _index, test, line in lines)
               + "fi\n")
    checks = " && ".join(f"{test}" for _index, test in tests) or "true"
    return script + f'if {checks}; then echo "hosts_ok=yes"; else echo "hosts_ok=no"; fi\n'


def timezone_script(zone: str, *, check_only: bool = False) -> str:
    if zone and not TIMEZONE_RE.fullmatch(zone):
        raise HostConfigError(f"时区无效: {zone!r}")
    quoted = shlex.quote(zone) if zone else ""
    change = (would("timezone", f'[ "$before" != {quoted} ]') if check_only
              else f'if [ "$before" != {quoted} ]; then timedatectl set-timezone {quoted}; fi\n')
    return ("set -eu\n"
            'before=$(timedatectl show -p Timezone --value)\nprintf "before=%s\\n" "$before"\n'
            + (f'[ -f /usr/share/zoneinfo/{quoted} ] || {{ echo "未知时区 {quoted}"; exit 4; }}\n'
               + change if zone else "")
            + 'printf "after=%s\\n" "$(timedatectl show -p Timezone --value)"\n'
            'printf "synced=%s\\n" "$(timedatectl show -p NTPSynchronized --value 2>/dev/null || true)"\n')


def config_line_value(text: str, key: str) -> str:
    """The value config_line_script compares: first active KEY= line, after the first '=', spaces collapsed."""
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=(.*)$")
    for line in text.splitlines():
        match = pattern.match(line)
        if match:
            return " ".join(match.group(1).split())
    return ""


def config_line_script(path: str, key: str, value: str, service: str, backup_dir, *,
                       check_only: bool = False) -> str:
    """Set `KEY=value` in a systemd config file (resolved.conf DNS=, timesyncd.conf NTP=).

    As infra/infra-setup.py: values compare whitespace-normalised, a missing unit is skipped and a masked
    unit is unmasked and enabled. Unlike a global sed, only the first active line (else the first
    commented one) is replaced, so the file never gains a second KEY= line.
    check_only=True prints would_write/would_unmask and changes nothing.
    """
    if not re.fullmatch(r"[A-Z][A-Za-z]*", key) or not re.fullmatch(r"[a-z][a-z0-9-]*", service):
        raise HostConfigError(f"无效的配置键或服务名: {key} {service}")
    active, commented = f"^[[:space:]]*{key}[[:space:]]*=", f"^[[:space:]]*#[[:space:]]*{key}[[:space:]]*="
    backup = ""
    if backup_dir is not None:
        # Keep the first copy of this run: a later edit of the same file must not replace the original.
        backup = (f"  mkdir -p {shlex.quote(backup_dir)}\n"
                  f"  b={shlex.quote(backup_dir)}/{shlex.quote(os.path.basename(path))}\n"
                  '  if [ -f "$f" ] && [ ! -e "$b" ]; then cp -a "$f" "$b"; fi\n')
    head = (
        "set -eu\n"
        f"f={shlex.quote(path)}\nwant={shlex.quote(value)}\nunit={service}.service\n"
        'load=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null || true)\n'
        'if [ -z "$load" ] || [ "$load" = "not-found" ]; then echo "result=service_missing"; exit 0; fi\n'
        'state=$(systemctl is-enabled "$unit" 2>/dev/null || true)\n'
        f"current() {{ grep -E '{active}' \"$f\" 2>/dev/null | head -n 1 | sed 's/^[^=]*=//' | xargs || true; }}\n"
        'before=$(current)\nprintf "before=%s\\n" "$before"\n')
    if check_only:
        return (head + would("write", '[ "$before" != "$want" ]') + would("unmask", '[ "$state" = "masked" ]')
                + 'printf "after=%s\\n" "$before"\n'
                'printf "active=%s\\n" "$(systemctl is-active "$unit" || true)"\n')
    return (
        head + "changed=0\n"
        'if [ "$before" != "$want" ]; then\n'
        + backup +
        f"  has=0; grep -qE '{active}' \"$f\" 2>/dev/null && has=1\n"
        f"  {{ [ -f \"$f\" ] && cat \"$f\"; true; }} | awk -v line=\"{key}=$want\" -v has=\"$has\" "
        f"-v on='{active}' -v off='{commented}' '\n"
        '    !done && has == "1" && $0 ~ on { print line; done = 1; next }\n'
        '    !done && has == "0" && $0 ~ off { print line; done = 1; next }\n'
        "    { print }\n"
        "    END { if (!done) print line }' > \"$f.host-new\"\n"
        '  cat "$f.host-new" > "$f"\n'
        '  rm -f "$f.host-new"\n'
        "  changed=1\n"
        "fi\n"
        'if [ "$state" = "masked" ]; then\n'
        '  systemctl unmask "$unit"\n'
        '  systemctl enable --now "$unit"\n'
        'elif [ "$changed" = 1 ]; then\n'
        '  systemctl restart "$unit"\n'
        "fi\n"
        'printf "after=%s\\n" "$(current)"\n'
        'printf "active=%s\\n" "$(systemctl is-active "$unit" || true)"\n')


def authorized_keys_script(key_lines: list, user_home: str = "/root", *, check_only: bool = False) -> str:
    """Append missing keys to ~/.ssh/authorized_keys; existing entries are never rewritten.

    check_only=True only counts: added=0 and missing=<keys that would be appended>.
    """
    for line in key_lines:
        if not PUBLIC_KEY_RE.fullmatch(line):
            raise HostConfigError("公钥行格式无效")
    home = shlex.quote(user_home)
    if check_only:
        return (
            f"set -eu\nf={home}/.ssh/authorized_keys\nmissing=0\n"
            "while IFS= read -r key; do\n"
            '  [ -n "$key" ] || continue\n'
            "  blob=$(printf '%s\\n' \"$key\" | awk '{print $2}')\n"
            '  grep -qF -- "$blob" "$f" 2>/dev/null || missing=$((missing + 1))\n'
            "done <<'HOST_KEYS'\n" + "\n".join(key_lines) + "\nHOST_KEYS\n"
            'printf "added=0\\nmissing=%s\\n" "$missing"\n')
    return (
        f"set -eu\numask 077\nmkdir -p {home}/.ssh\nchmod 700 {home}/.ssh\n"
        f"f={home}/.ssh/authorized_keys\ntouch \"$f\"\nchmod 600 \"$f\"\n"
        'if [ -s "$f" ] && [ -n "$(tail -c 1 "$f")" ]; then printf \'\\n\' >> "$f"; fi\n'
        "added=0\nmissing=0\n"
        "while IFS= read -r key; do\n"
        '  [ -n "$key" ] || continue\n'
        "  blob=$(printf '%s\\n' \"$key\" | awk '{print $2}')\n"
        '  if ! grep -qF -- "$blob" "$f"; then\n'
        "    printf '%s\\n' \"$key\" >> \"$f\"\n"
        "    added=$((added + 1))\n"
        "  fi\n"
        '  grep -qF -- "$blob" "$f" || missing=$((missing + 1))\n'
        "done <<'HOST_KEYS'\n" + "\n".join(key_lines) + "\nHOST_KEYS\n"
        'printf "added=%s\\nmissing=%s\\n" "$added" "$missing"\n')


def root_keypair_script(*, check_only: bool = False) -> str:
    """Ensure root has an ed25519 key pair (no passphrase, used host-to-host) and print its public key.

    check_only=True prints the public key when present, else would_create=yes.
    """
    if check_only:
        return ("set -eu\n"
                "if [ -f /root/.ssh/id_ed25519 ] && [ -f /root/.ssh/id_ed25519.pub ]; then\n"
                '  printf "pubkey=%s\\n" "$(cat /root/.ssh/id_ed25519.pub)"\n'
                'else echo "would_create=yes"; fi\n')
    return ("set -eu\numask 077\nmkdir -p /root/.ssh\nchmod 700 /root/.ssh\n"
            "if [ ! -f /root/.ssh/id_ed25519 ]; then\n"
            "  ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519\n"
            '  echo "created=yes"\n'
            "fi\n"
            'printf "pubkey=%s\\n" "$(cat /root/.ssh/id_ed25519.pub)"\n')


def ping_script(address: str, interface: str = "", count: int = 3) -> str:
    """reachable=yes|no for an IPv4 peer, optionally forced out of one interface."""
    ipaddress.IPv4Address(address)
    if interface and not IFNAME_RE.fullmatch(interface):
        raise HostConfigError(f"接口名无效: {interface!r}")
    via = f" -I {interface}" if interface else ""
    return ("set -u\n"
            f"if ping -c {int(count)} -W 2{via} {address} >/dev/null 2>&1; then echo reachable=yes; "
            "else echo reachable=no; fi\n")


def peer_ssh_check_script(peer_address: str, user: str = "root", *, record_host_key: bool = True) -> str:
    """Key-only login from this host to the peer address; records the peer host key on first contact.

    Verification is by address only (owner 2026-10-19: no host names in connectivity tests or
    verification): the peer must report `peer_address` on one of its own interfaces (peer_has_address).
    record_host_key=False (check-only) uses StrictHostKeyChecking=yes so known_hosts is never written.
    """
    address = str(ipaddress.ip_address(peer_address))
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,31}", user):
        raise HostConfigError(f"用户名无效: {user!r}")
    policy = "accept-new" if record_host_key else "yes"
    # stdout carries only the peer's `ip -o addr show`; ssh's own messages (e.g. "Warning: Permanently
    # added ...") go to stderr and are reported separately.
    return ("set -u\n"
            "errf=$(mktemp /tmp/host-peer-ssh.XXXXXX)\n"
            f"out=$(ssh -o BatchMode=yes -o StrictHostKeyChecking={policy} -o LogLevel=ERROR -o ConnectTimeout=10 "
            f"{user}@{address} ip -o addr show 2>\"$errf\")\n"
            "rc=$?\n"
            'printf "rc=%s\\n" "$rc"\n'
            f"if printf '%s\\n' \"$out\" | awk -v a={address} '{{ split($4, p, \"/\"); if (p[1] == a) f = 1 }} "
            "END { exit !f }'; then echo peer_has_address=yes; else echo peer_has_address=no; fi\n"
            "printf 'error=%s\\n' \"$(tr '\\n' ' ' < \"$errf\" | cut -c1-300)\"\n"
            'rm -f "$errf"\n')


# ------------------------------------------------------------------- netplan

NETPLAN_READ_SCRIPT = (
    "set -eu\n"
    "for f in /etc/netplan/*.yaml; do\n"
    '  [ -e "$f" ] || continue\n'
    "  printf '__NETPLAN_FILE__ %s\\n' \"$(basename \"$f\")\"\n"
    "  base64 < \"$f\" | tr -d '\\n'\n"
    "  printf '\\n'\n"
    "done\n")


def netplan_document(mgmt_device: str, mgmt_cidr: str, gateway: str, others: dict) -> dict:
    """Static addresses, DHCP off; the default route uses routes (gateway4 is deprecated)."""
    ethernets = {mgmt_device: {"dhcp4": False, "addresses": [mgmt_cidr],
                               "routes": [{"to": "default", "via": gateway}]}}
    for device, cidr in sorted(others.items()):
        ethernets[device] = {"dhcp4": False, "addresses": [cidr]}
    for device in ethernets:
        if not IFNAME_RE.fullmatch(device):
            raise HostConfigError(f"接口名无效: {device!r}")
    return {"network": {"version": 2, "ethernets": ethernets}}


def render_netplan(document: dict) -> str:
    return yaml_module().safe_dump(document, sort_keys=False, default_flow_style=False)


def parse_netplan_listing(text: str) -> dict:
    files, current = {}, None
    for line in text.splitlines():
        if line.startswith("__NETPLAN_FILE__ "):
            name = line.split(" ", 1)[1].strip()
            if not NETPLAN_NAME_RE.fullmatch(name):
                raise HostConfigError(f"netplan 文件名不安全: {name!r}")
            current = "/etc/netplan/" + name
            files[current] = ""
        elif current is not None and line.strip():
            try:
                files[current] = base64.b64decode(line.strip(), validate=True).decode("utf-8")
            except (ValueError, UnicodeError) as exc:
                raise HostConfigError(f"无法解码 {current} 的内容") from exc
            current = None
    return files


def file_ethernets(path: str, text: str) -> dict:
    try:
        document = yaml_module().safe_load(text) or {}
    except HostConfigError:
        raise
    except Exception as exc:
        raise HostConfigError(f"{path} 不是有效的 YAML，停止，不覆盖") from exc
    ethernets = (document.get("network") or {}).get("ethernets") if isinstance(document, dict) else None
    if ethernets is None:
        return {}
    if not isinstance(ethernets, dict):
        raise HostConfigError(f"{path} 的 network.ethernets 不是映射")
    return ethernets


def effective_ethernets(files: dict) -> dict:
    result = {}
    for path in sorted(files):
        for device, config in file_ethernets(path, files[path]).items():
            result.setdefault(str(device), {}).update(config or {})
    return result


def interface_intent(config: dict):
    try:
        addresses = frozenset(str(ipaddress.IPv4Interface(str(item))) for item in config.get("addresses") or [])
    except ValueError:
        return None
    gateway = config.get("gateway4")
    for route in config.get("routes") or []:
        if isinstance(route, dict) and str(route.get("to")) in {"default", "0.0.0.0/0"}:
            gateway = route.get("via")
    return addresses, config.get("dhcp4") in (True, "true", "yes"), str(gateway) if gateway else None


def netplan_equivalent(effective: dict, desired: dict) -> bool:
    """Same addresses, DHCP off, same default route; deprecated gateway4 counts as different."""
    for device, want in desired["network"]["ethernets"].items():
        have = effective.get(device)
        if have is None or "gateway4" in have or interface_intent(have) != interface_intent(want):
            return False
    return True


def netplan_conflicts(files: dict, desired: dict) -> list:
    """Other netplan files that also configure the desired interfaces (netplan merges them)."""
    devices = set(desired["network"]["ethernets"])
    return sorted(path for path, text in files.items()
                  if path != NETPLAN_TARGET and devices & set(map(str, file_ethernets(path, text))))


def netplan_apply_script(yaml_text: str, conflicts: list, backup_dir: str, *, write: bool) -> str:
    """Back up, write, `netplan generate` (restore on failure), then apply outside this session."""
    for path in conflicts:
        if not path.startswith("/etc/netplan/") or not NETPLAN_NAME_RE.fullmatch(path.rsplit("/", 1)[1]):
            raise HostConfigError(f"netplan 文件名不安全: {path!r}")
    lines = ["set -eu", f"backup={shlex.quote(backup_dir)}", 'mkdir -p "$backup/netplan"',
             'cp -a /etc/netplan/. "$backup/netplan/"']
    if write:
        for path in conflicts:
            lines.append(f'mv {shlex.quote(path)} "$backup/disabled-$(basename {shlex.quote(path)})"')
        payload = base64.b64encode(yaml_text.encode("utf-8")).decode("ascii")
        lines += [f"printf %s {payload} | base64 -d > {NETPLAN_TARGET}.host-new",
                  f"chmod 600 {NETPLAN_TARGET}.host-new",
                  f"mv {NETPLAN_TARGET}.host-new {NETPLAN_TARGET}"]
    lines += ["if ! netplan generate; then",
              "  rm -f /etc/netplan/*.yaml",
              '  cp -a "$backup/netplan/." /etc/netplan/',
              '  echo "result=generate_failed_restored"',
              "  exit 3",
              "fi",
              # The apply must outlive the SSH session: a job backgrounded just before the pty
              # closes can still receive SIGHUP, so prefer a systemd timer and otherwise settle first.
              # A transient timer is only accurate to 1 min by default, hence AccuracySec. The exit
              # code lands in netplan-apply.rc, so a verifier can tell "applied" from "not yet run".
              'rm -f "$backup/netplan-apply.rc"',
              "if command -v systemd-run >/dev/null 2>&1; then",
              '  systemd-run --quiet --unit "host-netplan-apply-$(date +%s)" --on-active=3 '
              "--timer-property=AccuracySec=100ms "
              '/bin/sh -c "netplan apply > $backup/netplan-apply.log 2>&1; echo \\$? > $backup/netplan-apply.rc"',
              "else",
              '  setsid nohup sh -c "sleep 3; netplan apply; echo \\$? > $backup/netplan-apply.rc" '
              '> "$backup/netplan-apply.log" 2>&1 < /dev/null &',
              "  sleep 1",
              "fi",
              'echo "result=apply_scheduled"']
    return "\n".join(lines) + "\n"


def network_facts_script(devices: list) -> str:
    for device in devices:
        if not IFNAME_RE.fullmatch(device):
            raise HostConfigError(f"接口名无效: {device!r}")
    return ("set -u\n"
            f"for d in {' '.join(devices)}; do\n"
            "  printf 'dev=%s oper=%s mac=%s addrs=%s\\n' \"$d\" "
            "\"$(cat /sys/class/net/$d/operstate 2>/dev/null)\" \"$(cat /sys/class/net/$d/address 2>/dev/null)\" "
            "\"$(ip -4 -o addr show dev $d 2>/dev/null | awk '{print $4}' | tr '\\n' ',')\"\n"
            "done\n"
            "printf 'default=%s\\n' \"$(ip route show default 2>/dev/null | head -n 1)\"\n")


def parse_network_facts(text: str) -> dict:
    facts = {"devices": {}, "default": ""}
    for line in text.splitlines():
        if line.startswith("dev="):
            fields = dict(item.split("=", 1) for item in line.split() if "=" in item)
            facts["devices"][fields.get("dev", "")] = {
                "oper": fields.get("oper", "").casefold(), "mac": fields.get("mac", "").casefold(),
                "addrs": sorted(item for item in fields.get("addrs", "").split(",") if item)}
        elif line.startswith("default="):
            facts["default"] = line.split("=", 1)[1].strip()
    return facts


def network_problems(facts: dict, mgmt_device: str, mgmt_mac: str, mgmt_cidr: str, gateway: str,
                     others: dict) -> tuple:
    """(problems, pending): management must be complete; other links are checked only when up."""
    problems, pending = [], []
    devices = facts["devices"]
    mgmt = devices.get(mgmt_device, {})
    if mgmt.get("mac") != mgmt_mac:
        problems.append(f"{mgmt_device} MAC 为 {mgmt.get('mac') or '空'}，应为 {mgmt_mac}")
    if mgmt_cidr not in mgmt.get("addrs", []):
        problems.append(f"{mgmt_device} 没有 {mgmt_cidr}（实际 {mgmt.get('addrs')}）")
    route = facts.get("default", "").split()
    if not ("via" in route and route[route.index("via") + 1:route.index("via") + 2] == [gateway]
            and "dev" in route and route[route.index("dev") + 1:route.index("dev") + 2] == [mgmt_device]):
        problems.append(f"默认路由应为 via {gateway} dev {mgmt_device}，实际 {facts.get('default') or '无'}")
    for device, cidr in sorted(others.items()):
        state = devices.get(device, {})
        if state.get("oper") != "up":
            pending.append(f"{device} 链路 {state.get('oper') or '未知'}，{cidr} 待链路 UP 后验证")
        elif cidr not in state.get("addrs", []):
            problems.append(f"{device} 没有 {cidr}（实际 {state.get('addrs')}）")
    return problems, pending


# ---------------------------------------------------------------------- IPMI

def ipmi_lan_read_script(channel: int) -> str:
    return f"set -eu\nipmitool lan print {int(channel)}\n"


def ipmi_lan_set_script(channel: int, ip: str, mask: str, gateway: str) -> str:
    """Every command runs and reports `lanset=<rc> <command> | <output>`; success is decided by the
    `lan print` read-back, so a BMC that returns 1 without a word still shows which command it was."""
    for value in (ip, mask, gateway):
        ipaddress.IPv4Address(value)
    channel = int(channel)
    commands = (f"ipsrc static", f"ipaddr {ip}", f"netmask {mask}", f"defgw ipaddr {gateway}")
    lines = ["set -u",
             'run() { out=$(ipmitool lan set "$@" 2>&1); rc=$?; '
             'printf \'lanset=%s %s | %s\\n\' "$rc" "$*" "$(printf \'%s\' "$out" | tr \'\\n\' \' \')"; }']
    for command in commands:
        lines += [f"run {channel} {command}", "sleep 1"]
    lines.append(f"ipmitool lan print {channel}")
    return "\n".join(lines) + "\n"


def parse_lan_print(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep and key.strip():
            fields.setdefault(key.strip(), value.strip())
    return {"source": fields.get("IP Address Source", ""), "ip": fields.get("IP Address", ""),
            "mask": fields.get("Subnet Mask", ""), "gateway": fields.get("Default Gateway IP", "")}


def lan_matches(state: dict, want: dict) -> bool:
    return ("static" in state.get("source", "").casefold()
            and all(state.get(key) == want[key] for key in ("ip", "mask", "gateway")))


def ipmi_channel_access_script(channel: int, enable: bool = False) -> str:
    """IPMI over LAN is the channel's Access Mode; `lan set <ch> access on` makes it "always available"."""
    channel = int(channel)
    return "set -eu\n" + (f"ipmitool lan set {channel} access on\n" if enable else "") + f"ipmitool channel info {channel}\n"


def parse_channel_access(text: str) -> dict:
    """Access Mode of the volatile (active) and the non-volatile settings of `ipmitool channel info`."""
    modes, section = {}, ""
    for line in text.splitlines():
        if "Non-Volatile Settings" in line:
            section = "non_volatile"
        elif "Volatile(active) Settings" in line:
            section = "volatile"
        key, sep, value = line.partition(":")
        if sep and section and key.strip() == "Access Mode":
            modes.setdefault(section, value.strip())
    return modes


def lan_access_on(modes: dict) -> bool:
    return all(modes.get(key) == "always available" for key in ("volatile", "non_volatile"))


def ipmi_lan_power_status_script(address: str, user: str) -> str:
    """Over the network to the BMC, as the IPMI user: the password is prompted (-a), never an argument."""
    address = str(ipaddress.IPv4Address(address))
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,16}", user):
        raise HostConfigError(f"IPMI 用户名无效: {user!r}")
    return ("set -u\n"
            f"ipmitool -I lanplus -H {address} -U {user} -a chassis power status\n"
            "echo power_rc=$?\n")


def ipmi_user_list_script(channel: int) -> str:
    return f"set -eu\nipmitool user list {int(channel)}\n"


def parse_user_list(text: str) -> list:
    users = []
    for line in text.splitlines():
        tokens = line.split()
        if tokens and tokens[0].isdigit():
            name = tokens[1] if len(tokens) > 1 and tokens[1] not in {"true", "false"} else ""
            users.append((int(tokens[0]), name))
    return users


def pick_ipmi_user_id(users: list, name: str) -> tuple:
    """(id, create): reuse the slot already named `name`, else the first empty slot from ID 3."""
    ids = [uid for uid, user in users if user == name]
    if len(ids) > 1:
        raise HostConfigError(f"IPMI 用户 {name} 出现在多个 ID: {ids}")
    if ids:
        return ids[0], False
    free = [uid for uid, user in users if not user and uid >= 3]
    if not free:
        raise HostConfigError("没有空闲的 IPMI 用户 ID（3 及以上）")
    return free[0], True


def ipmi_user_set_script(channel: int, uid: int, name: str, create: bool) -> str:
    """The password is not an argument: ipmitool prompts for it on the terminal."""
    channel, uid = int(channel), int(uid)
    lines = ["set -eu"]
    if create:
        lines.append(f"ipmitool user set name {uid} {shlex.quote(name)}")
    lines += [f"ipmitool user set password {uid}",
              f"ipmitool channel setaccess {channel} {uid} callin=on ipmi=on link=on privilege=4",
              f"ipmitool user enable {uid}",
              f"ipmitool channel getaccess {channel} {uid}"]
    return "\n".join(lines) + "\n"


def ipmi_user_test_script(uid: int) -> str:
    """`ipmitool user test` prompts for the password on the terminal (never an argument); the caller
    answers that prompt. password_ok=yes when the stored 16-byte password matches."""
    uid = int(uid)
    return ("set -u\n"
            f"if ipmitool user test {uid} 16; then echo password_ok=yes; else echo password_ok=no; fi\n")


def parse_getaccess(text: str) -> dict:
    fields = {}
    for line in text.splitlines():
        key, sep, value = line.partition(":")
        if sep:
            fields[key.strip()] = value.strip()
    return {key: fields.get(key, "") for key in
            ("User Name", "Link Authentication", "IPMI Messaging", "Privilege Level", "Enable Status")}
