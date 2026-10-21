"""Render one existing-project IB NVOS component; never execute or authorize it.

The command contract comes from NVOS IB Installation Management, not Ethernet
Cumulus. OS install defaults to reboot: returned-zero cannot prove activation.
SSH/device identity, remote path trust, activation/reconnect/config/health and
the final-OS barrier belong to the future fixed executor and remain OPEN.
"""
from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
from urllib.parse import urlsplit
import math

from ibsw_upgrade_contract import InventoryDevice, UpgradePolicy, _cpld_targets, _file, _root, select_os_path
from project_contract import normalize_redundancy_mac, validate_service_endpoint


from ibsw_upgrade_contract import _fixed_layout
_MODULE_DIR = Path(__file__).resolve().parent
_TEMPLATE = _fixed_layout(__file__) / "upgrade-component.sh"


def parse_download_results(raw):
    """Bounded numeric curl observations only, never install/activation proof."""
    if type(raw) is not bytes or len(raw)>512*1024:
        raise ValueError('bounded original download log required')
    rows=[]
    for line in raw.splitlines(keepends=True):
        if not line.startswith(b'IBSW_DOWNLOAD_RESULT=') or not line.endswith(b'\n'):
            continue
        value=line.rstrip(b'\n').decode('ascii')
        fields=value.split('=',1)[1].split('|')
        if (len(fields)!=8 or any(re.fullmatch(r'[0-9]{1,20}',v) is None for v in fields[:6])
                or any(re.fullmatch(r'[0-9]{1,20}(?:\.[0-9]{1,9})?',v) is None for v in fields[6:])):
            raise ValueError('malformed download observation')
        attempt,start,end,code,http,size=map(int,fields[:6])
        elapsed,speed=map(float,fields[6:])
        if (attempt!=len(rows)+1 or attempt>4 or end<start or not 0<=code<=255
                or not 0<=http<=599 or not all(math.isfinite(x) and x>=0 for x in (elapsed,speed))):
            raise ValueError('invalid download attempt sequence or measurement')
        if rows and rows[-1]['curl_exit']==0 and rows[-1]['http_status']==200:
            raise ValueError('download attempts after success are forbidden')
        rows.append(dict(attempt=attempt,started_epoch=start,finished_epoch=end,curl_exit=code,http_status=http,
            bytes_downloaded=size,elapsed_seconds=elapsed,average_bytes_per_second=speed,raw_line=value))
    return rows


def download_ack_bytes(run_id,raw_line):
    if (type(run_id) is not str or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}',run_id) is None
            or type(raw_line) is not bytes or b'\n' in raw_line or len(raw_line)>512):
        raise ValueError('original bounded download acknowledgement required')
    return b'IBSW_DOWNLOAD_ACK_V1|'+run_id.encode('ascii')+b'|'+raw_line+b'\n'


def _scp_download_pair(content_marker, raw_line):
    """Validate two public SCP DATA records, never an execution permission."""
    import base64
    if (type(content_marker) is not bytes or type(raw_line) is not bytes
            or len(content_marker) + len(raw_line) + 2 > 4096
            or any(char in content_marker or char in raw_line for char in (b'\n', b'\r'))):
        raise ValueError('bounded complete SCP download pair required')
    try:
        marker = content_marker.decode('ascii').split('|')
        fields = raw_line.decode('ascii').split('|')
        if (len(marker) != 5 or marker[0] != 'IBSW_SCP_CONTENT_VERIFIED=1'
                or re.fullmatch(r'[0-9a-f]{64}', marker[1]) is None
                or re.fullmatch(r'[A-Za-z0-9_-]+', marker[2]) is None
                or re.fullmatch(r'[1-9][0-9]{0,18}', marker[3]) is None
                or re.fullmatch(r'[0-9a-f]{64}', marker[4]) is None):
            raise ValueError()
        decoded = base64.b64decode(marker[2] + '=' * (-len(marker[2]) % 4),
                                   altchars=b'-_', validate=True)
        if base64.urlsafe_b64encode(decoded).rstrip(b'=').decode('ascii') != marker[2]:
            raise ValueError()
        path = decoded.decode('utf-8')
        if (not path.startswith('/') or len(decoded) > 4096
                or any(ord(char) < 32 or ord(char) == 127 for char in path)):
            raise ValueError()
        size = int(marker[3])
        if not 0 < size < 2**63:
            raise ValueError()
        if (len(fields) != 8 or fields[0] != 'IBSW_SCP_DOWNLOAD_RESULT=1'
                or any(re.fullmatch(r'[0-9]{1,20}', value) is None for value in fields[1:6])
                or fields[3:5] != ['0', '0']
                or any(re.fullmatch(r'[0-9]{1,20}(?:\.[0-9]{1,9})?', value) is None
                       for value in fields[6:])):
            raise ValueError()
        start, end, code, status, downloaded = map(int, fields[1:6])
        elapsed, speed = map(float, fields[6:])
        if (end < start or downloaded != size
                or not all(math.isfinite(value) and value >= 0 for value in (elapsed, speed))):
            raise ValueError()
    except (ValueError, UnicodeError):
        raise ValueError('invalid SCP download pair') from None
    row = dict(attempt=1, started_epoch=start, finished_epoch=end,
               scp_exit=code, reserved_status=status, bytes_downloaded=downloaded,
               elapsed_seconds=elapsed, average_bytes_per_second=speed,
               content_marker=content_marker, raw_line=raw_line)
    return row, (marker[1], path, size, marker[4])


def parse_scp_download_results(payload, expected_content):
    """Exact two-record SCP DATA packet; caller must separately govern stdout."""
    if (type(payload) is not bytes or len(payload) > 4096
            or not payload.endswith(b'\n') or payload.count(b'\n') != 2
            or b'\r' in payload
            or type(expected_content) is not dict
            or set(expected_content) != {'binding_sha256', 'path', 'size', 'sha256'}):
        raise ValueError('exact SCP download packet and content DATA required')
    binding, path, size, digest = (expected_content[key] for key in
                                 ('binding_sha256', 'path', 'size', 'sha256'))
    if (type(binding) is not str or re.fullmatch(r'[0-9a-f]{64}', binding) is None
            or type(digest) is not str or re.fullmatch(r'[0-9a-f]{64}', digest) is None
            or type(path) is not str or not path.startswith('/')
            or type(size) is not int or not 0 < size < 2**63
            or any(ord(char) < 32 or ord(char) == 127 for char in path)):
        raise ValueError('invalid expected SCP content DATA')
    try:
        if len(path.encode('utf-8')) > 4096:
            raise ValueError()
    except UnicodeError:
        raise ValueError('invalid expected SCP content DATA') from None
    first, second, _tail = payload.split(b'\n')
    if first.startswith(b'IBSW_SCP_CONTENT_VERIFIED='):
        marker, line = first, second
    elif second.startswith(b'IBSW_SCP_CONTENT_VERIFIED='):
        marker, line = second, first
    else:
        raise ValueError('one SCP content marker required')
    row, content = _scp_download_pair(marker, line)
    if content != (binding, path, size, digest):
        raise ValueError('SCP content DATA mismatch')
    return row


def scp_download_ack_bytes(run_id, content_marker, raw_line):
    """Fixed V2 wire DATA; not an owner record, grant or ACK publication."""
    import hashlib
    if (type(run_id) is not str
            or re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,95}', run_id) is None):
        raise ValueError('safe SCP download acknowledgement run required')
    _scp_download_pair(content_marker, raw_line)
    return (b'IBSW_SCP_DOWNLOAD_ACK_V2|' + run_id.encode('ascii') + b'|'
            + hashlib.sha256(content_marker).hexdigest().encode('ascii')
            + b'|' + raw_line + b'\n')


@dataclass(frozen=True)
class RenderedStep:
    script: str
    target_version: str
    binding: tuple[str, ...]
    expected_install_effect: str = "REBOOT_EXPECTED"
    activation_state: str = "UNKNOWN"


def _validate_plan(policy, device, run_id, method, switch_dir):
    if not isinstance(policy, UpgradePolicy) or not isinstance(device, InventoryDevice):
        raise ValueError("existing typed project plan and inventory required")
    if method not in {"local", "http", "scp"}:
        raise ValueError("component declarations cover local/http/scp only; no HTTPS")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", run_id):
        raise ValueError("safe run binding required")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", device.hostname):
        raise ValueError("safe inventory hostname required")
    validate_service_endpoint(device.address, field="IB inventory IPv4")
    normalize_redundancy_mac(device.mac, label="IB inventory MAC")
    return _root(switch_dir)


def _package_url(package, method):
    _file(package.file)
    url = ""
    if method == "http":
        if not isinstance(package.url, str):
            raise ValueError("HTTP step needs the project planner's declared URL")
        parsed = urlsplit(package.url)
        if (parsed.scheme != "http" or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or not parsed.path.startswith("/")
                or re.search(r"[\x00-\x20\x7f]", package.url)):
            raise ValueError("plain project HTTP URL without credentials/control/query required")
        validate_service_endpoint(parsed.hostname, parsed.port or 80, field="IB package HTTP")
        url = package.url
    return url


def _render(policy, device, *, run_id, method, switch_dir, component,
            package, target_version, refresh=None, effect="REBOOT_EXPECTED"):
    switch_dir = _validate_plan(policy, device, run_id, method, switch_dir)
    url = _package_url(package, method)
    binding = (run_id, device.hostname, device.address, device.mac, component, target_version)
    values = {
        "IBSW_RUN_ID": run_id,
        "IBSW_COMPONENT": component,
        "IBSW_METHOD": method,
        "IBSW_PACKAGE_FILE": package.file,
        "IBSW_PACKAGE_URL": url,
        "IBSW_SWITCH_DIR": switch_dir,
        "IBSW_LOCAL_PACKAGE": str(Path(switch_dir) / package.file),
        "IBSW_BINDING_JSON": json.dumps(binding, ensure_ascii=True, separators=(",", ":")),
        "IBSW_EXPECTED_EFFECT": effect,
    }
    if refresh is not None:
        values.update(IBSW_REFRESH_FILE=refresh.file, IBSW_REFRESH_URL=_package_url(refresh, method),
                      IBSW_REFRESH_LOCAL=str(Path(switch_dir) / refresh.file))
    if method == "scp":
        import base64
        from ibsw_upgrade_scp import remote_helper_bytes
        # Fixed stdin-only target helper, never the old environment launcher.
        helper = b"import os\nos.environ.pop('IBSW_SCP_AUTH',None)\n" + remote_helper_bytes()
        values.update(IBSW_SCP_HELPER_B64=base64.b64encode(helper).decode('ascii'),
                      IBSW_SCP_PACKAGE_PATH=package.path)
        if refresh is not None:
            values['IBSW_SCP_REFRESH_PATH'] = refresh.path
    header = "#!/bin/bash\n# Generated IB NVOS component plan artifact; not execution permission.\n"
    header += "\n".join(key + "=" + shlex.quote(value) for key, value in values.items()) + "\n"
    if _fixed_layout(__file__) / "upgrade-component.sh" != _TEMPLATE:
        raise ValueError("fixed component template layout changed")
    template = _TEMPLATE.read_text(encoding="utf-8")
    # Fixed repository-owned section markers, not caller-provided code or eval.
    sections = {}
    for name in ("os", "bios", "cpld"):
        marker = "# IBSW_BODY_" + name.upper() + "\n"
        if template.count(marker) != 1:
            raise ValueError("fixed component template section missing or repeated")
    common, remainder = template.split("# IBSW_BODY_OS\n", 1)
    sections["os"], remainder = remainder.split("# IBSW_BODY_BIOS\n", 1)
    sections["bios"], sections["cpld"] = remainder.split("# IBSW_BODY_CPLD\n", 1)
    return RenderedStep(header + common + sections[component], target_version, binding, effect)


def render_os_step(policy: UpgradePolicy, device: InventoryDevice, *, run_id: str,
                   current_os: str, method: str, switch_dir: str = "/home/admin"):
    """Generate only first approved successor; caller data is not a permit."""
    _validate_plan(policy, device, run_id, method, switch_dir)
    remaining = select_os_path(policy, current_os)
    if not remaining:
        return None
    package = remaining[0]
    return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                   component="os", package=package, target_version=package.version)


def render_declared_step(policy, device, *, component, package_index=0,
                         run_id, method, switch_dir="/home/admin"):
    """Internal candidate artifact, NOT current/on-demand/OS-final permission.

    Caller indices select declared files only, never justify reinstall/downgrade.
    A future fixed executor must independently obtain live device observations.
    """
    from ibsw_upgrade_schedule import declared_step_key
    declared_step_key(policy, component, package_index)
    if component == "os":
        package = policy.os[package_index]
        return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                       component=component, package=package, target_version=package.version)
    if component == "bios":
        return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                       component=component, package=policy.bios, target_version=policy.bios.version)
    target = "+".join(identifier + "_" + revision for identifier, revision in policy.cpld_targets)
    return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                   component=component, package=policy.cpld_burn, refresh=policy.cpld_refresh,
                   target_version=target, effect="POWER_CYCLE_EXPECTED")


def _bios_key(version):
    if not isinstance(version, str) or not re.fullmatch(r"0ACQF_[0-9]+(?:\.[0-9]+)+", version):
        raise ValueError("unknown BIOS observation cannot establish no-downgrade")
    parts = tuple(int(part) for part in version.split("_", 1)[1].split("."))
    while len(parts) > 1 and parts[-1] == 0:
        parts = parts[:-1]
    return parts


def render_bios_step(policy: UpgradePolicy, device: InventoryDevice, *, run_id: str,
                     current_bios: str, method: str, switch_dir: str = "/home/admin"):
    """On-demand BIOS plan, not source/hardware compatibility or OS admission."""
    _validate_plan(policy, device, run_id, method, switch_dir)
    if not _bios_upgrade_needed(policy, current_bios):
        return None
    return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                   component="bios", package=policy.bios, target_version=policy.bios.version)


def _bios_upgrade_needed(policy, current_bios):
    """Pure on-demand comparison DATA, never execution permission."""
    if policy.bios is None:
        raise ValueError("selected BIOS policy required")
    current, target = _bios_key(current_bios), _bios_key(policy.bios.version)
    if current > target:
        raise ValueError("BIOS is newer than target; automatic downgrade forbidden")
    if current == target:
        return False
    return True


def render_cpld_step(policy: UpgradePolicy, device: InventoryDevice, *, run_id: str,
                     current_slots: tuple[tuple[str, str, str], ...], method: str,
                     switch_dir: str = "/home/admin"):
    """One BURN/REFRESH bundle plan; slot observations are not attestation."""
    _validate_plan(policy, device, run_id, method, switch_dir)
    if not _cpld_upgrade_needed(policy, current_slots):
        return None
    target_version = "+".join(identifier + "_" + revision for identifier, revision in policy.cpld_targets)
    return _render(policy, device, run_id=run_id, method=method, switch_dir=switch_dir,
                   component="cpld", package=policy.cpld_burn, refresh=policy.cpld_refresh,
                   target_version=target_version, effect="POWER_CYCLE_EXPECTED")


def _cpld_upgrade_needed(policy, current_slots):
    """Reuse the original no-downgrade comparator, not compatibility approval."""
    if policy.cpld_burn is None or policy.cpld_refresh is None or not policy.cpld_targets:
        raise ValueError("selected complete CPLD pair policy required")
    burn = _cpld_targets(policy.cpld_burn.file, "BURN")
    refresh = _cpld_targets(policy.cpld_refresh.file, "REFRESH")
    if burn != refresh or burn[1] != policy.cpld_targets:
        raise ValueError("CPLD BURN/REFRESH FUI and targets must match")
    if not isinstance(current_slots, tuple) or not current_slots:
        raise ValueError("CPLD slot observations required for no-downgrade selection")
    seen_slots, seen_ids = set(), set()
    targets = dict(policy.cpld_targets)
    needed = False
    for entry in current_slots:
        if not isinstance(entry, tuple) or len(entry) != 3 or not all(isinstance(item, str) for item in entry):
            raise ValueError("typed CPLD slot/ID/revision observation required")
        slot, identifier, revision = entry
        if (not re.fullmatch(r"CPLD[1-9][0-9]*", slot) or slot in seen_slots
                or not re.fullmatch(r"CPLD[0-9]+", identifier) or not re.fullmatch(r"REV[0-9]+", revision)):
            raise ValueError("unknown or duplicate CPLD slot observation")
        seen_slots.add(slot)
        if identifier not in targets:
            continue  # No new hardware/source compatibility matrix is inferred.
        seen_ids.add(identifier)
        current, target = int(revision[3:]), int(targets[identifier][3:])
        if current > target:
            raise ValueError("CPLD slot is newer than target; entire bundle downgrade forbidden")
        needed |= current < target
    if seen_ids != set(targets):
        raise ValueError("CPLD target revision observations incomplete")
    return needed
