"""IB switch (NVOS ib-sw) adapter for the fleet engine: upgrade v2 (owner 2026-10-23; review 15.1-15.13).

IbFamily tells tools/fleet_engine.py what an IB upgrade consists of (os -> bios -> cpld,
OS images relayed below 10G, v1 canary rules, v1 step rendering); LiveOps acts on one
switch through tools/fleet_ssh.py sessions and returns plain facts; the engine decides.
A later nvl-sw adapter supplies its own family, check script and ops on the same engine. Reused from v1 are only pure functions: the NVOS table parsers,
version/health judgements, the configuration comparator, the step renderer and the
owned runner, plus the SFTP-only authorized_keys read/replace. Nothing here takes a
shared lock or reads another switch's evidence.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass, field
import hashlib
import json
import posixpath
import re
import secrets
import shlex
import stat
import subprocess
import socket
import types
from pathlib import Path

from ibsw_upgrade_access import _key_lines, _read_keys, _replace_keys, merge_authorized_keys, AccessHold
from ibsw_upgrade_component import _bios_upgrade_needed, _cpld_upgrade_needed, render_declared_step
from ibsw_upgrade_contract import (compare_commands, parse_readonly_query_data, record_readonly_query,
                                   select_os_path, ssd_check_from_firmware, _documented_firmware_fields,
                                   _documented_table_lines, _version)
from ibsw_upgrade_executor import _owned_runner_bytes
from ibsw_upgrade_observer import (_assess_component_health, _assess_component_versions, _is_nvos_initializing,
                                   _require_upgrade_health, _NativeObservationHold)
from ibsw_upgrade_schedule import select_os_canaries
import fleet_engine
import fleet_ssh as ssh

SCRIPTS = Path(__file__).resolve().parents[1] / "infiniband/bringup/xdr-upgrade"
CHECK_SCRIPT = (SCRIPTS / "ibsw-v2-check.sh").read_bytes()
FETCH_HELPER = (Path(__file__).resolve().parent / "fleet_fetch_helper.py").read_bytes()
VERSION_ARGV = ("nv", "show", "system", "version")
FIRMWARE_ARGV = ("nv", "show", "platform", "firmware")
HEALTH_ARGV = ("nv", "show", "system", "health")
PREINSTALL_STAGES = {"PACKAGE_DOWNLOAD", "WAIT_DOWNLOAD_RECORD", "PACKAGE_READY", "IMAGE_FETCH", "BIOS_FETCH"}
CHECK_SECONDS = 300.0
VERIFY_SECONDS = 600.0
LONG_COMMAND_SECONDS = 120.0


class DeviceError(Exception):
    """Fixed reason code; `detail` is a safe short text, never device output or a secret."""

    def __init__(self, code, detail=""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code, self.detail = code, detail


# ---------------------------------------------------------------- check script

def run_check(session, mode, *args, timeout=CHECK_SECONDS):
    """Send ibsw-v2-check.sh over stdin; {item: (rc, stdout, stderr)}."""
    command = "/bin/bash -s -- " + " ".join(shlex.quote(str(value)) for value in (mode, *args))
    result = session.run(command, stdin=CHECK_SCRIPT, timeout=timeout)
    lines = result.stdout.split(b"\n")
    if (not result.complete or result.rc != 0 or not lines or lines[0] != b"IBSW_CHECK_BEGIN " + mode.encode()
            or b"IBSW_CHECK_END ok" not in lines):
        raise DeviceError("CHECK_INCOMPLETE", mode)
    items = {}
    for line in lines[1:]:
        if not line.startswith(b"IBSW_ITEM "):
            continue
        parts = line.split(b" ")
        if len(parts) != 5:
            raise DeviceError("CHECK_INCOMPLETE", mode)
        decode = (lambda value: b"" if value == b"-" else base64.b64decode(value, validate=True))
        items[parts[1].decode("ascii")] = (int(parts[2]), decode(parts[3]), decode(parts[4]))
    return items


def _text(items, name):
    rc, out, err = items[name]
    if rc != 0 or err:
        raise DeviceError(name.upper() + "_QUERY_FAILED")
    return out.decode("utf-8", "replace")


def _record(items, name, argv):
    rc, out, err = items[name]
    return record_readonly_query(argv, out, err, None if rc == 124 else rc)


def raw_row(command, item):
    rc, out, err = item
    return {"command": command, "stdout_base64": base64.b64encode(out).decode("ascii"),
            "stderr_base64": base64.b64encode(err).decode("ascii"), "returncode": None if rc == 124 else rc,
            "stream_complete": rc != 124}


# ---------------------------------------------------------------- facts and plan

@dataclass
class Run:
    name: str
    boot_id: str | None
    stdout_mtime: int | None
    alive: bool
    post_install: bool
    exit_code: str | None


@dataclass
class Facts:
    boot_id: str
    uptime: float
    now: int | None
    os_version: str
    os_record: object
    firmware_record: object
    health_record: object
    health_complete: bool
    before_commands: bytes | None
    pending_diff: bytes | None
    runs: list
    staged: dict
    uid: int | None = None
    home: str | None = None
    free_bytes: int | None = None
    capability_missing: tuple = ()
    raw: dict = field(default_factory=dict)

    def guard(self):
        """BUSY: an upgrade step is still running. PENDING: since this boot a step requested an install."""
        boot_time = (self.now - self.uptime) if self.now is not None else None
        for run in self.runs:
            if run.alive:
                return "BUSY", run.name
        for run in self.runs:
            if not run.post_install:
                continue
            if run.boot_id is not None:
                if run.boot_id == self.boot_id:
                    return "PREVIOUS_INSTALL_PENDING", run.name
            elif run.stdout_mtime is not None and boot_time is not None and run.stdout_mtime > boot_time:
                return "PREVIOUS_INSTALL_PENDING", run.name
        return None, None


def check_identity(items, device):
    rc, out, err = items["identity"]
    lines = out.decode("ascii", "replace").splitlines()
    if rc != 0 or err or len(lines) != 2:
        raise DeviceError("DEVICE_IDENTITY_QUERY_FAILED")
    if lines[0].strip().casefold() != device.hostname.casefold() or lines[1].strip().lower() != device.mac.lower():
        raise DeviceError("DEVICE_IDENTITY_MISMATCH")


def _boot(items):
    value = _text(items, "boot_id").strip()
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value):
        raise DeviceError("BOOT_ID_QUERY_FAILED")
    return value


def _runs(items):
    found = []
    for line in _text(items, "runs").splitlines():
        parts = line.split(" ")
        if len(parts) != 6 or not parts[0].startswith(".ibsw-"):
            continue
        found.append(Run(parts[0], None if parts[1] == "-" else parts[1],
                         int(parts[2]) if parts[2].isdigit() else None, parts[3] == "1", parts[4] == "1",
                         None if parts[5] == "-" else parts[5]))
    return found


def _staged(items):
    staged = {}
    if "staged" not in items:
        return staged
    for line in _text(items, "staged").splitlines():
        parts = line.split(" ")
        if len(parts) == 3 and parts[1].isdigit() and re.fullmatch(r"[0-9a-f]{64}", parts[2]):
            staged[parts[0]] = (int(parts[1]), parts[2])
    return staged


def facts_from(items, device):
    check_identity(items, device)
    os_record = _record(items, "version", VERSION_ARGV)
    parsed = parse_readonly_query_data(os_record)
    if parsed.state != "TEXT_DATA_PARSED":
        raise DeviceError("OS_VERSION_PARSE_FAILED")
    facts = Facts(
        boot_id=_boot(items),
        uptime=float(_text(items, "uptime").strip() or 0) if "uptime" in items else 0.0,
        now=int(_text(items, "now").strip()) if "now" in items and items["now"][0] == 0 else None,
        os_version=dict(parsed.fields)["image_version_text"],
        os_record=os_record,
        firmware_record=_record(items, "firmware", FIRMWARE_ARGV),
        health_record=_record(items, "health", HEALTH_ARGV),
        health_complete=items["health"][0] != 124,
        before_commands=items["config_show"][1] if items["config_show"][0] == 0 and not items["config_show"][2] else None,
        pending_diff=items["config_diff"][1] if items["config_diff"][0] == 0 and not items["config_diff"][2] else None,
        runs=_runs(items) if "runs" in items else [], staged=_staged(items), raw=items)
    if "account" in items:
        facts.uid, facts.home = parse_account(items["account"][1], expected_user=None)
    if "free_kib" in items and items["free_kib"][0] == 0 and items["free_kib"][1].strip().isdigit():
        facts.free_bytes = int(items["free_kib"][1].strip()) * 1024
    if "capability" in items and items["capability"][0] != 0:
        facts.capability_missing = tuple(items["capability"][1].decode("ascii", "replace").split()[1:])
    return facts


def parse_account(payload, *, expected_user):
    try:
        lines = payload.decode("utf-8").splitlines()
        uid, fields = int(lines[0]), lines[1].split(":")
        if len(lines) != 2 or len(fields) != 7 or int(fields[2]) != uid:
            raise ValueError()
        if expected_user is not None and fields[0] != expected_user:
            raise ValueError()
        return uid, fields[5]
    except (ValueError, IndexError, UnicodeError):
        raise DeviceError("REMOTE_ACCOUNT_QUERY_FAILED") from None


@dataclass
class Plan:
    os_path: tuple = ()
    bios: bool = False
    cpld: bool = False
    issues: tuple = ()
    rows: tuple = ()

    @property
    def needed(self):
        return tuple(name for name, flag in (("os", bool(self.os_path)), ("bios", self.bios), ("cpld", self.cpld)) if flag)


def cpld_slots(firmware_stdout):
    firmware = dict(_documented_firmware_fields(_documented_table_lines(firmware_stdout), targets=("CPLD",)))
    slots = []
    for slot, value in firmware.items():
        match = re.fullmatch(r"(CPLD[0-9]+)_(REV[0-9]+)", value)
        if match is None:
            raise ValueError("unknown CPLD Actual FW")
        slots.append((slot, match[1], match[2]))
    return tuple(slots)


def plan_device(policy, selected, facts):
    """Which components this switch needs, like v1's initial data plan (observer.py:385-442)."""
    rows, issues = [], []
    os_path, bios, cpld = (), False, False
    row = dict(component="os", current=facts.os_version, target=policy.final_os, action="PREREQUISITE_VERIFIED", path=[])
    rows.append(row)
    if "os" in selected:
        try:
            os_path = select_os_path(policy, facts.os_version)
            row.update(action="UPGRADE_REQUIRED" if os_path else "AT_TARGET_NO_FLASH",
                       path=[facts.os_version] + [package.version for package in os_path])
        except ValueError:
            row["action"] = "REVIEW_REQUIRED"
            issues.append(("os", "OS_UPGRADE_PATH_REJECTED"))
    elif _version(facts.os_version) != policy.final_os:
        issues.append(("os", "OS_FINAL_NOT_REACHED"))
    record = facts.firmware_record
    for component in ("bios", "cpld"):
        if component not in selected:
            continue
        entry = dict(component=component, current="UNVERIFIED", action="REVIEW_REQUIRED",
                     target=policy.bios.version if component == "bios" else
                     "+".join(name + "_" + version for name, version in policy.cpld_targets))
        rows.append(entry)
        try:
            if record.returncode != 0 or record.stderr:
                raise ValueError("firmware query incomplete")
            if component == "bios":
                current = dict(_documented_firmware_fields(_documented_table_lines(record.stdout), targets=("BIOS",)))["BIOS"]
                entry["current"] = current
                bios = _bios_upgrade_needed(policy, current)
                entry["action"] = "UPGRADE_REQUIRED" if bios else "AT_TARGET_NO_FLASH"
            else:
                slots = cpld_slots(record.stdout)
                entry["current"] = ";".join(f"{slot}={name}_{revision}" for slot, name, revision in slots)
                cpld = _cpld_upgrade_needed(policy, slots)
                entry["action"] = "UPGRADE_REQUIRED" if cpld else "AT_TARGET_NO_FLASH"
        except ValueError:
            issues.append((component, "FIRMWARE_QUERY_FAILED" if record.returncode != 0 or record.stderr else
                           component.upper() + "_VERSION_CHECK_FAILED"))
    return Plan(tuple(os_path), bios, cpld, tuple(issues), tuple(rows))


def health_state(record, *, complete, force):
    """(observed PASS/FAIL/UNAVAILABLE, reason code or None, admitted?) using v1's health gate."""
    result = _require_upgrade_health(record, force=True, complete=complete)
    code = result["reason_code"]
    observed = "PASS" if not code else "FAIL" if code == "HEALTH_PRECHECK_NOT_OK" else "UNAVAILABLE"
    return observed, code, (not code) or force


def ssd_row(policy, facts, basis):
    if policy.ssd_version is None or _version(facts.os_version) != policy.final_os:
        return None
    return ssd_check_from_firmware(policy.ssd_version, raw_row("nv show platform firmware", facts.raw["firmware"]),
                                   verification_basis=basis)


# ---------------------------------------------------------------- authorized_keys

@dataclass(frozen=True)
class AccessBackup:
    uid: int
    home: str
    payload: bytes

    def document(self, device, management_key):
        return dict(schema_version=1, hostname=device.hostname, address=device.address, mac=device.mac,
                    uid=self.uid, home=self.home, management_key=management_key,
                    authorized_keys_sha256=hashlib.sha256(self.payload).hexdigest())


def account(session, user):
    result = session.run('id -u; getent passwd "$(id -u)"')
    if not result.ok:
        raise DeviceError("REMOTE_ACCOUNT_QUERY_FAILED")
    return parse_account(result.stdout, expected_user=user)


def _access_error(error):
    code = getattr(error, "reason_code", None) or "AUTHORIZED_KEYS_UNSAFE"
    return DeviceError(code)


def read_keys(session, user):
    uid, home = account(session, user)
    try:
        payload, exists = _read_keys(session.sftp(), home, uid)
    except AccessHold as error:
        raise _access_error(error) from None
    return uid, home, payload, exists


def prepare_access(password_session, key_session_factory, *, user, management_line, management_fingerprint,
                   record_import):
    """Make sure the management key logs in, importing it with the password session if missing (v1 access.py:315-406)."""
    uid, home, payload, exists = read_keys(password_session, user)
    if management_fingerprint not in _key_lines(payload):
        try:
            desired = merge_authorized_keys(management_line, payload) if payload else management_line
            record_import(payload, desired)                    # durable request before the write
            _replace_keys(password_session.sftp(), home, uid, payload, desired, exists,
                          failure="MANAGEMENT_KEY_IMPORT_FAILED")
        except AccessHold as error:
            raise _access_error(error) from None
        payload = desired
    with key_session_factory() as session:
        verified_uid, verified_home, actual, _exists = read_keys(session, user)
    if (verified_uid, verified_home) != (uid, home):
        raise DeviceError("AUTHORIZED_KEYS_ACCOUNT_CHANGED")
    if actual != payload:
        raise DeviceError("AUTHORIZED_KEYS_CHANGED_DURING_RECOVERY")
    return AccessBackup(uid, home, payload)


def access_unchanged(session, backup, user):
    uid, home, current, _exists = read_keys(session, user)
    if (uid, home) != (backup.uid, backup.home):
        raise DeviceError("AUTHORIZED_KEYS_ACCOUNT_CHANGED")
    try:
        if merge_authorized_keys(backup.payload, current) != current:
            raise DeviceError("AUTHORIZED_KEYS_CHANGED_BEFORE_UPGRADE")
    except AccessHold as error:
        raise _access_error(error) from None


def restore_access(session, backup, user, *, record_restore):
    """Put back authorization lines that a reboot dropped; returns whether anything was written."""
    uid, home, current, exists = read_keys(session, user)
    if (uid, home) != (backup.uid, backup.home):
        raise DeviceError("AUTHORIZED_KEYS_ACCOUNT_CHANGED")
    try:
        merged = merge_authorized_keys(backup.payload, current)
        if merged == current:
            return False
        record_restore(current, merged)
        _replace_keys(session.sftp(), home, uid, current, merged, exists, failure="AUTHORIZED_KEYS_RESTORE_FAILED")
    except AccessHold as error:
        raise _access_error(error) from None
    return True


# ---------------------------------------------------------------- dispatch

@dataclass(frozen=True)
class Step:
    component: str
    package_index: int
    stage: str
    target_version: str
    script: bytes
    binding: tuple
    effect: str
    remote_dir: str = ""

    @property
    def header(self):
        return json.dumps(list(self.binding), ensure_ascii=True, separators=(",", ":"))


def render_step(policy, device, *, component, package_index, run_id, switch_dir):
    """The v1 component section with the local method: the package is already staged and verified."""
    rendered = render_declared_step(policy, device, component=component, package_index=package_index,
                                    run_id=run_id, method="local", switch_dir=switch_dir)
    stage = f"os-{package_index:04d}" if component == "os" else component
    return Step(component, package_index, stage, rendered.target_version, rendered.script.encode("utf-8"),
                tuple(rendered.binding), rendered.expected_install_effect)


def _remote_private(item, uid, *, directory):
    if (not (stat.S_ISDIR(item.st_mode) if directory else stat.S_ISREG(item.st_mode))
            or item.st_uid != uid or stat.S_IMODE(item.st_mode) != (0o700 if directory else 0o600)):
        raise DeviceError("REMOTE_PATH_UNSAFE")


def _upload(sftp, uid, path, payload):
    handle = sftp.open(path, "wx")
    try:
        sftp.chmod(path, 0o600)
        handle.write(payload)
        handle.flush()
    finally:
        handle.close()
    _remote_private(sftp.lstat(path), uid, directory=False)
    with sftp.open(path, "rb") as handle:
        if handle.read(len(payload) + 1) != payload:
            raise DeviceError("UPLOAD_READBACK_MISMATCH")


def upload_step(session, step, *, uid, run_id, hostname, switch_dir):
    """Private step directory with step.sh, runner.sh and empty logs (v1 executor.py:166-277 layout)."""
    sftp = session.sftp()
    path = "/"
    item = None
    for part in switch_dir.strip("/").split("/"):
        path = posixpath.join(path, part)
        item = sftp.lstat(path)
        if not stat.S_ISDIR(item.st_mode) or item.st_mode & 0o022:
            raise DeviceError("REMOTE_PATH_UNSAFE")
    if item is None or item.st_uid != uid:
        raise DeviceError("REMOTE_PATH_UNSAFE")
    remote_dir = posixpath.join(switch_dir, f".ibsw-{run_id}-{hostname}-{step.stage}-{secrets.token_hex(16)}")
    sftp.mkdir(remote_dir, 0o700)
    sftp.chmod(remote_dir, 0o700)
    _remote_private(sftp.lstat(remote_dir), uid, directory=True)
    remote = posixpath.join(remote_dir, "step.sh")
    _upload(sftp, uid, remote, step.script)
    binding = dict(run_id=run_id, node=dict(hostname=hostname), component=step.component, stage=step.stage,
                   script_sha256=hashlib.sha256(step.script).hexdigest())
    _upload(sftp, uid, posixpath.join(remote_dir, "runner.sh"), _owned_runner_bytes(binding, remote))
    for name in ("execution.stdout", "execution.stderr"):
        _upload(sftp, uid, posixpath.join(remote_dir, name), b"")
    return remote_dir


def launch_command(remote_dir):
    quoted = shlex.quote(remote_dir)
    return (f"cd {quoted} && /usr/bin/nohup /bin/bash runner.sh >>execution.stdout 2>>execution.stderr "
            f"</dev/null & printf '%s %s\\n' \"$(cat /proc/sys/kernel/random/boot_id)\" \"$!\" > "
            f"{quoted}/launch.record; printf 'IBSW_LAUNCH_REQUESTED\\n'")


def launch(session, remote_dir):
    """True when the switch confirmed the launch; raises SshError when that is unknown."""
    result = session.run(launch_command(remote_dir), timeout=ssh.COMMAND_SECONDS)
    return result.complete and result.rc == 0 and result.stdout == b"IBSW_LAUNCH_REQUESTED\n"


# ---------------------------------------------------------------- probing

def classify_step(text, step, boot_before):
    """Outcome of a step from its markers (review 15.2): running, exit_zero, preinstall_failed, exit_after_install."""
    header, exit_code, stages, component_stage, effect, footer = None, None, [], False, False, None
    for line in text.splitlines():
        if line.startswith("header "):
            header = line[len("header "):]
        elif line.startswith("exit "):
            tokens = line[len("exit "):].split()
            if tokens:
                if (len(tokens) == 7 and tokens[0] == "IBSW_OWNED_EXIT_V1" and tokens[3] == step.component
                        and tokens[4] == step.stage and tokens[5] == hashlib.sha256(step.script).hexdigest()
                        and re.fullmatch(r"[0-9]{1,3}", tokens[6])):
                    exit_code = int(tokens[6])
                else:
                    return "exit_after_install", "EXIT_RECORD_INVALID"
        elif line.startswith("IBSW_STAGE="):
            stages.append(line.split("=", 1)[1])
        elif line.startswith("IBSW_COMPONENT_STAGE="):
            component_stage = True
        elif line.startswith("IBSW_EXPECTED_EFFECT="):
            effect = True
        elif line.startswith("IBSW_EXECUTION_RC="):
            footer = line
    if exit_code is None:
        return "running", None
    if exit_code == 0:
        return "exit_zero", None
    if (header == step.header and stages and stages[-1] in PREINSTALL_STAGES and not component_stage
            and not effect and footer == f"IBSW_EXECUTION_RC={exit_code} IBSW_ACTIVATION_STATE=UNKNOWN"):
        return "preinstall_failed", stages[-1]
    return "exit_after_install", None


def status(session, step, boot_before):
    items = run_check(session, "status", step.remote_dir, timeout=60)
    boot = _boot(items)
    if boot != boot_before:
        return {"kind": "ok", "boot_id": boot, "outcome": "rebooted"}
    rc, out, _err = items["step"]
    if rc != 0:
        return {"kind": "ok", "boot_id": boot, "outcome": "running"}
    outcome, reason = classify_step(out.decode("utf-8", "replace"), step, boot_before)
    return {"kind": "ok", "boot_id": boot, "outcome": outcome, "reason": reason}


def ladder(session, boot_before):
    """Steps 3-5 of the reboot ladder in one session: boot_id, nvued, `nv show system version`."""
    items = run_check(session, "ladder", timeout=90)
    boot = _boot(items)
    if boot == boot_before:
        return {"kind": "boot_same", "boot_id": boot}
    rc, out, _err = items["nvued"]
    state = dict(line.split("=", 1) for line in out.decode("ascii", "replace").splitlines() if "=" in line)
    if rc != 0 or state.get("ActiveState") != "active" or state.get("SubState") != "running":
        return {"kind": "nvued_down", "boot_id": boot}
    rc, out, err = items["version"]
    if _is_nvos_initializing((out, err, rc, rc != 124)) or rc != 0 or err:
        return {"kind": "cli_down", "boot_id": boot}
    parsed = parse_readonly_query_data(record_readonly_query(VERSION_ARGV, out, err, rc))
    if parsed.state != "TEXT_DATA_PARSED":
        return {"kind": "cli_down", "boot_id": boot}
    return {"kind": "ready", "boot_id": boot, "version": dict(parsed.fields)["image_version_text"]}


def ping(address, *, run=subprocess.run):
    """reply / no_reply / error (exit 2 and other local failures are not a reboot signal)."""
    try:
        done = run(["ping", "-c", "3", "-W", "1", "-i", "0.2", "-q", address], stdin=subprocess.DEVNULL,
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15)
    except (OSError, subprocess.SubprocessError):
        return "error"
    return {0: "reply", 1: "no_reply"}.get(done.returncode, "error")


def tcp22(address, *, timeout=3.0):
    try:
        with socket.create_connection((address, 22), timeout=timeout):
            return True
    except OSError:
        return False


# ---------------------------------------------------------------- packages

def fetch(session, context, *, timeout):
    """Run the fetch helper on the switch; the context (maybe with a password) goes over stdin only."""
    code = base64.b64encode(FETCH_HELPER).decode("ascii")
    command = ("/usr/bin/python3 -c " + shlex.quote("import base64,sys;exec(base64.b64decode(sys.argv[1]))")
               + " " + code)
    result = session.run(command, stdin=(json.dumps(context, separators=(",", ":")) + "\n").encode(), timeout=timeout)
    lines = [line for line in result.stdout.decode("utf-8", "replace").splitlines()
             if line.startswith("IBSW_FETCH_RESULT=")]
    if len(lines) != 1:
        return {"ok": False, "class": "unknown", "code": "FETCH_RESULT_MISSING", "attempts": []}
    try:
        value = json.loads(lines[0].split("=", 1)[1])
    except ValueError:
        return {"ok": False, "class": "unknown", "code": "FETCH_RESULT_INVALID", "attempts": []}
    if value.get("class") not in ("source", "receiver", "unknown", "none") or type(value.get("ok")) is not bool:
        return {"ok": False, "class": "unknown", "code": "FETCH_RESULT_INVALID", "attempts": []}
    return value


# ---------------------------------------------------------------- verification

def assess(policy, step, facts, *, before, baseline_health, force_health):
    """Post-install judgement: versions, configuration and health, like v1 observer.py:980-989.

    Returns (state, reason, difference) with state VERIFIED, REPAIR or UNKNOWN."""
    try:
        _assess_component_versions(policy, types.SimpleNamespace(component=step.component,
                                                                 target_version=step.target_version),
                                   facts.os_record, facts.firmware_record)
    except (ValueError, KeyError):
        return "UNKNOWN", "COMPONENT_VERSION_NOT_VERIFIED", None
    if facts.pending_diff is None or facts.pending_diff.strip():
        return "UNKNOWN", "CONFIG_PENDING_NOT_EMPTY", None
    if facts.before_commands is None or not before:
        return "UNKNOWN", "CONFIG_BACKUP_QUERY_FAILED", None
    difference = compare_commands(before.decode("utf-8", "replace"), facts.before_commands.decode("utf-8", "replace"))
    try:
        _assess_component_health(baseline_health, facts.health_record, force=force_health)
    except _NativeObservationHold as error:
        return "UNKNOWN", getattr(error, "reason_code", "HEALTH_DEGRADED"), None
    if difference.state == "PASS":
        return "VERIFIED", None, difference
    if difference.state == "REPAIR_REQUIRED":
        return "REPAIR", None, difference
    return "UNKNOWN", "CONFIG_COMPARISON_REVIEW_REQUIRED", difference


def repair(session, device, before, after, difference, *, uid, switch_dir, record):
    """Apply only the missing NVUE lines (v1 observer.py:1044-1106); never shell, never resent automatically."""
    missing = ("\n".join(difference.missing) + "\n").encode("utf-8")

    def query(command, timeout=ssh.COMMAND_SECONDS):
        result = session.run(command, timeout=timeout)
        record(command, result)
        if not result.ok:
            raise DeviceError("CONFIG_REPAIR_FAILED", command.split(" /")[0])
        return result.stdout

    if query("nv config show -o commands") != after:
        raise DeviceError("CONFIG_REPAIR_FAILED", "export changed before repair")
    if query("nv config diff -o commands").strip():
        raise DeviceError("CONFIG_REPAIR_FAILED", "foreign pending change")
    remote = posixpath.join(switch_dir, f".ibsw-v2-repair-{secrets.token_hex(16)}.commands")
    _upload(session.sftp(), uid, remote, missing)
    try:
        query("nv config patch " + shlex.quote(remote))
        pending = query("nv config diff -o commands")
        patch = compare_commands(missing.decode("utf-8"), pending.decode("utf-8", "replace"))
        if patch.state != "PASS" or patch.added:
            raise DeviceError("CONFIG_REPAIR_FAILED", "pending differs from the missing lines")
        identity = session.run("hostname; cat /sys/class/net/eth0/address")
        check_identity({"identity": (identity.rc, identity.stdout, identity.stderr)}, device)
        query("nv config apply -y", LONG_COMMAND_SECONDS)
        query("nv config save", LONG_COMMAND_SECONDS)
        repaired = query("nv config show -o commands")
        if query("nv config diff -o commands").strip() or compare_commands(
                before.decode("utf-8"), repaired.decode("utf-8", "replace")).state != "PASS":
            raise DeviceError("CONFIG_REPAIR_FAILED", "baseline not restored")
        return repaired
    finally:
        try:
            session.sftp().remove(remote)
        except Exception:
            pass


# ---------------------------------------------------------------- live operations

@dataclass(frozen=True)
class ScpServer:
    """The ztp-server account switches pull from with --method scp (password typed by the operator)."""
    host: str
    user: str
    port: int
    host_keys: str
    password: str = field(repr=False)


class LiveOps:
    """What the engine calls, one switch per call, from worker threads. `journal(name, payload)` writes the
    switch's evidence durably and is called before every remote write (write-ahead)."""

    def __init__(self, *, pins, credentials, policy, selected, run_id, switch_dir="/home/admin", force_health=False,
                 management_line=None, method="http", scp_server=None, sock_factory=None,
                 ping_run=subprocess.run, tcp_probe=tcp22, relay_timeout=1200, connector=None, dir_for=None):
        if method not in ("http", "scp") or (method == "scp" and scp_server is None):
            raise ValueError("--method http, or scp with the ztp-server account")
        self.pins, self.creds, self.policy, self.selected = pins, credentials, policy, tuple(selected)
        self.run_id, self.switch_dir, self.force_health = run_id, switch_dir, force_health
        self.management_line, self.method, self.scp_server = management_line, method, scp_server
        self.sock_factory, self.ping_run, self.tcp_probe, self.relay_timeout = sock_factory, ping_run, tcp_probe, relay_timeout
        self.connector = connector          # tests: connector(device, method) -> session
        self._dir_for = dir_for             # tests: one directory per simulated switch

    def dir_for(self, device):
        """The switch's package/step directory (production: --local-dir, /home/admin)."""
        return self._dir_for(device) if self._dir_for else self.switch_dir

    def _open(self, device, method):
        if self.connector is not None:
            return self.connector(device, method)
        return ssh.connect(device.address, self.pins, self.creds, method=method, sock_factory=self.sock_factory)

    def _connect(self, device, *, password_fallback=True):
        """(session, key_rejected): the key first, the password only after an explicit rejection."""
        try:
            return self._open(device, "key"), False
        except ssh.SshError as error:
            if error.code != "AUTH_REJECTED" or not password_fallback or not self.creds.password:
                raise
        return self._open(device, "password"), True

    def _password(self, device):
        return self._open(device, "password")

    def precheck(self, device, *, upgrade, staged_names=(), journal):
        session, key_rejected = self._connect(device)
        with session:
            items = run_check(session, "precheck", self.dir_for(device), *staged_names)
        facts = facts_from(items, device)
        plan = plan_device(self.policy, self.selected, facts)
        observed, code, admitted = health_state(facts.health_record, complete=facts.health_complete,
                                                force=self.force_health)
        guard = facts.guard()
        backup = None
        if upgrade and plan.needed and not plan.issues and guard[0] is None:
            def record_import(current, desired):
                journal("access-bootstrap.json", dict(state="MANAGEMENT_KEY_IMPORT_REQUESTED",
                                                      original_base64=base64.b64encode(current).decode(),
                                                      desired_sha256=hashlib.sha256(desired).hexdigest()))
            with self._password(device) as password_session:   # the recovery password works before any write
                backup = prepare_access(password_session, lambda: self._connect(device, password_fallback=False)[0],
                                        user=self.creds.user, management_line=self.management_line,
                                        management_fingerprint=self.creds.key_fingerprint,
                                        record_import=record_import)
            journal("authorized_keys.before", backup.payload)
            journal("access-backup.json", backup.document(device, self.creds.key_fingerprint))
        return dict(facts=facts, plan=plan, health=dict(observed=observed, reason=code, admitted=admitted),
                    guard=guard, backup=backup, key_rejected=key_rejected)

    def fetch(self, device, package, *, size, sha256, holder=None, url=None):
        """Pull one package into the switch: from a holder switch (scp + password) or the ztp-server."""
        context = dict(dest_dir=self.dir_for(device), name=package.file, size=size, sha256=sha256)
        if holder is not None:
            context.update(method="scp", host=holder.address, user=self.creds.user, port=22,
                           host_keys=self.pins.known_hosts_text(holder.address),
                           path=posixpath.join(self.dir_for(holder), package.file), timeout=int(self.relay_timeout))
            context["password"] = self.creds.password            # the switches' own admin password
            budget = self.relay_timeout + 900
        elif self.method == "http":
            context.update(method="http", url=url or package.url, attempts=4, timeout=600)
            budget = 4 * 600 + 15 + 900
        else:
            server = self.scp_server
            context.update(method="scp", host=server.host, user=server.user, port=server.port,
                           host_keys=server.host_keys, path=package.path, timeout=int(self.relay_timeout))
            context["password"] = server.password
            budget = self.relay_timeout + 900
        session, _rejected = self._connect(device)
        with session:
            return fetch(session, context, timeout=budget)

    def dispatch(self, device, step, *, backup, staged, journal):
        """Re-check, upload and launch. Raises before the write-ahead record (nothing started);
        returns confirmed None when the launch outcome is unknown (treat as started)."""
        session, _rejected = self._connect(device, password_fallback=False)
        with session:
            items = run_check(session, "dispatch", self.dir_for(device), *staged)
            facts = facts_from(items, device)
            guard, where = facts.guard()
            if guard:
                return dict(state="GUARD", reason=guard, detail=where)
            plan = plan_device(self.policy, self.selected, facts)
            still = (bool(plan.os_path) and plan.os_path[0].version == step.target_version if step.component == "os"
                     else plan.bios if step.component == "bios" else plan.cpld)
            if not still:
                return dict(state="AT_TARGET", facts=facts)
            if step.component != "os" and _version(facts.os_version) != self.policy.final_os:
                return dict(state="BLOCKED", reason="OS_FINAL_NOT_REACHED")
            _observed, code, admitted = health_state(facts.health_record, complete=facts.health_complete,
                                                     force=self.force_health)
            if not admitted:
                return dict(state="HEALTH_BLOCKED", reason=code)
            before = facts.before_commands
            if before is None:
                return dict(state="FAILED", reason="CONFIG_BACKUP_QUERY_FAILED")
            try:
                before.decode("utf-8")
            except UnicodeError:
                return dict(state="FAILED", reason="CONFIG_BACKUP_NOT_TEXT")
            if not before.strip():
                return dict(state="FAILED", reason="CONFIG_BACKUP_EMPTY")
            if facts.pending_diff is None or facts.pending_diff.strip():
                return dict(state="FAILED", reason="CONFIG_PENDING_NOT_EMPTY")
            for name, expected in staged.items():
                if facts.staged.get(name) != tuple(expected):
                    return dict(state="FAILED", reason="STAGED_PACKAGE_CHANGED", detail=name)
            access_unchanged(session, backup, self.creds.user)
            uid, _home = account(session, self.creds.user)
            remote_dir = upload_step(session, step, uid=uid, run_id=self.run_id, hostname=device.hostname,
                                     switch_dir=self.dir_for(device))
            journal("dispatch.json", dict(state="REQUESTED", component=step.component, stage=step.stage,
                                          target_version=step.target_version, remote_dir=remote_dir,
                                          boot_before=facts.boot_id,
                                          script_sha256=hashlib.sha256(step.script).hexdigest()))
            try:
                confirmed = launch(session, remote_dir)
            except ssh.SshError:
                confirmed = None
        return dict(state="DISPATCHED", remote_dir=remote_dir, boot_before=facts.boot_id, confirmed=confirmed,
                    before_commands=before, health_record=facts.health_record, facts=facts)

    def _probe_session(self, device):
        """Key first, password when the key is rejected (no restore while probing; review 15.5)."""
        return self._connect(device)

    def status(self, device, step, boot_before):
        try:
            session, _rejected = self._probe_session(device)
        except ssh.SshError as error:
            return {"kind": "hostkey" if error.code == "HOST_KEY_MISMATCH" else
                    "auth_fail" if error.code == "AUTH_REJECTED" else "connect_fail"}
        try:
            with session:
                return status(session, step, boot_before)
        except (ssh.SshError, DeviceError):
            return {"kind": "connect_fail"}

    def ladder(self, device, boot_before, *, backup, journal):
        try:
            session, rejected = self._probe_session(device)
        except ssh.SshError as error:
            return {"kind": "hostkey" if error.code == "HOST_KEY_MISMATCH" else
                    "auth_fail" if error.code == "AUTH_REJECTED" else "connect_fail"}
        try:
            with session:
                result = ladder(session, boot_before)
                if result["kind"] == "ready" and rejected:
                    restore_access(session, backup, self.creds.user, record_restore=lambda current, merged: journal(
                        "access-restore-requested.json", dict(state="RESTORE_REQUESTED",
                                                              current_base64=base64.b64encode(current).decode(),
                                                              desired_sha256=hashlib.sha256(merged).hexdigest())))
                    result["restored"] = True
        except ssh.SshError:
            return {"kind": "connect_fail"}
        except DeviceError as error:
            return {"kind": "connect_fail"} if error.code == "CHECK_INCOMPLETE" else {"kind": "auth_fail",
                                                                                      "reason": error.code}
        if result.get("restored"):
            try:
                with self._connect(device, password_fallback=False)[0]:
                    pass
            except ssh.SshError:
                return {"kind": "auth_fail", "reason": "KEY_LOGIN_AFTER_RESTORE_FAILED"}
        return result

    def verify(self, device, step, *, boot_after, before, baseline_health, backup, journal):
        """VERIFIED / UNKNOWN / REBOOTED. Repairs only missing configuration, after a durable request.

        An SshError leaving here carries `repair_requested`: whether this attempt had already asked for
        repair-requested.json to be written. The engine retries a timed-out verification only when it had
        not (owner 2026-10-23), so a repair is never resent automatically."""
        attempt = {"repair_requested": False}
        try:
            return self._verify_once(device, step, boot_after=boot_after, before=before,
                                     baseline_health=baseline_health, backup=backup, journal=journal,
                                     attempt=attempt)
        except ssh.SshError as error:
            error.repair_requested = attempt["repair_requested"]
            raise

    def _verify_once(self, device, step, *, boot_after, before, baseline_health, backup, journal, attempt):
        record_restore = (lambda current, merged: journal("access-restore-requested.json", dict(
            state="RESTORE_REQUESTED", current_base64=base64.b64encode(current).decode(),
            desired_sha256=hashlib.sha256(merged).hexdigest())))
        session, _rejected = self._connect(device)
        repaired = False
        with session:
            restore_access(session, backup, self.creds.user, record_restore=record_restore)
            items = run_check(session, "verify", timeout=VERIFY_SECONDS)
            facts = facts_from(items, device)
            if facts.boot_id != boot_after:
                return dict(state="REBOOTED", boot_id=facts.boot_id)
            state, reason, difference = assess(self.policy, step, facts, before=before,
                                               baseline_health=baseline_health, force_health=self.force_health)
            if state == "REPAIR":
                attempt["repair_requested"] = True                 # set before the write: never under-reported
                journal("repair-requested.json", dict(state="REPAIR_REQUESTED", missing=list(difference.missing)))
                rows = []
                try:
                    uid, _home = account(session, self.creds.user)
                    repair(session, device, before, facts.before_commands, difference, uid=uid,
                           switch_dir=self.dir_for(device),
                           record=lambda command, result: rows.append(dict(command=command.split(" /")[0],
                                                                           rc=result.rc)))
                except (DeviceError, ssh.SshError) as error:
                    journal("repair-result.json", dict(state="UNKNOWN", reason=getattr(error, "code", "FAILED"),
                                                       commands=rows))
                    return dict(state="UNKNOWN", reason="CONFIG_REPAIR_FAILED", facts=facts)
                journal("repair-result.json", dict(state="REPAIRED", commands=rows))
                repaired = True
                items = run_check(session, "verify", timeout=VERIFY_SECONDS)
                facts = facts_from(items, device)
                state, reason, _difference = assess(self.policy, step, facts, before=before,
                                                    baseline_health=baseline_health, force_health=self.force_health)
            if state != "VERIFIED":
                return dict(state="UNKNOWN", reason=reason, facts=facts, repaired=repaired)
        with self._connect(device, password_fallback=False)[0] as key_session:   # FINAL_KEY_ACCESS_CHECK
            result = key_session.run("cat /proc/sys/kernel/random/boot_id")
            if not result.ok or result.stdout.decode("ascii", "replace").strip() != boot_after:
                return dict(state="REBOOTED", boot_id=result.stdout.decode("ascii", "replace").strip())
        return dict(state="VERIFIED", os_version=facts.os_version, repaired=repaired, facts=facts,
                    ssd=ssd_row(self.policy, facts, "POST_UPGRADE"))

    def ping(self, device):
        return ping(device.address, run=self.ping_run)

    def tcp(self, device):
        return self.tcp_probe(device.address)


# ---------------------------------------------------------------- family

class IbFamily(fleet_engine.Family):
    """IB ib-sw: os -> bios -> cpld like v1; OS images are relayed/staggered, BIOS/CPLD pulled directly."""
    name = "ib-sw"
    components = ("os", "bios", "cpld")
    required_programs = ("/bin/bash", "/usr/bin/nohup", "/usr/bin/python3", "/usr/bin/curl", "/usr/bin/scp",
                         "/usr/bin/sha256sum")

    def __init__(self, policy):
        self.policy = policy

    def packages(self, selected):
        policy, wanted = self.policy, []
        if "os" in selected:
            wanted += list(policy.os)
        if "bios" in selected and policy.bios:
            wanted.append(policy.bios)
        if "cpld" in selected and policy.cpld_burn:
            wanted += [policy.cpld_burn, policy.cpld_refresh]
        return wanted

    def steps(self, plan, component, infos):
        policy, StepPlan = self.policy, fleet_engine.StepPlan
        if component == "os":
            return [StepPlan("os", policy.os.index(package), (infos[package.path],), package.version)
                    for package in plan.os_path]
        if component == "bios":
            return [StepPlan("bios", 0, (infos[policy.bios.path],), policy.bios.version)] if plan.bios else []
        if component == "cpld" and plan.cpld:
            target = "+".join(name + "_" + version for name, version in policy.cpld_targets)
            return [StepPlan("cpld", 0, (infos[policy.cpld_burn.path], infos[policy.cpld_refresh.path]), target)]
        return []

    def canaries(self, component, members):
        """OS: v1's minimum route cover (schedule.py:18-74); BIOS/CPLD: the first switch in CSV order."""
        if not members:
            return []
        if component == "os":
            rows = [dict(row, hostname=host) for host, plan in members for row in plan.rows if row["component"] == "os"]
            return list(select_os_canaries(self.policy, rows, [host for host, _plan in members])["canaries"])
        return [members[0][0]]

    def render(self, device, step_plan, *, run_id, switch_dir):
        return render_step(self.policy, device, component=step_plan.component, package_index=step_plan.package_index,
                           run_id=run_id, switch_dir=switch_dir)

    def relay(self, component):
        return component == "os"

    def space_needed(self, plan, infos):
        """Room for one OS image twice (`nv action fetch` copies it); BIOS/CPLD are small."""
        return 2 * max((infos[package.path].size for package in plan.os_path if package.path in infos), default=0)
