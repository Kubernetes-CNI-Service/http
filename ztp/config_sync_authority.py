#!/usr/bin/env python3
"""Local single-writer F02 generations; not an independent rollback backend.

The held writer witness and replaceable pair detect partial replay/rollback.
Restoring all three images or their whole volume together is outside this
authority and must not be advertised as safe.
An interrupted publication leaves a persistent hold, not a previous success.
"""

from contextlib import contextmanager
import copy
from datetime import datetime
import fcntl
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import uuid


# v1 has ten fixed members, ASCII hostname <=253, operation ID <=512,
# generated trigger ID <=512+1+253=766, a
# uint64 dev:ino namespace, signed-64 generation and a 64-byte digest.
# The independent maximum compact JSON image is 1852 bytes; use a finite
# 2048-byte wire budget. Witness v1 is <512 bytes.
JOURNAL_MAX_BYTES = 2048
WITNESS_MAX_BYTES = 512
# Receipt v1 has 16 failed / 23 successful fixed fields. Its independent
# largest canonical image is 14331 B (1024 astral diagnostic code points,
# maximal identities and timestamps); 16 KiB bounds both canonical and
# indented writer images without truncating an input or a diagnostic.
RECEIPT_MAX_BYTES = 16384
MAX_GENERATION = 9223372036854775807
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,252}\Z")
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,511}\Z")
TRIGGER_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9:._-]{0,765}\Z")
NAMESPACE = re.compile(r"[0-9]{1,20}:[0-9]{1,20}\Z")
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
SOURCES = {"manual_config_sync_cli", "manual_config_sync_web"}
JOURNAL_FIELDS = {
    "schema_version", "hostname", "generation", "operation_id", "trigger_id",
    "trigger_source", "source_identity", "state", "veto", "receipt_sha256",
}
RECEIPT_COMMON_FIELDS = {
    "schema_version", "hostname", "type", "state", "started_at",
    "command_started_at", "operation", "effective_operation", "requested_operation",
    "operation_id", "trigger_source", "trigger_id", "finished_at", "generation",
    "source_identity",
}
RECEIPT_SUCCESS_FIELDS = RECEIPT_COMMON_FIELDS | {
    "transport_ip", "interface", "action", "command_ztp_log_sha256",
    "command_ztp_complete", "batch_identity_verified", "batch_identity_verified_at",
    "live_state_sha256",
}
RECEIPT_ACTION = "nv config replace <latest-hostname.yaml>; nv config apply -y; nv config save"
# Method V2 is a separate authority, not an alias for replace-config V1.
# The independent largest canonical success is 2270 B, failed diagnostic
# image 14134 B. Fixed identifiers plus <=1024 Unicode code points fit 16 KiB
# even in escaped ASCII JSON. Independent maximum-positive tests pin this
# budget; receipt bytes are rejected and retained, never truncated.
METHOD_RECEIPT_MAX_BYTES = 16384
METHOD_EXECUTORS = {
    "ztp_monitor_cycle": ("ztp", frozenset({"eth", "eth_spx", "spx", "air", "ib", "nvl"})),
    "initial_setup_managed": ("initial-setup", frozenset({"ib"})),
}
METHOD_COMMON_FIELDS = {
    "schema_version", "record_type", "hostname", "type", "config_method",
    "generation", "source_identity", "operation_id", "trigger_id",
    "trigger_source", "state", "reason",
}
METHOD_SUCCESS_FIELDS = METHOD_COMMON_FIELDS | {
    "batch_identity_verified", "config_verified", "interface", "transport_ip",
    "mac_plain", "live_state_sha256", "input_sha256", "source_receipt_sha256",
}


class AuthorityError(ValueError):
    pass


class ManagedInitialMethodCycle:
    """Management-host producer; never a replacement for nine-stage proof.

    The stdlib leaf accepts this optional object, not an import dependency.
    Its default disconnected execution remains unchanged and supplies no V2
    method authority. Current inputs are re-observed before and after BatchMode.
    """
    def __init__(self, project, initial):
        self.project = Path(project).resolve(strict=True)
        descriptor = _parent(self.project)
        try:
            self.project_identity = _identity(os.fstat(descriptor))[:5]
        finally:
            os.close(descriptor)
        self.initial = initial
        # Code is loaded from the repository; mutable profile inputs are not.
        self.tool_input_root = self.project / "infiniband/bringup/xdr-initial-setup"
        self.root = self.project / "99-output-ztp/configuration-methods"
        self.tickets, self.finished = {}, set()
        self.targets = []

    def _image(self, path):
        path = Path(path).resolve(strict=True)
        path.relative_to(self.project)
        descriptor = _parent(path.parent)
        fd = None
        try:
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
            before = os.fstat(fd)
            if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                    or before.st_uid != os.geteuid() or before.st_mode & 0o022
                    or not 0 < before.st_size <= 8 * 1024 * 1024):
                raise AuthorityError("unsafe managed initial input image")
            chunks, remaining = [], 8 * 1024 * 1024 + 1
            while remaining:
                chunk = os.read(fd, min(remaining, 65536))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if (len(raw) != before.st_size or _identity(os.fstat(fd)) != _identity(before)
                    or _identity(os.stat(path, follow_symlinks=False)) != _identity(before)):
                raise AuthorityError("managed initial input changed during held read")
            return str(path), _identity(before), hashlib.sha256(raw).hexdigest()
        finally:
            if fd is not None:
                os.close(fd)
            os.close(descriptor)

    def _check_project(self):
        descriptor = _parent(self.project)
        try:
            if _identity(os.fstat(descriptor))[:5] != self.project_identity:
                raise AuthorityError("managed initial project root changed")
        finally:
            os.close(descriptor)

    def _inputs(self):
        self._check_project()
        paths = [self.cache, self.cache.with_name(self.cache.name + ".sha256"),
                 self.csv, self.p2p, self.tool / "01-global.yaml"]
        paths.extend(sorted((self.tool / "publickey").glob("*.pub")))
        images = [self._image(path) for path in paths]
        # Fresh parser/profile validation is required too, not merely an old checksum.
        candidate = self.initial.load_target_cache(self.cache, self.csv, self.p2p,
                                                   public_key_tool=self.tool)
        if candidate is None or candidate[1] != self.targets:
            raise AuthorityError("managed initial current cache/input contract differs")
        self._check_project()
        if images != [self._image(path) for path in paths]:
            raise AuthorityError("managed initial input changed during parser validation")
        self._check_project()
        return images

    def start(self, tool, cache, csv_path, p2p, targets, services, keys):
        if self.tickets or not targets or any(target.ib.dev_type != "ib" for target in targets):
            raise AuthorityError("managed initial cycle has incompatible or reused targets")
        names = [target.ib.hostname.casefold() for target in targets]
        if len(names) != len(set(names)):
            raise AuthorityError("managed initial cycle has duplicate device identities")
        self.tool, self.cache, self.csv, self.p2p = map(Path, (tool, cache, csv_path, p2p))
        self.targets = list(targets)
        self.services, self.keys = copy.deepcopy(services), copy.deepcopy(keys)
        try:
            for target in targets:
                operation = "initial-" + uuid.uuid4().hex
                ticket = begin_method(self.root, target.ib.hostname, operation,
                                      operation + ":" + target.ib.hostname, "initial_setup_managed")
                self.tickets[target.ib.hostname.casefold()] = ticket
            if services is None or not keys:
                raise AuthorityError("managed initial method requires a complete services/key profile")
            self.initial.desired_service_commands(services, "")
            self.initial.key_install_command(keys)
            self.images = self._inputs()
            self.expected = {target.ib.hostname.casefold(): self.initial.initial_method_input_digest(target, services, keys)
                             for target in targets}
        except Exception:
            self.close()
            raise

    def complete(self, target, user, private_key, timeout, services, keys):
        name = target.ib.hostname.casefold()
        ticket = self.tickets[name]
        try:
            if (name in self.finished or self._inputs() != self.images
                    or services != self.services or keys != self.keys or private_key is None):
                raise AuthorityError("managed initial expected input changed or is incomplete")
            proof = self.initial.observe_managed_initial_configuration(target, user, private_key, timeout, services, keys)
            fields = {"schema_version", "hostname", "batch_identity_verified", "config_verified", "interface",
                      "transport_ip", "mac_plain", "live_state_sha256", "input_sha256", "observation_sha256", "reason"}
            if (not isinstance(proof, dict) or set(proof) != fields or type(proof["schema_version"]) is not int
                    or proof["schema_version"] != 1 or proof["hostname"] != target.ib.hostname
                    or proof["batch_identity_verified"] is not True or proof["config_verified"] is not True
                    or proof["interface"] != "eth0" or proof["transport_ip"] != target.ib.login_ip
                    or proof["mac_plain"] != self.initial.normalize_mac(target.ib.eth0_mac, field="managed initial eth0 MAC").replace(":", "")
                    or proof["input_sha256"] != self.expected[name] or proof["reason"] != ""
                    or self._inputs() != self.images or services != self.services or keys != self.keys):
                raise AuthorityError("managed initial own-session observation does not match current inputs")
            receipt = {"schema_version": 2, "record_type": "configuration_method", "hostname": target.ib.hostname,
                       "type": "ib", "config_method": "initial-setup", "state": "success", "reason": "",
                       **{field: ticket[field] for field in ("generation", "source_identity", "operation_id", "trigger_id", "trigger_source")},
                       **{field: proof[field] for field in ("batch_identity_verified", "config_verified", "interface", "transport_ip",
                                                         "mac_plain", "live_state_sha256", "input_sha256")},
                       "source_receipt_sha256": proof["observation_sha256"]}
            finish_method(self.root, ticket, receipt)
            if (read_method_receipt(self.root, target.ib.hostname) != receipt
                    or self._inputs() != self.images):
                raise AuthorityError("managed initial publication could not be re-observed")
            self.finished.add(name)
            return True
        except Exception:
            self.fail_unfinished(target)
            return False

    def fail_unfinished(self, target):
        name = target.ib.hostname.casefold()
        if name in self.tickets and name not in self.finished:
            ticket = self.tickets[name]
            current = read_method_current(self.root, target.ib.hostname)
            if current is not None and all(current[field] == ticket[field] for field in (
                    "generation", "source_identity", "hostname", "operation_id", "trigger_id", "trigger_source")):
                # A failed post-publication read may follow our own success.
                # Compare the exact newly observed image under the writer lock;
                # never revoke an unrelated/newer writer's work.
                revoke_method(self.root, target.ib.hostname, expected=current)
            self.finished.add(name)

    def close(self):
        for target in self.targets:
            self.fail_unfinished(target)


def monitor_source_observation_allows_completion(device):
    """Explicit bootstrap source veto, not current generation/application proof."""
    if "configuration_source_observation" not in device:
        return True
    observed = device["configuration_source_observation"]
    fields = {"schema_version", "source", "source_receipt_verified", "hostname",
              "mac_plain", "raw_sha256", "source_fingerprint", "reason"}
    if (not isinstance(observed, dict) or set(observed) != fields
            or type(observed["schema_version"]) is not int or observed["schema_version"] != 1
            or observed["source_receipt_verified"] is not True
            or any(not isinstance(observed[key], str) for key in fields - {
                "schema_version", "source_receipt_verified"})):
        return False
    hostname = device.get("hostname")
    mac = device.get("mac_plain") or device.get("mac")
    return (device.get("config_method") == "ztp"
            and observed["source"] == "monitor_bootstrap_applied" and observed["reason"] == ""
            and isinstance(hostname, str) and HOST.fullmatch(hostname) is not None
            and observed["hostname"].casefold() == hostname.casefold()
            and isinstance(mac, str) and re.fullmatch(
                r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}", mac) is not None
            and observed["mac_plain"] == mac.replace(":", "").lower()
            and DIGEST.fullmatch(observed["raw_sha256"]) is not None
            and DIGEST.fullmatch(observed["source_fingerprint"]) is not None)


def monitor_observation_allows_completion(device):
    """Honor an explicit fresh observation's veto; never mint a receipt.

    Legacy snapshots without this field retain their separate nine-stage
    contract. Every current analyze_switch result supplies the field, even
    on early failure. A structurally positive observation is only a necessary
    condition, not configuration application or generation authority.
    """
    if (not monitor_source_observation_allows_completion(device)
            or not monitor_method_observation_allows_completion(device)):
        return False
    if "configuration_observation" not in device:
        return True
    return monitor_live_observation_verified(device)


def monitor_method_observation_allows_completion(device):
    """Honor an explicit method-era veto without minting or borrowing history."""
    if "configuration_method_authority" not in device:
        return True
    try:
        receipt = decode_method_receipt(wire(device["configuration_method_authority"]))
    except (AuthorityError, TypeError, UnicodeError):
        return False
    if (receipt["state"] != "success" or receipt["config_method"] != "ztp"
            or receipt["trigger_source"] != "ztp_monitor_cycle"
            or device.get("config_method") != receipt["config_method"]
            or device.get("type") != receipt["type"]
            or not monitor_live_observation_verified(device)
            or not monitor_source_observation_allows_completion(device)):
        return False
    fresh = device["configuration_observation"]
    source = device.get("configuration_source_observation")
    return (isinstance(source, dict)
            and all(receipt[field] == fresh[field] for field in (
                "hostname", "interface", "transport_ip", "mac_plain", "live_state_sha256"))
            and receipt["input_sha256"] == source.get("raw_sha256")
            and receipt["source_receipt_sha256"] == source.get("source_fingerprint"))


def monitor_live_observation_verified(device):
    """Require explicit own-session live evidence, independent of apply source."""
    if "configuration_observation" not in device:
        return False
    observed = device["configuration_observation"]
    fields = {"schema_version", "source", "batch_identity_verified", "hostname",
              "interface", "transport_ip", "mac_plain", "live_state_sha256", "reason"}
    if (not isinstance(observed, dict) or set(observed) != fields
            or type(observed["schema_version"]) is not int or observed["schema_version"] != 1
            or observed["batch_identity_verified"] is not True
            or any(not isinstance(observed[key], str) for key in fields - {
                "schema_version", "batch_identity_verified"})):
        return False
    hostname = device.get("hostname")
    if (observed["source"] != "monitor_batchmode" or observed["reason"] != ""
            or not isinstance(hostname, str) or not HOST.fullmatch(hostname)
            or observed["hostname"].casefold() != hostname.casefold()
            or observed["interface"] not in {"eth0", "eth1"}
            or not DIGEST.fullmatch(observed["live_state_sha256"])
            or not re.fullmatch(r"[0-9a-f]{12}", observed["mac_plain"])):
        return False
    address = observed["transport_ip"]
    try:
        ipaddress.ip_address(address)
    except ValueError:
        return False
    candidates = device.get("candidate_identity", {})
    if not isinstance(candidates, dict):
        return False
    if address in candidates:
        selected = candidates[address]
        if not isinstance(selected, (list, tuple)) or len(selected) != 2:
            return False
        interface, mac = selected
    elif address == device.get("ip"):
        interface, mac = "eth0", device.get("mac_plain") or device.get("mac")
    else:
        return False
    if (not isinstance(mac, str) or not re.fullmatch(
            r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}", mac)):
        return False
    return (interface == observed["interface"]
            and mac.replace(":", "").lower() == observed["mac_plain"])


def monitor_current_config_sync_allows_application(device):
    """Read-only projection gate: manual application is never ZTP completion.

    The writer/monitor reconciler supplies this projection only after checking
    the captured local era and its secure current receipt. Finalization still
    checks a closed projection against this observation's own live digest;
    absent legacy evidence, truthy flags and another source cannot qualify.
    """
    current = device.get("configuration_authority")
    fields = {"schema_version", "source", "observation_source", "state", "veto",
              "generation", "source_identity", "live_state_sha256", "reason"}
    if (not isinstance(current, dict) or set(current) != fields
            or type(current["schema_version"]) is not int or current["schema_version"] != 1
            or type(current["generation"]) is not int
            or not 1 <= current["generation"] <= MAX_GENERATION
            or current["veto"] is not False
            or any(not isinstance(current[key], str) for key in fields - {
                "schema_version", "generation", "veto"})
            or current["source"] != "local_config_sync_authority"
            or current["observation_source"] != "monitor_batchmode"
            or current["state"] != "success" or current["reason"] != ""
            or not NAMESPACE.fullmatch(current["source_identity"])
            or any(int(part) > 2 ** 64 - 1 for part in current["source_identity"].split(":"))
            or not DIGEST.fullmatch(current["live_state_sha256"])
            or not monitor_live_observation_verified(device)):
        return False
    return current["live_state_sha256"] == device["configuration_observation"]["live_state_sha256"]


# Closed bootstrap applied-input V1 response, including its header and YAML.
# This is source provenance, never current live state or a generation authority.
APPLIED_CONFIG_MAX_BYTES = 8 * 1024 * 1024
APPLIED_CONFIG_MAGIC = "ZTP_APPLIED_CONFIG_V1"
APPLIED_SOURCE_KINDS = {"dedicated", "default", "fallback", "fallback_default"}
APPLIED_MODES = {"replace", "patch"}
SAFE_RECEIPT_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
SAFE_RECEIPT_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9@%+,:._/-]{0,511}$")
SAFE_SOURCE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,254}$")


def _applied_result_fingerprint(returncode: int, stdout: str) -> str:
    digest = hashlib.sha256()
    digest.update(str(returncode).encode("ascii", errors="strict"))
    digest.update(b"\0")
    digest.update(stdout.encode("utf-8"))
    return digest.hexdigest()


def _validate_applied_at(value: str) -> bool:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return False
    return parsed.tzinfo is not None


def decode_applied_config(returncode, stdout, expected_mac, *, max_bytes=APPLIED_CONFIG_MAX_BYTES):
    """Decode already-collected fixed helper bytes without I/O or generation minting.

    Absence or corruption is returned as untrusted audit evidence.  The live
    normalized ``nv config show`` comparison still proceeds; a receipt never
    replaces or weakens the current-running-config check.
    """
    stdout = stdout or ""
    fingerprint = _applied_result_fingerprint(returncode, stdout)

    def unavailable(reason: str) -> dict:
        return {
            "trusted": False,
            "fingerprint": fingerprint,
            "reason": reason,
            "receipt": {},
            "raw_yaml": "",
        }

    if returncode:
        return unavailable("设备尚无可读取的成功 ZTP 输入凭据")
    encoded = stdout.encode("utf-8")
    if len(encoded) > max_bytes:
        return unavailable(
            f"设备 ZTP 输入凭据超过 {max_bytes} bytes 安全上限"
        )
    separator = "\n---\n"
    header, marker, raw_yaml = stdout.partition(separator)
    lines = header.splitlines()
    if not marker or not lines or lines[0] != APPLIED_CONFIG_MAGIC:
        return unavailable("设备 ZTP 输入凭据协议头或分隔符无效")
    if not raw_yaml:
        return unavailable("设备 ZTP 输入凭据没有原始 YAML")
    receipt = {}
    for line in lines[1:]:
        if not line or "=" not in line:
            return unavailable("设备 ZTP receipt 含无效字段行")
        key, value = line.split("=", 1)
        value_is_safe = bool(SAFE_RECEIPT_VALUE.fullmatch(value)) or (
            key == "failed_raw_sha256" and value == ""
        )
        if (
            not SAFE_RECEIPT_KEY.fullmatch(key)
            or key in receipt
            or not value_is_safe
        ):
            return unavailable("设备 ZTP receipt 字段名、字段值或唯一性无效")
        receipt[key] = value
    required = {
        "schema", "status", "source_kind", "apply_mode", "raw_sha256",
        "source_name", "eth0_mac", "applied_at",
    }
    missing = sorted(required - set(receipt))
    if missing:
        return unavailable("设备 ZTP receipt 缺少字段: " + ", ".join(missing))
    optional = {"failed_raw_sha256", "failed_source_name"}
    unknown = sorted(set(receipt) - required - optional)
    if unknown:
        return unavailable("设备 ZTP receipt 含未知字段: " + ", ".join(unknown))
    if receipt["schema"] != "1" or receipt["status"] != "success":
        return unavailable("设备 ZTP receipt schema/status 不是成功的 V1 凭据")
    if receipt["source_kind"] not in APPLIED_SOURCE_KINDS:
        return unavailable("设备 ZTP receipt source_kind 无效")
    if receipt["apply_mode"] not in APPLIED_MODES:
        return unavailable("设备 ZTP receipt apply_mode 无效")
    if (receipt["source_kind"], receipt["apply_mode"]) not in {
        ("dedicated", "replace"), ("dedicated", "patch"),
        ("default", "patch"), ("fallback", "patch"),
        ("fallback_default", "patch"),
    }:
        return unavailable("设备 ZTP receipt 来源与应用模式不一致")
    if receipt["source_kind"] == "fallback_default":
        if "failed_raw_sha256" not in receipt:
            return unavailable("设备 ZTP receipt 缺少失败专属来源摘要")
    elif set(receipt) & optional:
        return unavailable("设备 ZTP receipt 含非回退模式的失败来源字段")
    if not SAFE_SOURCE_NAME.fullmatch(receipt["source_name"]):
        return unavailable("设备 ZTP receipt source_name 不是安全文件名")
    if not _validate_applied_at(receipt["applied_at"]):
        return unavailable("设备 ZTP receipt applied_at 不是带时区时间")
    raw_digest = hashlib.sha256(raw_yaml.encode("utf-8")).hexdigest()
    if (
        not re.fullmatch(r"[0-9a-f]{64}", receipt["raw_sha256"])
        or raw_digest != receipt["raw_sha256"]
    ):
        return unavailable("设备 ZTP receipt 的 YAML SHA-256 校验失败")
    failed_digest = receipt.get("failed_raw_sha256", "")
    if "failed_raw_sha256" in receipt and not re.fullmatch(
        r"[0-9a-f]{64}", failed_digest,
    ):
        return unavailable("设备 ZTP receipt failed_raw_sha256 无效")
    mac_pattern = r"(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}|[0-9A-Fa-f]{12}"
    if (not isinstance(expected_mac, str) or not re.fullmatch(mac_pattern, expected_mac)
            or not re.fullmatch(mac_pattern, receipt["eth0_mac"])):
        return unavailable("设备 ZTP receipt 或清单 eth0 MAC 格式无效")
    expected_mac = expected_mac.replace(":", "").lower()
    receipt_mac = receipt["eth0_mac"].replace(":", "").lower()
    if receipt_mac != expected_mac:
        return unavailable("设备 ZTP receipt 的 eth0 MAC 与清单身份不一致")
    failed_source_name = receipt.get("failed_source_name")
    if failed_source_name is not None and failed_source_name != (
        expected_mac.replace(":", "") + ".mode"
    ):
        return unavailable("设备 ZTP receipt failed_source_name 与设备身份不一致")

    stable_receipt = {key: receipt[key] for key in sorted(receipt)}
    trusted_fingerprint = hashlib.sha256(
        json.dumps(
            stable_receipt, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8") + b"\0" + raw_digest.encode("ascii")
    ).hexdigest()
    return {
        "trusted": True,
        "fingerprint": trusted_fingerprint,
        "reason": "",
        "receipt": receipt,
        "raw_yaml": raw_yaml,
    }


def wire(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def receipt_digest(value):
    return hashlib.sha256(wire(value)).hexdigest()


def _members(pairs):
    value = dict(pairs)
    if len(value) != len(pairs):
        raise AuthorityError("duplicate authority member")
    return value


def _decode(raw, limit):
    if not raw or len(raw) > limit:
        raise AuthorityError("authority wire size is outside its versioned bound")
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_members)
    except (ValueError, UnicodeError) as exc:
        raise AuthorityError("invalid authority JSON") from exc
    if not isinstance(value, dict):
        raise AuthorityError("authority is not a closed object")
    return value


def decode_receipt(raw):
    """Closed local completion v1; a failed receipt carries no success proof."""
    value = _decode(raw, RECEIPT_MAX_BYTES)
    success = value.get("state") == "triggered"
    fields = RECEIPT_SUCCESS_FIELDS if success else RECEIPT_COMMON_FIELDS | {"reason"}
    if (set(value) != fields or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
            or value["state"] not in {"triggered", "failed"}
            or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= MAX_GENERATION
            or not isinstance(value["type"], str)
            or value["type"] not in {"eth", "eth_spx", "spx", "air", "ib", "nvl"}
            or value["trigger_source"] not in SOURCES):
        raise AuthorityError("closed completion receipt schema mismatch")
    for name, pattern in (("hostname", HOST), ("operation_id", IDENTIFIER),
                          ("trigger_id", TRIGGER_IDENTIFIER), ("source_identity", NAMESPACE)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise AuthorityError("invalid completion receipt identity")
    if any(int(part) > 2 ** 64 - 1 for part in value["source_identity"].split(":")):
        raise AuthorityError("completion receipt namespace exceeds uint64")
    if any(value[name] != "replace-config" for name in (
            "operation", "effective_operation", "requested_operation")):
        raise AuthorityError("completion receipt operation mismatch")

    def instant(name, *, empty=False):
        text = value[name]
        if text == "" and empty:
            return None
        if (not isinstance(text, str)
                or not re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?[+-][0-9]{2}:[0-9]{2}", text)):
            raise AuthorityError("invalid completion receipt timestamp")
        try:
            result = datetime.fromisoformat(text)
            if result.utcoffset() is None:
                raise ValueError("missing timezone")
            return result
        except ValueError as exc:
            raise AuthorityError("invalid completion receipt timestamp") from exc

    started = instant("started_at")
    command = instant("command_started_at", empty=not success)
    finished = instant("finished_at")
    if started > finished or (command is not None and not started <= command <= finished):
        raise AuthorityError("completion receipt execution window is inverted")
    if not success:
        if not isinstance(value["reason"], str) or len(value["reason"]) > 1024:
            raise AuthorityError("completion receipt diagnostic exceeds v1 bound")
        return value
    observed = instant("batch_identity_verified_at")
    if (value["batch_identity_verified"] is not True
            or type(value["command_ztp_complete"]) is not bool
            or not command <= observed <= finished
            or value["action"] != RECEIPT_ACTION
            or not isinstance(value["interface"], str)
            or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value["interface"])
            or not isinstance(value["transport_ip"], str) or len(value["transport_ip"]) > 45
            or not isinstance(value["live_state_sha256"], str)
            or not DIGEST.fullmatch(value["live_state_sha256"])
            or not isinstance(value["command_ztp_log_sha256"], str)
            or (value["command_ztp_log_sha256"] and not DIGEST.fullmatch(value["command_ztp_log_sha256"]))):
        raise AuthorityError("invalid same-session completion proof")
    try:
        ipaddress.ip_address(value["transport_ip"])
    except ValueError as exc:
        raise AuthorityError("invalid completion receipt transport IP") from exc
    return value


def decode_method_receipt(raw):
    """Closed V2 method proof; no clock, manual action or legacy promotion.

    Necessary producer evidence only: consumers must additionally bind their
    own current session and expected state. This codec does not execute a
    method, observe a device, or supply missing nine-stage completion.
    """
    value = _decode(raw, METHOD_RECEIPT_MAX_BYTES)
    success = value.get("state") == "success"
    fields = METHOD_SUCCESS_FIELDS if success else METHOD_COMMON_FIELDS
    if (set(value) != fields
            or type(value["schema_version"]) is not int or value["schema_version"] != 2
            or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= MAX_GENERATION
            or any(not isinstance(value[name], str) for name in fields - {
                "schema_version", "generation", "batch_identity_verified", "config_verified"})
            or value["record_type"] != "configuration_method"
            or value["state"] not in {"success", "failed"}
            or value["trigger_source"] not in METHOD_EXECUTORS):
        raise AuthorityError("closed method receipt V2 schema mismatch")
    method, types = METHOD_EXECUTORS[value["trigger_source"]]
    if value["config_method"] != method or value["type"] not in types:
        raise AuthorityError("method receipt executor/type mismatch")
    for name, pattern in (("hostname", HOST), ("operation_id", IDENTIFIER),
                          ("trigger_id", TRIGGER_IDENTIFIER), ("source_identity", NAMESPACE)):
        if not pattern.fullmatch(value[name]):
            raise AuthorityError("invalid method receipt identity")
    if any(int(part) > 2 ** 64 - 1 for part in value["source_identity"].split(":")):
        raise AuthorityError("method receipt namespace exceeds uint64")
    try:
        value["reason"].encode("utf-8")
    except UnicodeError as exc:
        raise AuthorityError("method diagnostic is not valid Unicode") from exc
    if len(value["reason"]) > 1024 or (success and value["reason"] != ""):
        raise AuthorityError("method diagnostic exceeds V2 contract")
    if success:
        if (value["batch_identity_verified"] is not True or value["config_verified"] is not True
                or value["interface"] not in {"eth0", "eth1"}
                or not re.fullmatch(r"[0-9a-f]{12}", value["mac_plain"])
                or len(value["transport_ip"]) > 45
                or any(not DIGEST.fullmatch(value[name]) for name in (
                    "live_state_sha256", "input_sha256", "source_receipt_sha256"))):
            raise AuthorityError("method receipt lacks strict own-session proof")
        try:
            ipaddress.ip_address(value["transport_ip"])
        except ValueError as exc:
            raise AuthorityError("invalid method transport address") from exc
    return value


def decode_journal(raw, namespace):
    return _decode_journal(raw, namespace, version=1, sources=SOURCES)


def decode_method_journal(raw, namespace):
    value = _decode_journal(raw, namespace, version=2, sources=METHOD_EXECUTORS)
    if any(int(part) > 2 ** 64 - 1 for part in value["source_identity"].split(":")):
        raise AuthorityError("method journal namespace exceeds uint64")
    return value


def _decode_journal(raw, namespace, *, version, sources):
    value = _decode(raw, JOURNAL_MAX_BYTES)
    if (set(value) != JOURNAL_FIELDS
            or type(value["schema_version"]) is not int or value["schema_version"] != version
            or type(value["generation"]) is not int
            or not 1 <= value["generation"] <= MAX_GENERATION
            or type(value["veto"]) is not bool
            or not isinstance(value["state"], str)
            or value["state"] not in {"pending", "success", "failed"}
            or value["veto"] is not (value["state"] != "success")
            or not isinstance(value["trigger_source"], str)
            or value["trigger_source"] not in sources
            or not isinstance(value["source_identity"], str)
            or not NAMESPACE.fullmatch(value["source_identity"])
            or value["source_identity"] != namespace):
        raise AuthorityError("closed authority schema/namespace/veto mismatch")
    for name, pattern in (("hostname", HOST), ("operation_id", IDENTIFIER), ("trigger_id", TRIGGER_IDENTIFIER)):
        if not isinstance(value[name], str) or not pattern.fullmatch(value[name]):
            raise AuthorityError("invalid authority identity")
    digest = value["receipt_sha256"]
    if not isinstance(digest, str) or (digest and not DIGEST.fullmatch(digest)) \
            or (value["state"] == "success" and not digest):
        raise AuthorityError("invalid authority receipt digest")
    return value


def decode_witness(raw, *, generation, namespace, journal_sha256):
    value = _decode(raw, WITNESS_MAX_BYTES)
    if (set(value) != {"schema_version", "generation", "source_identity", "journal_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or type(value["generation"]) is not int
            or value["generation"] != generation
            or value["source_identity"] != namespace
            or value["journal_sha256"] != journal_sha256):
        raise AuthorityError("authority witness mismatch: partial replay/rollback")
    return value


def _parent(path, create=False):
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    path = Path(path).absolute()
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            if component == "..":
                raise AuthorityError("unsafe authority path")
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
                else:
                    # The new child's directory entry must be durable before
                    # a descendant journal can be advertised as durable.
                    os.fsync(descriptor)
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        metadata = os.fstat(descriptor)
        if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
            raise AuthorityError("unsafe authority namespace owner/mode")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid,
            value.st_gid, value.st_nlink, value.st_size, value.st_mtime_ns,
            value.st_ctime_ns)


def _private_regular(value):
    return (stat.S_ISREG(value.st_mode) and value.st_nlink == 1
            and value.st_uid == os.geteuid() and stat.S_IMODE(value.st_mode) == 0o600)


def _storage_key(hostname):
    normalized = hostname.casefold()
    # Reserve room below NAME_MAX=255 for '.witness.json', the UUID staging
    # suffix and separators. '@' cannot begin any legal hostname, so hashed
    # and literal components occupy disjoint namespaces.
    return normalized if len(normalized) <= 200 else "@" + hashlib.sha256(normalized.encode("ascii")).hexdigest()


@contextmanager
def _scope(root, hostname, write=False):
    if not isinstance(hostname, str) or not HOST.fullmatch(hostname):
        raise AuthorityError("unsafe authority hostname")
    root = Path(root)
    root_fd = _parent(root, create=write)
    private_fd = lock_fd = None
    try:
        if write:
            try:
                os.mkdir(".authority", 0o700, dir_fd=root_fd)
                os.fsync(root_fd)
            except FileExistsError:
                pass
        private_fd = os.open(".authority", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_fd)
        private = os.fstat(private_fd)
        if private.st_uid != os.geteuid() or stat.S_IMODE(private.st_mode) != 0o700:
            raise AuthorityError("unsafe private authority directory")
        key = _storage_key(hostname)
        lock_fd = os.open(
            key + ".lock", os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK
            | (os.O_CREAT if write else 0), 0o600, dir_fd=private_fd,
        )
        if not _private_regular(os.fstat(lock_fd)):
            raise AuthorityError("unsafe authority lock")
        try:
            fcntl.flock(lock_fd, (fcntl.LOCK_EX if write else fcntl.LOCK_SH) | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise AuthorityError("authority writer is active") from exc
        held = os.fstat(root_fd)
        held_lock = os.fstat(lock_fd)
        namespace = f"{held.st_dev}:{held.st_ino}"

        def validate_scope():
            visible = _parent(root)
            try:
                current = os.fstat(visible)
                if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
                    raise AuthorityError("authority namespace rebound")
                named = os.stat(".authority", dir_fd=visible, follow_symlinks=False)
                if ((private.st_dev, private.st_ino, private.st_uid, private.st_mode)
                        != (named.st_dev, named.st_ino, named.st_uid, named.st_mode)):
                    raise AuthorityError("authority directory rebound")
                lock = os.stat(key + ".lock", dir_fd=private_fd, follow_symlinks=False)
                if _identity(held_lock) != _identity(lock) or not _private_regular(lock):
                    raise AuthorityError("authority lock rebound")
            finally:
                os.close(visible)

        def advance_writer_witness(raw, validate_transaction):
            nonlocal held_lock
            validate_transaction()
            os.ftruncate(lock_fd, 0)
            os.lseek(lock_fd, 0, os.SEEK_SET)
            remaining = memoryview(raw)
            while remaining:
                written = os.write(lock_fd, remaining)
                if written <= 0:
                    raise AuthorityError("writer witness did not progress")
                remaining = remaining[written:]
            held_lock = os.fstat(lock_fd)
            os.fsync(lock_fd)
            validate_transaction()

        validate_scope()
        yield private_fd, key, namespace, validate_scope, advance_writer_witness
        validate_scope()
    finally:
        if lock_fd is not None:
            os.close(lock_fd)
        if private_fd is not None:
            os.close(private_fd)
        os.close(root_fd)


def _read(descriptor, name, limit, allow_empty=False):
    try:
        file_fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("unsafe authority file") from exc
    try:
        before = os.fstat(file_fd)
        minimum = 0 if allow_empty else 1
        if not _private_regular(before) or not minimum <= before.st_size <= limit:
            raise AuthorityError("unsafe authority file metadata/size")
        chunks, remaining = [], limit + 1
        while remaining:
            chunk = os.read(file_fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        after = os.fstat(file_fd)
        named = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if len(raw) != before.st_size or _identity(before) != _identity(after) \
                or _identity(before) != _identity(named):
            raise AuthorityError("authority file changed during read")
        return raw
    finally:
        os.close(file_fd)


def _current(descriptor, key, namespace, *, decoder=decode_journal):
    try:
        os.stat(key + ".pending", dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        pass
    else:
        raise AuthorityError("interrupted authority transaction: persistent hold")
    raw = _read(descriptor, key + ".journal.json", JOURNAL_MAX_BYTES)
    witness_raw = _read(descriptor, key + ".witness.json", WITNESS_MAX_BYTES)
    writer_raw = _read(descriptor, key + ".lock", WITNESS_MAX_BYTES, allow_empty=True)
    if raw is None and witness_raw is None:
        if writer_raw:
            raise AuthorityError("authority history erased after writer initialization")
        return None
    if raw is None or witness_raw is None:
        raise AuthorityError("incomplete authority pair")
    value = decoder(raw, namespace)
    decode_witness(
        witness_raw, generation=value["generation"], namespace=namespace,
        journal_sha256=hashlib.sha256(raw).hexdigest(),
    )
    decode_witness(
        writer_raw, generation=value["generation"], namespace=namespace,
        journal_sha256=hashlib.sha256(raw).hexdigest(),
    )
    if _storage_key(value["hostname"]) != key:
        raise AuthorityError("authority hostname does not match its local key")
    return value


def read_current(root, hostname):
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, _validate, _advance):
            return _current(descriptor, key, namespace)
    except FileNotFoundError:
        # Missing storage is unknown, never a receipt eligible for promotion.
        return None
    except OSError as exc:
        raise AuthorityError("authority storage could not be authenticated") from exc


def read_current_receipt(root, hostname, path):
    """Authenticate one existing receipt while holding its generation lock.

    Readers never create history, accept a path outside run/host/result.json,
    or infer the current generation from receipt/report wall clocks. A valid
    historical receipt is not current evidence; unsafe or contradictory images
    are explicit errors and are retained untouched.
    """
    root = Path(root).absolute()
    path = Path(path)
    path = path.absolute() if path.is_absolute() else root / path
    try:
        relative = path.relative_to(root)
    except ValueError as exc:
        raise AuthorityError("receipt path is outside authority namespace") from exc
    parts = relative.parts
    if (len(parts) != 3 or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,199}", parts[0])
            or not isinstance(hostname, str) or not HOST.fullmatch(hostname)
            or parts[1].casefold() != hostname.casefold()
            or parts[2] != "result.json"):
        raise AuthorityError("receipt path is not a closed run/hostname/result.json")
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, validate, _advance):
            current = _current(descriptor, key, namespace)
            if current is None or current["state"] != "success" or current["veto"] is not False:
                return None
            parent = _parent(path.parent)
            try:
                held = _identity(os.fstat(parent))
                receipt_image = _snapshot(parent, "result.json")
                raw = _read(parent, "result.json", RECEIPT_MAX_BYTES)
                if raw is None:
                    return None
                receipt = decode_receipt(raw)
                visible = _parent(path.parent)
                try:
                    if held != _identity(os.fstat(visible)):
                        raise AuthorityError("receipt parent rebound during read")
                finally:
                    os.close(visible)
                validate()
                if _current(descriptor, key, namespace) != current:
                    raise AuthorityError("receipt generation changed during read")
                if _snapshot(parent, "result.json") != receipt_image:
                    raise AuthorityError("receipt image changed after read")
                if (receipt["state"] != "triggered"
                        or any(receipt[field] != current[field] for field in (
                            "hostname", "generation", "source_identity", "operation_id",
                            "trigger_id", "trigger_source",
                        ))):
                    return None
                if receipt_digest(receipt) != current["receipt_sha256"]:
                    raise AuthorityError("current receipt digest disagrees with local authority")
                return receipt
            finally:
                os.close(parent)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("receipt storage could not be authenticated") from exc


def _snapshot(descriptor, name):
    try:
        value = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not _private_regular(value):
        raise AuthorityError("unsafe authority destination")
    return _identity(value)


def _stage(descriptor, name, raw, expected, validate):
    temporary = "." + name + "." + uuid.uuid4().hex + ".tmp"
    file_fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                      0o600, dir_fd=descriptor)
    renamed = False
    staged = os.fstat(file_fd)
    held_fd = None
    try:
        with os.fdopen(file_fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            staged = os.fstat(stream.fileno())
            os.fsync(stream.fileno())
            named = os.stat(temporary, dir_fd=descriptor, follow_symlinks=False)
            if (_identity(staged) != _identity(os.fstat(stream.fileno()))
                    or _identity(staged) != _identity(named) or not _private_regular(named)):
                raise AuthorityError("authority temporary changed during staging")
            held_fd = os.dup(stream.fileno())
        validate()
        if _snapshot(descriptor, name) != expected:
            raise AuthorityError("authority destination rebound during staging")
        if (_identity(os.fstat(held_fd)) != _identity(staged)
                or _snapshot(descriptor, temporary) != _identity(staged)):
            raise AuthorityError("authority temporary rebound before publication")
        os.replace(temporary, name, src_dir_fd=descriptor, dst_dir_fd=descriptor)
        renamed = True
        # Rename may legitimately advance ctime, but the held inode is still
        # the only source of publication identity. Never trust a named image
        # installed by another writer after the replacement.
        published = os.fstat(held_fd)
        if (_identity(staged)[:-1] != _identity(published)[:-1]
                or not _private_regular(published)
                or _snapshot(descriptor, name) != _identity(published)):
            raise AuthorityError("authority image changed during publication")
        os.fsync(descriptor)
        validate()
        if (_identity(os.fstat(held_fd)) != _identity(published)
                or _snapshot(descriptor, name) != _identity(published)):
            raise AuthorityError("authority image changed during directory sync")
        return _identity(published)
    finally:
        try:
            if not renamed:
                try:
                    named = os.stat(temporary, dir_fd=descriptor, follow_symlinks=False)
                except FileNotFoundError:
                    pass
                else:
                    # Clean only this unchanged staged image; never unlink a
                    # foreign file or alias occupying our controlled name.
                    if _private_regular(named) and _identity(named) == _identity(staged):
                        os.unlink(temporary, dir_fd=descriptor)
        finally:
            if held_fd is not None:
                os.close(held_fd)


def _publish(descriptor, key, value, validate, advance_writer_witness, *, decoder=decode_journal):
    raw = wire(value)
    decoder(raw, value["source_identity"])
    validate()
    names = (key + ".witness.json", key + ".journal.json")
    expected = {name: _snapshot(descriptor, name) for name in names}
    marker = key + ".pending"
    marker_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600, dir_fd=descriptor)

    def retain_hold():
        try:
            hold_fd = os.open(marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                              0o600, dir_fd=descriptor)
        except FileExistsError:
            # Any pre-existing guard remains HOLD; do not overwrite it.
            return
        try:
            os.write(hold_fd, b"F02 authority durability uncertain\n")
            os.fsync(hold_fd)
        finally:
            os.close(hold_fd)
        os.fsync(descriptor)

    try:
        with os.fdopen(marker_fd, "wb") as stream:
            stream.write(b"F02 authority transaction pending\n")
            stream.flush()
            guard = _identity(os.fstat(stream.fileno()))
            os.fsync(stream.fileno())

        def validate_transaction():
            validate()
            if _snapshot(descriptor, marker) != guard:
                raise AuthorityError("authority transaction guard rebound")

        validate_transaction()
        os.fsync(descriptor)
        validate_transaction()
        witness = {
            "schema_version": 1, "generation": value["generation"],
            "source_identity": value["source_identity"],
            "journal_sha256": hashlib.sha256(raw).hexdigest(),
        }
        # The held single-writer inode witnesses the current image before
        # the replaceable pair is published. Replaying both old members,
        # including a same-generation success after veto, cannot replace this
        # current witness. All three images still share a recovery domain.
        advance_writer_witness(wire(witness), validate_transaction)
        published = {}
        published[names[0]] = _stage(
            descriptor, names[0], wire(witness), expected[names[0]], validate_transaction,
        )
        published[names[1]] = _stage(
            descriptor, names[1], raw, expected[names[1]], validate_transaction,
        )

        def validate_published_pair():
            validate()
            for name, identity in published.items():
                if _snapshot(descriptor, name) != identity:
                    raise AuthorityError("authority pair changed before completion")

        validate_transaction()
        validate_published_pair()
        os.unlink(marker, dir_fd=descriptor)
        os.fsync(descriptor)
        # Earlier members can be rebound while the other member or final
        # directory sync runs. No positive completion may escape that window.
        validate_published_pair()
    except BaseException:
        # Even a removed/rebound marker or late cleanup failure must not
        # expose an earlier success as the current causal authority.
        retain_hold()
        raise


def begin(root, hostname, operation_id, trigger_id, trigger_source):
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        previous = _current(descriptor, key, namespace)
        generation = previous["generation"] + 1 if previous else 1
        value = {
            "schema_version": 1, "hostname": hostname, "generation": generation,
            "operation_id": operation_id, "trigger_id": trigger_id,
            "trigger_source": trigger_source, "source_identity": namespace,
            "state": "pending", "veto": True, "receipt_sha256": "",
        }
        _publish(descriptor, key, value, validate, advance)
        return value


def revoke(root, hostname, *, expected=None):
    """Withdraw the existing configuration era before another mutating action.

    This negative transition cannot mint a new successful observation or borrow
    its old digest. Only begin/finish from a new actual config writer can later
    establish success in a strictly newer generation.
    """
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        current = _current(descriptor, key, namespace)
        if expected is not None:
            # Observers must compare while holding the same writer lock. A
            # read-before-lock check could withdraw another writer's new era.
            decode_journal(wire(expected), namespace)
            if current != expected:
                return None
        if current is None:
            return None
        value = {**current, "state": "failed", "veto": True, "receipt_sha256": ""}
        if value != current:
            _publish(descriptor, key, value, validate, advance)
        return value


def finish(root, ticket, result):
    if not isinstance(ticket, dict):
        raise AuthorityError("completion ticket is not a closed object")
    try:
        result = decode_receipt(wire(result))
    except (TypeError, UnicodeError) as exc:
        raise AuthorityError("completion receipt is not serializable") from exc
    with _scope(root, ticket.get("hostname"), write=True) as (descriptor, key, namespace, validate, advance):
        # Python considers True == 1 (and 1.0 == 1); dictionary equality is
        # not a schema/type check for an incoming completion ticket.
        decode_journal(wire(ticket), namespace)
        current = _current(descriptor, key, namespace)
        if current != ticket or current["state"] != "pending":
            raise AuthorityError("completion is not the current pending generation")
        if (not isinstance(result, dict) or type(result.get("generation")) is not int
                or result.get("generation") != ticket["generation"]
                or any(result.get(field) != ticket[field] for field in (
                    "hostname", "operation_id", "trigger_id", "trigger_source", "source_identity",
                ))):
            raise AuthorityError("completion does not carry its own generation/identity")
        success = (result.get("state") == "triggered"
                   and result.get("batch_identity_verified") is True
                   and isinstance(result.get("live_state_sha256"), str)
                   and DIGEST.fullmatch(result["live_state_sha256"]) is not None)
        value = {**current, "state": "success" if success else "failed",
                 "veto": not success, "receipt_sha256": receipt_digest(result)}
        _publish(descriptor, key, value, validate, advance)
        return value


def read_method_current(root, hostname):
    """Read-only V2 boundary; absent storage remains unknown, not success."""
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, _validate, _advance):
            return _current(descriptor, key, namespace, decoder=decode_method_journal)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("method storage could not be authenticated") from exc


def begin_method(root, hostname, operation_id, trigger_id, trigger_source):
    """Mint a local boundary BEFORE observation/application, never from time."""
    # Reject invalid/foreign sources and identities before _scope can create
    # a directory or lock.  This prototype is never written or returned;
    # the actual namespace/era are captured under the held local writer.
    prototype = {"schema_version": 2, "hostname": hostname, "generation": 1,
                 "operation_id": operation_id, "trigger_id": trigger_id,
                 "trigger_source": trigger_source, "source_identity": "0:0",
                 "state": "pending", "veto": True, "receipt_sha256": ""}
    try:
        decode_method_journal(wire(prototype), "0:0")
    except (TypeError, UnicodeError) as exc:
        raise AuthorityError("method boundary is not serializable") from exc
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        previous = _current(descriptor, key, namespace, decoder=decode_method_journal)
        value = {**prototype, "generation": previous["generation"] + 1 if previous else 1,
                 "source_identity": namespace}
        _publish(descriptor, key, value, validate, advance, decoder=decode_method_journal)
        return value


def revoke_method(root, hostname, *, expected):
    """Compare under the writer lock; an older observer cannot revoke newer work."""
    _validate_method_ticket(expected)
    if not isinstance(hostname, str) or expected["hostname"].casefold() != hostname.casefold():
        raise AuthorityError("method revocation hostname disagrees with ticket")
    with _scope(root, hostname, write=True) as (descriptor, key, namespace, validate, advance):
        decode_method_journal(wire(expected), namespace)
        current = _current(descriptor, key, namespace, decoder=decode_method_journal)
        if current is None or current != expected:
            return None
        value = {**current, "state": "failed", "veto": True, "receipt_sha256": ""}
        if value != current:
            _publish(descriptor, key, value, validate, advance, decoder=decode_method_journal)
        return value


def _validate_method_ticket(ticket):
    """Validate the wire contract before any storage side effect."""
    if not isinstance(ticket, dict):
        raise AuthorityError("method ticket is not a closed object")
    try:
        decode_method_journal(wire(ticket), ticket.get("source_identity"))
    except (TypeError, UnicodeError) as exc:
        raise AuthorityError("method ticket is not serializable") from exc


def finish_method(root, ticket, result):
    """Publish only an own-ticket V2 result, under the existing durable fence.

    A receipt may be visible while its journal is still pending: that window
    cannot authorize success. Publication/cleanup failure retains the hold.
    The root must be dedicated to method V2; V1 readers/writers reject it.
    """
    _validate_method_ticket(ticket)
    try:
        result = decode_method_receipt(wire(result))
    except (TypeError, UnicodeError) as exc:
        raise AuthorityError("method receipt is not serializable") from exc
    with _scope(root, ticket.get("hostname"), write=True) as (descriptor, key, namespace, validate, advance):
        decode_method_journal(wire(ticket), namespace)
        current = _current(descriptor, key, namespace, decoder=decode_method_journal)
        if current != ticket or current["state"] != "pending":
            raise AuthorityError("method completion is not the current pending generation")
        if any(result[field] != ticket[field] for field in (
                "hostname", "generation", "source_identity", "operation_id", "trigger_id", "trigger_source")):
            raise AuthorityError("method completion does not carry its own local ticket")
        name = key + ".method.json"
        expected = _snapshot(descriptor, name)
        # Authenticate a prior image before replacing it; do not repair a
        # foreign/symlink/multi-link object into an apparently trusted receipt.
        _read(descriptor, name, METHOD_RECEIPT_MAX_BYTES)
        image = _stage(descriptor, name, wire(result), expected, validate)

        def validate_receipt():
            validate()
            if _snapshot(descriptor, name) != image:
                raise AuthorityError("method receipt rebound during publication")

        success = result["state"] == "success"
        value = {**current, "state": "success" if success else "failed", "veto": not success,
                 "receipt_sha256": receipt_digest(result)}
        _publish(descriptor, key, value, validate_receipt, advance, decoder=decode_method_journal)
        return value


def read_method_receipt(root, hostname):
    """Read the one fixed private method receipt while holding its local era."""
    try:
        with _scope(root, hostname) as (descriptor, key, namespace, validate, _advance):
            current = _current(descriptor, key, namespace, decoder=decode_method_journal)
            if current is None or current["state"] != "success" or current["veto"] is not False:
                return None
            name = key + ".method.json"
            image = _snapshot(descriptor, name)
            raw = _read(descriptor, name, METHOD_RECEIPT_MAX_BYTES)
            if raw is None:
                raise AuthorityError("current method receipt is missing")
            receipt = decode_method_receipt(raw)
            validate()
            if (_snapshot(descriptor, name) != image
                    or _current(descriptor, key, namespace, decoder=decode_method_journal) != current):
                raise AuthorityError("method receipt or generation changed during read")
            if (receipt["state"] != "success"
                    or any(receipt[field] != current[field] for field in (
                        "hostname", "generation", "source_identity", "operation_id", "trigger_id", "trigger_source"))
                    or receipt_digest(receipt) != current["receipt_sha256"]):
                raise AuthorityError("current method receipt disagrees with local era")
            return receipt
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise AuthorityError("method receipt storage could not be authenticated") from exc


def managed_initial_main(argv=None):
    """Explicit management entry; no implicit active project or device action."""
    import argparse
    import importlib.util
    import sys
    parser = argparse.ArgumentParser(description="Managed initial-setup with causal local method receipts")
    parser.add_argument("--project", type=Path, required=True, help="explicit owned project containing all runtime inputs")
    parser.add_argument("initial_args", nargs=argparse.REMAINDER, help="after --, the original initial-setup arguments (requires --apply)")
    args = parser.parse_args(argv)
    source = Path(__file__).resolve().parent.parent / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
    spec = importlib.util.spec_from_file_location("_http_managed_initial_setup", source)
    if spec is None or spec.loader is None:
        raise AuthorityError("managed initial executor is unavailable")
    initial = importlib.util.module_from_spec(spec)
    previous_module = sys.modules.get(spec.name)
    previous_argv = sys.argv
    sys.modules[spec.name] = initial
    cycle = None
    try:
        spec.loader.exec_module(initial)
        cycle = ManagedInitialMethodCycle(args.project, initial)
        forwarded = args.initial_args[1:] if args.initial_args[:1] == ["--"] else args.initial_args
        sys.argv = [str(source), *forwarded]
        return initial.main(method_cycle=cycle)
    except (AuthorityError, OSError, ValueError, initial.SetupError) as exc:
        # No remote output or credentials enter this local diagnostic.
        print("managed initial-setup rejected: " + type(exc).__name__, file=sys.stderr)
        return 2
    finally:
        try:
            if cycle is not None and hasattr(cycle, "targets"):
                cycle.close()
        finally:
            if getattr(initial, "REPORT_HANDLE", None) is not None:
                initial.REPORT_HANDLE.close()
            sys.argv = previous_argv
            if previous_module is None:
                sys.modules.pop(spec.name, None)
            else:
                sys.modules[spec.name] = previous_module


if __name__ == "__main__":
    raise SystemExit(managed_initial_main())
