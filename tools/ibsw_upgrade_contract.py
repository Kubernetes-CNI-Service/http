"""Pure IBSW planning slice. No SSH, package IO, or firmware authorization.

Package paths here are lexical candidates, NOT proof of safe symlinks,
availability, compatible hardware, approved transitions, or published files.
The commands classifier deliberately HOLDs grammar it cannot prove equivalent.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import PurePosixPath
import base64
import csv
import fnmatch
import io
import ipaddress
import json
import posixpath
import re
import shlex
from typing import Optional

from project_contract import (
    detect_global_schema_version, normalize_redundancy_mac,
    parse_device_csv_layout, safe_load_global_yaml,
    require_device_csv_row_width, validate_service_endpoint,
    validate_optional_ib_upgrade,
    _ibsw_mapping as _mapping, _ibsw_version as _version,
    _ibsw_version_key as _version_key, _ibsw_file as _file,
    _ibsw_root as _root, _ibsw_subdir as _subdir, _ibsw_ib as _ib,
    _ibsw_cpld_targets as _cpld_targets,
    _ibsw_validate_upgrade as _validate_upgrade,
)


@dataclass(frozen=True)
class _ReadonlyQueryRecord:
    argv: tuple[str, ...]
    stdout: bytes
    stderr: bytes
    returncode: Optional[int]
    parser_state: str = field(default="PARSER_DEFERRED", init=False)
    execution_state: str = field(default="NOT_EXECUTED", init=False)


def record_readonly_query(argv, stdout: bytes, stderr: bytes, returncode: Optional[int]):
    """Retain supplied query bytes only; never execute, parse or attest them.

    A zero return code is not a version/identity fact or execution permission.
    None and nonzero statuses remain raw data. This does not establish that a
    transport captured complete output; that belongs to the future fixed reader.
    Unknown grammar, binary data and stderr are preserved without decoding,
    trimming or inferred OS paths. The OS parser remains explicitly deferred.
    """
    if (type(argv) is not tuple or not all(type(token) is str for token in argv)
            or argv not in (("nv", "show", "system", "version"),
                            ("nv", "show", "platform", "firmware"),
                            ("nv", "show", "system", "health"))):
        raise ValueError("one fixed readonly query argv tuple required")
    if type(stdout) is not bytes or type(stderr) is not bytes:
        raise ValueError("original immutable stdout/stderr bytes required")
    if returncode is not None and type(returncode) is not int:
        raise ValueError("original integer returncode or None required")
    return _ReadonlyQueryRecord(argv, stdout, stderr, returncode)


@dataclass(frozen=True)
class _ParsedReadonlyQueryData:
    state: str
    fields: tuple[tuple[str, str], ...]
    reason: Optional[str] = None
    execution_state: str = field(default="NOT_EXECUTED", init=False)
    attestation_state: str = field(default="DATA_ONLY_UNATTESTED", init=False)


def _documented_table_lines(stdout):
    if not stdout or len(stdout) > 4 * 1024 * 1024:
        raise ValueError("empty/over-limit documented table")
    text = stdout.decode("ascii").replace("\r\n", "\n")
    if re.search(r"[^\x20-\x7e\n]", text):
        raise ValueError("binary/control bytes are not documented table text")
    lines = [line.rstrip(" ") for line in text.strip("\n").split("\n")]
    if any(not line for line in lines):
        raise ValueError("unknown empty row inside documented table")
    return lines


def _documented_os_fields(lines):
    if (len(lines) < 2 or lines[0].strip(" ") != "operational"
            or not re.fullmatch(r"-{2,} {2,}-{2,}", lines[1])):
        raise ValueError("unknown/incomplete operational system version table")
    if len(lines) != 6:
        # Observed NVOS 25.02.8008: image is a parent, not a version value.
        # Do not guess from a kernel/base-os string or an unrelated number.
        roots, image, in_image, children = {}, False, False, {}
        for line in lines[2:]:
            if line == "image":
                if image:
                    raise ValueError("duplicate image section")
                image, in_image = True, True
                continue
            if line.startswith("  "):
                row = re.fullmatch(r"  (build-id|build-date) {2,}(\S(?:.*\S)?)", line)
                if not in_image or row is None or row[1] in children:
                    raise ValueError("unknown/duplicate image child or image section missing")
                children[row[1]] = row[2]
            else:
                row = re.fullmatch(r"(onie|kernel|base-os|product-release) {2,}(\S(?:.*\S)?)", line)
                if row is None or row[1] in roots:
                    raise ValueError("unknown/duplicate system version row")
                roots[row[1]], in_image = row[2], False
        if (not image or set(roots) != {"onie", "kernel", "base-os", "product-release"}
                or set(children) != {"build-id", "build-date"}):
            raise ValueError("incomplete hierarchical system version table")
        label = re.fullmatch(r"nvos-([0-9]+\.[0-9]+\.[0-9]+)", children["build-id"])
        if label is None or roots["product-release"] != label[1]:
            raise ValueError("unknown image build-id or conflicting product-release")
        return (("image", children["build-id"]), ("image_version_text", label[1]))
    values = {}
    for line in lines[2:]:
        row = re.fullmatch(r"(kernel|build-date|image|onie) {2,}(\S(?:.*\S)?)", line)
        if row is None or row[1] in values:
            raise ValueError("unknown/duplicate system version row")
        values[row[1]] = row[2]
    if set(values) != {"kernel", "build-date", "image", "onie"}:
        raise ValueError("missing operational system version field")
    image = values["image"]
    label = re.fullmatch(r"nvos-([0-9]+\.[0-9]+\.[0-9]+)", image)
    if label is None:
        raise ValueError("unknown image label/suffix; no version fallback")
    return (("image", image), ("image_version_text", label[1]))


def _documented_firmware_fields(lines, *, targets=("BIOS", "CPLD")):
    """CPLD selects every observed slot, not a hard-coded hardware layout."""
    if len(lines) < 3:
        raise ValueError("incomplete platform firmware table")
    header = re.fullmatch(r"(Name) {2,}(Actual FW) {2,}(Part Number) {2,}(FW Source)", lines[0])
    if header is None or not re.fullmatch(r"-{2,}(?: {2,}-{2,}){3}", lines[1]):
        raise ValueError("unknown firmware columns/separator")
    starts = tuple(header.start(index) for index in range(1, 5))
    if tuple(match.start() for match in re.finditer(r"-+", lines[1])) != starts:
        raise ValueError("firmware header/separator column boundaries disagree")
    if (type(targets) is not tuple or not targets or len(set(targets)) != len(targets)
            or any(item not in {"BIOS", "CPLD", "SSD"} and not re.fullmatch(r"CPLD[1-9][0-9]*", item) for item in targets)
            or ("CPLD" in targets and any(item != "CPLD" and item.startswith("CPLD") for item in targets))):
        raise ValueError("fixed firmware DATA target subset required")
    values, seen = {}, set()
    for line in lines[2:]:
        if len(line) <= starts[-1]:
            raise ValueError("truncated firmware row")
        columns = [line[starts[index]:starts[index + 1]].strip(" ") for index in range(3)]
        columns.append(line[starts[-1]:].strip(" "))
        name, actual, _part_number, source = columns
        if (any(not item for item in columns) or not re.fullmatch(r"[A-Za-z][A-Za-z0-9_-]*", name)
                or " " in actual or " " in source or name in seen):
            raise ValueError("unknown/duplicate firmware row or column layout")
        seen.add(name)
        cpld_slot = re.fullmatch(r"CPLD[1-9][0-9]*", name)
        if name.startswith("CPLD") and cpld_slot is None and any(item.startswith("CPLD") for item in targets):
            raise ValueError("unknown CPLD slot layout")
        if name in targets or ("CPLD" in targets and cpld_slot is not None):
            if actual == "N/A":
                raise ValueError("target Actual FW missing; never use Part Number")
            values[name] = actual
        # Non-target Actual FW, Part Number and FW Source may legitimately be
        # N/A. They are neither a target-version failure nor compatibility data.
    result = []
    for target in targets:
        names = (sorted((name for name in values if name.startswith("CPLD")), key=lambda name: int(name[4:]))
                 if target == "CPLD" else [target])
        if not names or any(name not in values for name in names):
            raise ValueError("required BIOS/CPLD/SSD Actual FW row missing")
        result.extend((name, values[name]) for name in names)
    return tuple(result)


def parse_readonly_query_data(record):
    """Pure bounded NVOS IB 25.02.8008 documented TEXT grammar, DATA only.

    Source: installation-management-commands version/firmware table examples.
    Not a claim about all releases, complete transport capture, live identity,
    freshness or activation. Keep the original raw record and its deferred
    parser state unchanged. Do not infer current versions or dispatch permits.
    """
    if type(record) is not _ReadonlyQueryRecord:
        raise ValueError("original immutable fixed query record required")
    record_readonly_query(record.argv, record.stdout, record.stderr, record.returncode)
    if record.argv == ("nv", "show", "system", "health"):
        return _parse_global_health_data(record.stdout, record.stderr, record.returncode)
    if record.returncode != 0:
        return _ParsedReadonlyQueryData("HOLD", (), "query status is nonzero/unfinished")
    if record.stderr:
        return _ParsedReadonlyQueryData("HOLD", (), "original query stderr is not empty")
    try:
        lines = _documented_table_lines(record.stdout)
        fields = (_documented_os_fields(lines) if record.argv == ("nv", "show", "system", "version")
                  else _documented_firmware_fields(lines))
    except ValueError as error:
        return _ParsedReadonlyQueryData("HOLD", (), str(error))
    return _ParsedReadonlyQueryData("TEXT_DATA_PARSED", fields)


def _parse_global_health_data(stdout, stderr, returncode):
    """Shared documented 6077/7002/8008/1010 global-health TEXT facts only.

    Not a collector, baseline comparator, sampling policy or native health
    permit. Legacy fixed two-query evidence rounds remain unchanged.
    No Data is an empty issues section ONLY with explicit global OK; it is
    never an inference of readiness from elapsed time or an empty observation.
    """
    if (type(stdout) is not bytes or type(stderr) is not bytes
            or (returncode is not None and type(returncode) is not int)):
        raise ValueError("original immutable health bytes and integer/None status required")
    if returncode != 0 or stderr:
        return _ParsedReadonlyQueryData("UNKNOWN", (), "health query unfinished/nonzero/stderr")
    try:
        if not stdout or len(stdout) > 4 * 1024 * 1024:
            raise ValueError("empty/over-limit health table")
        text = stdout.decode("ascii").replace("\r\n", "\n")
        if re.search(r"[^\x20-\x7e\n]", text):
            raise ValueError("binary/control health output")
        lines = [line.strip(" ") for line in text.split("\n") if line.strip(" ")]
        if (len(lines) < 7 or not re.fullmatch(r"operational {2,}applied", lines[0])
                or not re.fullmatch(r"-{2,} {2,}-{2,} {2,}-{2,}", lines[1])
                or lines[4] not in {"Health issues", "Health Issues"} or not re.fullmatch(r"={2,}", lines[5])):
            raise ValueError("unknown/incomplete global health layout")
        values = {}
        for row in lines[2:4]:
            match = re.fullmatch(r"(status|status-led) {2,}(\S(?:.*\S)?)", row)
            if match is None or match[1] in values:
                raise ValueError("missing/duplicate global health field")
            values[match[1]] = match[2]
        if (set(values) != {"status", "status-led"} or values["status"] not in {"OK", "Not OK"}
                or values["status-led"] not in {"green", "amber", "off"}):
            raise ValueError("unsupported global health field value")
        issues = []
        if lines[6:] != ["No Data"]:
            if len(lines) < 9:
                raise ValueError("incomplete original health issues table")
            divider = re.fullmatch(r"(-{2,})( {2,})(-{2,})", lines[7])
            if divider is None:
                raise ValueError("unknown health issues columns")
            width, gap = len(divider[1]), len(divider[2])
            if (lines[6][:width].strip(" ") != "Component" or lines[6][width:width + gap] != " " * gap
                    or lines[6][width + gap:] != "Status information"):
                raise ValueError("health issue header/columns disagree")
            for row in lines[8:]:
                component, information = row[:width].strip(" "), row[width + gap:]
                if (not component or not information or row[width:width + gap] != " " * gap
                        or not re.search(r"[A-Za-z0-9]", component)
                        or information.startswith(" ") or (component, information) in issues):
                    raise ValueError("incomplete/duplicate health issue row")
                issues.append((component, information))
        if (values["status"] == "OK") != (not issues):
            raise ValueError("global health status/issue facts contradict")
        return _ParsedReadonlyQueryData("TEXT_HEALTH_DATA_PARSED", (
            ("global_status", values["status"]), ("status_led", values["status-led"]),
            ("issues_json", json.dumps(issues, ensure_ascii=True, separators=(",", ":")))))
    except ValueError as error:
        return _ParsedReadonlyQueryData("UNKNOWN", (), str(error))


class SharedUpgradeHold(ValueError):
    """Common source/record safety failure; the whole batch must stop."""


def _validate_component_fact(component, hostname, package_index, target_version,
                             raw_records, evidence_paths):
    if (component not in ("os", "bios", "cpld")
            or type(hostname) is not str
            or re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", hostname) is None
            or type(package_index) is not int or package_index < 0
            or (component != "os" and package_index != 0)
            or type(target_version) is not str or not target_version
            or len(target_version) > 1024
            or type(raw_records) is not tuple or type(evidence_paths) is not tuple):
        raise ValueError("fixed component result facts required")
    for path in evidence_paths:
        if (type(path) is not str or not path.startswith(hostname + "/")
                or any(part in ("", ".", "..") for part in path.split("/"))
                or any(char in path for char in ("\\", "\x00", "\n", "\r"))):
            raise ValueError("original node-relative evidence references required")
    if len(set(evidence_paths)) != len(evidence_paths):
        raise ValueError("duplicate evidence reference")


@dataclass(frozen=True)
class ComponentDispatchResult:
    """Fixed backend facts, NOT caller approval, completion or canary release."""
    component: str
    hostname: str
    package_index: int
    stage: str
    target_version: str
    state: str
    expected_effect: str
    raw_records: tuple
    evidence_paths: tuple

    def __post_init__(self):
        _validate_component_fact(self.component, self.hostname, self.package_index,
                                 self.target_version, self.raw_records, self.evidence_paths)
        expected_stage = f"os-{self.package_index:04d}" if self.component == "os" else self.component
        if (self.stage != expected_stage or self.state not in ("NO_WRITE", "DISPATCHED_UNKNOWN")
                or self.expected_effect not in ("NONE", "REBOOT_EXPECTED", "ACTIVATION_EXPECTED", "POWER_CYCLE_EXPECTED")):
            raise ValueError("fixed dispatch state, stage and effect required")


@dataclass(frozen=True)
class ComponentCompletionResult:
    """Observed backend result shape only; persisted JSON never grants writes.

    The fixed live observer must independently validate original evidence,
    identity, actual versions, configuration and health before constructing
    VERIFIED. Constructing this data object alone proves none of those facts.
    """
    component: str
    hostname: str
    package_index: int
    target_version: str
    state: str
    raw_records: tuple
    evidence_paths: tuple
    observed_os_version: Optional[str] = None
    reason: Optional[str] = None

    def __post_init__(self):
        _validate_component_fact(self.component, self.hostname, self.package_index,
                                 self.target_version, self.raw_records, self.evidence_paths)
        if self.state not in ("VERIFIED", "FAIL", "UNKNOWN"):
            raise ValueError("fixed completion fact state required")
        if self.observed_os_version is not None and (type(self.observed_os_version) is not str
                                                     or not self.observed_os_version):
            raise ValueError("actual observed OS text required")
        if self.state == "VERIFIED" and (not self.raw_records or not self.evidence_paths
                                         or not self.observed_os_version):
            raise ValueError("verified shape requires original observation references")
        if self.reason is not None and (type(self.reason) is not str or not self.reason
                                         or len(self.reason) > 512):
            raise ValueError("bounded fixed result reason required")


@dataclass(frozen=True)
class Package:
    file: str
    version: Optional[str]
    path: str
    url: Optional[str] = None


@dataclass(frozen=True)
class UpgradePolicy:
    package_dir: str
    final_os: str
    os: tuple[Package, ...] = ()
    bios: Optional[Package] = None
    cpld_burn: Optional[Package] = None
    cpld_refresh: Optional[Package] = None
    cpld_targets: tuple[tuple[str, str], ...] = ()
    ssd_version: Optional[str] = None
    os_stages: tuple[tuple[int, ...], ...] = ()


def load_global_text(text: str) -> dict:
    document = safe_load_global_yaml(text)
    if not isinstance(document, dict):
        raise ValueError("global must be mapping")
    validate_optional_ib_upgrade(document)
    return document


@dataclass(frozen=True)
class InputPaths:
    project: Optional[str]
    csv_path: str
    global_path: str
    output_path: str


def plan_input_paths(entry, *, cwd, run_id, project=None, csv_path=None, global_path=None):
    """Plan lexical locations only. No active-project lookup or filesystem IO.

    A future filesystem admission layer must pin actual descriptors, resolve
    managed aliases and enforce same-project identities before these paths are
    usable. Caller-supplied run_id is NOT proof of unique/exclusive creation.
    """
    if not isinstance(cwd, str) or not cwd.startswith("/"):
        raise ValueError("explicit absolute caller cwd required")
    if not isinstance(run_id, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", run_id):
        raise ValueError("safe run_id required")
    def absolute(value):
        if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
            raise ValueError("invalid input path")
        return posixpath.normpath(value if value.startswith("/") else posixpath.join(cwd, value))
    entry_dir = PurePosixPath(absolute(entry)).parent
    project_root = PurePosixPath(absolute(project)) if project is not None else None
    root = project_root or entry_dir
    chosen_csv = PurePosixPath(absolute(csv_path)) if csv_path is not None else root / ("02-devices_config.csv" if project_root else "ib.csv")
    chosen_global = PurePosixPath(absolute(global_path)) if global_path is not None else root / "01-global.yaml"
    if project_root:
        for selected in (chosen_csv, chosen_global):
            try:
                selected.relative_to(project_root)
            except ValueError as exc:
                raise ValueError("explicit project input cannot silently use foreign source") from exc
        output = project_root / "99-output-ib_nvl" / "bringup" / "xdr-upgrade-logs" / run_id
    else:
        output = entry_dir / "xdr-upgrade-logs" / run_id
    return InputPaths(str(project_root) if project_root else None, str(chosen_csv), str(chosen_global), str(output))


@dataclass(frozen=True)
class InventoryDevice:
    hostname: str
    address: str
    mac: str


@dataclass(frozen=True)
class InventoryInputIssue:
    """Fixed per-device input refusal; never a target or SSH permission."""
    hostname: str
    csv_row: int
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class InventorySnapshot:
    csv_text: str
    global_text: str
    schema_version: int
    devices: tuple[InventoryDevice, ...]
    blocked_devices: tuple[InventoryInputIssue, ...] = ()


def snapshot_inventory(csv_text: str, global_text: str) -> InventorySnapshot:
    """Freeze supplied text and target identities; never reopen source paths.

    CSV identity fields describe expectations, not authenticated device facts.
    legacy lists with no approved MAC authority are intentionally unsupported.
    """
    if not isinstance(csv_text, str) or not isinstance(global_text, str) or max(len(csv_text), len(global_text)) > 4 * 1024 * 1024:
        raise ValueError("bounded text inputs required")
    document = load_global_text(global_text)
    schema = detect_global_schema_version(document)
    devices, blocked_devices = [], []
    seen_names, seen_addresses, seen_macs = set(), set(), set()
    try:
        reader = csv.reader(io.StringIO(csv_text), strict=True)
        header = next(reader, None)
        if header is None:
            raise ValueError("CSV header required")
        parse_device_csv_layout(header, schema)
        for lineno, row in enumerate(reader, 2):
            if not row or all(not cell.strip() for cell in row):
                continue
            require_device_csv_row_width(row, len(header), schema, lineno=lineno)
            if len(row) < 2:
                raise ValueError("CSV type column required")
            if row[1].strip().casefold() != "ib":
                continue
            if len(row) < 7:
                raise ValueError("IB row must contain all necessary identity columns through eth0_mac")
            hostname = row[0].strip()
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", hostname) or hostname.casefold() == "na":
                raise ValueError("explicit safe expected hostname required")
            # Only these two expected per-device field failures are isolated.
            # Schema, shared sources and ambiguous duplicate identities remain
            # batch refusals. Never invent a MAC or admit a malformed endpoint.
            reasons = []
            address, mac = None, None
            missing = {"", "na", "n/a", "none", "null"}
            raw_address, raw_mac = row[3].strip(), row[6].strip()
            if raw_address.casefold() in missing:
                reasons.append("ETH0_IP_MISSING")
            else:
                try:
                    address = validate_service_endpoint(raw_address, field="IB eth0_ip").host
                except ValueError:
                    reasons.append("ETH0_IP_INVALID")
            if raw_mac.casefold() in missing:
                reasons.append("ETH0_MAC_MISSING")
            else:
                try:
                    mac = normalize_redundancy_mac(raw_mac, label="IB eth0_mac")
                except ValueError:
                    reasons.append("ETH0_MAC_INVALID")
            if (hostname.casefold() in seen_names
                    or (address is not None and address in seen_addresses)
                    or (mac is not None and mac in seen_macs)):
                raise ValueError("duplicate IB target identity/address")
            seen_names.add(hostname.casefold())
            if address is not None:
                seen_addresses.add(address)
            if mac is not None:
                seen_macs.add(mac)
            if reasons:
                blocked_devices.append(InventoryInputIssue(hostname, lineno, tuple(reasons)))
            else:
                devices.append(InventoryDevice(hostname, address, mac))
    except csv.Error as exc:
        raise ValueError("invalid CSV format; no legacy fallback") from exc
    if not devices and not blocked_devices:
        raise ValueError("no IB targets")
    return InventorySnapshot(csv_text, global_text, schema, tuple(devices), tuple(blocked_devices))


def select_inventory_devices(snapshot, pattern=None):
    """Select only validated IB hostnames; retain the complete original inputs.

    CLI patterns are case-insensitive shell-style hostname globs, not paths,
    shell commands or regular expressions. No match is an error, never all.
    """
    if not isinstance(snapshot, InventorySnapshot):
        raise ValueError("validated original IB inventory required")
    if pattern is None:
        return snapshot
    if (type(pattern) is not str or not pattern or len(pattern) > 255
            or re.fullmatch(r"[A-Za-z0-9._*?\[\]!\-]+", pattern) is None):
        raise ValueError("nonempty bounded hostname glob required for --devices")
    devices = tuple(node for node in snapshot.devices
                    if fnmatch.fnmatchcase(node.hostname.casefold(), pattern.casefold()))
    blocked = tuple(node for node in snapshot.blocked_devices
                    if fnmatch.fnmatchcase(node.hostname.casefold(), pattern.casefold()))
    if not devices and not blocked:
        raise ValueError("--devices matched no IB devices")
    return InventorySnapshot(snapshot.csv_text, snapshot.global_text,
                             snapshot.schema_version, devices, blocked)


validate_optional_upgrade = validate_optional_ib_upgrade


def _fixed_layout(module_file):
    """One complete fixed bundle; canonical identity wins over local decoys."""
    from pathlib import Path
    directory = Path(module_file).resolve().parent
    canonical = directory.parent / 'infiniband/bringup/xdr-upgrade'
    if directory.name == 'tools' and (canonical / 'upgrade.py').is_file():
        if (directory / 'upgrade.py').is_file():
            raise ValueError('ambiguous fixed runtime layouts')
        if (canonical / 'ibsw_upgrade_driver.py').is_file():
            raise ValueError('fixed runtime layout/source disagreement')
        scripts = canonical
    else:
        scripts = directory
        if not (scripts / 'upgrade.py').is_file():
            raise ValueError('complete fixed flat runtime entry required')
    modules = ('ibsw_upgrade_driver', 'ibsw_upgrade_contract', 'ibsw_upgrade_inputs',
               'ibsw_upgrade_component', 'ibsw_upgrade_schedule', 'ibsw_upgrade_observer',
               'ibsw_upgrade_executor', 'ibsw_upgrade_access', 'ibsw_upgrade_pipeline',
               '_package_common', 'project_contract', 'ssh_key_preparation',
               'ib_bringup_runtime_guard')
    if (any(not (directory / (name + '.py')).is_file() for name in modules)
            or any(not (scripts / name).is_file() for name in
                   ('upgrade.py', 'upgrade.sh', 'upgrade-component.sh',
                    'upgrade-owned-runner.sh', 'requirements.txt'))):
        raise ValueError('incomplete selected fixed runtime bundle')
    return scripts


def normalize_upgrade(document, *, selected, method, package_dir=None):
    if method not in {"local", "scp", "http"}:
        raise ValueError("supported transports: local, scp, http; no HTTPS")
    selected = tuple(selected)
    if not selected or len(set(selected)) != len(selected) or set(selected) - {"os", "bios", "cpld"}:
        raise ValueError("select explicit unique supported components")
    ib = _ib(document)
    if ib is None or "upgrade" not in ib:
        raise ValueError("explicit IB upgrade policy required; no legacy constants")
    final, default_root, validated = _validate_upgrade(ib)
    root = _root(package_dir) if package_dir is not None else default_root
    if set(selected) - set(validated):
        raise ValueError("selected component requires explicit policy")
    endpoint = http_root = None
    if method == "http":
        common = _mapping(document.get("common"), "common")
        mgmt = _mapping(common.get("mgmt"), "mgmt")
        http = _mapping(mgmt.get("http"), "http")
        if http.get("status") != "enabled":
            raise ValueError("project HTTP is not enabled")
        endpoint = validate_service_endpoint(http.get("address"), http.get("port", 80), field="common.mgmt.http")
        http_root = PurePosixPath(_root(http.get("http_root")))
    def package(file, version, subdir):
        path = PurePosixPath(root) / subdir / file
        url = None
        if endpoint:
            try:
                relative = path.relative_to(http_root)
            except ValueError as exc:
                raise ValueError("package is outside HTTP root; approved mapping unavailable") from exc
            url = endpoint.origin + "/" + relative.as_posix()
        return Package(file, version, path.as_posix(), url)
    os = tuple(package(*entry) for entry in validated.get("os", ())) if "os" in selected else ()
    bios = package(*validated["bios"]) if "bios" in selected else None
    burn = refresh = None
    targets = ()
    if "cpld" in selected:
        burn_file, refresh_file, subdir, targets = validated["cpld"]
        burn = package(burn_file, None, subdir)
        refresh = package(refresh_file, None, subdir)
    return UpgradePolicy(root, final, os, bios, burn, refresh, targets, validated.get("ssd"),
                         validated.get('os_stages',()) if 'os' in selected else ())


def ssd_check_from_firmware(expected_version, row, *, verification_basis):
    """Informational comparison only; never component or device admission."""
    result=dict(state='WARNING',status='UNAVAILABLE',expected_version=expected_version,
        observed_version=None,reason_code='SSD_FIRMWARE_QUERY_FAILED',informational_only=True,
        verification_basis=verification_basis)
    if (type(row) is not dict or row.get('command')!='nv show platform firmware'
            or row.get('returncode')!=0 or row.get('stderr_base64') or row.get('stream_complete') is not True):
        return result
    try:
        payload=base64.b64decode(row['stdout_base64'],validate=True)
        actual=dict(_documented_firmware_fields(_documented_table_lines(payload),targets=('SSD',)))['SSD']
    except (ValueError,KeyError,TypeError):
        result['reason_code']='SSD_VERSION_UNAVAILABLE'
        return result
    if re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]{0,127}',actual) is None:
        result['reason_code']='SSD_VERSION_UNAVAILABLE'
        return result
    result['observed_version']=actual
    if actual==expected_version:
        result.update(state='PASS',status='MATCH',reason_code=None)
    else:
        result.update(status='MISMATCH',reason_code='SSD_VERSION_MISMATCH')
    return result


def ssd_check_from_completion(policy, dispatch, completion):
    """Informational DATA from this step's post-query only, never a gate.

    No fourth component, version ordering, package lookup, retry or write
    permission. In particular, pre-dispatch firmware cannot certify post-OS SSD.
    """
    if (policy.ssd_version is None or dispatch.component != "os"
            or dispatch.target_version != policy.final_os):
        return None
    result = dict(state="NOT_CHECKED", status="NOT_REACHED", expected_version=policy.ssd_version,
                  observed_version=None, reason_code="OS_POSTCHECK_NOT_REACHED", informational_only=True,
                  verification_basis='POST_OS_UPGRADE')
    rows = [row for row in completion.raw_records[len(dispatch.raw_records):]
            if row["command"] == "nv show platform firmware"]
    if not rows:
        return result
    return ssd_check_from_firmware(policy.ssd_version,rows[-1],verification_basis='POST_OS_UPGRADE')


def select_os_path(policy: UpgradePolicy, current: str, *, available=None) -> tuple[Package, ...]:
    """Choose one declared candidate per later stage; pure DATA, no filesystem IO.

    No additional model/transition matrix is inferred or required. This is
    package selection, not transfer, activation or post-activation verification.
    """
    normalized = _version(current)
    stages=policy.os_stages or tuple((index,) for index in range(len(policy.os)))
    if available is not None and (type(available) is not frozenset or any(type(p) is not str for p in available)):
        raise ValueError('explicit available package path set required')
    current_stage=next((number for number,group in enumerate(stages)
                        if any(policy.os[index].version==normalized for index in group)),None)
    if current_stage is None:
        raise ValueError("current OS is absent from the declared approved path")
    path=[]
    for group in stages[current_stage+1:]:
        chosen=next((policy.os[index] for index in group
                     if available is None or policy.os[index].path in available),None)
        if chosen is None:
            raise ValueError('OS stage has no available declared package; never skip a stage')
        path.append(chosen)
    return tuple(path)


@dataclass(frozen=True)
class CommandsDifference:
    state: str
    missing: tuple[str, ...]
    added: tuple[str, ...]
    changed: tuple[tuple[str, str], ...]
    holds: tuple[str, ...]


def _parse_commands(text):
    """Read a complete NVUE export without a device-field whitelist.

    Tokens are comparison DATA, never shell code. Masked/sensitive values may
    be compared as opaque text; their actual value is not thereby verified.
    Replay safety is checked separately, and only for commands actually lost.
    """
    parsed, holds = {}, []
    if not isinstance(text, str) or not text.strip() or len(text) > 4 * 1024 * 1024:
        return parsed, ["empty or invalid export"]
    if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", text):
        return parsed, ["control bytes in export require review"]
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            words = tuple(shlex.split(line, posix=True))
        except ValueError:
            holds.append("unparseable quoting")
            continue
        if words in (("nv", "config", "apply"), ("nv", "config", "apply", "-y"),
                     ("nv", "config", "save")):
            continue  # Export framing is not configuration to replay.
        if words[:2] != ("nv", "set") or len(words) < 4:
            holds.append("non-configuration command in export requires review")
            continue
        group = re.fullmatch(r"(eth|ib|swp)([0-9]+)-([0-9]+)", words[3]) if words[:3] == ("nv", "set", "interface") else None
        if group and 0 <= int(group[2]) <= int(group[3]) <= 4096:
            # Bounded known range syntax, not an arbitrary NVUE expression.
            for number in range(int(group[2]), int(group[3])+1):
                interface = group[1] + str(number)
                expanded = words[:3] + (interface,) + words[4:]
                parsed.setdefault(expanded, ((), shlex.join(expanded)))
        else:
            parsed.setdefault(words, ((), line))
    if not parsed and not holds:
        holds.append("export contains no configuration commands")
    return parsed, holds


def _scalar_command_key(words):
    """Known scalar conflicts require review; unknown paths are not guessed."""
    if words[:4] == ("nv", "set", "system", "hostname") and len(words) == 5:
        return words[:-1]
    if words[:3] == ("nv", "set", "system") and words[3:-1] in (
            ("config", "auto-save", "state"), ("ztp", "config-save"),
            ("date-time", "timezone"), ("ssh-server", "state")):
        return words[:-1]
    if (words[:3] == ("nv", "set", "interface")
            and re.fullmatch(r"(?:eth|ib|swp)[0-9]+", words[3]) and words[4:-1] in (
            ("link", "state"), ("type",), ("description",), ("ipv4", "gateway"), ("ipv4", "address"))):
        return words[:-1]
    return None


def _missing_command_replay_issue(words, line):
    """No password masks, credentials, placeholders or shell-like recovery."""
    if (any(re.search(r"password|secret|credential|private-key", value, re.I) for value in words[2:-1])
            or re.search(r"\*{2,}|<[^>]+>", line)):
        return "sensitive or masked missing configuration requires manual recovery"
    if re.search(r"[$`;&|<>]", line):
        return "shell-like or placeholder missing configuration requires manual recovery"
    if (_scalar_command_key(words) is None
            and not (words[:5] in (("nv","set","system","ntp","server"),
                                   ("nv","set","system","dns","server")) and len(words) == 6)):
        return "unknown missing configuration semantics requires manual recovery"
    return None


def same_backup_snapshot(before: bytes, current: bytes) -> bool:
    """Detect actual write-time drift; not a backup/field-grammar validator."""
    if any(type(value) is not bytes or not value.strip() for value in (before, current)):
        return False
    try:
        def lines(value):
            return frozenset(line.strip() for line in value.decode("utf-8").splitlines()
                             if line.strip() and not line.lstrip().startswith("#"))
        return lines(before) == lines(current)
    except UnicodeError:
        return False


def compare_commands(before: str, after: str) -> CommandsDifference:
    old, old_holds = _parse_commands(before)
    new, new_holds = _parse_commands(after)
    holds = list(old_holds + new_holds)
    missing_keys = [key for key in old if key not in new]
    added_keys = [key for key in new if key not in old]
    missing = tuple(old[key][1] for key in missing_keys)
    added = tuple(new[key][1] for key in added_keys)
    added_scalars = {}
    for key in added_keys:
        scalar = _scalar_command_key(key)
        if scalar is not None:
            added_scalars.setdefault(scalar, []).append(key)
    changed = tuple((old[key][1], new[other][1]) for key in missing_keys
                    for other in added_scalars.get(_scalar_command_key(key), ()))
    for key in missing_keys:
        issue = _missing_command_replay_issue(key, old[key][1])
        if issue and issue not in holds:
            holds.append(issue)
    state = "HOLD" if holds or changed else "REPAIR_REQUIRED" if missing else "PASS"
    # Do not expose a partly understood patch as executable recovery input.
    return CommandsDifference(state, () if state == "HOLD" else missing, added, changed, tuple(holds))


@dataclass(frozen=True)
class CommandsRepairPlan:
    """Plan data only: no collection success, authentication or apply permit."""
    binding: tuple[str, ...]
    difference: CommandsDifference
    patch_text: str
    export_command: str = "nv config show -o commands"


def plan_commands_restore(before: str, after: str, *, device: InventoryDevice,
                          run_id: str, stage: str) -> CommandsRepairPlan:
    """Compare identically scoped commands exports and plan pure missing text.

    Uses the single conservative classifier above, not a second grammar. The
    caller must separately prove collection success/options, per-stage node
    identity, no foreign pending edits and post-patch health. A saved plan is
    not proof that an input scope is still open or that a device is authorized.
    Non-configuration text, unsafe missing values and known scalar conflicts
    HOLD the whole patch; additions remain.
    """
    if not isinstance(device, InventoryDevice):
        raise ValueError("typed expected inventory required")
    for label, value in (("run", run_id), ("stage", stage)):
        if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,95}", value):
            raise ValueError(f"safe {label} plan binding required")
    if not isinstance(device.hostname, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", device.hostname):
        raise ValueError("safe expected inventory hostname required")
    address = validate_service_endpoint(device.address, field="IB inventory IPv4").host
    mac = normalize_redundancy_mac(device.mac, label="IB inventory MAC")
    difference = compare_commands(before, after)
    patch = "\n".join(difference.missing) + "\n" if difference.state == "REPAIR_REQUIRED" else ""
    return CommandsRepairPlan((run_id, device.hostname, address, mac, stage), difference, patch)
