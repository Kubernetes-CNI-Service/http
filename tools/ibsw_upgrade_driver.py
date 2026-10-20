"""IB upgrade inputs and per-run logs, backups, requests and completion records.

The manual CLI uses prepare_manual_run/open_manual_run, with no deployment
eligibility, old-run inventory or filesystem locks. Legacy library APIs are kept
separate for compatibility; no saved plan/status replaces a live device check.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from contextlib import contextmanager
from datetime import datetime, timezone
import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import posixpath
import re
import secrets
import stat
import sys
import threading

from _package_common import _package_project_identity, _source_identity
from ibsw_upgrade_contract import (
    InputPaths, _ReadonlyQueryRecord, load_global_text, normalize_upgrade,
    plan_input_paths, record_readonly_query, snapshot_inventory, select_inventory_devices,
    plan_commands_restore, InventoryDevice,
    parse_readonly_query_data, _version,
    ComponentDispatchResult, ComponentCompletionResult, SharedUpgradeHold, compare_commands,
)
from ibsw_upgrade_inputs import (
    MAXIMUM_INPUT_BYTES, _CandidateDescriptor, _EvidenceIdentity, _HeldFile, _raise_cleanup_issues, open_managed_inputs,
    open_regular_inputs, open_standalone_inputs,
)
from ibsw_upgrade_component import render_declared_step
from ibsw_upgrade_schedule import (declared_step_key, component_order, COMPONENT_REGISTRY,
    component_status_document, validate_component_status_document,
    native_component_status_document, validate_native_component_status_document)
from project_contract import BRINGUP_OUTPUT_SPECS
from ssh_key_preparation import public_key_identity_bytes


_LOCAL_REQUEST_LOCK = threading.RLock()


def _utc_now():
    return datetime.now(timezone.utc)


def _new_manual_run_id():
    """Readable UTC/command prefix plus the original 128-bit unique nonce."""
    return _utc_now().astimezone(timezone.utc).strftime('%Y%m%d_%H%M%SZ')+'_upgrade_'+secrets.token_hex(16)


def _valid_run_name(name):
    if type(name) is not str:
        return False
    if re.fullmatch(r'run-[0-9a-f]{32}',name):
        return True
    match=re.fullmatch(r'([0-9]{8}_[0-9]{6}Z)_upgrade_[0-9a-f]{32}',name)
    if match is None:
        return False
    try:
        datetime.strptime(match[1],'%Y%m%d_%H%M%SZ')
    except ValueError:
        return False
    return True


@dataclass(frozen=True)
class PrepareArguments:
    paths: InputPaths
    selected: tuple[str, ...]
    method: str
    package_dir: str | None
    switch_dir: str
    argv: tuple[str, ...]
    canary_mode: str = "default"
    devices_pattern: str | None = None
    exclusive_config_window: bool = False
    standalone_inputs: bool = False
    force_health: bool = False


def _absolute(value, cwd):
    if not isinstance(value, str) or not value or "\x00" in value or "\\" in value:
        raise ValueError("invalid explicit path")
    return posixpath.normpath(value if value.startswith("/") else posixpath.join(cwd, value))


def parse_prepare_args(entry, cwd, args):
    """Pure subset of the original input/phase/transport argument contract."""
    if not isinstance(args, (tuple, list)) or not all(isinstance(arg, str) for arg in args):
        raise ValueError("explicit string argv required")
    values, selected, controls, only = {}, set(), set(), None
    taking = {"--method", "--project", "--ib-csv", "--global", "--package-dir",
              "--scp-root", "--source-root", "--local-dir", "--http-scheme", "--devices"}
    index = 0
    while index < len(args):
        option = args[index]
        if option in taking:
            index += 1
            if index == len(args):
                raise ValueError(f"{option} requires a value")
            if option == "--devices" and (option in values or not args[index]
                    or len(args[index]) > 255
                    or re.fullmatch(r"[A-Za-z0-9._*?\[\]!\-]+", args[index]) is None):
                raise ValueError("one nonempty bounded hostname glob required for --devices")
            if option in values and values[option] != args[index]:
                raise ValueError(f"conflicting repeated {option}")
            values[option] = args[index]
        elif option in ("--os", "--bios", "--cpld"):
            selected.add(option[2:])
        elif option in ("--os-only", "--bios-only", "--cpld-only"):
            current = option[2:-5]
            if only is not None and only != current:
                raise ValueError("conflicting component-only selectors")
            only = current
        elif option in ("--all", "-A", "--os-first"):
            selected.update(("os", "bios", "cpld"))
        elif option in ("--scripts-only", "--skip-canary", "--yes", "-y", "--exclusive-config-window", "--standalone-inputs", "--force"):
            controls.add(option)
        else:
            raise ValueError(f"prepare-only option unsupported; execution remains OPEN: {option}")
        index += 1
    if only is not None:
        if selected and selected != {only}:
            raise ValueError("component-only selector cannot include another component")
        selected = {only}
    method = values.get("--method")
    scheme = values.get("--http-scheme")
    if scheme is not None:
        if scheme != "http" or method not in (None, "http"):
            raise ValueError("conflicting HTTP selector or unsupported HTTPS")
        method = scheme
    method = method or "scp"
    if method not in ("scp", "local", "http"):
        raise ValueError("supported transports: scp, local, http; no HTTPS")
    paths = plan_input_paths(entry, cwd=cwd, run_id="pending", project=values.get("--project"),
                             csv_path=values.get("--ib-csv"), global_path=values.get("--global"))
    roots = {_absolute(values[key], cwd) for key in ("--package-dir", "--scp-root", "--source-root") if key in values}
    if len(roots) > 1:
        raise ValueError("conflicting package directory overrides")
    return PrepareArguments(paths, component_order(tuple(selected or COMPONENT_REGISTRY)),
                            method, next(iter(roots)) if roots else None,
                            values.get("--local-dir", "/home/admin"), tuple(args),
                            "skip" if "--skip-canary" in controls else "default", values.get("--devices"),
                            "--exclusive-config-window" in controls, "--standalone-inputs" in controls,
                            "--force" in controls)


def _selected_opener(parsed):
    if parsed.standalone_inputs:
        return open_standalone_inputs
    return open_managed_inputs if stat.S_ISLNK(os.lstat(parsed.paths.global_path).st_mode) else open_regular_inputs


def _selected_inventory(session, parsed):
    """Filter a freshly verified full original snapshot, never its raw inputs."""
    return select_inventory_devices(session.inventory(), parsed.devices_pattern)


def preflight_inventory_selection(entry, cwd, args):
    """Close original sources before returning names; no output or authority.

    CLI may call this before prompting. The real prepare/native path must open
    and verify its own fresh originals rather than reuse this tuple as a grant.
    """
    parsed = parse_prepare_args(entry, cwd, args)
    try:
        managed = stat.S_ISLNK(os.lstat(parsed.paths.global_path).st_mode)
    except OSError as error:
        raise ValueError("selected global is missing; no active-project fallback") from error
    with _selected_opener(parsed)(parsed.paths) as session:
        snapshot = _selected_inventory(session, parsed)
        normalize_upgrade(load_global_text(snapshot.global_text), selected=parsed.selected,
                          method=parsed.method, package_dir=parsed.package_dir)
        session.verify()
    return snapshot


def preflight_device_selection(entry, cwd, args):
    """Compatibility names-only DATA API; blocked rows never become nodes."""
    return tuple(node.hostname for node in preflight_inventory_selection(entry, cwd, args).devices)


class PreparationHold(ValueError):
    def __init__(self, detail, run_directory=None):
        self.run_directory = str(run_directory) if run_directory is not None else None
        suffix = f"; created namespace residue retained at {self.run_directory}" if self.run_directory else ""
        super().__init__("HOLD: prepare-only artifact transaction incomplete: " + detail + suffix)


class _CreatedFileDescriptor:
    """Register a create slot immediately; never close an unbound/foreign slot."""
    def __init__(self, fd):
        self.fd = fd
        self.owner = None

    def bind_named_preimage(self, metadata):
        self.owner = _CandidateDescriptor(self.fd, metadata)

    def conditional_close(self):
        if self.owner is None:
            return ValueError("unknown exclusive-create descriptor residue remains HOLD")
        return self.owner.conditional_close()


def _artifact_output_location(session, paths):
    """Use the same live input binding for new and reopened private artifacts."""
    logical = Path(paths.output_path).parent
    if paths.project is not None:
        anchor_path = Path(paths.project)
        relative = logical.relative_to(anchor_path)
    else:
        anchor_path, relative = logical.parent, Path(logical.name)
        original_parent = session._directory(anchor_path)
        try:
            named = os.stat(logical.name, dir_fd=original_parent.fd, follow_symlinks=False)
        except FileNotFoundError:
            named = None
        if named is not None and stat.S_ISLNK(named.st_mode):
            bound = any(alias.name == logical.name and alias.directory.path == logical.parent
                        for alias in session._aliases)
            if session._managed_project is None or not bound:
                raise ValueError("output alias has no live same-project input binding")
            session.verify()
            anchor_path = session._managed_project
            name = "infiniband/bringup/xdr-upgrade/xdr-upgrade-logs"
            relative = Path(dict(BRINGUP_OUTPUT_SPECS)[name])
    return anchor_path, relative


_REQUEST_LOCK_NAME = ".request-inventory.lock"
_REQUEST_LOCK_MARKER = b"IBSW_REQUEST_NAMESPACE_V1\n"


class _RequestNamespaceLease:
    """Cooperative local original-FD lock; not hostile-UID/native permission."""
    def __init__(self, parent_fd, parent_identity):
        self.parent_fd, self.fd, self.owner = parent_fd, None, None
        self.locked, self.closed = False, False
        self.parent_identity = parent_identity
        if _package_project_identity(os.fstat(parent_fd)) != parent_identity:
            raise ValueError("original bound output namespace descriptor changed")
        _OutputScope._safe_directory(os.fstat(parent_fd))
        flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0)
        try:
            try:
                named = os.stat(_REQUEST_LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
            except FileNotFoundError:
                named = None
            created = named is None
            self.fd = os.open(_REQUEST_LOCK_NAME, flags | (os.O_CREAT | os.O_EXCL if created else 0),
                              0o600, dir_fd=parent_fd)
            if created:
                self.owner = _CreatedFileDescriptor(self.fd)
                named = os.stat(_REQUEST_LOCK_NAME, dir_fd=parent_fd, follow_symlinks=False)
                self.owner.bind_named_preimage(named)
            else:
                self.owner = _CandidateDescriptor(self.fd, named)
            self.object_key = (named.st_dev, named.st_ino, stat.S_IFMT(named.st_mode))
            opened = os.fstat(self.fd)
            if (_source_identity(named) != _source_identity(opened) or not stat.S_ISREG(opened.st_mode)
                    or opened.st_uid != os.geteuid() or opened.st_nlink != 1
                    or stat.S_IMODE(opened.st_mode) != 0o600):
                raise ValueError("original owned namespace lock required")
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise PreparationHold("cooperative request namespace lock busy") from error
            self.locked = True
            if created:
                offset = 0
                while offset < len(_REQUEST_LOCK_MARKER):
                    count = os.write(self.fd, _REQUEST_LOCK_MARKER[offset:])
                    if count <= 0:
                        raise ValueError("namespace lock initialization made no progress")
                    offset += count
                os.fsync(self.fd)
                os.fsync(parent_fd)
            self.identity = _source_identity(os.fstat(self.fd))
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    def verify(self):
        if self.closed or not self.locked:
            raise ValueError("request namespace lease is not live")
        if _package_project_identity(os.fstat(self.parent_fd)) != self.parent_identity:
            raise ValueError("original output namespace FD changed")
        for metadata in (os.fstat(self.fd), os.stat(_REQUEST_LOCK_NAME, dir_fd=self.parent_fd, follow_symlinks=False)):
            if _source_identity(metadata) != self.identity:
                raise ValueError("original namespace lock FD/name changed")
        if os.pread(self.fd, len(_REQUEST_LOCK_MARKER) + 1, 0) != _REQUEST_LOCK_MARKER:
            raise ValueError("unknown namespace lock marker; preserve original")
        if (_source_identity(os.fstat(self.fd)) != self.identity
                or _source_identity(os.stat(_REQUEST_LOCK_NAME, dir_fd=self.parent_fd, follow_symlinks=False)) != self.identity):
            raise ValueError("namespace lock changed during source verification")

    def close(self):
        if self.closed:
            return
        issues = []
        if self.locked and hasattr(self, "identity"):
            try:
                self.verify()
            except BaseException as error:
                issues.append(error)
        self.closed = True
        if self.fd is not None and self.locked:
            try:
                metadata = os.fstat(self.fd)
                if (metadata.st_dev, metadata.st_ino, stat.S_IFMT(metadata.st_mode)) != self.object_key:
                    raise ValueError("unknown reused lock descriptor; do not unlock foreign")
                fcntl.flock(self.fd, fcntl.LOCK_UN)
            except BaseException as error:
                issues.append(error)
        if self.owner is not None:
            try:
                issue = self.owner.conditional_close()
                if issue is not None:
                    issues.append(issue)
            except BaseException as error:
                issues.append(error)
        for error in issues:
            if not isinstance(error, Exception):
                raise error
        _raise_cleanup_issues(issues)


class _OutputScope:
    def __init__(self, session, paths, run_id, *, manual_execution=False):
        self.session = session
        self.edges, self.owners, self.files = [], [], []
        self.cleanup_issues = []
        self.closed = False
        self.namespace_lease = None
        self.run_directory = None
        try:
            anchor_path, relative = _artifact_output_location(session, paths)
            self.anchor = session._directory(anchor_path)
            self.root_path = anchor_path
            self.verify()
            parent = self.anchor.fd
            for name in relative.parts:
                parent = self._directory_child(parent, name)
                self.root_path /= name
            parent_identity = self.edges[-1][3] if self.edges else self.anchor.edges[-1][3]
            if not manual_execution:
                self.namespace_lease = _RequestNamespaceLease(parent, parent_identity)
            parent = self._directory_child(parent, run_id, exclusive=True)
            self.run_directory = self.root_path / run_id
            self.fd = parent
            self.verify()
            if stat.S_IMODE(os.fstat(self.fd).st_mode) != 0o700:
                raise ValueError("private run directory mode must be 0700")
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            if isinstance(original, Exception):
                residue = "; unknown descriptor residue remains HOLD" if self.cleanup_issues else ""
                raise PreparationHold(str(original) + residue, self.run_directory) from original
            raise

    @staticmethod
    def _safe_directory(metadata):
        if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o022):
            raise ValueError("artifact parent must be an owned, non-group/other-writable real directory")

    def _directory_child(self, parent, name, exclusive=False):
        if not name or name in (".", "..") or "/" in name:
            raise ValueError("fixed output directory component required")
        self.verify()
        if exclusive:
            os.mkdir(name, 0o700, dir_fd=parent)
            self.run_directory = self.root_path / name
        else:
            try:
                os.stat(name, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                os.mkdir(name, 0o700, dir_fd=parent)
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        self._safe_directory(named)
        fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), dir_fd=parent)
        self.owners.append(_CandidateDescriptor(fd, named))
        key = _package_project_identity(named)
        if _package_project_identity(os.fstat(fd)) != key:
            raise ValueError("artifact directory changed before initial FD verification")
        self.edges.append((parent, name, fd, key))
        self.verify()
        return fd

    def _file_object(self, name, fd, original):
        opened = os.fstat(fd)
        named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        key = lambda item: (item.st_dev, item.st_ino, item.st_mode, item.st_nlink, item.st_uid)
        if (key(opened) != key(original) or key(named) != key(original)
                or not stat.S_ISREG(opened.st_mode) or opened.st_nlink != 1
                or opened.st_uid != os.geteuid() or stat.S_IMODE(opened.st_mode) != 0o600):
            raise ValueError("artifact original file FD/name ownership changed")

    def verify(self):
        if self.closed:
            raise ValueError("artifact output scope is closed")
        self.session.verify()
        self.anchor.verify()
        self._safe_directory(os.fstat(self.anchor.fd))
        for parent, name, fd, key in self.edges:
            opened = os.fstat(fd)
            named = os.stat(name, dir_fd=parent, follow_symlinks=False)
            self._safe_directory(opened)
            if _package_project_identity(opened) != key or _package_project_identity(named) != key:
                raise ValueError("artifact directory original FD/name changed")
        for name, fd, original, identity, payload in self.files:
            self._file_object(name, fd, original)
            if (_source_identity(os.fstat(fd)) != identity
                    or _source_identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != identity
                    or os.pread(fd, len(payload) + 1, 0) != payload):
                raise ValueError("artifact original bytes/identity changed")
        # Output byte checks must not conceal a changed original input.
        self.session.verify()
        # Nor may the last input read conceal drift of a previously checked
        # artifact. The original output FDs/names stay open until the end.
        for name, fd, _original, identity, _payload in self.files:
            if (_source_identity(os.fstat(fd)) != identity
                    or _source_identity(os.stat(name, dir_fd=self.fd, follow_symlinks=False)) != identity):
                raise ValueError("artifact changed during final input verification")
        lease = getattr(self, "namespace_lease", None)
        if lease is not None:
            lease.verify()

    def write(self, name, payload):
        self.verify()
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0), 0o600, dir_fd=self.fd)
        owner = _CreatedFileDescriptor(fd)
        self.owners.append(owner)
        named = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
        owner.bind_named_preimage(named)
        self._file_object(name, fd, named)
        offset = 0
        while offset < len(payload):
            self._file_object(name, fd, named)
            count = os.write(fd, payload[offset:])
            if count <= 0:
                raise ValueError("artifact write made no progress")
            offset += count
            self.verify()
        os.fsync(fd)
        self._file_object(name, fd, named)
        identity = _source_identity(os.fstat(fd))
        self.files.append((name, fd, named, identity, payload))
        self.verify()

    def close(self):
        if self.closed:
            return
        self.closed = True
        lease = getattr(self, "namespace_lease", None)
        if lease is not None:
            try:
                lease.close()
            except BaseException as error:
                self.cleanup_issues.append(error)
        for owner in reversed(self.owners):
            try:
                issue = owner.conditional_close()
                if issue is not None:
                    self.cleanup_issues.append(issue)
            except BaseException as error:
                self.cleanup_issues.append(error)
        for error in self.cleanup_issues:
            if not isinstance(error, Exception):
                raise error
        _raise_cleanup_issues(self.cleanup_issues)


def _json_bytes(document):
    return (json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + "\n").encode("utf-8")


_QUERY_DATA_SPECS = (
    ("system-version", ("nv", "show", "system", "version")),
    ("platform-firmware", ("nv", "show", "platform", "firmware")),
)
_HEALTH_QUERY_DATA_SPECS = _QUERY_DATA_SPECS + (
    ("system-health", ("nv", "show", "system", "health")),
)


def _query_round_specs(schema_version):
    if type(schema_version) is not int or schema_version not in (1, 2):
        raise ValueError("only fixed legacy/health query DATA schemas")
    return _QUERY_DATA_SPECS if schema_version == 1 else _HEALTH_QUERY_DATA_SPECS


_QUERY_DATA_STATES = {"parser_state": "PARSER_DEFERRED", "execution_state": "NOT_EXECUTED",
                      "attestation_state": "DATA_ONLY_UNATTESTED", "observation_state": "UNKNOWN"}


def _query_data_result(record):
    # Validation reuses the existing data-only leaf, never a second version parser.
    original = record_readonly_query(record.argv, record.stdout, record.stderr, record.returncode)
    return {"schema_version": 1, "argv": list(original.argv), "returncode": original.returncode,
        "stdout_bytes": len(original.stdout), "stdout_sha256": hashlib.sha256(original.stdout).hexdigest(),
        "stderr_bytes": len(original.stderr), "stderr_sha256": hashlib.sha256(original.stderr).hexdigest(),
        **_QUERY_DATA_STATES}


def _query_data_binding(run_id, query_id, node, plan_sha256, input_sha256, result_hashes, *, schema_version=1):
    _query_round_specs(schema_version)
    return {"schema_version": schema_version, "state": "DATA_FILES_COMMITTED", "query_id": query_id,
        "run_id": run_id, "node": asdict(node), "plan_sha256": plan_sha256,
        "input_sha256": input_sha256, "results_sha256": result_hashes, **_QUERY_DATA_STATES}


def _before_commands_binding(step_binding, stdout):
    """Raw DATA hash graph only, never proof of a native backup/permission."""
    return {"schema_version": 1, "state": "BEFORE_COMMANDS_DATA_COMMITTED",
        "execution_state": "NOT_EXECUTED", "attestation_state": "DATA_ONLY_UNATTESTED",
        "command": ["nv", "config", "show", "-o", "commands"], "returncode": 0,
        "stdout_bytes": len(stdout), "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": 0, "stderr_sha256": hashlib.sha256(b"").hexdigest(), "binding": step_binding}


_COMMANDS_PHASES = ("before", "after", "repaired")
_PENDING_DIFF_RAW = ("pending-diff.stdout.bin", "pending-diff.stderr.bin")
_PENDING_DIFF_FILES = set(_PENDING_DIFF_RAW) | {"pending-diff-binding.json"}
_STAGE_HEALTH_PHASES = ("before", "after")
_STAGE_HEALTH_RAW = tuple(phase + "-health." + stream + ".bin"
    for phase in _STAGE_HEALTH_PHASES for stream in ("stdout", "stderr"))
_EMPTY_STAGE_DATA_RAW = _PENDING_DIFF_RAW + _STAGE_HEALTH_RAW
_OWNED_RUNNER_FILES = {"runner.sh", "runner-binding.json"}
_OWNED_EXIT_FILES = {"owned-exit.record", "owned-exit-binding.json"}
_NVUED_CHECK_FILES = {f'nvued-check-{number:02d}.json' for number in range(1,6)}
_DOWNLOAD_FILES = {f'download-attempt-{number:02d}.json' for number in range(1,5)}


def _download_document(binding,dispatch_payload,lines):
    from ibsw_upgrade_component import parse_download_results
    rows=parse_download_results(lines)
    if not rows or binding['component']!='os':
        raise ValueError('only original OS curl measurements are recorded')
    return dict(schema_version=1,state='DOWNLOAD_MEASUREMENT_DATA_ONLY',binding=binding,
        dispatch_sha256=hashlib.sha256(dispatch_payload).hexdigest(),
        raw_lines_base64=base64.b64encode(lines).decode('ascii'),measurement=rows[-1])


_MAX_COMPONENT_RAW_RECORDS = 512


def _component_raw_records(records, *, allow_empty=False):
    if not isinstance(records, (tuple, list)) or (not records and not allow_empty) or len(records) > _MAX_COMPONENT_RAW_RECORDS:
        raise ValueError("bounded original component raw records required")
    for row in records:
        if (type(row) is not dict or set(row) != {"command", "stdout_base64", "stderr_base64", "returncode", "stream_complete"}
                or type(row["command"]) is not str or not row["command"] or "\x00" in row["command"]
                or type(row["stream_complete"]) is not bool
                or (row["returncode"] is not None and type(row["returncode"]) is not int)):
            raise ValueError("unknown component raw record shape")
        for key in ("stdout_base64", "stderr_base64"):
            if type(row[key]) is not str or len(base64.b64decode(row[key], validate=True)) > MAXIMUM_INPUT_BYTES:
                raise ValueError("bounded original component raw bytes required")
    return list(records)


def _nvued_check_records(records):
    rows=_component_raw_records(records)
    commands=[row['command'] for row in rows]
    expected=['cat /proc/sys/kernel/random/boot_id',
              'systemctl show nvued.service --property=ActiveState --property=SubState --no-pager']
    if commands not in (expected,expected+['nv show system version']):
        raise ValueError('only fixed original boot/service/CLI readiness records are admitted')
    return rows


def _component_repair_missing_bytes(before, after, missing):
    """Validate exact missing-only NVUE text; never arbitrary replay commands."""
    if any(type(raw) is not bytes or not raw or len(raw) > MAXIMUM_INPUT_BYTES
           for raw in (before, after, missing)):
        raise ValueError("bounded original before/after/missing bytes required")
    difference = compare_commands(before.decode("utf-8"), after.decode("utf-8"))
    if (difference.state != "REPAIR_REQUIRED"
            or missing != ("\n".join(difference.missing) + "\n").encode("utf-8")):
        raise ValueError("only exact independently classified missing configuration can be repaired")
    return missing


def _component_repair_records_complete(rows):
    # SFTP write/readback is an operation observation, not a shell exit code.
    # Its original source/handle comparison belongs to the fixed uploader.
    return all(row["stream_complete"] is True and not row["stderr_base64"]
        and (row["returncode"] is None if row["command"].startswith("SFTP_WRITE_READBACK ")
             else row["returncode"] == 0) for row in rows)


def _validate_package_source_data_graph(files, binding, read):
    """Strict persisted DATA only; never reconstruct a live package owner."""
    if 'package-source.json' not in files:
        return
    names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
    if not set(names).issubset(files):
        raise ValueError('source DATA requires complete original request/runner')
    raw = read('package-source.json')
    document = json.loads(raw)
    if (type(document) is not dict or set(document) != {
            'schema_version', 'state', 'execution_state', 'activation_state',
            'binding', 'declared_method', 'originals_sha256', 'packages'}
            or type(document['schema_version']) is not int or document['schema_version'] != 1
            or document['state'] != 'PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY'
            or document['execution_state'] != 'NOT_EXECUTED'
            or document['activation_state'] != 'UNKNOWN'
            or document['binding'] != binding or document['declared_method'] != 'local'
            or re.findall(rb'(?m)^IBSW_METHOD=([a-z]+)$', read('step.sh')) != [b'local']
            or raw != _json_bytes(document)
            or document['originals_sha256'] != {name: hashlib.sha256(read(name)).hexdigest() for name in names}):
        raise ValueError('original source DATA/hash graph changed')
    request = json.loads(read('request.json'))
    token = request.get('request_id') if type(request) is dict else None
    if (type(token) is not str or not re.fullmatch(r'[0-9a-f]{32}', token)
            or read('request.json') != _json_bytes(dict(schema_version=1, state='REQUESTED',
                activation_state='UNKNOWN', execution_state='NOT_EXECUTED', binding=binding, request_id=token))):
        raise ValueError('source DATA requires actual original request bytes')
    packages = document['packages']
    if type(packages) is not dict or len(packages) != (2 if binding['component'] == 'cpld' else 1):
        raise ValueError('exact component package DATA set required')
    for path, row in packages.items():
        if (type(path) is not str or not posixpath.isabs(path) or posixpath.normpath(path) != path
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or type(row) is not dict or set(row) != {'size', 'sha256'}
                or type(row['size']) is not int or row['size'] <= 0
                or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
            raise ValueError('strict package source DATA fields required')


def _validate_scp_request_content_graph(files, binding, read):
    """Strict schema2 SCP request DATA only; never reconstruct a live owner."""
    if 'scp-source-request.json' not in files:
        return
    names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
    if not set(names).issubset(files):
        raise ValueError('SCP request content DATA requires complete original request/runner')
    raw = read('scp-source-request.json')
    document = json.loads(raw)
    if (type(document) is not dict or set(document) != {
            'schema_version', 'state', 'execution_state', 'activation_state',
            'binding', 'declared_method', 'request_id', 'originals_sha256', 'packages'}
            or type(document['schema_version']) is not int or document['schema_version'] != 2
            or document['state'] != 'SCP_REQUEST_CONTENT_DATA_ONLY'
            or document['execution_state'] != 'NOT_EXECUTED'
            or document['activation_state'] != 'UNKNOWN'
            or type(binding) is not dict or binding.get('component') not in ('os', 'bios', 'cpld')
            or document['binding'] != binding or document['declared_method'] != 'scp'
            or re.findall(rb'(?m)^IBSW_METHOD=([a-z]+)$', read('step.sh')) != [b'scp']
            or raw != _json_bytes(document)
            or document['originals_sha256'] != {name: hashlib.sha256(read(name)).hexdigest() for name in names}):
        raise ValueError('original SCP request content/hash graph changed')
    request = json.loads(read('request.json'))
    token = request.get('request_id') if type(request) is dict else None
    if (type(token) is not str or not re.fullmatch(r'[0-9a-f]{32}', token)
            or document['request_id'] != token
            or read('request.json') != _json_bytes(dict(schema_version=1, state='REQUESTED',
                activation_state='UNKNOWN', execution_state='NOT_EXECUTED', binding=binding, request_id=token))):
        raise ValueError('SCP request content DATA requires actual original request bytes')
    packages = document['packages']
    if type(packages) is not dict or len(packages) != (2 if binding['component'] == 'cpld' else 1):
        raise ValueError('exact SCP component package DATA set required')
    for path, row in packages.items():
        if (type(path) is not str or not posixpath.isabs(path) or posixpath.normpath(path) != path
                or any(ord(c) < 32 or ord(c) == 127 for c in path)
                or type(row) is not dict or set(row) != {'size', 'sha256'}
                or type(row['size']) is not int or row['size'] <= 0
                or type(row['sha256']) is not str or not re.fullmatch(r'[0-9a-f]{64}', row['sha256'])):
            raise ValueError('strict SCP package source DATA fields required')



def _validate_component_graph(files, binding, read, *, switch_dir):
    """Separate schema2 byte graph. No file or JSON field grants dispatch."""
    files = set(files)
    allowed = {"step.sh", "step-binding.json", "before.commands", "before-binding.json",
               "component-preflight.json", "request.json", "runner.sh", "runner-binding.json",
               "component-dispatch.json", "component-completion.json", "after.commands", "missing.commands",
               "component-repair.json", "component-repair-result.json", "observed-after.commands",
               "repaired.commands", "configuration-diff.json", "versions.json", "execution.stdout", "execution.stderr"} | _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "scp-source-request.json"}
    if not files <= allowed or not {"step.sh", "step-binding.json", "before.commands", "before-binding.json",
                                     "component-preflight.json"} <= files:
        raise ValueError("partial/unknown component stage graph")
    _validate_package_source_data_graph(files, binding, read)
    _validate_scp_request_content_graph(files, binding, read)
    before, before_binding = read("before.commands"), read("before-binding.json")
    if not before or before_binding != _json_bytes(_before_commands_binding(binding, before)):
        raise ValueError("original component before hash graph changed")
    preflight = json.loads(read("component-preflight.json"))
    health_override=preflight.get('health_override',False)
    if (type(health_override) is not bool or set(preflight) != {"schema_version", "state", "component", "package_index", "binding", "os_version",
            "before_sha256", "before_binding_sha256", "health_record", "pending_diff_base64", "query_records"} | ({'health_override'} if health_override else set())
            or preflight["schema_version"] != 2 or preflight["state"] != "COMPONENT_PREFLIGHT_DATA_ONLY"
            or preflight["binding"] != binding or preflight["component"] != binding["component"]
            or preflight["package_index"] != binding["package_index"]
            or preflight["before_sha256"] != hashlib.sha256(before).hexdigest()
            or preflight["before_binding_sha256"] != hashlib.sha256(before_binding).hexdigest()
            or base64.b64decode(preflight["pending_diff_base64"], validate=True).strip()):
        raise ValueError("original component preflight graph changed")
    records = _component_raw_records(preflight["query_records"])
    health = [r for r in records if r["command"] == "nv show system health"]
    if (len(health) != 1 or health[0] != preflight["health_record"] or (not health_override and
            (health[0]["returncode"] != 0 or health[0]["stream_complete"] is not True or health[0]["stderr_base64"] != ""))):
        raise ValueError("original component health graph changed")
    runner_files = files & _OWNED_RUNNER_FILES
    if runner_files:
        if runner_files != _OWNED_RUNNER_FILES:
            raise ValueError("partial component runner originals")
        runner_binding = json.loads(read("runner-binding.json"))
        if runner_binding != _owned_runner_binding(binding, runner_binding.get("remote_script"), read("runner.sh")):
            raise ValueError("component runner original hash graph changed")
    if "component-dispatch.json" in files:
        if not {"request.json", "runner.sh", "runner-binding.json"} <= files:
            raise ValueError("component dispatch missing original request/runner")
        document = json.loads(read("component-dispatch.json"))
        if (document.get("schema_version") != 2 or document.get("binding") != binding
                or document.get("request_sha256") != hashlib.sha256(read("request.json")).hexdigest()
                or document.get("runner_binding_sha256") != hashlib.sha256(read("runner-binding.json")).hexdigest()
                or document.get("launch_kind") != "OWNED_RUNNER_V1"):
            raise ValueError("original component dispatch binding changed")
        records = _component_raw_records(document["records"])
        from ibsw_upgrade_executor import _owned_launch_command
        if records[-1]["command"] != _owned_launch_command(document["remote_script"]):
            raise ValueError("original component launch chain changed")
    repair_files = {"after.commands", "missing.commands", "component-repair.json"}
    for name in sorted(files & _DOWNLOAD_FILES):
        document=json.loads(read(name))
        number=int(name[len('download-attempt-'):-len('.json')])
        if ('component-dispatch.json' not in files or document!=_download_document(binding,
                read('component-dispatch.json'),base64.b64decode(document['raw_lines_base64'],validate=True))
                or document['measurement']['attempt']!=number
                or any(f'download-attempt-{i:02d}.json' not in files for i in range(1,number))):
            raise ValueError('original download measurement graph changed')
    for name in sorted(files & _NVUED_CHECK_FILES):
        document=json.loads(read(name))
        attempt=int(name[len('nvued-check-'):-len('.json')])
        if (set(document)!={'schema_version','state','binding','attempt','dispatch_sha256','raw_records'}
                or document['schema_version']!=2 or document['state']!='NVUED_READINESS_DATA_ONLY'
                or document['binding']!=binding or document['attempt']!=attempt
                or 'component-dispatch.json' not in files
                or document['dispatch_sha256']!=hashlib.sha256(read('component-dispatch.json')).hexdigest()):
            raise ValueError('nvued observation binding differs from the original component')
        _nvued_check_records(document['raw_records'])
    if files & (repair_files | {"component-repair-result.json"}):
        if not repair_files <= files or "component-dispatch.json" not in files:
            raise ValueError("partial component repair originals; no retry")
        after, missing, plan = read("after.commands"), read("missing.commands"), read("component-repair.json")
        _component_repair_missing_bytes(before, after, missing)
        repair = json.loads(plan)
        if (set(repair) != {"schema_version", "state", "binding", "before_sha256", "after_sha256",
                "missing_sha256", "preflight_sha256", "dispatch_sha256", "request_sha256", "raw_records"}
                or repair["schema_version"] != 2 or repair["state"] != "REQUESTED" or repair["binding"] != binding
                or any(repair[field] != hashlib.sha256(raw).hexdigest() for field, raw in (
                    ("before_sha256", before), ("after_sha256", after), ("missing_sha256", missing),
                    ("preflight_sha256", read("component-preflight.json")),
                    ("dispatch_sha256", read("component-dispatch.json")), ("request_sha256", read("request.json"))))):
            raise ValueError("original component repair plan binding changed")
        _component_raw_records(repair["raw_records"])
        if "component-repair-result.json" in files:
            result = json.loads(read("component-repair-result.json"))
            if (set(result) != {"schema_version", "state", "binding", "plan_sha256", "repaired_base64", "raw_records"}
                    or result["schema_version"] != 2 or result["state"] not in {"REPAIRED", "UNKNOWN"}
                    or result["binding"] != binding or result["plan_sha256"] != hashlib.sha256(plan).hexdigest()):
                raise ValueError("original component repair result binding changed")
            repaired = base64.b64decode(result["repaired_base64"], validate=True)
            rows = _component_raw_records(result["raw_records"], allow_empty=result["state"] == "UNKNOWN")
            if result["state"] == "REPAIRED" and (not repaired or len(repaired) > MAXIMUM_INPUT_BYTES
                    or compare_commands(before.decode("utf-8"), repaired.decode("utf-8")).state != "PASS"
                    or not _component_repair_records_complete(rows)):
                raise ValueError("repaired DATA requires complete preserved configuration and raw records")
    if "component-completion.json" in files:
        document = json.loads(read("component-completion.json"))
        if (document.get("schema_version") != 2 or document.get("binding") != binding
                or document.get("state") not in {"VERIFIED", "FAIL", "UNKNOWN"}
                or document.get("preflight_sha256") != hashlib.sha256(read("component-preflight.json")).hexdigest()
                or document.get("dispatch_sha256") != (hashlib.sha256(read("component-dispatch.json")).hexdigest()
                                                      if "component-dispatch.json" in files else None)):
            raise ValueError("original component completion graph changed")
        _component_raw_records(document["raw_records"], allow_empty=document["state"] != "VERIFIED")
        if document["state"] == "VERIFIED" and "component-repair.json" in files:
            if ("component-repair-result.json" not in files
                    or json.loads(read("component-repair-result.json"))["state"] != "REPAIRED"):
                raise ValueError("incomplete repair cannot be a verified component completion")
    return files & {"step.sh", "step-binding.json", "request.json"}, {}, False


def _stage_health_files(phase):
    if type(phase) is not str or phase not in _STAGE_HEALTH_PHASES:
        raise ValueError("only fixed before/after local health declarations")
    return {phase + "-health.stdout.bin", phase + "-health.stderr.bin", phase + "-health-binding.json"}


def _stage_health_binding(binding, request, phase, record, *, before=None, postcondition=None):
    _stage_health_files(phase)
    if (binding["component"] != "os" or type(record) is not _ReadonlyQueryRecord
            or record.argv != ("nv", "show", "system", "health")):
        raise ValueError("original OS stage and fixed immutable health raw DATA required")
    return {"schema_version": 1, "state": "STAGE_HEALTH_DECLARATION_DATA", "phase": phase,
        "provenance": "LOCAL_STAGE_DECLARATION_ONLY", "health_state": "UNKNOWN",
        "execution_state": "NOT_EXECUTED", "dispatch_state": "HOLD", "attestation_state": "DATA_ONLY_UNATTESTED",
        "step_binding": binding, "request_sha256": hashlib.sha256(request).hexdigest(),
        "query_result": _query_data_result(record),
        "before_binding_sha256": hashlib.sha256(before).hexdigest() if before is not None else None,
        "postcondition": postcondition}


def _owned_runner_binding(binding, remote, runner):
    return {"schema_version": 1, "state": "OWNED_RUNNER_DECLARED_DATA", "binding": binding,
        "remote_script": remote, "runner_sha256": hashlib.sha256(runner).hexdigest(),
        "execution_state": "NOT_EXECUTED", "attestation_state": "DATA_ONLY_UNATTESTED"}


def _owned_exit_binding(binding, runner, request, dispatch, raw):
    from ibsw_upgrade_executor import _owned_exit_data
    return {"schema_version": 1, "binding": binding, "runner_sha256": hashlib.sha256(runner).hexdigest(),
        "request_sha256": hashlib.sha256(request).hexdigest(), "dispatch_sha256": hashlib.sha256(dispatch).hexdigest(),
        "record_sha256": hashlib.sha256(raw).hexdigest(), **_owned_exit_data(binding, raw)}


def _pending_diff_binding(step_binding, stdout, stderr, originals):
    """Opaque diff DATA, including empty stdout; never infer pending safety."""
    if stderr or len(stdout) + len(stderr) > MAXIMUM_INPUT_BYTES:
        raise ValueError("complete bounded diff DATA required")
    names = ("before.commands", "before-binding.json", "after.commands", "after-binding.json")
    return {"schema_version": 1, "state": "PENDING_DIFF_DATA_COMMITTED", "execution_state": "NOT_EXECUTED",
        "attestation_state": "DATA_ONLY_UNATTESTED", "pending_state": "UNKNOWN", "dispatch_state": "HOLD",
        "command": ["nv", "config", "diff", "-o", "commands"], "returncode": 0,
        "stdout_bytes": len(stdout), "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest(), "binding": step_binding,
        "original_commands_sha256": {name: hashlib.sha256(originals[name]).hexdigest() for name in names}}


def _commands_phase_binding(step_binding, phase, stdout, originals):
    if phase == "before":
        return _before_commands_binding(step_binding, stdout)  # Original bytes unchanged.
    result = _before_commands_binding(step_binding, stdout)
    result.update(state=phase.upper() + "_COMMANDS_DATA_COMMITTED", phase=phase,
        original_commands_sha256={name: hashlib.sha256(payload).hexdigest() for name, payload in originals.items()})
    return result


def _restore_data_plan(step_binding, before, after):
    """Only the existing pure classifier; no pending/current/permission claim."""
    node = InventoryDevice(**step_binding["node"])
    try:
        plan = plan_commands_restore(before.decode("utf-8-sig"), after.decode("utf-8-sig"),
                                     device=node, run_id=step_binding["run_id"], stage=step_binding["stage"])
        difference, patch = asdict(plan.difference), plan.patch_text.encode("utf-8")
    except UnicodeError:
        difference = {"state": "HOLD", "missing": (), "added": (), "changed": (), "holds": ("invalid UTF8 export",)}
        patch = b""
    result = {"state": "MISSING_ONLY_PLAN_DATA", "execution_state": "NOT_EXECUTED",
        "dispatch_state": "HOLD", "pending_state": "UNKNOWN", "binding": step_binding,
        "difference_state": difference.pop("state"), **difference,
        "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest(),
        "patch_bytes": len(patch), "patch_sha256": hashlib.sha256(patch).hexdigest()}
    return result, patch


def _restore_data_binding(step_binding, plan_bytes, patch):
    return {"schema_version": 1, "state": "RESTORE_PLAN_DATA_COMMITTED", "execution_state": "NOT_EXECUTED",
        "dispatch_state": "HOLD", "pending_state": "UNKNOWN", "binding": step_binding,
        "plan_sha256": hashlib.sha256(plan_bytes).hexdigest(), "patch_sha256": hashlib.sha256(patch).hexdigest(),
        "patch_bytes": len(patch)}


def _stage_data_members(files):
    remainder, phases = set(files), []
    remainder.discard("package-source.json")
    remainder.discard("scp-source-request.json")
    health = []
    for phase in _STAGE_HEALTH_PHASES:
        group = _stage_health_files(phase)
        present = remainder.intersection(group)
        if present:
            if (present != group or "request.json" not in files or
                    (phase == "after" and ("before" not in health or "postconditions" not in files or "os-dispatch.json" not in files))):
                raise ValueError("partial/out-of-order original stage health DATA")
            health.append(phase)
            remainder -= group
    for pair in (_OWNED_RUNNER_FILES, _OWNED_EXIT_FILES):
        present = remainder.intersection(pair)
        if present and present != pair:
            raise ValueError("partial original owned runner/exit DATA")
        remainder -= pair
    if set(files).intersection(_OWNED_EXIT_FILES) and (not _OWNED_RUNNER_FILES.issubset(files)
            or "request.json" not in files or "os-dispatch.json" not in files):
        raise ValueError("owned exit DATA requires original runner/request/dispatch")
    has_post = "postconditions" in remainder
    remainder.discard("postconditions")
    has_dispatch = "os-dispatch.json" in remainder
    remainder.discard("os-dispatch.json")
    pending = remainder.intersection(_PENDING_DIFF_FILES)
    if pending and pending != _PENDING_DIFF_FILES:
        raise ValueError("partial original pending diff DATA")
    remainder -= _PENDING_DIFF_FILES
    for phase in _COMMANDS_PHASES:
        pair = {phase + ".commands", phase + "-binding.json"}
        present = remainder.intersection(pair)
        if present and (present != pair or (phase != "before" and _COMMANDS_PHASES[_COMMANDS_PHASES.index(phase)-1] not in phases)):
            raise ValueError("partial/out-of-order commands DATA pair; preserve originals")
        if present:
            phases.append(phase); remainder -= pair
    if pending and "after" not in phases:
        raise ValueError("pending diff DATA requires original before/after")
    if has_dispatch and ("before" not in phases or "request.json" not in remainder):
        raise ValueError("OS dispatch DATA requires original request/before")
    if has_post and not has_dispatch:
        raise ValueError("postcondition DATA requires original OS request/dispatch")
    pair = {"restore-plan.json", "restore-binding.json"}
    present = remainder.intersection(pair)
    if present and (present != pair or "after" not in phases):
        raise ValueError("partial original restore DATA plan")
    if "missing.commands" in remainder and not present:
        raise ValueError("unknown missing.commands residue")
    has_patch = "missing.commands" in remainder
    remainder -= pair | {"missing.commands"}
    if remainder not in ({"step.sh", "step-binding.json"}, {"step.sh", "step-binding.json", "request.json"}):
        raise ValueError("unknown stage/commands residue")
    return remainder, tuple(phases), bool(present), has_patch


def _validate_commands_data_graph(files, step_binding, read, *, read_postconditions=None, switch_dir=None):
    """Historical and live readers share one original byte/hash graph contract."""
    if "component-preflight.json" in files:
        return _validate_component_graph(files, step_binding, read, switch_dir=switch_dir)
    remainder, phases, has_restore, has_patch = _stage_data_members(files)
    _validate_package_source_data_graph(files, step_binding, read)
    _validate_scp_request_content_graph(files, step_binding, read)
    originals = {}
    for phase in phases:
        raw_name, meta_name = phase + ".commands", phase + "-binding.json"
        raw = read(raw_name)
        expected = _json_bytes(_commands_phase_binding(step_binding, phase, raw, originals))
        metadata = read(meta_name)
        if metadata != expected:
            raise ValueError("original commands DATA hash graph changed")
        originals[raw_name], originals[meta_name] = raw, metadata
    if set(files).intersection(_PENDING_DIFF_FILES):
        expected = _pending_diff_binding(step_binding, read(_PENDING_DIFF_RAW[0]), read(_PENDING_DIFF_RAW[1]), originals)
        if read("pending-diff-binding.json") != _json_bytes(expected):
            raise ValueError("original pending diff DATA hash graph changed")
    if has_restore:
        expected_plan, patch = _restore_data_plan(step_binding, originals["before.commands"], originals["after.commands"])
        expected_bytes = _json_bytes(expected_plan)
        if read("restore-plan.json") != expected_bytes or has_patch != bool(patch):
            raise ValueError("original missing-only DATA plan changed")
        if patch and read("missing.commands") != patch:
            raise ValueError("original missing.commands changed")
        if read("restore-binding.json") != _json_bytes(_restore_data_binding(step_binding, expected_bytes, patch)):
            raise ValueError("original restore DATA binding changed")
    if "os-dispatch.json" in files:
        payload = read("os-dispatch.json")
        document = json.loads(payload)
        if type(document) is not dict:
            raise ValueError("unknown original OS dispatch DATA")
        runner_binding = None
        if "launch_kind" in document:
            if document["launch_kind"] != "OWNED_RUNNER_V1" or not _OWNED_RUNNER_FILES.issubset(files):
                raise ValueError("unknown launch kind/original owned runner graph missing")
            runner_binding = read("runner-binding.json")
        expected = _os_dispatch_data(step_binding, read("request.json"), document.get("remote_script"), document.get("records"), runner_binding=runner_binding)
        if payload != _json_bytes(expected):
            raise ValueError("original OS dispatch DATA graph changed; no replay")
    if _OWNED_RUNNER_FILES.issubset(files):
        from ibsw_upgrade_executor import _owned_runner_bytes
        document = json.loads(read("runner-binding.json"))
        remote = document.get("remote_script") if type(document) is dict else None
        if type(remote) is not str or switch_dir is None or posixpath.dirname(posixpath.dirname(remote)) != switch_dir:
            raise ValueError("original declared remote root required for owned runner DATA")
        runner = _owned_runner_bytes(step_binding, remote)
        if read("runner.sh") != runner or read("runner-binding.json") != _json_bytes(_owned_runner_binding(step_binding, remote, runner)):
            raise ValueError("original owned runner/source/binding changed")
        if _OWNED_EXIT_FILES.issubset(files):
            expected = _owned_exit_binding(step_binding, runner, read("request.json"), read("os-dispatch.json"), read("owned-exit.record"))
            if read("owned-exit-binding.json") != _json_bytes(expected):
                raise ValueError("original child record/source/hash graph changed")
    rounds = {}
    if "postconditions" in files:
        if read_postconditions is None:
            raise ValueError("original postcondition graph reader required")
        rounds = read_postconditions()
    for phase in _STAGE_HEALTH_PHASES:
        if _stage_health_files(phase).issubset(files):
            raw_name, error_name, meta_name = (phase + "-health.stdout.bin", phase + "-health.stderr.bin", phase + "-health-binding.json")
            payload = read(meta_name)
            metadata = json.loads(payload)
            postcondition = None
            if phase == "after":
                reference = metadata.get("postcondition") if type(metadata) is dict else None
                round_id = reference.get("round_id") if type(reference) is dict else None
                if type(round_id) is not str or type(rounds) is not dict or round_id not in rounds:
                    raise ValueError("original verified health postcondition round required")
                postcondition = {"round_id": round_id, "post_binding_sha256": rounds[round_id]}
            result = metadata.get("query_result") if type(metadata) is dict else None
            if type(result) is not dict:
                raise ValueError("original stage health result required")
            record = record_readonly_query(("nv", "show", "system", "health"), read(raw_name), read(error_name), result.get("returncode"))
            expected = _stage_health_binding(step_binding, read("request.json"), phase, record,
                before=read("before-health-binding.json") if phase == "after" else None, postcondition=postcondition)
            if payload != _json_bytes(expected):
                raise ValueError("original stage health bytes/request/round graph changed")
    return remainder, originals, has_restore


def _post_version_data(binding, final_target, record):
    """Shared pure comparison only. Supplied bytes never prove native completion."""
    if binding["component"] != "os" or record.argv != ("nv", "show", "system", "version"):
        raise ValueError("original bound OS query required")
    value = parse_readonly_query_data(record)
    if value.state != "TEXT_DATA_PARSED":
        raise ValueError("unknown/incomplete original OS version output")
    observed = dict(value.fields)["image_version_text"]
    if _version(observed) != _version(binding["target_version"]):
        raise ValueError("observed version does not match original requested step target")
    return {"match_result": "VERSION_TARGET_MATCH", "target_version": binding["target_version"],
        "final_target": final_target, "observed_version": observed,
        "target_scope": "FINAL_VERSION_ONLY" if _version(observed) == _version(final_target) else "INTERMEDIATE",
        "activation_state": "UNKNOWN", "attestation_state": "DATA_ONLY_UNATTESTED"}


def _post_original_uid(dispatch):
    """Original fixed id -u raw chain member, not a caller account claim."""
    value = base64.b64decode(json.loads(dispatch)["records"][4]["stdout_base64"], validate=True)
    if not re.fullmatch(rb"[0-9]+\n", value):
        raise ValueError("original dispatch numeric uid is unknown")
    return int(value)


def _post_log_data(remote, stdout, stderr, metadata, *, expected_uid):
    """Opaque log snapshots, not an installer exit/status/activation oracle."""
    if (type(stdout) is not bytes or type(stderr) is not bytes
            or max(len(stdout), len(stderr)) > 4 * 1024 * 1024 or type(metadata) is not dict
            or set(metadata) - {"remote_directory", "uid", "observation_state", "connection_source"}
            or not {"remote_directory", "uid", "observation_state"}.issubset(metadata)
            or metadata["remote_directory"] != posixpath.dirname(remote)
            or type(metadata["uid"]) is not int or metadata["uid"] != expected_uid
            or metadata["observation_state"] != "LOG_SNAPSHOT_ONLY"):
        raise ValueError("finite original private log DATA required")
    source = metadata.get("connection_source")
    if source is not None:
        if (type(source) is not dict or set(source) != {"server_host_key_fingerprint", "authentication",
                "identity_stdout_base64", "identity_stderr_base64", "identity_returncode"}
                or source["authentication"] not in {"publickey", "password"}
                or type(source["server_host_key_fingerprint"]) is not str
                or not re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", source["server_host_key_fingerprint"])
                or type(source["identity_returncode"]) is not int or source["identity_returncode"] != 0
                or source["identity_stderr_base64"] != ""):
            raise ValueError("unknown public signed-observation DATA fields; no secret fields")
        value = source["identity_stdout_base64"]
        if type(value) is not str or base64.b64encode(base64.b64decode(value, validate=True)).decode("ascii") != value:
            raise ValueError("noncanonical original identity bytes")
    return {"remote_directory": metadata["remote_directory"], "uid": metadata["uid"],
        "observation_state": "LOG_SNAPSHOT_ONLY", "connection_source": source,
        "stdout_bytes": len(stdout), "stdout_sha256": hashlib.sha256(stdout).hexdigest(),
        "stderr_bytes": len(stderr), "stderr_sha256": hashlib.sha256(stderr).hexdigest()}


def _post_binding(binding, request, dispatch, round_id, version, log_metadata, match):
    return {"schema_version": 1, "state": "POSTCONDITION_DATA_COMMITTED", "round_id": round_id,
        "binding": binding, "request_sha256": hashlib.sha256(request).hexdigest(),
        "dispatch_sha256": hashlib.sha256(dispatch).hexdigest(),
        "version_result_sha256": hashlib.sha256(version).hexdigest(),
        "log_metadata_sha256": hashlib.sha256(log_metadata).hexdigest(), **match}


def _os_dispatch_data(binding, request, remote, records, *, runner_binding=None):
    """Lossless original process-chain DATA only; never a completion receipt."""
    if binding["component"] != "os" or type(remote) is not str or not remote.startswith("/"):
        raise ValueError("fixed declared OS/private absolute script required")
    parent, filename = posixpath.split(remote)
    prefix = ".ibsw-" + binding["run_id"] + "-" + binding["node"]["hostname"] + "-" + binding["stage"] + "-"
    if (filename != "step.sh" or posixpath.normpath(remote) != remote
            or not re.fullmatch(re.escape(prefix) + "[0-9a-f]{32}", posixpath.basename(parent))):
        raise ValueError("unknown remote private OS script")
    from ibsw_upgrade_executor import _launch_command, _owned_launch_command, _owned_runner_bytes, _CAPABILITY_COMMAND
    extra = {}
    if runner_binding is not None:
        runner = _owned_runner_bytes(binding, remote)
        if type(runner_binding) is not bytes or runner_binding != _json_bytes(_owned_runner_binding(binding, remote, runner)):
            raise ValueError("original runner/binding required for fixed owned launch")
        extra = {"launch_kind": "OWNED_RUNNER_V1", "runner_sha256": hashlib.sha256(runner).hexdigest(),
                 "runner_binding_sha256": hashlib.sha256(runner_binding).hexdigest()}
    commands = ["hostname; cat /sys/class/net/eth0/address", "nv show system version", _CAPABILITY_COMMAND,
                "nv config show -o commands", "id -u", "hostname; cat /sys/class/net/eth0/address",
                "nv show system version", _owned_launch_command(remote) if runner_binding is not None else _launch_command(remote)]
    if type(records) is not list or len(records) != len(commands):
        raise ValueError("complete original fixed process-chain DATA required")
    for index, (record, command) in enumerate(zip(records, commands)):
        if (type(record) is not dict or set(record) != {"command", "stdout_base64", "stderr_base64", "returncode", "stream_complete"}
                or record["command"] != command or type(record["stream_complete"]) is not bool
                or (record["returncode"] is not None and (type(record["returncode"]) is not int or record["returncode"] < 0))):
            raise ValueError("unknown original process-chain fields")
        for key in ("stdout_base64", "stderr_base64"):
            value = record[key]
            if type(value) is not str or base64.b64encode(base64.b64decode(value, validate=True)).decode("ascii") != value:
                raise ValueError("noncanonical original process bytes")
        if index < 7 and (record["returncode"] != 0 or not record["stream_complete"] or record["stderr_base64"]):
            raise ValueError("failed original precondition cannot become dispatch DATA")
    return {"schema_version": 1, "state": "OS_DISPATCH_DATA_ONLY", "execution_state": "POSSIBLY_DISPATCHED",
            "attestation_state": "DATA_ONLY_UNATTESTED", "activation_state": "UNKNOWN", "expected_effect": "REBOOT_EXPECTED",
            "binding": binding, "request_sha256": hashlib.sha256(request).hexdigest(), "remote_script": remote, "records": records, **extra}


def _declared_candidate_data(policy, device, *, run_id, method, switch_dir, plan_sha256,
                             input_sha256, component, package_index, stage_key):
    artifact = render_declared_step(policy, device, component=component, package_index=package_index,
        run_id=run_id, method=method, switch_dir=switch_dir)
    script = artifact.script.encode("utf-8")
    binding = {"schema_version": 1, "execution_state": "NOT_EXECUTED", "run_id": run_id,
        "node": asdict(device), "stage": stage_key, "component": component,
        "package_index": package_index, "target_version": artifact.target_version,
        "plan_sha256": plan_sha256, "script_sha256": hashlib.sha256(script).hexdigest(),
        "input_sha256": input_sha256}
    return script, binding


def _policy_document(policy):
    result = asdict(policy)
    if result.get('ssd_version') is None:
        result.pop('ssd_version', None)  # Preserve earlier no-SSD local plan bytes.
    if not result.get('os_stages'):
        result.pop('os_stages',None)  # Existing linear plan bytes remain unchanged.
    return result


def _declared_plan(parsed, paths, session, snapshot, policy, run_id, entry, cwd):
    project = session._managed_project or (Path(paths.project) if paths.project is not None else None)
    return {"state": "DECLARED_CANDIDATES_NOT_EXECUTED", "execution_state": "NOT_EXECUTED",
            "script_state": "OPEN", "observations": "UNKNOWN", "run_id": run_id,
            "entry": _absolute(entry, cwd), "cwd": cwd, "argv": list(parsed.argv),
            "project": str(project) if project is not None else None,
            "selected": list(parsed.selected), "method": parsed.method,
            "canary_mode": parsed.canary_mode, "switch_dir": parsed.switch_dir,
            "input_paths": asdict(paths), "devices": [asdict(item) for item in snapshot.devices],
            "policy": _policy_document(policy),
            **({"skipped_devices": [asdict(item) for item in snapshot.blocked_devices]}
               if snapshot.blocked_devices else {}),
            **({"exclusive_config_window": True} if parsed.exclusive_config_window else {}),
            "open": ["current versions and authenticated identity", "on-demand component selection",
                     "SCP script implementation", "OS activation and final barrier", "fixed executor"]}


def prepare_not_executed_run(entry, cwd, args, *, manual_execution=False):
    """Prepare declarations and exact raw inputs; never execute component scripts."""
    parsed = parse_prepare_args(entry, cwd, args)
    run_id = _new_manual_run_id() if manual_execution else "run-" + secrets.token_hex(16)
    paths = replace(parsed.paths, output_path=str(Path(parsed.paths.output_path).parent / run_id))
    # Shape selection is not permission. Each selected API performs its own
    # first-open live binding; there is no failed-reader/closed-DTO fallback.
    try:
        managed = stat.S_ISLNK(os.lstat(paths.global_path).st_mode)
    except OSError as error:
        raise ValueError("selected global is missing; no active-project fallback") from error
    opener = _selected_opener(parsed)
    output = None
    with opener(paths) as session:
        snapshot = _selected_inventory(session, parsed)
        if not snapshot.devices:
            raise ValueError("no eligible IB targets; all selected devices have invalid eth0 identity inputs")
        policy = normalize_upgrade(load_global_text(snapshot.global_text), selected=parsed.selected,
                                   method=parsed.method, package_dir=parsed.package_dir)
        session.verify()
        plan = _declared_plan(parsed, paths, session, snapshot, policy, run_id, entry, cwd)
        try:
            output = _OutputScope(session, paths, run_id, manual_execution=manual_execution)
            output.write("plan.json", _json_bytes(plan))
            output.write("input-inventory.csv", session._files[0].payload)
            output.write("input-global.yaml", session._files[1].payload)
            evidence = {"state": "DECLARED_CANDIDATES_NOT_EXECUTED", "run_id": run_id,
                        "source_identities": [list(source.identity) for source in session._files],
                        "source_names": [str(source.directory.path / source.name) for source in session._files],
                        "artifacts": {name: hashlib.sha256(payload).hexdigest()
                                      for name, _fd, _original, _identity, payload in output.files}}
            output.write("evidence.json", _json_bytes(evidence))
            output.verify()
            session.verify()
            output.close()
            session.verify()
            return {"state": "DECLARED_CANDIDATES_NOT_EXECUTED", "run_id": run_id,
                    "run_directory": str(output.run_directory)}
        except BaseException as original:
            if output is not None:
                try:
                    output.close()
                except BaseException as cleanup:
                    if not any(issue is cleanup for issue in output.cleanup_issues):
                        output.cleanup_issues.append(cleanup)
                    # Match the existing owned-scope priority: original NI
                    # wins; a new cleanup NI outranks an ordinary primary.
                    if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                        raise
            if isinstance(original, Exception):
                if isinstance(original, PreparationHold):
                    raise
                residue = "; unknown descriptor residue remains HOLD" if output is not None and output.cleanup_issues else ""
                raise PreparationHold(str(original) + residue, output.run_directory if output is not None else None) from original
            raise


class _JournalWriter(_OutputScope):
    """Reuse private EXCL file writes while the original run/input FDs stay live."""
    def __init__(self, scope, directory):
        self.scope, self.session, self.anchor = scope, scope.session, directory
        self.fd, self.run_directory = directory.fd, directory.path
        self.edges, self.owners, self.files, self.cleanup_issues = [], [], [], []
        self.closed = False

    def verify(self):
        self.scope.verify()
        super().verify()
        self.scope.verify()

    def finish(self):
        original = sys.exc_info()[1]
        try:
            self.close()
        except BaseException as error:
            self.scope.cleanup_issues.append(error)
            if original is None or (isinstance(original, Exception) and not isinstance(error, Exception)):
                raise
            # Preserve a primary interrupt; a new cleanup interrupt outranks
            # an ordinary error. Unknown cleanup residue still blocks reuse.


def _query_public_fingerprint(payload):
    _algorithm, blob = public_key_identity_bytes(payload)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii")


def _known_host_endpoint_matches(field, endpoints):
    """Match exact endpoint text or an OpenSSH |1| HMAC-SHA1 host token.

    SHA1 is required by the OpenSSH hostname-hiding format, not used for key
    fingerprints. No DNS, wildcard, enrollment or remote IO is performed.
    """
    if b"|" not in field:
        return bool(endpoints.intersection(field.decode("ascii").split(",")))
    parts = field.split(b"|")
    if len(parts) != 4 or parts[0] != b"":
        raise ValueError("invalid hashed known_hosts endpoint")
    if parts[1] != b"1":
        raise ValueError("unsupported known_hosts hash format")
    try:
        salt, digest = (base64.b64decode(value, validate=True) for value in parts[2:])
    except (ValueError, binascii.Error) as error:
        raise ValueError("invalid hashed known_hosts endpoint") from error
    if (len(salt) != 20 or len(digest) != 20
            or base64.b64encode(salt) != parts[2] or base64.b64encode(digest) != parts[3]):
        raise ValueError("invalid hashed known_hosts endpoint")
    return any(hmac.compare_digest(hmac.new(salt, endpoint.encode("ascii"), hashlib.sha1).digest(), digest)
               for endpoint in endpoints)


def _offline_literal_host_pins(payload, address):
    """Exact endpoint DATA from literal or hashed pre-provisioned records.

    Hashes only hide endpoint names; actual remote keys must still match their
    SHA256 pins. Wildcard/CA policies and host-key enrollment are not inferred.
    """
    endpoints, found = {address, "[" + address + "]:22"}, set()
    for line in payload.splitlines():
        if not line.strip() or line.lstrip().startswith(b"#"):
            continue
        fields = line.split()
        if fields[0].startswith(b"@"):
            if len(fields) > 1 and _known_host_endpoint_matches(fields[1], endpoints):
                raise ValueError("marked host trust entry needs actual native policy")
            continue
        if not _known_host_endpoint_matches(fields[0], endpoints):
            continue
        if len(fields) < 3:
            raise ValueError("incomplete exact endpoint public key")
        found.add(_query_public_fingerprint(fields[1] + b" " + fields[2] + b"\n"))
    if not found:
        raise ValueError("no exact pre-provisioned literal endpoint pin; never TOFU")
    return tuple(sorted(found))


class _OpaqueQueryIdentityFd:
    """Own an original identity FD without reading/exporting private bytes."""
    def __init__(self, path, directory):
        self.directory, self.name = directory, path.name
        self.fd, self.owner, self.cleanup_issues = None, None, []
        try:
            directory.verify()
            named = os.stat(self.name, dir_fd=directory.fd, follow_symlinks=False)
            if (not stat.S_ISREG(named.st_mode) or named.st_uid != os.geteuid() or named.st_nlink != 1
                    or named.st_mode & 0o077 or not 0 < named.st_size <= 1024 * 1024):
                raise ValueError("finite private owned non-shared identity file required")
            self.identity = _source_identity(named)
            self.fd = os.open(self.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0), dir_fd=directory.fd)
            self.owner = _CandidateDescriptor(self.fd, named)
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    def verify(self):
        if self.fd is None:
            raise ValueError("identity FD scope is closed")
        self.directory.verify()
        if (_source_identity(os.fstat(self.fd)) != self.identity
                or _source_identity(os.stat(self.name, dir_fd=self.directory.fd, follow_symlinks=False)) != self.identity):
            raise ValueError("original private identity FD/name changed")
        self.directory.verify()

    def close(self):
        if self.fd is not None:
            issue = self.owner.conditional_close() if self.owner is not None else ValueError("unknown identity descriptor residue")
            self.fd = None
            if issue is not None:
                self.cleanup_issues.append(issue)
        _raise_cleanup_issues(self.cleanup_issues)


class _ReadonlyQueryInputs:
    """Live offline DATA input leaf. Never a native/signed/current permit."""
    def __init__(self, scope, node, *, known_hosts_path, identity_path, management_public_path, user):
        self.scope, self.closed, self.files = scope, False, []
        self._native_observation_consumed = False
        self._original_selection = None
        try:
            scope.verify()
            if type(user) is not str or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9._-]{0,63}", user):
                raise ValueError("typed SSH account required")
            # Source the node from the original live CSV snapshot, not the
            # caller's DTO or an editable scope.devices dictionary.
            matches = tuple(item for item in _selected_inventory(scope.session, scope.parsed).devices if item.hostname == node)
            if len(matches) != 1:
                raise ValueError("node absent from original live CSV")
            self.node, self.user = matches[0], user
            if (identity_path is None) != (management_public_path is None):
                raise ValueError("paired explicit SSH key sources required")
            keyless = identity_path is None and management_public_path is None
            held = {}
            sources = (("known_hosts", known_hosts_path),) if keyless else (
                ("known_hosts", known_hosts_path), ("identity", identity_path),
                ("management_public", management_public_path))
            for label, source in sources:
                path = Path(source)
                if not path.is_absolute() or str(path) != posixpath.normpath(str(path)):
                    raise ValueError("explicit absolute source path required; no HOME/default reads")
                directory = scope.session._directory(path.parent)
                if label == "identity":
                    original = _OpaqueQueryIdentityFd(path, directory)
                else:
                    original = _HeldFile(path, directory)
                self.files.append(original)
                metadata = os.fstat(original.fd)
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                    raise ValueError("safely owned read-only source required")
                held[label] = original
            identity = None if keyless else held["identity"]
            public = None if keyless else held["management_public"]
            self._identity = identity
            self.host_pins = _offline_literal_host_pins(held["known_hosts"].payload, self.node.address)
            self.management_public = None if keyless else _query_public_fingerprint(public.payload)
            self._original_selection = (scope, node, user, held["known_hosts"], identity, public)
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    def verify(self):
        if self.closed:
            raise ValueError("offline query input scope is closed")
        selection = self._original_selection
        # Constructor partial cleanup retains the already registered originals.
        # This private tuple is an internal selection anchor, not an unforgeable
        # capability or a caller-issued execution permit.
        scope = self.scope if selection is None else selection[0]
        if selection is not None and ((selection[4] is None) != (selection[5] is None)):
            raise ValueError("original paired SSH key roles changed")
        originals = tuple(self.files) if selection is None else (
            (selection[3],) if selection[4] is None and selection[5] is None else selection[3:])
        scope.verify()
        for original in originals:
            original.verify()
        if selection is not None:
            _scope, node_name, user, known, identity, public = selection
            matches = tuple(item for item in _selected_inventory(scope.session, scope.parsed).devices if item.hostname == node_name)
            if (self.scope is not scope or len(matches) != 1 or self.node != matches[0]
                    or self.user != user or self._identity is not identity
                    or len(self.files) != len(originals)
                    or any(actual is not original for actual, original in zip(self.files, originals))
                    or self.host_pins != _offline_literal_host_pins(known.payload, matches[0].address)
                    or self.management_public != (None if identity is None else _query_public_fingerprint(public.payload))):
                raise ValueError("readonly leaf selection differs from original live sources")
        scope.verify()

    def verify_io_identity(self):
        """Cheap original-source checks while draining a bounded read-only stream.

        Full bytes, selection, trust and all retained evidence are rechecked at
        command boundaries. This is not a cached authorization or write permit.
        """
        scope = self.scope
        if self.closed or scope.closed or scope.cleanup_issues:
            raise SharedUpgradeHold('original query scope is not live')
        scope.session._require_open()
        for alias in scope.session._aliases:
            alias.verify()
        sources = tuple(scope.session._metadata_files)+tuple(scope.session._files)+tuple(self.files)
        for original in sources:
            original.directory.verify()
            if type(original) is _OpaqueQueryIdentityFd:
                original.verify()  # Already metadata-only; never reads private bytes.
            else:
                original.verify_identity()
        if scope._active_request_lease is not None:
            scope._active_request_lease.verify()

    def declaration(self):
        self.verify()
        return {"state": "DATA_ONLY", "connection_state": "NOT_CONNECTED", "key_possession": "NOT_ATTESTED",
            "node": asdict(self.node), "user": self.user, "host_key_fingerprints": self.host_pins,
            "management_public_fingerprint": self.management_public,
            "queries": tuple(argv for _label, argv in _QUERY_DATA_SPECS)}

    def observe_readonly_once(self, *, password=None):
        """Fixed native readonly reader only, never a dispatch/current permit.

        Explicit paired None selects a leaf without management key sources and
        requires an explicit password before SDK access. Password-only CLI input
        selection remains OPEN. Keyed leaves keep both original key sources even
        with an explicit password; authentication never automatically falls back.
        No connection/provider/query/version argument can be supplied.
        """
        if self._native_observation_consumed:
            raise ValueError("readonly native attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_observer import _observe_live_inputs_once
        return _observe_live_inputs_once(self, password=password)

    def observe_initial_plan_once(self, *, password=None):
        """Initial observed DATA only; no external current/observation carrier.

        Shares the one-shot native attempt. A closed result cannot establish
        current-at-execution, OS_FINAL or any future dispatch permission.
        """
        if self._native_observation_consumed:
            raise ValueError("readonly native attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_observer import _observe_live_inputs_once
        return _observe_live_inputs_once(self, password=password, initial_plan=True)

    def capture_readonly_health_once(self, *, password=None):
        """Explicit fixed triple raw DATA collector; default pair is unchanged.

        Returned EOF booleans are diagnostic DATA, not transferable native,
        health or OS_FINAL authority. Shares the original one-shot attempt.
        """
        if self._native_observation_consumed:
            raise ValueError("readonly native attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_observer import _capture_live_health_queries_once
        return _capture_live_health_queries_once(self, password=password)

    def capture_before_commands_once(self, component, *, package_index=0, password=None):
        """Fixed native raw capture into an existing declared DATA stage only."""
        return self.capture_commands_once("before", component, package_index=package_index, password=password)

    def capture_commands_once(self, phase, component, *, package_index=0, password=None):
        """Fixed-phase raw DATA only; 'after/repaired' do not attest execution."""
        if type(phase) is not str or phase not in _COMMANDS_PHASES:
            raise ValueError("only fixed commands DATA phases")
        if self._native_observation_consumed:
            raise ValueError("readonly native attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        scope = self._original_selection[0]
        # Original source/stage/script/binding and pre-existing data checks
        # precede any SDK import, auth, socket or config collection.
        scope._commands_capture_stage(self, phase, component, package_index)
        from ibsw_upgrade_observer import _observe_live_inputs_once
        return _observe_live_inputs_once(self, password=password, commands_capture=(phase, component, package_index))

    def capture_pending_diff_once(self, component, *, package_index=0, password=None):
        """One fixed raw diff sample; empty output cannot authorize config writes."""
        if self._native_observation_consumed:
            raise ValueError("readonly native attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        self._original_selection[0]._commands_capture_stage(self, "pending-diff", component, package_index)
        from ibsw_upgrade_observer import _observe_live_inputs_once
        return _observe_live_inputs_once(self, password=password, pending_diff=(component, package_index))

    def execute_next_os_once(self, *, password=None):
        """Uninstalled ONE native OS path, no caller current/index/permit."""
        if self._native_observation_consumed:
            raise ValueError("native attempt consumed; never retry dispatch")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_executor import _execute_os_once
        return _execute_os_once(self, password=password)

    def execute_component_once(self, component, *, password=None):
        if self._native_observation_consumed:
            raise ValueError("native component attempt consumed; never retry")
        self._native_observation_consumed = True
        self.verify()
        if component not in self._original_selection[0].parsed.selected:
            raise ValueError("unselected original component")
        from ibsw_upgrade_executor import _execute_component_once
        return _execute_component_once(self, component, password=password)

    def observe_os_postcondition_once(self, *, package_index, password=None):
        """Only fixed new signed read; stage index is not current/PASS permission."""
        if self._native_observation_consumed:
            raise ValueError("native observation attempt consumed; no retry")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_executor import _observe_os_postcondition_once
        return _observe_os_postcondition_once(self, package_index, password=password)

    def observe_os_configuration_once(self, *, package_index, password=None):
        """One fixed live readonly version/config DATA sample, never OS_FINAL."""
        if self._native_observation_consumed:
            raise ValueError("native observation attempt consumed; no retry")
        self._native_observation_consumed = True
        self.verify()
        from ibsw_upgrade_executor import _observe_os_postcondition_once
        return _observe_os_postcondition_once(self, package_index, password=password, include_configuration=True)

    def close(self):
        if self.closed:
            return
        issues = []
        try:
            self.verify()
        except BaseException as error:
            issues.append(error)
        self.closed = True
        selection = self._original_selection
        originals = self.files if selection is None else (
            (selection[3],) if selection[4] is None and selection[5] is None else selection[3:])
        for original in reversed(originals):
            try:
                original.close()
            except BaseException as error:
                issues.append(error)
        for error in issues:
            if not isinstance(error, Exception):
                raise error
        _raise_cleanup_issues(issues)

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except BaseException as error:
            if value is None or (isinstance(value, Exception) and not isinstance(error, Exception)):
                raise
        return False


class _ManualJournalTransaction:
    """Current-process journal scope only; no lock file, flock or history IO.

    The coordinator's RLock serializes its own worker status writes. This is
    not a cross-process lock or a promise of safety against another upgrader.
    """
    def __init__(self):
        self.closed = False

    def verify(self):
        if self.closed:
            raise ValueError("current-run journal transaction is closed")

    def close(self):
        self.closed = True



def _fixed_package_source_api(scope):
    """Fresh fixed sibling source/object proof; never import by search path.

    Existing no-follow input owners close before a package factory may run.
    Compiled source is compared, not executed for an already loaded provider.
    Missing providers execute only the held fixed bytes, never a foreign loader.
    This is a fixed local source contract, not a hostile-interpreter sandbox.
    """
    import builtins
    import errno as stdlib_errno
    import importlib.machinery
    import importlib.util
    import math as stdlib_math
    import time as stdlib_time
    from types import CodeType, FunctionType, ModuleType
    from ibsw_upgrade_inputs import _HeldDirectory

    name = 'ibsw_upgrade_scp'
    path = Path(__file__).absolute().parent / (name + '.py')
    directory = source = None
    module = created = result = None
    primary = None
    cleanup = []
    try:
        directory = _HeldDirectory(path.parent)
        source = _HeldFile(path, directory)
        info = os.fstat(source.fd)
        if info.st_nlink != 1 or info.st_mode & 0o022:
            raise SharedUpgradeHold('fixed package provider source is unsafe')
        code = compile(source.payload, str(path), 'exec',
                       dont_inherit=True, optimize=sys.flags.optimize)

        def original_code(parent, selected):
            matches = [item for item in parent.co_consts
                       if type(item) is CodeType and item.co_name == selected]
            if len(matches) != 1:
                raise SharedUpgradeHold('fixed provider definition is not unique')
            return matches[0]

        module = sys.modules.get(name)
        if name in sys.modules and module is None:
            raise SharedUpgradeHold('cached absent provider marker is not import permission')
        if module is None:
            spec = importlib.util.spec_from_file_location(name, str(path))
            module = importlib.util.module_from_spec(spec)
            created = module
            sys.modules[name] = module  # Dataclass declaration needs its own slot.
            exec(code, module.__dict__)
        if type(module) is not ModuleType or sys.modules.get(name) is not module:
            raise SharedUpgradeHold('foreign package provider module')
        namespace = vars(module)
        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')
        if (namespace.get('__name__') != name or namespace.get('__file__') != str(path)
                or type(spec) is not importlib.machinery.ModuleSpec
                or type(loader) is not importlib.machinery.SourceFileLoader
                or spec.name != name or spec.origin != str(path) or spec.loader is not loader
                or loader.name != name or loader.path != str(path)
                or namespace.get('__builtins__') is not builtins.__dict__):
            raise SharedUpgradeHold('fixed package provider origin changed')

        def function(value, expected):
            if (type(value) is not FunctionType or value.__globals__ is not namespace
                    or value.__module__ != name or value.__code__ != expected
                    or value.__closure__ is not None or value.__defaults__ is not None
                    or value.__kwdefaults__ is not None):
                raise SharedUpgradeHold('foreign package provider function')
            return value

        factory = function(namespace.get('package_content_owner'),
                           original_code(code, 'package_content_owner'))
        for selected in ('_identity', '_directory_identity', '_object_key'):
            function(namespace.get(selected), original_code(code, selected))
        owner_class = namespace.get('_PackageContentOwner')
        if (type(owner_class) is not type or owner_class.__bases__ != (object,)
                or owner_class.__module__ != name):
            raise SharedUpgradeHold('foreign package provider class')
        class_code = original_code(code, '_PackageContentOwner')
        methods = {item.co_name: item for item in class_code.co_consts if type(item) is CodeType}
        members = vars(owner_class)
        if (set(members) != set(methods) | {'__module__', '__doc__', '__dict__', '__weakref__'}
                or members['__doc__'] is not None):
            raise SharedUpgradeHold('package provider class namespace changed')
        for selected, expected in methods.items():
            function(members.get(selected), expected)
        error_class = namespace.get('ContentHold')
        if (type(error_class) is not type or error_class.__bases__ != (ValueError,)
                or error_class.__module__ != name
                or not set(vars(error_class)) <= {'__module__', '__doc__', '__weakref__'}):
            raise SharedUpgradeHold('package provider error class changed')
        for selected, expected in (
                ('os', os), ('Path', Path), ('stat', stat), ('hashlib', hashlib),
                ('threading', threading), ('time', stdlib_time),
                ('math', stdlib_math), ('errno', stdlib_errno)):
            if namespace.get(selected) is not expected:
                raise SharedUpgradeHold('package provider original dependency changed')
        source.verify()
        if (sys.modules.get(name) is not module
                or namespace.get('package_content_owner') is not factory
                or namespace.get('_PackageContentOwner') is not owner_class):
            raise SharedUpgradeHold('package provider original object joint changed')
        result = module, factory, owner_class
    except BaseException as error:
        primary = error
    finally:
        for held in (source, directory):
            if held is not None:
                try:
                    held.close()
                except BaseException as error:
                    cleanup.append(error)
                    if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                        primary = error
        if cleanup:
            # Unknown source cleanup poisons this actual scope; never retry FDs.
            scope.cleanup_issues.extend(cleanup)
            if scope._package_source_lifecycle_failure is None:
                scope._package_source_lifecycle_failure = SharedUpgradeHold(
                    'fixed package provider source cleanup uncertain; parent retained')
        if primary is not None and created is not None and sys.modules.get(name) is created:
            del sys.modules[name]
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        raise SharedUpgradeHold('fixed package source provider audit failed') from None
    return result


class _PreparedRunScope:
    """Live local DATA transaction only. No dispatcher or device-result writer."""
    def __init__(self, entry, cwd, args, run_directory, *, manual_execution=False):
        self.manual_execution = manual_execution
        self._open_context = (entry, cwd, tuple(args))
        self.closed = False
        self.session = None
        self.files = {}
        self._peer_evidence = {}
        self.cleanup_issues = []
        self._active_request_lease = None
        self._native_schedule_started = False
        self._cooperative_status_snapshots = False
        self._native_completions = {}
        self._package_source_owner = None
        self._package_source_owner_class = None
        self._package_source_parent = None
        self._package_source_selection = None
        self._package_source_owns = False
        self._package_source_borrowers = set()
        self._package_source_lifecycle_failure = None
        self._native_component_canaries = {}
        self.run_directory = Path(run_directory)
        try:
            self.parsed = parse_prepare_args(entry, cwd, args)
            self.run_id = self.run_directory.name
            if not _valid_run_name(self.run_id):
                raise ValueError("original private run nonce required")
            paths = replace(self.parsed.paths, output_path=str(Path(self.parsed.paths.output_path).parent / self.run_id))
            managed = stat.S_ISLNK(os.lstat(paths.global_path).st_mode)
            self.session = _selected_opener(self.parsed)(paths)
            snapshot = _selected_inventory(self.session, self.parsed)
            if not snapshot.devices:
                raise ValueError("no eligible IB targets; all selected devices have invalid eth0 identity inputs")
            self.policy = normalize_upgrade(load_global_text(snapshot.global_text), selected=self.parsed.selected,
                                            method=self.parsed.method, package_dir=self.parsed.package_dir)
            self.devices = {item.hostname: item for item in snapshot.devices}
            anchor, relative = _artifact_output_location(self.session, paths)
            if self.run_directory != anchor / relative / self.run_id:
                raise ValueError("run is outside original live input output binding")
            self.namespace_parents = [self.session._directory(anchor)]
            prefix = anchor
            for name in relative.parts:
                prefix /= name
                self.namespace_parents.append(self.session._directory(prefix))
            for parent in self.namespace_parents:
                _OutputScope._safe_directory(os.fstat(parent.fd))
            self.directory = self.session._directory(self.run_directory)
            self._private_directory(self.directory)
            expected_plan = _json_bytes(_declared_plan(self.parsed, paths, self.session, snapshot,
                                                     self.policy, self.run_id, entry, cwd))
            plan = self._hold(self.directory, "plan.json", expected_plan)
            self._hold(self.directory, "input-inventory.csv", self.session._files[0].payload)
            self._hold(self.directory, "input-global.yaml", self.session._files[1].payload)
            expected_evidence = {"state": "DECLARED_CANDIDATES_NOT_EXECUTED", "run_id": self.run_id,
                "source_identities": [list(source.identity) for source in self.session._files],
                "source_names": [str(source.directory.path / source.name) for source in self.session._files],
                "artifacts": {name: hashlib.sha256(payload).hexdigest() for name, payload in (
                    ("plan.json", expected_plan), ("input-inventory.csv", self.session._files[0].payload),
                    ("input-global.yaml", self.session._files[1].payload))}}
            self._hold(self.directory, "evidence.json", _json_bytes(expected_evidence))
            self.plan_sha256 = hashlib.sha256(plan.payload).hexdigest()
            self.verify()
        except BaseException as original:
            try:
                self.close()
            except BaseException as cleanup:
                if not any(issue is cleanup for issue in self.cleanup_issues):
                    self.cleanup_issues.append(cleanup)
                # Keep an original operator interruption; a new cleanup
                # interruption must not become an ordinary constructor HOLD.
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise

    @staticmethod
    def _private_directory(directory):
        _OutputScope._safe_directory(os.fstat(directory.fd))
        if stat.S_IMODE(os.fstat(directory.fd).st_mode) != 0o700:
            raise ValueError("private node/stage/run directory must be 0700")

    def freeze_package_sources(self, selections, *, deadline, max_fds):
        """Freeze explicit LOCAL declaration sources, not device-current authority."""
        self.verify()
        provider, package_content_owner, owner_class = _fixed_package_source_api(self)
        if (not self.manual_execution or self.parsed.method != 'local'
                or self._native_schedule_started or self._package_source_owner is not None
                or self._package_source_parent is not None
                or type(selections) is not tuple or not selections):
            raise SharedUpgradeHold('original parent LOCAL source DATA selection required')
        selected, paths = [], set()
        for row in selections:
            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                    or type(row[1]) is not int or row[0] not in self.parsed.selected):
                raise SharedUpgradeHold('original selected component/index required')
            selected.append(row)
            paths.update(Path(p.path) for p in self._package_source_packages(*row))
        if len(set(selected)) != len(selected):
            raise SharedUpgradeHold('duplicate source stage selection')
        if (sys.modules.get('ibsw_upgrade_scp') is not provider
                or vars(provider).get('package_content_owner') is not package_content_owner
                or vars(provider).get('_PackageContentOwner') is not owner_class):
            raise SharedUpgradeHold('original package provider changed before factory')
        try:
            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),
                                          deadline=deadline, max_fds=max_fds)
        except BaseException:
            # The real constructor owns any partial originals/cleanup. No owner
            # returned to adopt; revoke this parent group before another freeze.
            if self._package_source_lifecycle_failure is None:
                self._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original package source acquisition failed; parent group retained')
            raise  # Preserve the original error/NI object and its existing cause.
        # Register the actual owner before any later verification can fail.
        self._package_source_owner = owner
        self._package_source_owner_class = owner_class
        self._package_source_owns = True
        self._package_source_selection = (tuple(sorted(selected)), self.policy,
                                         self.run_directory, self.plan_sha256)
        try:
            self.verify()
        except BaseException as original:
            try:
                owner.close()
            except BaseException as cleanup:
                self.cleanup_issues.append(cleanup)
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise
        return owner

    def freeze_scp_package_sources(self, selections, *, deadline, max_fds):
        """Freeze explicit SCP declaration sources, never native dispatch permission."""
        self.verify()
        provider, package_content_owner, owner_class = _fixed_package_source_api(self)
        if (not self.manual_execution or self.parsed.method != 'scp'
                or self._native_schedule_started or self._package_source_owner is not None
                or self._package_source_parent is not None
                or type(selections) is not tuple or not selections):
            raise SharedUpgradeHold('original parent SCP source DATA selection required')
        selected, paths = [], set()
        for row in selections:
            if (type(row) is not tuple or len(row) != 2 or type(row[0]) is not str
                    or type(row[1]) is not int or row[0] not in self.parsed.selected):
                raise SharedUpgradeHold('original selected component/index required')
            selected.append(row)
            paths.update(Path(p.path) for p in self._package_source_packages(*row))
        if len(set(selected)) != len(selected):
            raise SharedUpgradeHold('duplicate source stage selection')
        if (sys.modules.get('ibsw_upgrade_scp') is not provider
                or vars(provider).get('package_content_owner') is not package_content_owner
                or vars(provider).get('_PackageContentOwner') is not owner_class):
            raise SharedUpgradeHold('original package provider changed before factory')
        try:
            owner = package_content_owner(self.policy.package_dir, tuple(sorted(paths)),
                                          deadline=deadline, max_fds=max_fds)
        except BaseException:
            # The real constructor owns any partial originals/cleanup. No owner
            # returned to adopt; revoke this parent group before another freeze.
            if self._package_source_lifecycle_failure is None:
                self._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original package source acquisition failed; parent group retained')
            raise  # Preserve the original error/NI object and its existing cause.
        # Register the actual owner before any later verification can fail.
        self._package_source_owner = owner
        self._package_source_owner_class = owner_class
        self._package_source_owns = True
        self._package_source_selection = (tuple(sorted(selected)), self.policy,
                                         self.run_directory, self.plan_sha256)
        try:
            self.verify()
        except BaseException as original:
            try:
                owner.close()
            except BaseException as cleanup:
                self.cleanup_issues.append(cleanup)
                if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    raise
            raise
        return owner

    def _package_source_packages(self, component, index):
        if component not in self.parsed.selected or type(index) is not int:
            raise SharedUpgradeHold('foreign declared package source stage')
        if component == 'os' and 0 <= index < len(self.policy.os):
            return (self.policy.os[index],)
        if index == 0 and component == 'bios' and self.policy.bios is not None:
            return (self.policy.bios,)
        if index == 0 and component == 'cpld' and self.policy.cpld_burn is not None and self.policy.cpld_refresh is not None:
            return (self.policy.cpld_burn, self.policy.cpld_refresh)
        raise SharedUpgradeHold('foreign declared source index')

    def _verify_package_source_owner(self):
        if self._package_source_lifecycle_failure is not None:
            raise self._package_source_lifecycle_failure
        owner = self._package_source_owner
        if owner is None:
            return
        parent = self if self._package_source_owns else self._package_source_parent
        if type(parent) is _PreparedRunScope and parent._package_source_lifecycle_failure is not None:
            raise parent._package_source_lifecycle_failure
        if (type(parent) is not _PreparedRunScope
                or self._package_source_owner_class is not parent._package_source_owner_class
                or type(owner) is not parent._package_source_owner_class
                or parent.closed or parent.cleanup_issues or not parent._package_source_owns
                or parent._package_source_owner is not owner
                or self._package_source_selection is not parent._package_source_selection
                or self._package_source_selection[1:] != (self.policy, self.run_directory, self.plan_sha256)
                or (parent is not self and (getattr(self, '_readiness_parent', None) is not parent
                    or getattr(self, '_readiness_node', None) not in self.devices))):
            raise SharedUpgradeHold('original parent source owner/borrow changed')
        # No parent.verify recursion and no source descriptor reopening.
        owner.verify()

    def _capture_package_source_data_locked(self, leaf, component, package_index):
        """Persist original LOCAL prelaunch DATA. No SCP wire/launch/ACK."""
        if (self._active_request_lease is None or self.closed or not self.manual_execution
                or self.parsed.method != 'local' or type(leaf) is not _ReadonlyQueryInputs
                or leaf.scope is not self or leaf._original_selection[0] is not self
                or self._package_source_parent is None
                or getattr(self, '_readiness_node', None) != leaf.node.hostname):
            raise SharedUpgradeHold('original leased child DATA scope required')
        try:
            self._verify_package_source_owner()
            if (component, package_index) not in self._package_source_selection[0]:
                raise SharedUpgradeHold('unfrozen source stage')
            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)
            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
            held = {name: self._hold(stage, name) for name in names}
            packages = {}
            for package in self._package_source_packages(component, package_index):
                row = self._package_source_owner._files.get(Path(package.path))
                if row is None or type(row[4]) is not str:
                    raise SharedUpgradeHold('original package not retained by parent')
                packages[package.path] = dict(size=row[3][6], sha256=row[4])
            document = dict(schema_version=1, state='PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY',
                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,
                declared_method='local', originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()
                    for name, obj in held.items()}, packages=packages)
            payload = _json_bytes(document)
            originals = {name: obj.payload for name, obj in held.items()}
            originals['package-source.json'] = payload
            _validate_package_source_data_graph(set(originals), binding, originals.__getitem__)
            self.verify(); leaf.verify()
            if 'package-source.json' in os.listdir(stage.fd):
                self._hold(stage, 'package-source.json', payload)
            else:
                self._commit_exclusive_binding(stage, payload, 'package-source.json')
            self.verify(); leaf.verify()
            return None

        except BaseException:
            # Revoke this entire original source group, without altering the
            # primary exception object/cause or adopting any persisted DATA.
            parent = self._package_source_parent
            if (type(parent) is _PreparedRunScope
                    and getattr(self, '_readiness_parent', None) is parent
                    and self._package_source_owner is not None
                    and self._package_source_owner is parent._package_source_owner):
                if parent._package_source_lifecycle_failure is None:
                    parent._package_source_lifecycle_failure = SharedUpgradeHold(
                        'original source companion capture uncertain; shared group retained')
                if self._package_source_lifecycle_failure is None:
                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure
            raise

    def _capture_scp_request_content_locked(self, leaf, component, package_index):
        """Persist original SCP request content DATA. No wire/launch/ACK."""
        if (self._active_request_lease is None or self.closed or not self.manual_execution
                or self.parsed.method != 'scp' or type(leaf) is not _ReadonlyQueryInputs
                or leaf.scope is not self or leaf._original_selection[0] is not self
                or self._package_source_parent is None
                or getattr(self, '_readiness_node', None) != leaf.node.hostname):
            raise SharedUpgradeHold('original leased SCP child DATA scope required')
        try:
            self._verify_package_source_owner()
            if (component, package_index) not in self._package_source_selection[0]:
                raise SharedUpgradeHold('unfrozen source stage')
            stage, binding, args = self._owned_runner_stage(leaf, component, package_index)
            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
            held = {name: self._hold(stage, name) for name in names}
            packages = {}
            for package in self._package_source_packages(component, package_index):
                row = self._package_source_owner._files.get(Path(package.path))
                if row is None or type(row[4]) is not str:
                    raise SharedUpgradeHold('original package not retained by parent')
                packages[package.path] = dict(size=row[3][6], sha256=row[4])
            document = dict(schema_version=2, state='SCP_REQUEST_CONTENT_DATA_ONLY',
                execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,
                declared_method='scp', request_id=json.loads(held['request.json'].payload)['request_id'],
                originals_sha256={name: hashlib.sha256(obj.payload).hexdigest()
                    for name, obj in held.items()}, packages=packages)
            payload = _json_bytes(document)
            originals = {name: obj.payload for name, obj in held.items()}
            originals['scp-source-request.json'] = payload
            _validate_scp_request_content_graph(set(originals), binding, originals.__getitem__)
            self.verify(); leaf.verify()
            if 'scp-source-request.json' in os.listdir(stage.fd):
                self._hold(stage, 'scp-source-request.json', payload)
            else:
                self._commit_exclusive_binding(stage, payload, 'scp-source-request.json')
            self.verify(); leaf.verify()
            return None

        except BaseException:
            # Revoke this entire original source group, without altering the
            # primary exception object/cause or adopting any persisted DATA.
            parent = self._package_source_parent
            if (type(parent) is _PreparedRunScope
                    and getattr(self, '_readiness_parent', None) is parent
                    and self._package_source_owner is not None
                    and self._package_source_owner is parent._package_source_owner):
                if parent._package_source_lifecycle_failure is None:
                    parent._package_source_lifecycle_failure = SharedUpgradeHold(
                        'original SCP request content capture uncertain; shared group retained')
                if self._package_source_lifecycle_failure is None:
                    self._package_source_lifecycle_failure = parent._package_source_lifecycle_failure
            raise

    def fork_readiness_scope(self, node, source_baselines=()):
        """Independent startup owner; never concurrently mutate parent maps."""
        if self.closed or self._native_schedule_started or node not in self.devices:
            raise SharedUpgradeHold('startup scope is outside the original pre-upgrade selection')
        # A source-group failure rejects another borrower before any child FD opens.
        self._verify_package_source_owner()
        child = _PreparedRunScope(*self._open_context, self.run_directory,
                                  manual_execution=self.manual_execution)
        try:
            if (child.plan_sha256 != self.plan_sha256 or child.policy != self.policy
                    or [(p.identity,p.payload) for p in child.session._files] !=
                       [(p.identity,p.payload) for p in self.session._files]):
                raise SharedUpgradeHold('startup worker original inputs differ from parent')
            child._readiness_parent, child._readiness_node = self, node
            child._os_source_baselines = dict(source_baselines)
            if self._package_source_owner is not None:
                child._package_source_owner = self._package_source_owner
                child._package_source_owner_class = self._package_source_owner_class
                child._package_source_parent = self
                child._package_source_selection = self._package_source_selection
                self._package_source_borrowers.add(child)
                child._verify_package_source_owner()
            return child
        except BaseException as original:
            try:
                child.close()
            except BaseException as cleanup:
                if isinstance(original,Exception) and not isinstance(cleanup,Exception): raise
            raise

    def adopt_readiness_scope(self, child, node):
        """Parent-only move of ORIGINAL FD owners, not reopening saved DATA.

        Only this run's startup route/access artifacts may be transferred.
        Common source/plan FDs remain independently owned; closing the worker
        cannot invalidate the parent's moved evidence or original directories.
        """
        try:
            self.verify(); child.verify()
            if (type(child) is not _PreparedRunScope or child is self
                    or getattr(child,'_readiness_parent',None) is not self
                    or getattr(child,'_readiness_node',None) != node
                    or self._native_schedule_started or child._native_schedule_started
                    or self._active_request_lease is not None or child._active_request_lease is not None
                    or child.run_directory != self.run_directory or child.plan_sha256 != self.plan_sha256
                    or child.policy != self.policy or child.manual_execution != self.manual_execution
                    or [(p.identity,p.payload) for p in child.session._files] !=
                       [(p.identity,p.payload) for p in self.session._files]):
                raise ValueError('foreign or inactive startup evidence scope')
            prefix = self.run_directory / node
            moving = {key:held for key,held in child.files.items() if Path(key[0]).is_relative_to(prefix)}
            for key,held in moving.items():
                relative = (Path(key[0])/key[1]).relative_to(prefix)
                if not (relative.parts in (('os-route-plan.json',),('startup-diagnostics.json',),('ssd-preflight.json',)) or
                        (relative.parts[0] == 'ssh-access' and len(relative.parts) in (2,3)
                         and relative.name in ('authorized_keys.before','access-backup.json',
                                               'access-bootstrap.json','access-bootstrap-result.json'))):
                    raise ValueError('non-startup artifact cannot be adopted')
                if key in self.files:
                    raise ValueError('duplicate startup target evidence')
                held.verify()
            routes = getattr(child,'_frozen_os_routes',{})
            if any(name != node for name in routes) or node in getattr(self,'_frozen_os_routes',{}):
                raise ValueError('duplicate or foreign frozen startup route')
            baselines = dict(getattr(self,'_os_source_baselines',{}))
            from ibsw_upgrade_executor import _package_source_snapshot, _PackageSourceHold
            for path,snapshot in getattr(child,'_os_source_baselines',{}).items():
                packages = [package for package in self.policy.os if package.path == path]
                if len(packages) != 1:
                    raise ValueError('foreign package in startup source baseline')
                try:
                    actual = _package_source_snapshot(self.policy.package_dir,packages[0])
                except _PackageSourceHold as error:
                    raise _PackageSourceHold('PACKAGE_SOURCE_CHANGED',path) from error
                if (path in baselines and baselines[path] != snapshot) or actual != snapshot:
                    raise _PackageSourceHold('PACKAGE_SOURCE_CHANGED',path)
                baselines[path] = snapshot
            if routes:
                original = moving[(str(prefix),'os-route-plan.json')]
                if original.payload != _json_bytes(routes[node]):
                    raise ValueError('frozen route differs from original startup evidence')
            # All identities/paths/source consistency checked before a move.
            for key,held in moving.items():
                directory_key = str(held.directory.path)
                parent_directory = self.session._directories.get(directory_key)
                if parent_directory is None:
                    self.session._directories[directory_key] = child.session._directories.pop(directory_key)
                else:
                    parent_directory.verify(); held.directory.verify()
                    if parent_directory.fd != held.directory.fd:
                        raise ValueError('startup original directory FD changed')
                    held.directory = parent_directory
                self.files[key] = child.files.pop(key)
            if routes:
                if not hasattr(self,'_frozen_os_routes'): self._frozen_os_routes = {}
                self._frozen_os_routes[node] = routes[node]
            self._os_source_baselines = baselines
            self._health_overrides=getattr(self,'_health_overrides',[])+getattr(child,'_health_overrides',[])
            self._health_checks=getattr(self,'_health_checks',[])+getattr(child,'_health_checks',[])
            self.verify(); child.verify()
        except Exception as error:
            from ibsw_upgrade_executor import _PackageSourceHold
            if isinstance(error,_PackageSourceHold): raise
            raise SharedUpgradeHold('startup original evidence/source transfer failed; no component dispatch') from error

    def _record_startup_diagnostic(self,node,error):
        return self._record_query_failure(node,error,startup=True)

    def _record_health_preflight(self):
        """One parent-only, immutable raw health journal, not an admission token.

        One run-level file avoids retaining one extra descriptor per device or
        query. Later component health bytes also remain in their original stage
        evidence and run-report.health_checks; no new SSH query is issued here.
        This is a batch journal: at most one original STARTUP observation per
        selected device, not a component's bounded command trace. Validate every
        record separately and retain the existing bounded local-file size.
        """
        try:
            self.verify()
            original=getattr(self,'_health_checks',[])
            if not isinstance(original,(tuple,list)) or len(original)>len(self.devices):
                raise ValueError('startup health count exceeds original selected devices')
            checks=list(original)
            if not checks: return None
            if self._native_schedule_started:
                raise ValueError('original fixed startup health records required')
            seen=set()
            for record in checks:
                if (type(record) is not dict or type(record.get('hostname')) is not str or
                        record['hostname'] not in self.devices or record['hostname'] in seen or
                        record.get('phase')!='STARTUP'):
                    raise ValueError('one original startup health observation per selected device required')
                raw=record.get('raw_record')
                _component_raw_records([raw])
                if raw['command']!='nv show system health':
                    raise ValueError('only original fixed startup health query records required')
                seen.add(record['hostname'])
            payload=_json_bytes(dict(schema_version=1,
                state='HEALTH_PREFLIGHT_OBSERVATION_ONLY',execution_state='NOT_EXECUTED',
                run_id=self.run_id,plan_sha256=self.plan_sha256,
                input_sha256=[hashlib.sha256(p.payload).hexdigest() for p in self.session._files],
                checks=checks))
            if len(payload)>MAXIMUM_INPUT_BYTES:
                raise ValueError('bounded original startup health journal bytes required')
            with self._request_namespace_lease():
                self._commit_exclusive_binding(self.directory,payload,'health-preflight.json')
            return 'health-preflight.json'
        except Exception as error:
            raise SharedUpgradeHold('HEALTH_PREFLIGHT_EVIDENCE_SAVE_FAILED') from error

    def _record_install_precheck_failure(self,node,error):
        return self._record_query_failure(node,error,startup=False)

    def _record_startup_ssd(self,node,records,check):
        """One bounded local raw observation file, never a native write token."""
        from ibsw_upgrade_executor import _raw_record
        try:
            self.verify()
            if (node not in self.devices or self._native_schedule_started
                    or getattr(self,'_readiness_node',None)!=node or type(records) is not tuple
                    or len(records)!=2 or any(type(r) is not _ReadonlyQueryRecord for r in records)
                    or tuple(r.argv for r in records)!=tuple(argv for _,argv in _QUERY_DATA_SPECS)
                    or type(check) is not dict or check.get('verification_basis')!='PREFLIGHT_OS_AT_TARGET'):
                raise ValueError('original fixed startup SSD observation required')
            rows=[_raw_record(' '.join(r.argv),(r.stdout,r.stderr,r.returncode,r.returncode is not None)) for r in records]
            _component_raw_records(rows)
            with self._request_namespace_lease():
                path=self.run_directory/node
                if not path.exists(): os.mkdir(path,0o700)
                directory=self.session._directory(path); self._private_directory(directory)
                self._commit_exclusive_binding(directory,_json_bytes(dict(schema_version=1,
                    state='SSD_PREFLIGHT_OBSERVATION_ONLY',execution_state='NOT_EXECUTED',
                    run_id=self.run_id,node=asdict(self.devices[node]),plan_sha256=self.plan_sha256,
                    input_sha256=[hashlib.sha256(source.payload).hexdigest() for source in self.session._files],
                    query_records=rows,observation=check)),'ssd-preflight.json')
            return node+'/ssd-preflight.json'
        except Exception as error:
            raise SharedUpgradeHold('SSD_PREFLIGHT_EVIDENCE_SAVE_FAILED; no component dispatch') from error

    def _record_query_failure(self,node,error,*,startup):
        """Private raw read-only failure evidence; never an admission token."""
        records=getattr(error,'records',())
        from ibsw_upgrade_access import AccessHold
        access_diagnostic=error.diagnostic if isinstance(error,AccessHold) else None
        if not records and access_diagnostic is None: return None
        if (node not in self.devices or (startup and (self._native_schedule_started or
                getattr(self,'_readiness_node',None)!=node)) or (not startup and not self._native_schedule_started)):
            raise SharedUpgradeHold('foreign startup diagnostic target')
        from ibsw_upgrade_executor import _raw_record
        rows=[]
        for record in records:
            if type(record) is not _ReadonlyQueryRecord: raise SharedUpgradeHold('invalid startup raw diagnostic')
            raw=_raw_record(' '.join(record.argv),(record.stdout,record.stderr,record.returncode,
                                                  record.returncode is not None))
            capture=getattr(error,'capture_raw',None)
            captured=capture.get('query_record') if type(capture) is dict else None
            if type(captured) is dict and captured.get('command')==raw['command']:
                _component_raw_records([captured])
                if any(captured[key]!=raw[key] for key in raw if key!='stream_complete'):
                    raise SharedUpgradeHold('original query diagnostic bytes differ')
                raw=captured
            rows.append(raw)
        with self._request_namespace_lease():
            path=self.run_directory/node
            if not path.exists(): os.mkdir(path,0o700)
            directory=self.session._directory(path); self._private_directory(directory)
            payload=_json_bytes(dict(schema_version=1,state='PREFLIGHT_FAILURE_DATA_ONLY',hostname=node,
                reason_code=getattr(error,'reason_code','READONLY_QUERY_FAILED'),query_records=rows,
                access_diagnostic=access_diagnostic,
                safe_diagnostic=(getattr(error,'capture_raw',None) or {}).get('safe_diagnostic',{})
                    if type(getattr(error,'capture_raw',None)) is dict else {}))
            self._commit_exclusive_binding(directory,payload,'startup-diagnostics.json' if startup else 'pre-install-diagnostics.json')
        return str(path)

    def _hold(self, directory, name, expected=None, *, allow_empty=False):
        if type(allow_empty) is not bool or (allow_empty and name not in ("stdout.bin", "stderr.bin") + _EMPTY_STAGE_DATA_RAW):
            raise ValueError("empty artifact policy is restricted to raw query outputs")
        key = (str(directory.path), name)
        if key not in self.files:
            held = _HeldFile(directory.path / name, directory, allow_empty=allow_empty)
            self.files[key] = held
        held = self.files[key]
        held.verify()
        metadata = os.fstat(held.fd)
        if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
                or stat.S_IMODE(metadata.st_mode) != 0o600):
            raise ValueError("original private artifact ownership required")
        if expected is not None and held.payload != expected:
            raise ValueError("original prepared plan/input/script bytes do not match live declaration")
        return held

    def verify(self):
        if self.closed or self.session is None:
            raise ValueError("prepared run scope is closed")
        if self.cleanup_issues:
            raise ValueError("HOLD: unknown journal cleanup residue; scope cannot be reused")
        self._verify_package_source_owner()
        self.session.verify()
        for held in self.files.values():
            held.verify()
        self.session.verify()
        for held in self.files.values():
            held.verify_identity()
        for evidence in self._peer_evidence.values():
            evidence.verify()
        if self._active_request_lease is not None:
            self._active_request_lease.verify()

    @contextmanager
    def _request_namespace_lease(self):
        # Separate original-FD scopes may share one namespace in this process.
        # Serialize journal transactions, not remote completion/reboot waits.
        with _LOCAL_REQUEST_LOCK:
            with self._request_namespace_lease_unlocked() as lease:
                yield lease

    def enable_cooperative_status_snapshots(self):
        """Status is a lease-scoped negative snapshot, never a positive grant.

        Only the fixed in-process parallel coordinator uses this mode. Immutable
        plans, source FDs, requests, dispatch/completion and evidence stay held.
        Default/legacy scopes retain their original long-lived status binding.
        """
        self.verify()
        self._cooperative_status_snapshots = True

    @contextmanager
    def _request_namespace_lease_unlocked(self):
        self.verify()
        if self._active_request_lease is not None:
            raise PreparationHold("nested request namespace lease is unsupported")
        if self.manual_execution:
            lease = _ManualJournalTransaction()
        else:
            parent = self.namespace_parents[-1]
            lease = _RequestNamespaceLease(parent.fd, parent.edges[-1][3])
        self._active_request_lease = lease
        try:
            self.verify()
            yield lease
            self.verify()
        finally:
            original = sys.exc_info()[1]
            status_cleanup = None
            if self._cooperative_status_snapshots:
                try:
                    status_names = {name + "-status.json" for name in COMPONENT_REGISTRY}
                    for key in list(self.files):
                        if key[1] in status_names:
                            held = self.files[key]
                            held.verify()
                            held.close()
                            del self.files[key]
                except BaseException as cleanup:
                    self.cleanup_issues.append(cleanup)
                    status_cleanup = cleanup
            self._active_request_lease = None
            try:
                lease.close()
            except BaseException as cleanup:
                self.cleanup_issues.append(cleanup)
                if status_cleanup is None or (isinstance(status_cleanup, Exception) and not isinstance(cleanup, Exception)):
                    status_cleanup = cleanup
            if status_cleanup is not None and (original is None or
                    (isinstance(original, Exception) and not isinstance(status_cleanup, Exception))):
                raise status_cleanup

    def _check_retained_requests_locked(self, node):
        """Legacy history is not a gate for an explicitly started manual run."""
        if self.manual_execution:
            self.verify()
            if node not in self.devices:
                raise ValueError("target is outside the current manual run")
            return
        self._inventory_requests_locked(node)

    def component_attempt_may_have_started(self, node, component):
        """Inspect only THIS run for a request; never interpret older history.

        A request or dispatch is uncertain even if publication or launch later
        raised. Any unreadable current evidence also remains conservative.
        """
        self.verify()
        if not self.manual_execution:
            return True
        if node not in self.devices or component not in self.parsed.selected:
            raise SharedUpgradeHold("current selected node/component required")
        try:
            os.stat(node, dir_fd=self.directory.fd, follow_symlinks=False)
        except FileNotFoundError:
            return False
        node_directory = self.session._directory(self.run_directory / node)
        self._private_directory(node_directory)
        stages = ([declared_step_key(self.policy, component, index) for index in range(len(self.policy.os))]
                  if component == "os" else [component])
        for stage in stages:
            try:
                os.stat(stage, dir_fd=node_directory.fd, follow_symlinks=False)
            except FileNotFoundError:
                continue
            directory = self.session._directory(node_directory.path / stage)
            self._private_directory(directory)
            for name in ("request.json", "component-dispatch.json", "os-dispatch.json"):
                try:
                    os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                return True
        self.verify()
        return False

    def _inventory_requests_locked(self, node):
        """Read retained history in this original namespace, never current-stat filter.

        Negative inventory is private to this held lease, not a native permission
        or proof about removed history/different roots. Never repair/clear records.
        """
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        namespace = self.namespace_parents[-1]
        entry_count, byte_count = 0, 0
        observed = []
        target = self.devices[node]

        def names(directory):
            nonlocal entry_count
            result = set(os.listdir(directory.fd))
            entry_count += len(result)
            limit = max(512, min(16384, 64 * len(self.devices))) if self._cooperative_status_snapshots else 512
            if entry_count > limit:
                raise ValueError("bounded request inventory exceeded; do not truncate history")
            observed.append((directory, result))
            return result

        def directory(parent, name):
            result = self.session._directory(parent.path / name)
            self._private_directory(result)
            return result

        def raw(parent, name, *, allow_empty=False):
            nonlocal byte_count
            metadata = os.stat(name, dir_fd=parent.fd, follow_symlinks=False)
            byte_count += metadata.st_size
            if byte_count > 16 * 1024 * 1024:
                raise ValueError("bounded request bytes exceeded; history is not empty")
            return self._hold(parent, name, allow_empty=allow_empty).payload

        def document(payload):
            result = json.loads(payload)
            if not isinstance(result, dict) or _json_bytes(result) != payload:
                raise ValueError("unknown/noncanonical original journal object")
            return result

        try:
            run_names = names(namespace)
            if _REQUEST_LOCK_NAME not in run_names:
                raise ValueError("original request namespace marker missing")
            for run_name in sorted(run_names - {_REQUEST_LOCK_NAME}):
                if not _valid_run_name(run_name):
                    raise ValueError("unknown retained namespace entry")
                run = directory(namespace, run_name)
                members = names(run)
                baseline = {"plan.json", "input-inventory.csv", "input-global.yaml", "evidence.json"}
                if not baseline.issubset(members):
                    raise ValueError("partial original prepared run")
                plan_bytes = raw(run, "plan.json")
                csv_bytes, global_bytes = raw(run, "input-inventory.csv"), raw(run, "input-global.yaml")
                plan, evidence = document(plan_bytes), document(raw(run, "evidence.json"))
                parsed = parse_prepare_args(plan["entry"], plan["cwd"], tuple(plan["argv"]))
                snapshot = select_inventory_devices(
                    snapshot_inventory(csv_bytes.decode("utf-8-sig"), global_bytes.decode("utf-8-sig")),
                    parsed.devices_pattern)
                policy = normalize_upgrade(load_global_text(snapshot.global_text), selected=parsed.selected,
                    method=parsed.method, package_dir=parsed.package_dir)
                devices = {item.hostname: item for item in snapshot.devices}
                paths = replace(parsed.paths, output_path=str(Path(parsed.paths.output_path).parent / run_name))
                expected_plan_keys = set(json.loads(self.files[(str(self.run_directory), "plan.json")].payload)) - {"exclusive_config_window", "skipped_devices"}
                if parsed.exclusive_config_window:
                    expected_plan_keys.add("exclusive_config_window")
                if snapshot.blocked_devices:
                    expected_plan_keys.add("skipped_devices")
                if (set(plan) != expected_plan_keys
                        or plan.get("exclusive_config_window", False) is not parsed.exclusive_config_window
                        or plan["run_id"] != run_name or plan["state"] != "DECLARED_CANDIDATES_NOT_EXECUTED"
                        or plan["execution_state"] != "NOT_EXECUTED" or plan["observations"] != "UNKNOWN"
                        or plan["script_state"] != "OPEN" or plan["input_paths"] != asdict(paths)
                        or plan["devices"] != [asdict(item) for item in snapshot.devices]
                        or _json_bytes(plan.get("skipped_devices", [])) != _json_bytes([asdict(item) for item in snapshot.blocked_devices])
                        or _json_bytes(plan["policy"]) != _json_bytes(_policy_document(policy)) or plan["method"] != parsed.method
                        or plan["selected"] != list(parsed.selected) or plan["switch_dir"] != parsed.switch_dir
                        or plan["canary_mode"] != parsed.canary_mode):
                    raise ValueError("original plan does not match its retained raw inputs")
                digests = {name: hashlib.sha256(payload).hexdigest() for name, payload in (
                    ("plan.json", plan_bytes), ("input-inventory.csv", csv_bytes), ("input-global.yaml", global_bytes))}
                if (set(evidence) != {"state", "run_id", "source_identities", "source_names", "artifacts"}
                        or evidence["state"] != "DECLARED_CANDIDATES_NOT_EXECUTED" or evidence["run_id"] != run_name
                        or evidence["artifacts"] != digests or not isinstance(evidence["source_identities"], list)
                        or len(evidence["source_identities"]) != 2 or not isinstance(evidence["source_names"], list)
                        or len(evidence["source_names"]) != 2
                        or any(not isinstance(identity, list) or len(identity) != len(self.session._files[0].identity)
                               or any(type(value) is not int for value in identity) for identity in evidence["source_identities"])
                        or any(not isinstance(name, str) or not name.startswith("/") or name != posixpath.normpath(name)
                               for name in evidence["source_names"])):
                    raise ValueError("original evidence/raw hash graph incomplete")
                status_names = {component + "-status.json" for component in parsed.selected}
                registry_status = {component + "-status.json" for component in COMPONENT_REGISTRY}
                if _package_project_identity(os.fstat(run.fd)) == _package_project_identity(os.fstat(self.directory.fd)):
                    # Only this ORIGINAL held run: only-mode must neither read
                    # nor be blocked by another component's fixed status name.
                    # Prior runs keep their original strict history contract.
                    members = members - (registry_status - status_names)
                present_status = members & registry_status
                if present_status:
                    if present_status != status_names:
                        raise ValueError("partial/unselected historical component lists")
                    for component in parsed.selected:
                        status = document(raw(run, component + "-status.json"))
                        initial = component_status_document(component, run_name, digests["plan.json"],
                            [digests["input-inventory.csv"], digests["input-global.yaml"]],
                            [asdict(item) for item in snapshot.devices],
                            snapshot.devices[0].hostname if parsed.canary_mode == "default" else None)
                        if status.get("schema_version") in (2, 3):
                            initial.update(schema_version=status['schema_version'], execution_state="OBSERVATION_FACTS_ONLY")
                            if status['schema_version'] == 3:
                                initial.update(canaries=[initial['canary']] if initial['canary'] is not None else [], canary_routes=[])
                            validate_native_component_status_document(status, initial)
                        else:
                            validate_component_status_document(status, initial)
                        for row in status["targets"]:
                            same = (row["node"]["hostname"].casefold() == target.hostname.casefold(),
                                    row["node"]["mac"] == target.mac, row["node"]["address"] == target.address)
                            for reference in row["evidence"]:
                                if self._cooperative_status_snapshots and not any(same):
                                    continue  # This target cannot reuse another device's evidence.
                                parts = reference["path"].split("/")
                                original_stage = directory(directory(run, parts[0]), parts[1])
                                if hashlib.sha256(raw(original_stage, parts[2])).hexdigest() != reference["sha256"]:
                                    raise ValueError("original component evidence drift")
                            if row["manual_required"] and any(same):
                                raise PreparationHold("UNKNOWN/manual component review for retained target", self.run_directory)
                    members = members - status_names
                # Old source identities/names describe history only. No reopening
                # old project inputs, nor comparison with current input stat.
                for hostname in sorted(members - baseline):
                    if hostname not in devices:
                        raise ValueError("unknown historical node")
                    historical = devices[hostname]
                    if self._cooperative_status_snapshots and not any((
                            historical.hostname.casefold() == target.hostname.casefold(),
                            historical.mac == target.mac, historical.address == target.address)):
                        continue  # That device validates its own private stages before dispatch.
                    node_dir = directory(run, hostname)
                    stages = names(node_dir)
                    if not stages:
                        raise ValueError("partial original node directory")
                    if "queries" in stages:
                        collection = directory(node_dir, "queries")
                        rounds = names(collection)
                        if not rounds:
                            raise ValueError("partial original query collection")
                        for query_id in sorted(rounds):
                            if not re.fullmatch(r"query-[0-9a-f]{32}", query_id):
                                raise ValueError("unknown original query round")
                            query = directory(collection, query_id)
                            binding = document(raw(query, "query-binding.json"))
                            specs = _query_round_specs(binding.get("schema_version"))
                            if names(query) != {"query-binding.json"} | {label for label, _argv in specs}:
                                raise ValueError("partial/unknown original query round")
                            result_hashes = {}
                            for label, argv in specs:
                                output = directory(query, label)
                                if names(output) != {"stdout.bin", "stderr.bin", "result.json"}:
                                    raise ValueError("partial original query output")
                                stdout = raw(output, "stdout.bin", allow_empty=True)
                                stderr = raw(output, "stderr.bin", allow_empty=True)
                                result_bytes = raw(output, "result.json")
                                result = document(result_bytes)
                                record = record_readonly_query(argv, stdout, stderr, result["returncode"])
                                if result != _query_data_result(record):
                                    raise ValueError("original query result/raw hash graph changed")
                                result_hashes[label] = hashlib.sha256(result_bytes).hexdigest()
                            expected = _query_data_binding(run_name, query_id, historical, digests["plan.json"],
                                [digests["input-inventory.csv"], digests["input-global.yaml"]], result_hashes,
                                schema_version=binding["schema_version"])
                            if binding != expected:
                                raise ValueError("original query binding/raw input hash graph changed")
                            # DATA only: neither success code nor committed files
                            # parse versions, certify completeness or clear UNKNOWN.
                    for stage_key in sorted(stages - {"queries"}):
                        stage = directory(node_dir, stage_key)
                        files = names(stage)
                        if "component-preflight.json" in files:
                            request_files = files & {"step.sh", "step-binding.json", "request.json"}
                        else:
                            request_files, _phases, _has_restore, _has_patch = _stage_data_members(files)
                        script = raw(stage, "step.sh")
                        binding = document(raw(stage, "step-binding.json"))
                        component, index = binding["component"], binding["package_index"]
                        if component not in parsed.selected or declared_step_key(policy, component, index) != stage_key:
                            raise ValueError("unknown declared historical stage")
                        target_version = (policy.os[index].version if component == "os" else policy.bios.version
                            if component == "bios" else "+".join(identifier + "_" + revision for identifier, revision in policy.cpld_targets))
                        expected_binding = {"schema_version": 1, "execution_state": "NOT_EXECUTED", "run_id": run_name,
                            "node": asdict(historical), "stage": stage_key, "component": component,
                            "package_index": index, "target_version": target_version,
                            "plan_sha256": digests["plan.json"], "script_sha256": hashlib.sha256(script).hexdigest(),
                            "input_sha256": [digests["input-inventory.csv"], digests["input-global.yaml"]]}
                        if binding != expected_binding:
                            raise ValueError("original script/binding/raw hash graph changed")
                        _validate_commands_data_graph(files, binding,
                            lambda name: raw(stage, name, allow_empty=name in _EMPTY_STAGE_DATA_RAW),
                            read_postconditions=lambda: self._read_postconditions(stage, binding, policy.final_os,
                                directory, names, raw), switch_dir=parsed.switch_dir)
                        if "request.json" not in request_files:
                            continue  # Exact complete declared stage, NOT_DISPATCHED.
                        request_bytes = raw(stage, "request.json")
                        request = document(request_bytes)
                        token = request["request_id"]
                        if (not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token)
                                or request != {"schema_version": 1, "state": "REQUESTED", "activation_state": "UNKNOWN",
                                    "execution_state": "NOT_EXECUTED", "binding": binding, "request_id": token}):
                            raise ValueError("unknown original pending request")
                        same = (historical.hostname.casefold() == target.hostname.casefold(),
                                historical.mac == target.mac, historical.address == target.address)
                        if any(same):
                            if (all(same) and run.path == self.run_directory
                                    and self._completed_component_stage_is_original(stage, binding)):
                                continue
                            kind = "same target" if all(same) else "identity collision"
                            raise PreparationHold("UNKNOWN retained request " + kind + ": " + str(stage.path), self.run_directory)
            for parent, original_names in observed:
                parent.verify()
                if set(os.listdir(parent.fd)) != original_names:
                    raise ValueError("retained inventory namespace changed under lease")
            self.verify()
        except Exception as error:
            if isinstance(error, PreparationHold):
                raise
            raise PreparationHold("UNKNOWN/partial retained inventory; no new request", self.run_directory) from error

    def open_readonly_query_inputs(self, node, *, known_hosts_path, identity_path,
                                   management_public_path, user="admin"):
        return _ReadonlyQueryInputs(self, node, known_hosts_path=known_hosts_path,
            identity_path=identity_path, management_public_path=management_public_path, user=user)

    def _initial_component_status(self, component):
        if component not in self.parsed.selected:
            raise ValueError("unselected component status must not be consumed")
        return component_status_document(component, self.run_id, self.plan_sha256,
            [hashlib.sha256(source.payload).hexdigest() for source in self.session._files],
            [asdict(item) for item in self.devices.values()],
            next(iter(self.devices)) if self.parsed.canary_mode == "default" else None)

    def _initial_native_component_status(self, component, schema_version=3):
        initial = self._initial_component_status(component)
        initial.update(schema_version=schema_version, execution_state='OBSERVATION_FACTS_ONLY')
        if schema_version == 3:
            initial.update(canaries=[initial['canary']] if initial['canary'] is not None else [], canary_routes=[])
        return initial

    def initialize_component_status_data(self):
        """Explicit selected-only DATA initialization; old prepare stays unchanged."""
        with self._request_namespace_lease():
            writer = _JournalWriter(self, self.directory)
            try:
                for component in component_order(self.parsed.selected):
                    name = component + "-status.json"
                    payload = _json_bytes(self._initial_component_status(component))
                    writer.write(name, payload)
                    self._hold(self.directory, name, payload)
                os.fsync(self.directory.fd)
                self.verify()
            except Exception as error:
                raise PreparationHold("component status initialization incomplete; preserve original lists", self.run_directory) from error
            finally:
                writer.finish()

    def _read_component_status_locked(self, component):
        initial = self._initial_component_status(component)  # Selection before name/stat/open.
        self.verify()
        held = self._hold(self.directory, component + "-status.json")
        document = json.loads(held.payload)
        if _json_bytes(document) != held.payload:
            raise ValueError("noncanonical component status DATA")
        if document.get("schema_version") in (2, 3):
            initial = self._initial_native_component_status(component, document['schema_version'])
            validate_native_component_status_document(document, initial)
        else:
            validate_component_status_document(document, initial)
        for row in document["targets"]:
            for reference in row["evidence"]:
                parts = reference["path"].split("/")
                path = self.run_directory / parts[0] / parts[1]
                if self._cooperative_status_snapshots and (str(path), parts[2]) not in self.files:
                    # Other devices' references are negative transaction DATA,
                    # never a positive completion grant for this live scope.
                    # Verify original name/FD/hash, retain its full identity
                    # guard, then close the file FD. Directory originals remain
                    # shared/held; future scope.verify still detects tampering.
                    directory = self.session._directory(path)
                    self._private_directory(directory)
                    held_reference = _HeldFile(path / parts[2], directory)
                    try:
                        metadata = os.fstat(held_reference.fd)
                        if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
                                or stat.S_IMODE(metadata.st_mode) != 0o600):
                            raise ValueError('original private artifact ownership required')
                        if hashlib.sha256(held_reference.payload).hexdigest() != reference['sha256']:
                            raise ValueError('original component status evidence drift')
                        key = (str(path), parts[2])
                        original = self._peer_evidence.get(key)
                        if original is None:
                            self._peer_evidence[key] = _EvidenceIdentity(held_reference)
                        elif original.identity != held_reference.identity:
                            raise ValueError('original peer evidence cannot be replaced')
                        self._peer_evidence[key].verify()
                    finally:
                        held_reference.close()
                else:
                    directory = self.session._directory(path)
                    self._private_directory(directory)
                    if hashlib.sha256(self._hold(directory, parts[2]).payload).hexdigest() != reference["sha256"]:
                        raise ValueError("original component status evidence drift")
        self.verify()
        return document

    def read_component_status_data(self, component):
        """Read original list DATA, never a native/PASS/OS_FINAL gate."""
        self._initial_component_status(component)
        with self._request_namespace_lease():
            return self._read_component_status_locked(component)

    def _component_negative_preflight_locked(self, node, component):
        """Stop on original current-run canary negatives; never issue permission.

        The fixed executor calls this after retained inventory under the same
        lease. Legacy absence and NOT_EXECUTED add no negative fact; neither
        proves canary acceptance, current OS, health or permission to dispatch.
        """
        if type(component) is not str or component not in self.parsed.selected or node not in self.devices:
            raise ValueError("selected original target/component required before status IO")
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        try:
            os.stat(component + "-status.json", dir_fd=self.directory.fd, follow_symlinks=False)
        except FileNotFoundError:
            self.verify()
            return  # Legacy no-list DATA is not a positive admission.
        document = self._read_component_status_locked(component)
        for name in document.get('canaries', [document['canary']] if document['canary'] is not None else []):
            canary = next(row for row in document["targets"] if row["node"]["hostname"] == name)
            if canary["state"] in {"FAIL", "UNKNOWN"}:
                raise PreparationHold("component canary requires manual review; no further " + component + " dispatch", self.run_directory)

    def record_component_status_data(self, component, node, state, reason):
        """Negative local DATA only. No caller PASS, reset or permission accepted."""
        if (component not in self.parsed.selected or node not in self.devices
                or state not in {"FAIL", "UNKNOWN"} or not isinstance(reason, str)
                or not reason or len(reason) > 512):
            raise ValueError("selected original target and negative component DATA required")
        with self._request_namespace_lease():
            document = self._read_component_status_locked(component)
            row = next(item for item in document["targets"] if item["node"]["hostname"] == node)
            if row["manual_required"]:
                raise PreparationHold("manual component review cannot be automatically reset/replaced", self.run_directory)
            references = []
            for (parent, name), original in sorted(self.files.items()):
                try:
                    relative = Path(parent).relative_to(self.run_directory)
                except ValueError:
                    # Inventory also holds prior-run originals. They remain
                    # verified by scope.verify(), not adopted as this run's logs.
                    continue
                if (len(relative.parts) == 2 and relative.parts[0] == node
                        and (relative.parts[1] == component if component != "os"
                             else re.fullmatch(r"os-[0-9]{4}", relative.parts[1]) is not None)
                        and name in {"step-binding.json", "request.json", "os-dispatch.json"}):
                    original.verify()
                    references.append({"path": str(relative / name), "sha256": hashlib.sha256(original.payload).hexdigest()})
            row.update(state=state, manual_required=True, reason=reason, evidence=references)
            document["revision"] += 1
            validate_component_status_document(document, self._initial_component_status(component))
            fixed = component + "-status.json"
            temporary = "." + component + "-status-" + secrets.token_hex(16) + ".tmp"
            old_key = (str(self.directory.path), fixed)
            old = self.files[old_key]
            writer = _JournalWriter(self, self.directory)
            published = False
            try:
                payload = _json_bytes(document)
                writer.write(temporary, payload)  # Original EXCL0600 and file fsync.
                writer.verify(); old.verify(); self.verify()
                fd = writer.files[0][1]
                preimage = os.fstat(fd)
                key = (preimage.st_dev, preimage.st_ino)
                os.replace(temporary, fixed, src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd)
                published = True
                named, opened = os.stat(fixed, dir_fd=self.directory.fd, follow_symlinks=False), os.fstat(fd)
                if ((opened.st_dev, opened.st_ino) != key or _source_identity(named) != _source_identity(opened)
                        or os.pread(fd, len(payload) + 1, 0) != payload):
                    raise ValueError("component status publication lost original candidate")
                # Only this transaction's old status FD is retired; global held
                # file/name/bytes checks are unchanged for every other original.
                old.close()
                del self.files[old_key]
                new = self._hold(self.directory, fixed, payload)
                if (os.fstat(new.fd).st_dev, os.fstat(new.fd).st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                    raise ValueError("new component status FD is not the original written inode")
                os.fsync(self.directory.fd)
                self.verify()
                return document
            except BaseException as error:
                if published:
                    # A rename/directory durability fault is not a successful
                    # update; retain the physical list and quarantine this scope.
                    self.cleanup_issues.append(error)
                if isinstance(error, Exception):
                    raise PreparationHold("component status update uncertain; preserve UNKNOWN/residue", self.run_directory) from error
                raise
            finally:
                writer.finish()

    def initialize_native_component_status_data(self):
        try:
            with self._request_namespace_lease():
                writer = _JournalWriter(self, self.directory)
                try:
                    for component in component_order(self.parsed.selected):
                        initial = self._initial_native_component_status(component)
                        payload = _json_bytes(initial)
                        writer.write(component + "-status.json", payload)
                        self._hold(self.directory, component + "-status.json", payload)
                    os.fsync(self.directory.fd)
                    self.verify()
                finally:
                    writer.finish()
        except Exception as error:
            raise SharedUpgradeHold("native component fact lists could not be created exclusively") from error

    def _record_native_component_status(self, component, node, completion):
        if type(completion) is not ComponentCompletionResult or completion.hostname != node or completion.component != component:
            raise SharedUpgradeHold("original fixed component observation required")
        stage = declared_step_key(self.policy, component, completion.package_index)
        item = self._native_completions.get((node, stage))
        if item is None or item[1] is not completion or not self._has_component_completion(item[0], completion):
            raise SharedUpgradeHold("original completion must be held before updating its DATA list")
        reference = {"path": node + "/" + stage + "/component-completion.json",
                     "sha256": hashlib.sha256(item[2].payload).hexdigest()}
        return self._update_native_component_status(component, node, completion.state,
            completion.reason or (None if completion.state == "VERIFIED" else "fixed observation incomplete"), [reference])

    def _record_native_component_failure(self, component, node, state, reason):
        if state not in {"FAIL", "UNKNOWN"} and not (self.manual_execution and state == "NOT_EXECUTED"):
            raise SharedUpgradeHold("negative observation only")
        return self._update_native_component_status(component, node, state, reason, [])

    def _record_native_component_canary(self, component, node):
        """Record the fixed scheduler's first eligible node for this component.

        This is attribution DATA, not a release. Selection occurs once before
        any attempt in the component; a failed canary is never retried/rotated.
        """
        return self._record_native_component_canaries(component, (node,))

    def _record_native_component_canaries(self, component, nodes, routes=()):
        """Once-only complete set, before attempts; attribution is not a permit."""
        nodes = tuple(nodes)
        if (not self._native_schedule_started or self.parsed.canary_mode != 'default'
                or component in self._native_component_canaries or len(set(nodes)) != len(nodes)
                or any(n not in self.devices for n in nodes)):
            raise SharedUpgradeHold('native component canaries cannot be reset')
        self._update_native_component_status(component, None, None, None, [],
            canary=nodes[0] if nodes else None, canaries=list(nodes), canary_routes=list(routes))
        self._native_component_canaries[component] = nodes

    def _record_native_component_no_canary(self, component):
        """Fixed coordinator attribution for an independently checked component.

        Not a release/reset: single-use, before terminal observations. Installer
        admission still needs live native preflight and the checks-only guard.
        """
        return self._record_native_component_canaries(component, ())

    def _update_native_component_status(self, component, node, state, reason, references, *, canary=None,
                                        canaries=None, canary_routes=None):
        try:
            with self._request_namespace_lease():
                document = self._read_component_status_locked(component)
                if document["schema_version"] not in (2, 3):
                    raise ValueError("native observations require their separate schema")
                if node is None:
                    if ((canary is not None and canary not in self.devices)
                            or any(row["state"] != "NOT_EXECUTED" for row in document["targets"])):
                        raise ValueError("canary attribution must precede all component attempts")
                    attribution = dict(canary=canary)
                    if document['schema_version'] == 3:
                        attribution.update(canaries=list(canaries if canaries is not None else
                            (canary,) if canary is not None else ()), canary_routes=list(canary_routes or ()))
                    elif canaries is not None and len(canaries) > 1:
                        raise ValueError('legacy status cannot hold multiple canaries')
                    if all(document[k] == value for k, value in attribution.items()):
                        return document
                    document.update(attribution)
                else:
                    row = next(r for r in document["targets"] if r["node"]["hostname"] == node)
                    if row["state"] != "NOT_EXECUTED":
                        raise ValueError("terminal component observation cannot be reset")
                    row.update(state=state, reason=reason, evidence=references, manual_required=state in {"FAIL", "UNKNOWN"})
                document["revision"] += 1
                initial = self._initial_native_component_status(component, document['schema_version'])
                validate_native_component_status_document(document, initial)
                fixed = component + "-status.json"
                temporary = "." + component + "-status-" + secrets.token_hex(16) + ".tmp"
                old_key = (str(self.directory.path), fixed)
                old = self.files[old_key]
                writer = _JournalWriter(self, self.directory)
                published = False
                try:
                    payload = _json_bytes(document)
                    writer.write(temporary, payload)
                    writer.verify(); old.verify(); self.verify()
                    fd = writer.files[0][1]
                    preimage = os.fstat(fd)
                    key = (preimage.st_dev, preimage.st_ino)
                    os.replace(temporary, fixed, src_dir_fd=self.directory.fd, dst_dir_fd=self.directory.fd)
                    published = True
                    named, opened = os.stat(fixed, dir_fd=self.directory.fd, follow_symlinks=False), os.fstat(fd)
                    if ((opened.st_dev, opened.st_ino) != key or _source_identity(named) != _source_identity(opened)
                            or os.pread(fd, len(payload) + 1, 0) != payload):
                        raise ValueError("native fact list lost its original candidate")
                    old.close()
                    del self.files[old_key]
                    new = self._hold(self.directory, fixed, payload)
                    if (os.fstat(new.fd).st_dev, os.fstat(new.fd).st_ino) != key:
                        raise ValueError("native list original written inode changed")
                    os.fsync(self.directory.fd)
                    self.verify()
                    return document
                except BaseException as error:
                    if published:
                        self.cleanup_issues.append(error)
                    raise
                finally:
                    writer.finish()
        except Exception as error:
            raise SharedUpgradeHold("native component fact recording uncertain; stop the batch") from error

    def prepare_readonly_query_data(self, node, records):
        """Preserve the legacy fixed two-query/schema1 DATA contract."""
        return self._prepare_readonly_query_round(node, records, schema_version=1)

    def prepare_readonly_health_query_data(self, node, records):
        """Explicit fixed version/firmware/health schema2, never native capture."""
        return self._prepare_readonly_query_round(node, records, schema_version=2)

    def _prepare_readonly_query_round(self, node, records, *, schema_version):
        """Commit supplied fixed-query bytes as untrusted local DATA, not observe.

        No native transport, grammar, freshness, identity or dispatch permission
        is inferred. A round is never rewritten; partial evidence remains HOLD.
        """
        self.verify()
        specs = _query_round_specs(schema_version)
        if node not in self.devices or type(records) is not tuple or len(records) != len(specs):
            raise ValueError("exact declared node and fixed immutable query records required")
        results = []
        for record, (_label, argv) in zip(records, specs):
            if type(record) is not _ReadonlyQueryRecord or record.argv != argv:
                raise ValueError("original fixed queries in declared order required")
            result = _query_data_result(record)
            if max(len(record.stdout), len(record.stderr)) > MAXIMUM_INPUT_BYTES:
                raise ValueError("original query bytes exceed held-file limit; never truncate")
            results.append(_json_bytes(result))
        with self._request_namespace_lease():
            query_id = "query-" + secrets.token_hex(16)
            directory = self.directory
            try:
                for parent in self.namespace_parents:
                    self.verify()
                    os.fsync(parent.fd)
                for name, exclusive in ((node, False), ("queries", False), (query_id, True)):
                    try:
                        os.mkdir(name, 0o700, dir_fd=directory.fd)
                        os.fsync(directory.fd)
                    except FileExistsError:
                        if exclusive:
                            raise PreparationHold("existing query round preserved; no overwrite", self.run_directory)
                    directory = self.session._directory(directory.path / name)
                    self._private_directory(directory)
                    self.verify()
                query = directory
                result_hashes = {}
                for (label, _argv), record, result_bytes in zip(specs, records, results):
                    os.mkdir(label, 0o700, dir_fd=query.fd)
                    os.fsync(query.fd)
                    output = self.session._directory(query.path / label)
                    self._private_directory(output)
                    writer = _JournalWriter(self, output)
                    try:
                        for name, payload in (("stdout.bin", record.stdout), ("stderr.bin", record.stderr), ("result.json", result_bytes)):
                            writer.write(name, payload)
                            self._hold(output, name, payload, allow_empty=name in ("stdout.bin", "stderr.bin"))
                        os.fsync(output.fd)
                        writer.verify()
                    finally:
                        writer.finish()
                    result_hashes[label] = hashlib.sha256(result_bytes).hexdigest()
                binding = _query_data_binding(self.run_id, query_id, self.devices[node], self.plan_sha256,
                    [hashlib.sha256(source.payload).hexdigest() for source in self.session._files], result_hashes,
                    schema_version=schema_version)
                self._commit_query_binding(query, _json_bytes(binding))
                self.verify()
                return {"state": "DATA_FILES_COMMITTED", "query_directory": str(query.path), **_QUERY_DATA_STATES}
            except Exception as error:
                if isinstance(error, PreparationHold):
                    raise
                raise PreparationHold("query DATA incomplete; preserve original round", directory.path) from error

    def _commit_query_binding(self, directory, payload):
        return self._commit_exclusive_binding(directory, payload, "query-binding.json")

    def _commit_exclusive_binding(self, directory, payload, final_name):
        if final_name not in _NVUED_CHECK_FILES | _DOWNLOAD_FILES | {"package-source.json", "scp-source-request.json", "query-binding.json", "before-binding.json", "after-binding.json",
                              "repaired-binding.json", "restore-binding.json", "pending-diff-binding.json", "os-dispatch.json", "post-binding.json",
                              "runner-binding.json", "owned-exit-binding.json", "before-health-binding.json", "after-health-binding.json",
                              "component-preflight.json", "component-dispatch.json", "component-completion.json",
                              "component-repair.json", "component-repair-result.json", "run-report.json", "os-route-plan.json", "startup-diagnostics.json", "pre-install-diagnostics.json", "ssd-preflight.json",
                              "observed-after.commands", "repaired.commands", "configuration-diff.json",
                              "versions.json", "execution.stdout", "execution.stderr", "health-preflight.json",
                              "access-backup.json", "authorized_keys.before", "access-request.json", "access-result.json",
                              "access-bootstrap.json", "access-bootstrap-result.json"}:
            raise ValueError("only fixed internal DATA binding names")
        temporary = "." + final_name.removesuffix(".json") + "-" + secrets.token_hex(16) + ".json"
        writer = _JournalWriter(self, directory)
        try:
            writer.write(temporary, payload)
            writer.verify()
            os.link(temporary, final_name, src_dir_fd=directory.fd, dst_dir_fd=directory.fd,
                    follow_symlinks=False)
            fd = writer.files[0][1]
            for name in (temporary, final_name):
                named, opened = os.stat(name, dir_fd=directory.fd, follow_symlinks=False), os.fstat(fd)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("original query binding namespace changed")
            if os.pread(fd, len(payload) + 1, 0) != payload:
                raise ValueError("original query binding bytes changed")
            self.verify()
            for name in (final_name, temporary):
                named, opened = os.stat(name, dir_fd=directory.fd, follow_symlinks=False), os.fstat(fd)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("original query binding candidate changed; preserve replacement")
            os.unlink(temporary, dir_fd=directory.fd)
            os.fsync(directory.fd)
            self._hold(directory, final_name, payload)
            self.verify()
        finally:
            writer.finish()

    def _before_commands_stage(self, leaf, component, package_index):
        return self._commands_capture_stage(leaf, "before", component, package_index)[:2]

    def _write_component_preflight_data_locked(self, leaf, component, package_index, preflight):
        if self._active_request_lease is None:
            raise SharedUpgradeHold("original component namespace lease required")
        writer = None
        try:
            leaf.verify()
            if leaf.scope is not self or component not in self.parsed.selected:
                raise ValueError("foreign original component preflight")
            stage = declared_step_key(self.policy, component, package_index)
            directory = self.session._directory(self.run_directory / leaf.node.hostname / stage)
            script, binding = self._candidate(leaf.node.hostname, component, package_index, stage)
            self._hold(directory, "step.sh", script); self._hold(directory, "step-binding.json", _json_bytes(binding))
            before = preflight["before_commands"]
            self._check_commands_phase_data("before", before, b"", 0)
            if (type(preflight["pending_diff"]) is not bytes or preflight["pending_diff"].strip()
                    or type(preflight["os_version"]) is not str):
                raise ValueError("original empty pending and actual OS required")
            records = _component_raw_records(preflight["query_records"])
            health = [r for r in records if r["command"] == "nv show system health"]
            actual = preflight["health_record"]
            forced=bool(self.parsed.force_health)
            if bool(preflight.get('health_override',False))!=forced:
                raise ValueError('health override must match original selected arguments')
            if (len(health) != 1 or type(actual) is not _ReadonlyQueryRecord
                    or actual.argv != ("nv", "show", "system", "health")
                    or (not forced and (health[0]["stream_complete"] is not True or health[0]["returncode"] != 0
                    or health[0]["stderr_base64"] != "" or actual.stderr or actual.returncode != 0))
                    or base64.b64decode(health[0]["stdout_base64"], validate=True) != actual.stdout):
                raise ValueError("actual health record differs from original query")
            before_binding = _json_bytes(_before_commands_binding(binding, before))
            payload = _json_bytes({"schema_version": 2, "state": "COMPONENT_PREFLIGHT_DATA_ONLY",
                "component": component, "package_index": package_index, "binding": binding,
                "os_version": preflight["os_version"], "before_sha256": hashlib.sha256(before).hexdigest(),
                "before_binding_sha256": hashlib.sha256(before_binding).hexdigest(),
                "health_record": health[0], "pending_diff_base64": base64.b64encode(preflight["pending_diff"]).decode("ascii"),
                "query_records": records,**({'health_override':True} if forced else {})})
            writer = _JournalWriter(self, directory)
            writer.write("before.commands", before)
            self._hold(directory, "before.commands", before)
            os.fsync(directory.fd); writer.verify(); leaf.verify()
            self._commit_exclusive_binding(directory, before_binding, "before-binding.json")
            self._commit_exclusive_binding(directory, payload, "component-preflight.json")
            leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold("component preflight originals could not be committed") from error
        finally:
            if writer is not None:
                writer.finish()

    def _write_component_dispatch_data_locked(self, leaf, component, data, request_payload, remote, records, *, owned_runner=True):
        from ibsw_upgrade_executor import _original_component_files, _owned_launch_command
        try:
            if self._active_request_lease is None or owned_runner is not True:
                raise ValueError("original owned component launch lease required")
            scope, directory, _script = _original_component_files(leaf, data)
            if scope is not self or data["component"] != component:
                raise ValueError("foreign component scope")
            request = self._hold(directory, "request.json", request_payload)
            self._hold(directory, "component-preflight.json")
            runner_binding = self._hold(directory, "runner-binding.json")
            rows = _component_raw_records(records)
            if (rows[-1]["command"] != _owned_launch_command(remote)
                    or any((r["stream_complete"] is not True or r["returncode"] != 0 or r["stderr_base64"] != "")
                           and not (self.parsed.force_health and r['command']=='nv show system health')
                           for r in rows[:-1])):
                raise ValueError("incomplete original component launch chain")
            uid = [r for r in rows if r["command"] == "id -u"]
            if len(uid) != 1 or not re.fullmatch(rb"[0-9]+\n", base64.b64decode(uid[0]["stdout_base64"], validate=True)):
                raise ValueError("one actual original uid required")
            payload = _json_bytes({"schema_version": 2, "state": "COMPONENT_DISPATCH_DATA_ONLY",
                "binding": data["binding"], "request_sha256": hashlib.sha256(request.payload).hexdigest(),
                "remote_script": remote, "records": rows, "launch_kind": "OWNED_RUNNER_V1",
                "runner_binding_sha256": hashlib.sha256(runner_binding.payload).hexdigest()})
            if len(payload) > MAXIMUM_INPUT_BYTES:
                raise ValueError("bounded original component chain exceeded")
            self._commit_exclusive_binding(directory, payload, "component-dispatch.json")
            leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold("component dispatch record failed; preserve UNKNOWN") from error

    def _prepare_component_repair_data(self, leaf, dispatch, after, missing, records):
        """Write-ahead originals only; returned patch is not an apply permit."""
        from ibsw_upgrade_executor import _bound_component_postcondition_inputs
        try:
            with self._request_namespace_lease():
                scope, directory, binding, _document, _remote = _bound_component_postcondition_inputs(leaf, dispatch)
                if scope is not self or "component-completion.json" in os.listdir(directory.fd):
                    raise ValueError("original unfinished component stage required")
                before = self._hold(directory, "before.commands").payload
                _component_repair_missing_bytes(before, after, missing)
                _validate_component_graph(set(os.listdir(directory.fd)), binding,
                    lambda name: self._hold(directory, name).payload, switch_dir=self.parsed.switch_dir)
                if "component-repair.json" in os.listdir(directory.fd):
                    raise ValueError("original repair attempt remains REQUESTED; no retry")
                rows = _component_raw_records(records)
                observed = [row for row in rows if row["command"] == "nv config show -o commands"]
                if (not observed or base64.b64decode(observed[-1]["stdout_base64"], validate=True) != after
                        or observed[-1]["stderr_base64"] or observed[-1]["returncode"] != 0
                        or observed[-1]["stream_complete"] is not True):
                    raise ValueError("original complete after.commands raw required")
                payload = _json_bytes({"schema_version": 2, "state": "REQUESTED", "binding": binding,
                    "before_sha256": hashlib.sha256(before).hexdigest(), "after_sha256": hashlib.sha256(after).hexdigest(),
                    "missing_sha256": hashlib.sha256(missing).hexdigest(),
                    "preflight_sha256": hashlib.sha256(self._hold(directory, "component-preflight.json").payload).hexdigest(),
                    "dispatch_sha256": hashlib.sha256(self._hold(directory, "component-dispatch.json").payload).hexdigest(),
                    "request_sha256": hashlib.sha256(self._hold(directory, "request.json").payload).hexdigest(),
                    "raw_records": rows})
                writer = _JournalWriter(self, directory)
                try:
                    for name, raw in (("after.commands", after), ("missing.commands", missing)):
                        writer.write(name, raw)
                        self._hold(directory, name, raw)
                    os.fsync(directory.fd); writer.verify(); leaf.verify()
                    self._commit_exclusive_binding(directory, payload, "component-repair.json")
                    leaf.verify()
                    return self._hold(directory, "missing.commands", missing)
                finally:
                    writer.finish()
        except Exception as error:
            raise SharedUpgradeHold("component repair originals could not be committed; no upload/apply") from error

    def _record_component_repair_result(self, leaf, dispatch, *, repaired, records, state):
        """Preserve one original repair outcome. Never an overall completion."""
        from ibsw_upgrade_executor import _bound_component_postcondition_inputs
        try:
            with self._request_namespace_lease():
                scope, directory, binding, _document, _remote = _bound_component_postcondition_inputs(leaf, dispatch)
                if (scope is not self or state not in {"REPAIRED", "UNKNOWN"} or type(repaired) is not bytes
                        or len(repaired) > MAXIMUM_INPUT_BYTES):
                    raise ValueError("fixed original component repair result required")
                _validate_component_graph(set(os.listdir(directory.fd)), binding,
                    lambda name: self._hold(directory, name).payload, switch_dir=self.parsed.switch_dir)
                plan = self._hold(directory, "component-repair.json")
                before = self._hold(directory, "before.commands").payload
                rows = _component_raw_records(records, allow_empty=state == "UNKNOWN")
                if state == "REPAIRED" and (not repaired
                        or compare_commands(before.decode("utf-8"), repaired.decode("utf-8")).state != "PASS"
                        or not _component_repair_records_complete(rows)):
                    raise ValueError("original repair is incomplete; preserve UNKNOWN")
                payload = _json_bytes({"schema_version": 2, "state": state, "binding": binding,
                    "plan_sha256": hashlib.sha256(plan.payload).hexdigest(),
                    "repaired_base64": base64.b64encode(repaired).decode("ascii"), "raw_records": rows})
                self._commit_exclusive_binding(directory, payload, "component-repair-result.json")
                leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold("component repair result uncertain; no following task") from error

    def _record_os_route_plan(self, leaf, initial, indices, snapshots):
        """Exclusive local planning DATA; never loaded to resume another run."""
        try:
            with self._request_namespace_lease():
                leaf.verify()
                if leaf.scope is not self or not leaf._native_observation_consumed or not self.policy.os_stages:
                    raise ValueError('original native alternative-route observation required')
                from ibsw_upgrade_contract import select_os_path
                original=parse_readonly_query_data(leaf._initial_os_record)
                if original.state!='TEXT_DATA_PARSED' or dict(original.fields)['image_version_text']!=initial:
                    raise ValueError('route origin must match the original native version query')
                wanted=select_os_path(self.policy,initial,available=frozenset(row[0] for row in snapshots))
                if tuple(self.policy.os.index(item) for item in wanted)!=indices or len(wanted)!=len(snapshots):
                    raise ValueError('route must include exactly one original candidate from every future stage')
                if leaf.node.hostname in getattr(self,'_frozen_os_routes',{}):
                    raise ValueError('an existing run route cannot be replanned')
                try: os.mkdir(leaf.node.hostname,0o700,dir_fd=self.directory.fd)
                except FileExistsError: pass
                os.fsync(self.directory.fd)
                directory=self.session._directory(self.run_directory/leaf.node.hostname)
                self._private_directory(directory)
                record=dict(schema_version=1,state='FROZEN_OS_ROUTE_DATA_ONLY',hostname=leaf.node.hostname,
                    run_id=self.run_id,plan_sha256=self.plan_sha256,initial=initial,indices=list(indices),
                    versions=[initial]+[item.version for item in wanted],sources=[list(row) for row in snapshots])
                self._commit_exclusive_binding(directory,_json_bytes(record),'os-route-plan.json')
                if not hasattr(self,'_frozen_os_routes'): self._frozen_os_routes={}
                if not hasattr(self,'_os_source_baselines'): self._os_source_baselines={}
                self._frozen_os_routes[leaf.node.hostname]=record
                for row in snapshots:
                    if row[0] in self._os_source_baselines and self._os_source_baselines[row[0]]!=tuple(row):
                        raise ValueError('shared chosen package changed during route preparation')
                    self._os_source_baselines[row[0]]=tuple(row)
                leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold('OS route evidence could not be recorded; no following task') from error

    def _record_download_attempt(self,leaf,dispatch,rows):
        """Durably save original pre-reboot numeric telemetry before remote ACK.

        Repeated polls may return identical measurements, never different bytes
        under an already committed attempt. No speed measurement admits success.
        """
        try:
            with self._request_namespace_lease():
                leaf.verify()
                if (not self.manual_execution or leaf.scope is not self
                        or not getattr(leaf,'_cooperative_completion',False)
                        or type(dispatch) is not ComponentDispatchResult or dispatch.component!='os'
                        or dispatch.state!='DISPATCHED_UNKNOWN' or dispatch.hostname!=leaf.node.hostname):
                    raise ValueError('original active OS dispatch required for telemetry')
                directory=self.session._directory(self.run_directory/leaf.node.hostname/dispatch.stage)
                _script,binding=self._candidate(leaf.node.hostname,dispatch.component,dispatch.package_index,dispatch.stage)
                names=set(os.listdir(directory.fd))
                _validate_component_graph(names,binding,lambda name:self._hold(directory,name).payload,
                                          switch_dir=self.parsed.switch_dir)
                original=self._hold(directory,'component-dispatch.json')
                for index,row in enumerate(rows,1):
                    lines=('\n'.join(r['raw_line'] for r in rows[:index])+'\n').encode('ascii')
                    document=_download_document(binding,original.payload,lines)
                    if document['measurement']!=row or row['attempt']!=index:
                        raise ValueError('foreign download measurement')
                    payload=_json_bytes(document); name=f'download-attempt-{index:02d}.json'
                    if name in names:
                        self._hold(directory,name,payload)
                    else:
                        if 'component-completion.json' in names:
                            raise ValueError('download measurement cannot be appended after completion')
                        self._commit_exclusive_binding(directory,payload,name)
                        names.add(name)
                        record=dict(hostname=leaf.node.hostname,stage=dispatch.stage,target_version=dispatch.target_version,
                                    measurement=row,path=str(directory.path/name))
                        self._download_measurements=getattr(self,'_download_measurements',[])+[record]
                        callback=getattr(self,'_download_callback',None)
                        if callback: callback(record)
                leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold('OS download measurements could not be durably recorded; install acknowledgement withheld') from error

    def _record_nvued_check(self, leaf, dispatch, attempt, records):
        """Persist each bounded live service query before waiting or verifying."""
        try:
            with self._request_namespace_lease():
                leaf.verify()
                if (not self.manual_execution or leaf.scope is not self
                        or not getattr(leaf,'_cooperative_completion',False)
                        or type(dispatch) is not ComponentDispatchResult
                        or dispatch.state!='DISPATCHED_UNKNOWN' or dispatch.hostname!=leaf.node.hostname
                        or type(attempt) is not int or attempt not in range(1,6)):
                    raise ValueError('original live post-reboot service check required')
                stage=declared_step_key(self.policy,dispatch.component,dispatch.package_index)
                if dispatch.stage!=stage:
                    raise ValueError('foreign service observation stage')
                directory=self.session._directory(self.run_directory/leaf.node.hostname/stage)
                _script,binding=self._candidate(leaf.node.hostname,dispatch.component,dispatch.package_index,stage)
                names=set(os.listdir(directory.fd))
                _validate_component_graph(names,binding,lambda name:self._hold(directory,name).payload,
                                          switch_dir=self.parsed.switch_dir)
                if 'component-completion.json' in names or any(
                        f'nvued-check-{number:02d}.json' not in names for number in range(1,attempt)):
                    raise ValueError('service checks must precede terminal completion and retain previous attempts')
                original=self._hold(directory,'component-dispatch.json')
                rows=_nvued_check_records(records)
                payload=_json_bytes(dict(schema_version=2,state='NVUED_READINESS_DATA_ONLY',binding=binding,
                    attempt=attempt,dispatch_sha256=hashlib.sha256(original.payload).hexdigest(),raw_records=rows))
                self._commit_exclusive_binding(directory,payload,f'nvued-check-{attempt:02d}.json')
                leaf.verify()
        except Exception as error:
            raise SharedUpgradeHold('nvued observation could not be recorded; no following task') from error

    def _record_component_completion_data(self, leaf, dispatch, completion):
        """Commit a fixed live factory observation, never infer one from disk."""
        try:
            with self._request_namespace_lease():
                leaf.verify()
                if (leaf.scope is not self or type(dispatch) is not ComponentDispatchResult
                        or type(completion) is not ComponentCompletionResult
                        or (dispatch.hostname, dispatch.component, dispatch.package_index, dispatch.target_version) !=
                           (completion.hostname, completion.component, completion.package_index, completion.target_version)
                        or dispatch.hostname != leaf.node.hostname):
                    raise ValueError("foreign original component completion")
                stage = declared_step_key(self.policy, dispatch.component, dispatch.package_index)
                if dispatch.stage != stage:
                    raise ValueError("foreign original completion stage")
                directory = self.session._directory(self.run_directory / leaf.node.hostname / stage)
                script, binding = self._candidate(leaf.node.hostname, dispatch.component, dispatch.package_index, stage)
                self._hold(directory, "step.sh", script); self._hold(directory, "step-binding.json", _json_bytes(binding))
                preflight = self._hold(directory, "component-preflight.json")
                names = set(os.listdir(directory.fd))
                _validate_component_graph(names, binding,
                    lambda name: self._hold(directory, name).payload, switch_dir=self.parsed.switch_dir)
                if completion.state == "VERIFIED" and "component-repair.json" in names:
                    repair_result = json.loads(self._hold(directory, "component-repair-result.json").payload)
                    if repair_result["state"] != "REPAIRED":
                        raise ValueError("unknown repair cannot release a verified component")
                dispatch_original = (self._hold(directory, "component-dispatch.json")
                                     if dispatch.state == "DISPATCHED_UNKNOWN" else None)
                expected_path = leaf.node.hostname + "/" + stage + "/component-completion.json"
                if completion.evidence_paths != (expected_path,):
                    raise ValueError("exact original completion path required")
                document = {"schema_version": 2, "state": completion.state, "binding": binding,
                    "target_version": completion.target_version, "observed_os_version": completion.observed_os_version,
                    "reason": completion.reason, "raw_records": _component_raw_records(completion.raw_records, allow_empty=completion.state != "VERIFIED"),
                    "preflight_sha256": hashlib.sha256(preflight.payload).hexdigest(),
                    "dispatch_sha256": hashlib.sha256(dispatch_original.payload).hexdigest() if dispatch_original else None}
                if self.manual_execution and getattr(leaf, '_cooperative_completion', False):
                    document.update(verification_basis='LIVE_POST_REBOOT' if dispatch_original else 'NO_WRITE_LIVE',
                                    installer_exit_code=None)
                payload = _json_bytes(document)
                self._commit_exclusive_binding(directory, payload, "component-completion.json")
                original = self._hold(directory, "component-completion.json", payload)
                self._write_component_review_evidence(directory, dispatch, completion, preflight)
                leaf.verify()
                self._native_completions[(leaf.node.hostname, stage)] = (dispatch, completion, original, binding)
        except Exception as error:
            raise SharedUpgradeHold("component completion commit failed; no following task") from error

    def _write_component_review_evidence(self, directory, dispatch, completion, preflight):
        """Private readable copies of live raw facts; never dispatch authority."""
        rows = list(completion.raw_records[len(dispatch.raw_records):])
        def payload(row):
            return base64.b64decode(row["stdout_base64"], validate=True)
        exports = [payload(row) for row in rows if row["command"] == "nv config show -o commands"
                   and row["returncode"] == 0 and row["stream_complete"] and not row["stderr_base64"]]
        before = self._hold(directory, "before.commands").payload
        if exports:
            self._commit_exclusive_binding(directory, exports[0], "observed-after.commands")
            differences = {"initial": asdict(compare_commands(before.decode(), exports[0].decode())),
                           "final": asdict(compare_commands(before.decode(), exports[-1].decode()))}
            self._commit_exclusive_binding(directory, _json_bytes(differences), "configuration-diff.json")
            if len(exports) > 1 and exports[-1] != exports[0]:
                self._commit_exclusive_binding(directory, exports[-1], "repaired.commands")
        versions = {"before_os": json.loads(preflight.payload)["os_version"],
                    "target": dispatch.target_version, "observed_os": completion.observed_os_version,
                    "queries": [row for row in completion.raw_records
                                if row["command"] in ("nv show system version", "nv show platform firmware")]}
        from ibsw_upgrade_contract import ssd_check_from_completion
        ssd_check = ssd_check_from_completion(self.policy, dispatch, completion)
        if ssd_check is not None:
            versions["ssd_check"] = ssd_check
        self._commit_exclusive_binding(directory, _json_bytes(versions), "versions.json")
        for name in ("execution.stdout", "execution.stderr"):
            found = [payload(row) for row in rows if row["command"].startswith("SFTP_READ ")
                     and row["command"].endswith("/"+name) and row["stream_complete"]]
            if found and found[-1]:
                self._commit_exclusive_binding(directory, found[-1], name)

    def write_run_report(self, document):
        """Create once after observations; never overwrite an older outcome."""
        try:
            with self._request_namespace_lease():
                if document.get("run_directory") != str(self.run_directory):
                    raise ValueError("report belongs to another run")
                self._commit_exclusive_binding(self.directory, _json_bytes(document), "run-report.json")
                self.verify()
        except Exception as error:
            raise SharedUpgradeHold("run report could not be saved reliably") from error

    def _has_component_completion(self, dispatch, completion):
        self.verify()
        item = self._native_completions.get((dispatch.hostname, dispatch.stage))
        if item is None or item[0] is not dispatch or item[1] is not completion:
            return False
        item[2].verify()
        return True

    def _completed_component_stage_is_original(self, directory, binding):
        item = self._native_completions.get((binding["node"]["hostname"], binding["stage"]))
        if item is None or item[1].state != "VERIFIED" or item[3] != binding:
            return False
        original = self._hold(directory, "component-completion.json")
        if original is not item[2]:
            return False
        original.verify()
        return True

    def _commands_capture_stage(self, leaf, phase, component, package_index, *, plan_only=False):
        from ibsw_upgrade_observer import _live_plan_inputs
        scope, _global, original_plan, declared, parsed, policy = _live_plan_inputs(leaf)
        if scope is not self or component not in parsed.selected:
            raise ValueError("before capture outside original selected stage")
        stage_key = declared_step_key(policy, component, package_index)
        directory = self.session._directory(self.directory.path / leaf.node.hostname / stage_key)
        self._private_directory(directory)
        script, binding = _declared_candidate_data(policy, leaf.node, run_id=declared["run_id"],
            method=parsed.method, switch_dir=parsed.switch_dir,
            plan_sha256=hashlib.sha256(original_plan.payload).hexdigest(),
            input_sha256=[hashlib.sha256(source.payload).hexdigest() for source in self.session._files],
            component=component, package_index=package_index, stage_key=stage_key)
        self._hold(directory, "step.sh", script)
        self._hold(directory, "step-binding.json", _json_bytes(binding))
        names = set(os.listdir(directory.fd))
        try:
            request_names, originals, has_restore = _validate_commands_data_graph(names, binding,
                lambda name: self._hold(directory, name, allow_empty=name in _EMPTY_STAGE_DATA_RAW).payload,
                read_postconditions=lambda: self._read_live_postconditions(directory, binding, policy.final_os), switch_dir=parsed.switch_dir)
            if plan_only:
                if "after.commands" not in originals or has_restore:
                    raise ValueError("original before/after required; existing restore DATA preserved")
            elif phase == "pending-diff":
                if "after.commands" not in originals or names.intersection(_PENDING_DIFF_FILES):
                    raise ValueError("original before/after required; existing pending DATA preserved")
            elif (type(phase) is not str or phase not in _COMMANDS_PHASES or phase + ".commands" in originals
                    or (phase != "before" and _COMMANDS_PHASES[_COMMANDS_PHASES.index(phase)-1] + ".commands" not in originals)):
                raise ValueError("existing/out-of-order commands capture preserved")
        except (ValueError, OSError) as error:
            raise PreparationHold("existing/partial commands data or unknown stage preserved", directory.path) from error
        if "request.json" in request_names:
            original = self._hold(directory, "request.json")
            request = json.loads(original.payload)
            token = request.get("request_id")
            if (type(token) is not str or not re.fullmatch(r"[0-9a-f]{32}", token)
                    or original.payload != _json_bytes({"schema_version": 1, "state": "REQUESTED",
                        "activation_state": "UNKNOWN", "execution_state": "NOT_EXECUTED",
                        "binding": binding, "request_id": token})):
                raise PreparationHold("original request remains unknown; preserve evidence", directory.path)
        leaf.verify()
        return directory, binding, originals

    def _write_before_commands_data(self, leaf, component, package_index, stdout, stderr, returncode):
        """Private raw DATA writer, NOT native attestation or execution permission.

        Only the fixed native factory can attribute its own captured bytes to
        an actual signed connection. A pure caller of this internal primitive
        receives untrusted DATA only, never a backup/write/OS-final admission.
        """
        return self._write_commands_phase_data(leaf, "before", component, package_index, stdout, stderr, returncode)

    @staticmethod
    def _check_commands_phase_data(phase, stdout, stderr, returncode):
        if (type(phase) is not str or phase not in _COMMANDS_PHASES
                or type(stdout) is not bytes or not 0 < len(stdout) <= MAXIMUM_INPUT_BYTES
                or type(stderr) is not bytes or stderr or type(returncode) is not int or returncode != 0):
            raise ValueError("before capture requires nonempty finite original stdout/empty stderr/status0")

    def _write_commands_phase_data(self, leaf, phase, component, package_index, stdout, stderr, returncode):
        """Private untrusted phase DATA writer, never a native/execution issuer."""
        self._check_commands_phase_data(phase, stdout, stderr, returncode)
        with self._request_namespace_lease():
            return self._write_commands_phase_data_locked(leaf, phase, component, package_index, stdout, stderr, returncode)

    def _write_before_commands_data_locked(self, leaf, component, package_index, stdout, stderr, returncode):
        return self._write_commands_phase_data_locked(leaf, "before", component, package_index, stdout, stderr, returncode)

    def _write_commands_phase_data_locked(self, leaf, phase, component, package_index, stdout, stderr, returncode):
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        self._check_commands_phase_data(phase, stdout, stderr, returncode)
        directory, binding, originals = self._commands_capture_stage(leaf, phase, component, package_index)
        writer = _JournalWriter(self, directory)
        try:
            writer.write(phase + ".commands", stdout)
            self._hold(directory, phase + ".commands", stdout)
            os.fsync(directory.fd)
            writer.verify(); leaf.verify()
            self._commit_exclusive_binding(directory, _json_bytes(_commands_phase_binding(binding, phase, stdout, originals)),
                                           phase + "-binding.json")
            leaf.verify()
            result = {"state": phase.upper() + "_COMMANDS_DATA_COMMITTED", "execution_state": "NOT_EXECUTED",
                    "attestation_state": "DATA_ONLY_UNATTESTED", "stage": binding["stage"],
                    "before_path" if phase == "before" else "commands_path": str(directory.path / (phase + ".commands"))}
            return result
        except Exception as error:
            raise PreparationHold("before DATA incomplete; preserve original bytes/residue", directory.path) from error
        finally:
            writer.finish()

    def plan_commands_restore_data(self, leaf, component, package_index=0):
        """Only original held before/after -> missing-only DATA; pending UNKNOWN.

        No caller text, bool/DTO or actual patch/apply/save/current permission.
        Repaired sampling is also DATA and never releases retained requests.
        """
        with self._request_namespace_lease():
            directory, binding, originals = self._commands_capture_stage(leaf, None, component, package_index, plan_only=True)
            plan, patch = _restore_data_plan(binding, originals["before.commands"], originals["after.commands"])
            payload = _json_bytes(plan)
            if max(len(payload), len(patch)) > MAXIMUM_INPUT_BYTES:
                raise PreparationHold("bounded restore DATA exceeded; no partial patch", directory.path)
            writer = _JournalWriter(self, directory)
            try:
                writer.write("restore-plan.json", payload)
                self._hold(directory, "restore-plan.json", payload)
                if patch:
                    writer.write("missing.commands", patch)
                    self._hold(directory, "missing.commands", patch)
                os.fsync(directory.fd); writer.verify(); leaf.verify()
                self._commit_exclusive_binding(directory, _json_bytes(_restore_data_binding(binding, payload, patch)),
                                               "restore-binding.json")
                leaf.verify()
                return plan
            except Exception as error:
                raise PreparationHold("restore DATA incomplete; preserve original evidence", directory.path) from error
            finally:
                writer.finish()

    def _write_pending_diff_data(self, leaf, component, package_index, stdout, stderr, returncode):
        """Private untrusted DATA only, not EOF attestation or pending permission.

        The fixed native factory independently requires actual EOF/status0;
        supplying bytes to this primitive cannot issue any native/write gate.
        """
        self._check_pending_diff_data(stdout, stderr, returncode)
        with self._request_namespace_lease():
            return self._write_pending_diff_data_locked(leaf, component, package_index, stdout, stderr, returncode)

    @staticmethod
    def _check_pending_diff_data(stdout, stderr, returncode):
        if (type(stdout) is not bytes or type(stderr) is not bytes or stderr
                or len(stdout) + len(stderr) > MAXIMUM_INPUT_BYTES
                or type(returncode) is not int or returncode != 0):
            raise ValueError("finite raw diff stdout/empty stderr/status0 required")

    def _write_pending_diff_data_locked(self, leaf, component, package_index, stdout, stderr, returncode):
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        self._check_pending_diff_data(stdout, stderr, returncode)
        directory, binding, originals = self._commands_capture_stage(leaf, "pending-diff", component, package_index)
        writer = _JournalWriter(self, directory)
        try:
            for name, payload in zip(_PENDING_DIFF_RAW, (stdout, stderr)):
                writer.write(name, payload)
                self._hold(directory, name, payload, allow_empty=True)
            os.fsync(directory.fd); writer.verify(); leaf.verify()
            self._commit_exclusive_binding(directory, _json_bytes(_pending_diff_binding(binding, stdout, stderr, originals)),
                                           "pending-diff-binding.json")
            leaf.verify()
            return {"state": "PENDING_DIFF_DATA_COMMITTED", "pending_state": "UNKNOWN", "dispatch_state": "HOLD",
                    "execution_state": "NOT_EXECUTED", "attestation_state": "DATA_ONLY_UNATTESTED",
                    "stage": binding["stage"]}
        except Exception as error:
            raise PreparationHold("pending diff DATA incomplete; preserve original residue", directory.path) from error
        finally:
            writer.finish()

    def _write_os_dispatch_data(self, leaf, data, request_payload, remote, records):
        """Private original chain archive; no native completion or pending reset."""
        with self._request_namespace_lease():
            return self._write_os_dispatch_data_locked(leaf, data, request_payload, remote, records)

    def _owned_runner_stage(self, leaf, component, package_index):
        from ibsw_upgrade_observer import _live_plan_inputs
        scope, _global, plan, declared, args, policy = _live_plan_inputs(leaf)
        if scope is not self or component not in args.selected:
            raise ValueError("original selected owned runner stage required")
        stage_key = declared_step_key(policy, component, package_index)
        stage = self.session._directory(self.run_directory / leaf.node.hostname / stage_key)
        self._private_directory(stage)
        script, binding = _declared_candidate_data(policy, leaf.node, run_id=declared["run_id"], method=args.method,
            switch_dir=args.switch_dir, plan_sha256=hashlib.sha256(plan.payload).hexdigest(),
            input_sha256=[hashlib.sha256(source.payload).hexdigest() for source in self.session._files],
            component=component, package_index=package_index, stage_key=stage_key)
        self._hold(stage, "step.sh", script); self._hold(stage, "step-binding.json", _json_bytes(binding))
        _validate_commands_data_graph(set(os.listdir(stage.fd)), binding,
            lambda name: self._hold(stage, name, allow_empty=name in _EMPTY_STAGE_DATA_RAW).payload,
            read_postconditions=lambda: self._read_live_postconditions(stage, binding, policy.final_os), switch_dir=args.switch_dir)
        leaf.verify()
        return stage, binding, args

    def prepare_owned_runner_data(self, leaf, component, package_index, *, remote_script):
        """Prepare original wrapper artifact only; no native launch/PID/permission."""
        with self._request_namespace_lease():
            return self._prepare_owned_runner_data_locked(leaf, component, package_index, remote_script=remote_script)

    def _prepare_owned_runner_data_locked(self, leaf, component, package_index, *, remote_script):
        from ibsw_upgrade_executor import _owned_runner_bytes
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        stage, binding, args = self._owned_runner_stage(leaf, component, package_index)
        if posixpath.dirname(posixpath.dirname(remote_script)) != args.switch_dir:
            raise ValueError("owned runner outside original declared root")
        if set(os.listdir(stage.fd)).intersection(_OWNED_RUNNER_FILES):
            raise PreparationHold("existing owned runner retained", stage.path)
        if "os-dispatch.json" in os.listdir(stage.fd) and json.loads(self._hold(stage, "os-dispatch.json").payload)["remote_script"] != remote_script:
            raise ValueError("owned runner conflicts with original dispatch remote")
        runner = _owned_runner_bytes(binding, remote_script)
        writer = _JournalWriter(self, stage)
        try:
            writer.write("runner.sh", runner); self._hold(stage, "runner.sh", runner)
            os.fsync(stage.fd); writer.verify(); leaf.verify()
            self._commit_exclusive_binding(stage, _json_bytes(_owned_runner_binding(binding, remote_script, runner)), "runner-binding.json")
            leaf.verify()
            return {"state": "OWNED_RUNNER_DECLARED_DATA", "execution_state": "NOT_EXECUTED", "activation_state": "UNKNOWN"}
        except Exception as error:
            raise PreparationHold("owned runner DATA incomplete; preserve original residue", stage.path) from error
        finally:
            writer.finish()

    def record_owned_script_exit_data(self, leaf, component, package_index, raw):
        """Supplied DATA only. Actual signed/kernel completion factory remains OPEN."""
        with self._request_namespace_lease():
            return self._record_owned_script_exit_data_locked(leaf, component, package_index, raw)

    def _record_owned_script_exit_data_locked(self, leaf, component, package_index, raw):
        from ibsw_upgrade_executor import _owned_exit_data
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        stage, binding, _args = self._owned_runner_stage(leaf, component, package_index)
        data = _owned_exit_data(binding, raw)
        names = set(os.listdir(stage.fd))
        if not _OWNED_RUNNER_FILES.issubset(names) or not {"request.json", "os-dispatch.json"}.issubset(names):
            raise ValueError("original runner/request/dispatch required")
        if names.intersection(_OWNED_EXIT_FILES):
            raise PreparationHold("original child record preserved; no overwrite", stage.path)
        runner = self._hold(stage, "runner.sh")
        request, dispatch = self._hold(stage, "request.json"), self._hold(stage, "os-dispatch.json")
        metadata = _json_bytes(_owned_exit_binding(binding, runner.payload, request.payload, dispatch.payload, raw))
        writer = _JournalWriter(self, stage)
        try:
            writer.write("owned-exit.record", raw); self._hold(stage, "owned-exit.record", raw)
            os.fsync(stage.fd); writer.verify(); leaf.verify()
            self._commit_exclusive_binding(stage, metadata, "owned-exit-binding.json")
            leaf.verify()
            return data
        except Exception as error:
            raise PreparationHold("owned child DATA incomplete; preserve original residue", stage.path) from error
        finally:
            writer.finish()

    def _write_os_dispatch_data_locked(self, leaf, data, request_payload, remote, records, *, owned_runner=False):
        from ibsw_upgrade_executor import _original_os_files
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        scope, directory, _script = _original_os_files(leaf, data)
        if scope is not self:
            raise ValueError("foreign original OS scope")
        request = self._hold(directory, "request.json", request_payload)
        self.inspect_step(leaf.node.hostname, "os", data["package_index"])
        if type(owned_runner) is not bool:
            raise ValueError("fixed private launch selection required")
        runner_binding = None
        if owned_runner:
            stage, binding, _args = self._owned_runner_stage(leaf, "os", data["package_index"])
            runner_binding = self._hold(stage, "runner-binding.json").payload
        payload = _json_bytes(_os_dispatch_data(data["binding"], request.payload, remote, records, runner_binding=runner_binding))
        if len(payload) > MAXIMUM_INPUT_BYTES:
            raise PreparationHold("bounded OS chain archive exceeded; remains UNKNOWN", directory.path)
        self._commit_exclusive_binding(directory, payload, "os-dispatch.json")
        leaf.verify()

    def _read_postconditions(self, stage, binding, final_target, directory, names, raw):
        """Unique historical/live seven-file DATA reader; never clears requests."""
        collection = directory(stage, "postconditions")
        rounds = names(collection)
        if not rounds or len(rounds) > 512:
            raise ValueError("partial/over-limit postcondition collection")
        request, dispatch = raw(stage, "request.json"), raw(stage, "os-dispatch.json")
        remote = json.loads(dispatch)["remote_script"]
        verified = {}
        for round_id in sorted(rounds):
            if not re.fullmatch(r"post-[0-9a-f]{32}", round_id):
                raise ValueError("unknown original postcondition round")
            original = directory(collection, round_id)
            if names(original) != {"version", "owned-logs", "post-binding.json"}:
                raise ValueError("partial/unknown postcondition round")
            version, logs = directory(original, "version"), directory(original, "owned-logs")
            if names(version) != {"stdout.bin", "stderr.bin", "result.json"} or names(logs) != {"stdout.bin", "stderr.bin", "metadata.json"}:
                raise ValueError("partial/unknown original postcondition output")
            record = record_readonly_query(("nv", "show", "system", "version"),
                raw(version, "stdout.bin", allow_empty=True), raw(version, "stderr.bin", allow_empty=True), 0)
            match = _post_version_data(binding, final_target, record)
            expected_version = _json_bytes({**_query_data_result(record), **match})
            if raw(version, "result.json") != expected_version:
                raise ValueError("postcondition version result/raw graph changed")
            stdout, stderr = raw(logs, "stdout.bin", allow_empty=True), raw(logs, "stderr.bin", allow_empty=True)
            metadata_bytes = raw(logs, "metadata.json")
            metadata = json.loads(metadata_bytes)
            expected_logs = _json_bytes(_post_log_data(remote, stdout, stderr,
                {key: metadata[key] for key in ("remote_directory", "uid", "observation_state", "connection_source")},
                expected_uid=_post_original_uid(dispatch)))
            if metadata_bytes != expected_logs:
                raise ValueError("postcondition owned log/raw graph changed")
            expected = _post_binding(binding, request, dispatch, round_id, expected_version, expected_logs, match)
            if raw(original, "post-binding.json") != _json_bytes(expected):
                raise ValueError("postcondition original request/dispatch binding changed")
            verified[round_id] = hashlib.sha256(_json_bytes(expected)).hexdigest()
        return verified  # Original byte/hash DATA only, never completion authority.

    def _read_live_postconditions(self, stage, binding, final_target=None):
        self.verify()
        if final_target is None:
            # Final version is read from the original global, not a cached policy.
            plan = json.loads(self.files[(str(self.run_directory), "plan.json")].payload)
            parsed = parse_prepare_args(plan["entry"], plan["cwd"], plan["argv"])
            final_target = normalize_upgrade(load_global_text(self.session._files[1].payload.decode("utf-8-sig")),
                selected=parsed.selected, method=parsed.method, package_dir=parsed.package_dir).final_os
        def directory(parent, name):
            result = self.session._directory(parent.path / name)
            self._private_directory(result)
            return result
        def names(parent):
            result = set(os.listdir(parent.fd))
            if len(result) > 512:
                raise ValueError("bounded postcondition names exceeded")
            return result
        verified = self._read_postconditions(stage, binding, final_target, directory, names,
            lambda parent, name, allow_empty=False: self._hold(parent, name, allow_empty=allow_empty).payload)
        self.verify()
        return verified

    def _write_step_health_data_locked(self, leaf, package_index, phase, record, *, post_round_id=None):
        """Untrusted LOCAL stage declaration only, never actual capture/time proof."""
        if self._active_request_lease is None:
            raise ValueError("original stage health namespace lease required")
        from ibsw_upgrade_executor import _step_health_data_inputs
        scope, stage, binding, request, before, postcondition = _step_health_data_inputs(leaf, package_index, phase, post_round_id)
        if scope is not self:
            raise ValueError("foreign original health scope")
        payload = _json_bytes(_stage_health_binding(binding, request.payload, phase, record,
            before=before, postcondition=postcondition))
        if max(len(record.stdout), len(record.stderr)) > MAXIMUM_INPUT_BYTES:
            raise ValueError("original stage health bytes exceed bounded input limit")
        writer = _JournalWriter(self, stage)
        try:
            for name, data in ((phase + "-health.stdout.bin", record.stdout), (phase + "-health.stderr.bin", record.stderr)):
                writer.write(name, data)
                self._hold(stage, name, data, allow_empty=True)
            writer.verify(); leaf.verify()
            self._commit_exclusive_binding(stage, payload, phase + "-health-binding.json")
            leaf.verify()
            return {"state": "STAGE_HEALTH_DECLARATION_DATA", "health_state": "UNKNOWN",
                "execution_state": "NOT_EXECUTED", "dispatch_state": "HOLD", "attestation_state": "DATA_ONLY_UNATTESTED"}
        except Exception as error:
            raise PreparationHold("local stage health DATA incomplete; preserve originals", stage.path) from error
        finally:
            writer.finish()

    def write_os_postcondition_data(self, leaf, package_index, record, stdout, stderr, metadata):
        """Local DATA primitive only; caller bytes cannot attest native EOF/PASS."""
        with self._request_namespace_lease():
            return self._write_os_postcondition_data_locked(leaf, package_index, record, stdout, stderr, metadata)

    def _write_os_postcondition_data_locked(self, leaf, package_index, record, stdout, stderr, metadata):
        from ibsw_upgrade_executor import _bound_os_postcondition_inputs
        if self._active_request_lease is None:
            raise PreparationHold("original postcondition namespace lease required")
        scope, stage, binding, request, dispatch, final_target, remote = _bound_os_postcondition_inputs(leaf, package_index)
        if scope is not self:
            raise ValueError("foreign postcondition original scope")
        match = _post_version_data(binding, final_target, record)
        version_bytes = _json_bytes({**_query_data_result(record), **match})
        log_bytes = _json_bytes(_post_log_data(remote, stdout, stderr, metadata,
            expected_uid=_post_original_uid(dispatch.payload)))
        try:
            os.mkdir("postconditions", 0o700, dir_fd=stage.fd)
            os.fsync(stage.fd)
        except FileExistsError:
            self._read_live_postconditions(stage, binding, final_target)
        collection = self.session._directory(stage.path / "postconditions")
        self._private_directory(collection)
        round_id = "post-" + secrets.token_hex(16)
        os.mkdir(round_id, 0o700, dir_fd=collection.fd)
        os.fsync(collection.fd)
        original = self.session._directory(collection.path / round_id)
        self._private_directory(original)
        writers = []
        try:
            for label, payloads in (("version", (("stdout.bin", record.stdout), ("stderr.bin", record.stderr), ("result.json", version_bytes))),
                                    ("owned-logs", (("stdout.bin", stdout), ("stderr.bin", stderr), ("metadata.json", log_bytes)))):
                os.mkdir(label, 0o700, dir_fd=original.fd)
                output = self.session._directory(original.path / label)
                self._private_directory(output)
                writer = _JournalWriter(self, output); writers.append(writer)
                for name, payload in payloads:
                    writer.write(name, payload)
                    self._hold(output, name, payload, allow_empty=name in {"stdout.bin", "stderr.bin"})
                os.fsync(output.fd)
                writer.verify(); leaf.verify()
            os.fsync(original.fd)
            self._commit_exclusive_binding(original, _json_bytes(_post_binding(binding, request.payload, dispatch.payload,
                round_id, version_bytes, log_bytes, match)), "post-binding.json")
            leaf.verify()
            return {"state": "POSTCONDITION_DATA_COMMITTED", "round_directory": str(original.path), **match}
        except Exception as error:
            raise PreparationHold("postcondition DATA incomplete; preserve original round", original.path) from error
        finally:
            # Each actual writer is attempted; operator interruptions retain priority.
            original_error = sys.exc_info()[1]
            cleanup = None
            for writer in reversed(writers):
                try:
                    writer.close()
                except BaseException as error:
                    self.cleanup_issues.append(error)
                    if cleanup is None or (isinstance(cleanup, Exception) and not isinstance(error, Exception)):
                        cleanup = error
            if cleanup is not None and (original_error is None or (isinstance(original_error, Exception) and not isinstance(cleanup, Exception))):
                raise cleanup

    def _stage(self, node, component, package_index, create=False):
        self.verify()
        if node not in self.devices or component not in self.parsed.selected:
            raise ValueError("node/component is outside this exact prepared plan")
        stage_key = declared_step_key(self.policy, component, package_index)
        if create:
            # Persist original run-path names before any write-ahead record;
            # original prepare writes already fsynced each plan/input file.
            for parent in self.namespace_parents:
                self.verify()
                os.fsync(parent.fd)
        directory = self.directory
        for name, exclusive in ((node, False), (stage_key, True)):
            if create:
                try:
                    os.mkdir(name, 0o700, dir_fd=directory.fd)
                    os.fsync(directory.fd)
                except FileExistsError:
                    if exclusive:
                        raise PreparationHold("existing step preserved; inspect original state", self.run_directory)
            directory = self.session._directory(directory.path / name)
            self._private_directory(directory)
            self.verify()
        return directory, stage_key

    def _candidate(self, node, component, package_index, stage_key):
        return _declared_candidate_data(self.policy, self.devices[node], run_id=self.run_id,
            method=self.parsed.method, switch_dir=self.parsed.switch_dir, plan_sha256=self.plan_sha256,
            input_sha256=[hashlib.sha256(source.payload).hexdigest() for source in self.session._files],
            component=component, package_index=package_index, stage_key=stage_key)

    def prepare_requested_step(self, node, component, package_index=0):
        with self._request_namespace_lease():
            return self._prepare_requested_step_locked(node, component, package_index)

    def _prepare_requested_step_locked(self, node, component, package_index=0):
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        self.verify()
        if node not in self.devices or component not in self.parsed.selected:
            raise ValueError("node/component is outside this exact prepared plan")
        stage_key = declared_step_key(self.policy, component, package_index)
        script, binding = self._candidate(node, component, package_index, stage_key)
        directory, stage_key = self._stage(node, component, package_index, create=True)
        writer = _JournalWriter(self, directory)
        try:
            writer.write("step.sh", script)
            writer.write("step-binding.json", _json_bytes(binding))
            os.fsync(directory.fd)
            self._hold(directory, "step.sh", script)
            self._hold(directory, "step-binding.json", _json_bytes(binding))
            writer.verify()
            self.verify()
            return str(directory.path)
        except Exception as error:
            raise PreparationHold("declared step incomplete; retain original evidence", directory.path) from error
        finally:
            writer.finish()

    def inspect_step(self, node, component, package_index=0):
        directory, stage_key = self._stage(node, component, package_index)
        script, binding = self._candidate(node, component, package_index, stage_key)
        self._hold(directory, "step.sh", script)
        self._hold(directory, "step-binding.json", _json_bytes(binding))
        names = set(os.listdir(directory.fd))
        try:
            names, _originals, _has_restore = _validate_commands_data_graph(names, binding,
                lambda name: self._hold(directory, name, allow_empty=name in _EMPTY_STAGE_DATA_RAW).payload,
                read_postconditions=lambda: self._read_live_postconditions(directory, binding), switch_dir=self.parsed.switch_dir)
        except (ValueError, OSError) as error:
            raise PreparationHold("unknown before/request residue; no replay", directory.path) from error
        if names == {"step.sh", "step-binding.json"}:
            state = "NOT_DISPATCHED"
        elif names == {"step.sh", "step-binding.json", "request.json"}:
            held = self._hold(directory, "request.json")
            try:
                request = json.loads(held.payload)
                token = request["request_id"]
                if not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{32}", token):
                    raise ValueError("invalid original request id")
                expected = {"schema_version": 1, "state": "REQUESTED", "activation_state": "UNKNOWN",
                            "execution_state": "NOT_EXECUTED", "binding": binding, "request_id": token}
                if held.payload != _json_bytes(expected):
                    raise ValueError("original request does not match held plan/script")
            except (ValueError, KeyError, TypeError) as error:
                raise PreparationHold("unknown original request; no replay", directory.path) from error
            state = "UNKNOWN"
        else:
            raise PreparationHold("unknown request/step residue; no replay", directory.path)
        self.verify()
        return {"state": state, "execution_state": "NOT_EXECUTED", "stage": stage_key}

    def request_prepared_step(self, node, component, package_index=0):
        with self._request_namespace_lease():
            return self._request_prepared_step_locked(node, component, package_index)

    def _request_prepared_step_locked(self, node, component, package_index=0):
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        if node not in self.devices:
            raise ValueError("node is outside this exact prepared plan")
        self._check_retained_requests_locked(node)
        return self._publish_requested_step_locked(node, component, package_index)

    def _publish_requested_step_locked(self, node, component, package_index=0):
        if self._active_request_lease is None:
            raise PreparationHold("original request namespace lease required")
        state = self.inspect_step(node, component, package_index)
        if state["state"] != "NOT_DISPATCHED":
            raise PreparationHold("UNKNOWN original request; automatic resend forbidden", self.run_directory)
        directory, stage_key = self._stage(node, component, package_index)
        _script, binding = self._candidate(node, component, package_index, stage_key)
        payload = _json_bytes({"schema_version": 1, "state": "REQUESTED", "activation_state": "UNKNOWN",
            "execution_state": "NOT_EXECUTED", "binding": binding, "request_id": secrets.token_hex(16)})
        temporary = ".request-" + secrets.token_hex(16) + ".json"
        writer = _JournalWriter(self, directory)
        try:
            writer.write(temporary, payload)  # Complete body + original file fsync.
            writer.verify()
            os.link(temporary, "request.json", src_dir_fd=directory.fd, dst_dir_fd=directory.fd,
                    follow_symlinks=False)  # Atomic same-FS publication; never replace.
            fd = writer.files[0][1]
            opened = os.fstat(fd)
            for name in (temporary, "request.json"):
                named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
                    raise ValueError("original request namespace changed")
            if os.pread(fd, len(payload) + 1, 0) != payload:
                raise ValueError("original request bytes changed")
            self.verify()
            # Final input verification must not conceal a replaced candidate.
            # This is a conditional observed-owner check, not a claim of an
            # atomic compare-and-unlink syscall against hostile same-UID writers.
            for name in ("request.json", temporary):
                named = os.stat(name, dir_fd=directory.fd, follow_symlinks=False)
                if (named.st_dev, named.st_ino) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                    raise ValueError("original request candidate changed; preserve replacement")
            os.unlink(temporary, dir_fd=directory.fd)  # Only this verified original candidate.
            os.fsync(directory.fd)  # Critical publication/directory durability boundary.
            self._hold(directory, "request.json", payload)
            return self.inspect_step(node, component, package_index)
        except Exception as error:
            raise PreparationHold("request publication uncertain; preserve UNKNOWN/residue", directory.path) from error
        finally:
            writer.finish()

    def close(self):
        if self.closed:
            if self._package_source_owner is not None or self._package_source_lifecycle_failure is not None:
                # Repeat calls report original source cleanup uncertainty but
                # never touch or retry potentially reused numeric FD slots.
                _raise_cleanup_issues(self.cleanup_issues)
            if self._package_source_lifecycle_failure is not None:
                raise self._package_source_lifecycle_failure
            return
        if self._package_source_owns and self._package_source_borrowers:
            # Revocation only. Keep original FDs while children still own borrows.
            # This marker is never cleared when the last borrower is released.
            if self._package_source_lifecycle_failure is None:
                self._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original package owner still has live or unknown child borrows')
            raise self._package_source_lifecycle_failure
        self.closed = True
        issues = list(self.cleanup_issues)
        for held in reversed(tuple(self.files.values())):
            try:
                held.close()
            except BaseException as error:
                issues.append(error)
        if self._package_source_owns and self._package_source_owner is not None:
            try:
                self._package_source_owner.close()
            except BaseException as error:
                issues.append(error)
        if self.session is not None:
            try:
                self.session.close()
            except BaseException as error:
                issues.append(error)
        if self._package_source_parent is not None and not issues:
            self._package_source_parent._package_source_borrowers.discard(self)
        # A lifecycle failure does not skip actual owned cleanup after borrows
        # release. Surface HOLD only after all files/holder/session were attempted.
        if (self._package_source_lifecycle_failure is not None
                and not any(issue is self._package_source_lifecycle_failure for issue in issues)):
            issues.append(self._package_source_lifecycle_failure)
        self.cleanup_issues = issues
        for error in issues:
            if not isinstance(error, Exception):
                raise error  # After every owned cleanup attempt, retain NI exact.
        _raise_cleanup_issues(issues)

    def __enter__(self):
        self.verify()
        return self

    def __exit__(self, kind, value, traceback):
        try:
            self.close()
        except BaseException as error:
            if value is None or (isinstance(value, Exception) and not isinstance(error, Exception)):
                raise
        return False


def open_prepared_run(entry, cwd, args, run_directory):
    """Fresh original input/plan/script scope; DATA only, never dispatch admission."""
    return _PreparedRunScope(entry, cwd, args, run_directory)


def _manual_input_args(args):
    args = tuple(args)
    return args if "--standalone-inputs" in args else args + ("--standalone-inputs",)


def prepare_manual_run(entry, cwd, args):
    """New explicit manual invocation; no deployment, history or file locks."""
    return prepare_not_executed_run(entry, cwd, _manual_input_args(args), manual_execution=True)


def open_manual_run(entry, cwd, args, run_directory):
    """Workers in one manual invocation share only that invocation's journal."""
    return _PreparedRunScope(entry, cwd, _manual_input_args(args), run_directory, manual_execution=True)
