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
import math
import os
from pathlib import Path
import posixpath
import re
import secrets
import shlex
import stat
import sys
import threading
import time

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
from ibsw_upgrade_component import render_declared_step, _scp_download_pair as _SCP_DOWNLOAD_PAIR
# Trusted-driver-import code/object anchor for graph-only DATA parsing. The
# later live producer audit still independently holds/compiles the full source.
_SCP_DOWNLOAD_PAIR_IMAGE = (_SCP_DOWNLOAD_PAIR, _SCP_DOWNLOAD_PAIR.__code__,
                            _SCP_DOWNLOAD_PAIR.__globals__)
from ibsw_upgrade_schedule import (declared_step_key, component_order, COMPONENT_REGISTRY,
    component_status_document, validate_component_status_document,
    native_component_status_document, validate_native_component_status_document)
from project_contract import BRINGUP_OUTPUT_SPECS
from ssh_key_preparation import public_key_identity_bytes


# Finite probe-runtime baseline at trusted driver import, before any invocation
# or test IO seam. This is not a whole-stdlib / prior-interpreter attestation.
_SCP_PROBE_MODULES = (json, base64, shlex, math, time, threading)
_SCP_PROBE_LEAVES = (json.loads, json.dumps, base64.b64encode, shlex.quote,
    math.isfinite, time.monotonic, time.sleep, threading.Lock, threading.Timer, threading.Event)
_SCP_PROBE_LEAF_STATE = tuple((type(value), getattr(value, '__code__', None),
    getattr(value, '__globals__', None)) for value in _SCP_PROBE_LEAVES)
_SCP_PROBE_CONTEXT = (contextmanager, contextmanager.__code__, contextmanager.__globals__,
    contextmanager.__globals__['_GeneratorContextManager'], sys.modules['contextlib'])


def _capture_native_scp_cpld_bootstrap():
    """Trusted normal driver-import originals, never a runtime refresh.

    This does not attest an interpreter already hostile before driver import.
    Nothing is captured successfully unless every temporary owner closes.
    """
    from types import ModuleType
    from ibsw_upgrade_inputs import _HeldDirectory
    component = sys.modules.get('ibsw_upgrade_component')
    if type(component) is not ModuleType or vars(component).get('render_declared_step') is not render_declared_step:
        raise SharedUpgradeHold('fixed CPLD renderer bootstrap unavailable')
    namespace = vars(component)
    rendered = namespace.get('RenderedStep')
    if type(rendered) is not type:
        raise SharedUpgradeHold('fixed CPLD rendered class bootstrap unavailable')
    class_members = tuple(vars(rendered).items())
    layout = namespace['_fixed_layout'](__file__)
    paths = (namespace['_TEMPLATE'], layout / 'upgrade-owned-runner.sh')
    if any(type(path) is not type(Path()) for path in paths):
        raise SharedUpgradeHold('fixed CPLD bootstrap paths unavailable')
    directory = None
    held = []
    images = []
    primary = None
    try:
        directory = _HeldDirectory(layout)
        for path in paths:
            if path.parent != layout:
                raise SharedUpgradeHold('fixed CPLD bootstrap layout changed')
            original = _HeldFile(path, directory)
            held.append(original)
            item = os.fstat(original.fd)
            if item.st_nlink != 1 or item.st_mode & 0o022:
                raise SharedUpgradeHold('fixed CPLD bootstrap template unsafe')
            identity = (item.st_dev, item.st_ino, item.st_mode, item.st_uid, item.st_gid,
                        item.st_nlink, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
            images.append((str(path), identity, original.payload))
        for original in held:
            original.verify()
        directory.verify()
    except BaseException as error:
        primary = error
    finally:
        for original in tuple(reversed(held)) + ((directory,) if directory is not None else ()):
            try:
                original.close()
            except BaseException as error:
                if primary is None or isinstance(primary, Exception) and not isinstance(error, Exception):
                    primary = error
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        raise SharedUpgradeHold('fixed CPLD bootstrap originals uncertain') from None
    return component, rendered, class_members, tuple(images), paths


_SCP_CPLD_BOOTSTRAP = _capture_native_scp_cpld_bootstrap()

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


def _scp_download_document(binding, dispatch_payload, read, lines):
    """Strict SCP measurement DATA; never infer a live owner from saved JSON."""
    from types import FunctionType
    image = _SCP_DOWNLOAD_PAIR_IMAGE
    if (type(image) is not tuple or len(image) != 3 or type(image[0]) is not FunctionType
            or _SCP_DOWNLOAD_PAIR is not image[0] or image[0].__code__ is not image[1]
            or image[0].__globals__ is not image[2] or image[0].__defaults__ is not None
            or image[0].__kwdefaults__ is not None or image[0].__closure__ is not None
            or image[2].get('_scp_download_pair') is not image[0]
            or image[2].get('re') is not re or image[2].get('math') is not math):
        raise ValueError('original imported SCP DATA parser changed')
    if type(binding) is not dict or binding.get('component') != 'os':
        raise ValueError('only original OS SCP measurement DATA')
    names = {'request.json', 'step.sh', 'step-binding.json', 'runner.sh',
             'runner-binding.json', 'scp-source-request.json'}
    _validate_scp_request_content_graph(names, binding, read)
    if read('step-binding.json') != _json_bytes(binding):
        raise ValueError('original SCP step binding bytes required')
    request_payload = read('request.json')
    companion_payload = read('scp-source-request.json')
    companion = json.loads(companion_payload)
    dispatch = json.loads(dispatch_payload)
    if (type(dispatch) is not dict or dispatch.get('schema_version') != 2
            or dispatch.get('state') != 'COMPONENT_DISPATCH_DATA_ONLY'
            or dispatch.get('launch_kind') != 'SCP_STDIN_OWNED_RUNNER_V2'
            or dispatch.get('binding') != binding
            or dispatch.get('request_sha256') != hashlib.sha256(request_payload).hexdigest()
            or dispatch.get('scp_companion_sha256') != hashlib.sha256(companion_payload).hexdigest()
            or len(companion['packages']) != 1):
        raise ValueError('original SCP dispatch/request/companion required')
    path, package = next(iter(companion['packages'].items()))
    expected = dict(binding_sha256=hashlib.sha256(read('step-binding.json')).hexdigest(),
                    path=path, size=package['size'], sha256=package['sha256'])
    if (type(lines) is not bytes or len(lines) > 4096 or not lines.endswith(b'\n')
            or lines.count(b'\n') != 2 or b'\r' in lines):
        raise ValueError('exact original SCP measurement packet required')
    first, second, _tail = lines.split(b'\n')
    if first.startswith(b'IBSW_SCP_CONTENT_VERIFIED='):
        marker, numeric = first, second
    else:
        marker, numeric = second, first
    parsed, content = image[0](marker, numeric)
    if content != (expected['binding_sha256'], path, package['size'], package['sha256']):
        raise ValueError('original SCP measurement content differs from companion')
    measurement = dict(parsed)
    measurement['content_marker'] = parsed['content_marker'].decode('ascii')
    measurement['raw_line'] = parsed['raw_line'].decode('ascii')
    return dict(schema_version=2, state='SCP_DOWNLOAD_MEASUREMENT_DATA_ONLY',
        binding=binding, dispatch_sha256=hashlib.sha256(dispatch_payload).hexdigest(),
        request_sha256=hashlib.sha256(request_payload).hexdigest(),
        companion_sha256=hashlib.sha256(companion_payload).hexdigest(),
        content_marker_sha256=hashlib.sha256(parsed['content_marker']).hexdigest(),
        raw_lines_base64=base64.b64encode(lines).decode('ascii'), measurement=measurement)


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



def _scp_component_launch_command_data(remote, runner_sha256, step_sha256):
    """Pure command DATA from the unique literal in the fixed original image.

    Do not call a mutable cached provider function during graph validation.
    Native writer/consumer separately require the live compiled producer joint.
    """
    import ast
    directory = Path(__file__).resolve().parent
    rows, primary, raw = [], None, None

    def identity(info):
        return info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode)

    def facts(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink,
                info.st_uid, info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    def opened(name, flags, parent=None):
        named = os.stat(name, dir_fd=parent, follow_symlinks=False)
        fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, 'O_CLOEXEC', 0), dir_fd=parent)
        rows.append((fd, identity(named)))
        if identity(os.fstat(fd)) != identity(named):
            raise ValueError('fixed graph image original identity changed')
        return fd, named

    try:
        parent, before_parent = opened(str(directory), os.O_RDONLY | os.O_DIRECTORY)
        fd, before = opened('ibsw_upgrade_scp.py', os.O_RDONLY, parent)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_mode & 0o022 or not 0 < before.st_size <= MAXIMUM_INPUT_BYTES):
            raise ValueError('bounded readonly original SCP image required')
        chunks, count = [], 0
        while count < before.st_size:
            part = os.read(fd, min(65536, before.st_size - count))
            if not part: raise ValueError('partial original SCP image')
            chunks.append(part); count += len(part)
        if (os.read(fd, 1) or facts(os.fstat(fd)) != facts(before)
                or facts(os.stat('ibsw_upgrade_scp.py', dir_fd=parent, follow_symlinks=False)) != facts(before)
                or identity(os.fstat(parent)) != identity(before_parent)
                or identity(os.stat(directory, follow_symlinks=False)) != identity(before_parent)):
            raise ValueError('original SCP image changed during graph read')
        raw = b''.join(chunks)
    except BaseException as error:
        primary = error
    finally:
        for fd, original in reversed(rows):
            try:
                if identity(os.fstat(fd)) != original:
                    raise ValueError('original graph source descriptor changed; no numeric retry')
                os.close(fd)
            except BaseException as error:
                if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                    primary = error
    if primary is not None: raise primary
    tree = ast.parse(raw)
    matches = [node for node in tree.body if isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(isinstance(target, ast.Name) and target.id == '_STDIN_LAUNCHER'
                for target in (node.targets if isinstance(node, ast.Assign) else (node.target,)))]
    if (len(matches) != 1 or not isinstance(matches[0].value, ast.Constant)
            or type(matches[0].value.value) is not str):
        raise ValueError('unique literal fixed stdin launcher required')
    expression = 'import base64;exec(base64.b64decode(' + repr(base64.b64encode(
        matches[0].value.value.encode()).decode()) + '))'
    return '/usr/bin/python3 -c ' + shlex.quote(expression) + ''.join(
        ' ' + shlex.quote(value) for value in (remote, runner_sha256, step_sha256))


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
                or document.get("runner_binding_sha256") != hashlib.sha256(read("runner-binding.json")).hexdigest()):
            raise ValueError("original component dispatch binding changed")
        records = _component_raw_records(document["records"])
        if document.get('launch_kind') == 'SCP_STDIN_OWNED_RUNNER_V2':
            if (set(document) != {'schema_version', 'state', 'binding', 'request_sha256',
                    'remote_script', 'records', 'launch_kind', 'runner_binding_sha256', 'scp_companion_sha256'}
                    or document.get('state') != 'COMPONENT_DISPATCH_DATA_ONLY'
                    or binding['component'] not in ('os', 'bios', 'cpld')
                    or (binding['component'] in ('bios', 'cpld') and binding['package_index'] != 0)
                    or 'scp-source-request.json' not in files
                    or 'package-source.json' in files
                    or document.get('scp_companion_sha256') != hashlib.sha256(read('scp-source-request.json')).hexdigest()
                    or posixpath.dirname(posixpath.dirname(document['remote_script'])) != switch_dir
                    or runner_binding.get('remote_script') != document['remote_script']
                    or records[-1]['stdout_base64'] != base64.b64encode(b'IBSW_LAUNCH_REQUESTED\n').decode('ascii')
                    or records[-1]['stderr_base64'] != '' or records[-1]['returncode'] != 0
                    or records[-1]['stream_complete'] is not True):
                raise ValueError('original SCP-only CPLD companion/remote graph required')
            expected = _scp_component_launch_command_data(document['remote_script'],
                hashlib.sha256(read('runner.sh')).hexdigest(), hashlib.sha256(read('step.sh')).hexdigest())
        elif document.get('launch_kind') == 'OWNED_RUNNER_V1':
            if 'scp-source-request.json' in files or 'scp_companion_sha256' in document:
                raise ValueError('SCP companion cannot authorize a V1 dispatch')
            from ibsw_upgrade_executor import _owned_launch_command
            expected = _owned_launch_command(document['remote_script'])
        else:
            raise ValueError('unknown original component launch kind')
        if records[-1]["command"] != expected:
            raise ValueError("original component launch chain changed")
    repair_files = {"after.commands", "missing.commands", "component-repair.json"}
    for name in sorted(files & _DOWNLOAD_FILES):
        document=json.loads(read(name))
        number=int(name[len('download-attempt-'):-len('.json')])
        if 'component-dispatch.json' not in files:
            raise ValueError('original download measurement graph changed')
        lines = base64.b64decode(document['raw_lines_base64'], validate=True)
        if 'scp-source-request.json' in files:
            expected_download = _scp_download_document(binding,
                read('component-dispatch.json'), read, lines)
        else:
            expected_download = _download_document(binding, read('component-dispatch.json'), lines)
        if ('component-dispatch.json' not in files or document != expected_download
                or document['measurement']['attempt'] != number
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


def _fixed_scp_source_api(scope, *, probe=False):
    """Fresh fixed-source/object joint, not source-instance or native authority.

    Cached provider code is compiled for comparison, never re-executed. The
    returned references are internal original-object anchors, not a permit.
    The old package-source audit/default is deliberately independent/unchanged.
    """
    import ast
    import base64 as std_base64
    import builtins
    import dataclasses
    import importlib.machinery
    import importlib.util
    import ipaddress
    import struct
    from types import CodeType, FunctionType, GetSetDescriptorType, ModuleType
    from ibsw_upgrade_inputs import _HeldDirectory

    if type(probe) is not bool:
        raise SharedUpgradeHold('fixed SCP source probe mode must be bool')
    if type(scope) is not _PreparedRunScope:
        raise SharedUpgradeHold('original SCP source scope required')
    scope.verify()  # A poisoned/closed parent must not reopen audit sources.
    if scope.closed or scope.cleanup_issues or scope._package_source_lifecycle_failure is not None:
        raise SharedUpgradeHold('fixed SCP source scope is not reusable')
    directory = None
    held = []
    created = module = result = primary = None
    cleanup = []
    name = 'ibsw_upgrade_scp'
    root = Path(__file__).absolute().parent

    def refuse():
        raise SharedUpgradeHold('fixed SCP source provider joint changed')

    def text(value, expected):
        return type(value) is str and value == expected

    def unique_code(parent, selected):
        values = [value for value in parent.co_consts
                  if type(value) is CodeType and value.co_name == selected]
        if len(values) != 1:
            refuse()
        return values[0]

    def function(value, expected, namespace, module_name, cells=(), annotations=None):
        if (type(value) is not FunctionType or value.__globals__ is not namespace
                or not text(value.__module__, module_name) or value.__code__ != expected
                or value.__defaults__ is not None or value.__kwdefaults__ is not None
                or type(value.__annotations__) is not dict):
            refuse()
        if annotations is not None:
            actual_annotations = value.__annotations__
            if (any(type(key) is not str for key in actual_annotations)
                    or set(actual_annotations) != set(annotations)):
                refuse()
            for key, original in annotations.items():
                if ((original is None and actual_annotations[key] is not None)
                        or original is not None and not text(actual_annotations[key], original)):
                    refuse()
        actual = () if value.__closure__ is None else value.__closure__
        if len(actual) != len(cells):
            refuse()
        for cell, original in zip(actual, cells):
            if cell.cell_contents is not original:
                refuse()
        return value

    def producer_function(value, expected, namespace, module_name, *, tuple_default=False,
                          native_keywords=False, cells=()):
        # Narrow additional signatures only. The default source19 function
        # validator and all its old call sites remain byte-for-byte unchanged.
        if (type(value) is not FunctionType or value.__globals__ is not namespace
                or not text(value.__module__, module_name) or value.__code__ != expected
                or type(value.__annotations__) is not dict or value.__annotations__):
            refuse()
        defaults = value.__defaults__
        if tuple_default:
            if (type(defaults) is not tuple or len(defaults) != 1
                    or type(defaults[0]) is not tuple or defaults[0]):
                refuse()
        elif defaults is not None:
            refuse()
        keywords = value.__kwdefaults__
        if native_keywords:
            if (type(keywords) is not dict or any(type(key) is not str for key in keywords)
                    or set(keywords) != {'capture_raw', 'reason_code'}
                    or keywords['capture_raw'] is not None
                    or not text(keywords['reason_code'], 'READONLY_QUERY_FAILED')):
                refuse()
        elif keywords is not None:
            refuse()
        actual = () if value.__closure__ is None else value.__closure__
        if len(actual) != len(cells) or any(cell.cell_contents is not original
                                         for cell, original in zip(actual, cells)):
            refuse()
        return value


    def fixed_module(value, expected_name, path):
        if type(value) is not ModuleType or sys.modules.get(expected_name) is not value:
            refuse()
        namespace = vars(value)
        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')
        if (not text(namespace.get('__name__'), expected_name) or not text(namespace.get('__file__'), str(path))
                or type(spec) is not importlib.machinery.ModuleSpec
                or type(loader) is not importlib.machinery.SourceFileLoader
                or not text(spec.name, expected_name) or not text(spec.origin, str(path)) or spec.loader is not loader
                or not text(loader.name, expected_name) or not text(loader.path, str(path))
                or namespace.get('__builtins__') is not builtins.__dict__):
            refuse()
        return namespace

    def original_data(tree, selected):
        values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == selected]
        if len(values) != 1:
            refuse()
        return ast.literal_eval(values[0])

    try:
        directory = _HeldDirectory(root)
        images = {}
        filenames = ('ibsw_upgrade_scp.py', 'ssh_key_preparation.py', Path(__file__).name)
        if probe:
            filenames += ('ibsw_upgrade_observer.py',)
        for filename in filenames:
            original = _HeldFile(root / filename, directory)
            held.append(original)  # Before any subsequent metadata/compile operation.
            info = os.fstat(original.fd)
            if info.st_nlink != 1 or info.st_mode & 0o022:
                refuse()
            images[filename] = (original, compile(original.payload, str(root / filename),
                'exec', dont_inherit=True, optimize=sys.flags.optimize))
        provider, code = images['ibsw_upgrade_scp.py']
        module = sys.modules.get(name)
        if name in sys.modules and module is None:
            refuse()  # A cached None is not cold-import permission.
        if module is None:
            spec = importlib.util.spec_from_file_location(name, str(root / 'ibsw_upgrade_scp.py'))
            module = importlib.util.module_from_spec(spec)
            created = module
            sys.modules[name] = module
            exec(code, vars(module))  # Only genuinely absent fixed held source.
        namespace = fixed_module(module, name, root / 'ibsw_upgrade_scp.py')
        factory = function(namespace.get('source_from_known_hosts'),
                           unique_code(code, 'source_from_known_hosts'), namespace, name)
        read_trust = function(namespace.get('_read_trust'), unique_code(code, '_read_trust'), namespace, name)
        shared_verify = function(namespace.get('verify_source_shared'),
                                 unique_code(code, 'verify_source_shared'), namespace, name)
        errors = namespace.get('ERRORS')
        expected_errors = original_data(ast.parse(provider.payload), 'ERRORS')
        if (type(errors) is not dict or type(expected_errors) is not dict
                or any(type(key) is not str or type(value) is not str for key, value in errors.items())
                or any(type(key) is not str or type(value) is not str for key, value in expected_errors.items())
                or errors != expected_errors):
            refuse()
        error_class = namespace.get('ScpHold')
        if (type(error_class) is not type or error_class.__bases__ != (ValueError,)
                or not text(error_class.__module__, name)
                or set(vars(error_class)) != {'__module__', '__doc__', '__init__', '__weakref__'}):
            refuse()
        error_init = function(vars(error_class)['__init__'],
            unique_code(unique_code(code, 'ScpHold'), '__init__'), namespace, name, (error_class,))

        # The genuine public-key and endpoint parsers are part of this actual
        # factory call graph; a correct provider filename alone is insufficient.
        key_module = sys.modules.get('ssh_key_preparation')
        key_namespace = fixed_module(key_module, 'ssh_key_preparation', root / 'ssh_key_preparation.py')
        key_code = images['ssh_key_preparation.py'][1]
        key_parser = function(key_namespace.get('public_key_identity_bytes'),
            unique_code(key_code, 'public_key_identity_bytes'), key_namespace, 'ssh_key_preparation')
        key_error = key_namespace.get('SshKeyPreparationError')
        if (type(key_error) is not type or key_error.__bases__ != (ValueError,)
                or not text(key_error.__module__, 'ssh_key_preparation')
                or set(vars(key_error)) != {'__module__', '__doc__', '__weakref__'}
                or key_namespace.get('PUBLIC_KEY_LIMIT') != 65536
                or type(key_namespace.get('PUBLIC_KEY_LIMIT')) is not int):
            refuse()
        for selected, expected in (('base64', std_base64), ('struct', struct)):
            if key_namespace.get(selected) is not expected:
                refuse()
        driver_module = sys.modules.get(__name__)
        driver_namespace = fixed_module(driver_module, __name__, root / Path(__file__).name)
        if driver_namespace is not globals() or driver_namespace.get('public_key_identity_bytes') is not key_parser:
            refuse()
        endpoint_parser = function(driver_namespace.get('_known_host_endpoint_matches'),
            unique_code(images[Path(__file__).name][1], '_known_host_endpoint_matches'),
            driver_namespace, __name__)

        source_class = namespace.get('ScpSource')
        if (type(source_class) is not type or source_class.__bases__ != (object,)
                or not text(source_class.__module__, name) or not text(source_class.__qualname__, 'ScpSource')):
            refuse()
        members = dict(vars(source_class))  # Original object snapshot, not a live mappingproxy alias.
        field_names = ('host', 'user', 'port', 'known_hosts_path', 'host_keys', 'password', '_identity')
        field_types = dict(zip(field_names, ('str', 'str', 'int', 'Path', 'bytes', 'str', 'tuple')))
        model = sys.version_info[:2]
        if model not in ((3, 9), (3, 12)):
            refuse()  # Only these reviewed generator shapes; no name-only fallback.
        expected_members = {'__module__', '__annotations__', '__dict__', '__weakref__', '__doc__',
            'verify', 'public_document', '__dataclass_params__', '__dataclass_fields__',
            '__init__', '__repr__', '__eq__', '__setattr__', '__delattr__', '__hash__'}
        if model == (3, 12):
            expected_members.add('__match_args__')
        if (set(members) != expected_members or type(members['__annotations__']) is not dict
                or any(type(key) is not str or type(value) is not str for key, value in members['__annotations__'].items())
                or members['__annotations__'] != field_types
                or model == (3, 12) and (type(members['__match_args__']) is not tuple
                    or any(type(value) is not str for value in members['__match_args__'])
                    or members['__match_args__'] != field_names)):
            refuse()
        for selected in ('__dict__', '__weakref__'):
            descriptor = members[selected]
            if (type(descriptor) is not GetSetDescriptorType
                    or descriptor.__objclass__ is not source_class or descriptor.__name__ != selected):
                refuse()
        class_code = unique_code(code, 'ScpSource')
        source_verify = function(members['verify'], unique_code(class_code, 'verify'), namespace, name)
        source_document = function(members['public_document'],
                                   unique_code(class_code, 'public_document'), namespace, name)
        params, fields = members['__dataclass_params__'], members['__dataclass_fields__']
        if (type(params) is not dataclasses._DataclassParams or type(fields) is not dict
                or any(type(key) is not str for key in fields) or tuple(fields) != field_names):
            refuse()
        for selected, expected in (('init', True), ('repr', True), ('eq', True),
                ('order', False), ('unsafe_hash', False), ('frozen', True)):
            if getattr(params, selected) is not expected:
                refuse()
        if model == (3, 12):
            for selected, expected in (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False)):
                if getattr(params, selected) is not expected:
                    refuse()
        for selected in field_names:
            field = fields[selected]
            if (type(field) is not dataclasses.Field or not text(field.name, selected)
                    or not text(field.type, field_types[selected]) or field.default is not dataclasses.MISSING
                    or field.default_factory is not dataclasses.MISSING or field.init is not True
                    or field.compare is not True or field.hash is not None
                    or field.repr is not (selected not in ('password', '_identity'))
                    or field._field_type is not dataclasses._FIELD
                    or field.metadata is not dataclasses._EMPTY_METADATA
                    or model == (3, 12) and field.kw_only is not False):
                refuse()

        # Compiler inputs below come only from these reviewed fixed fields and
        # the two original stdlib generator shapes, not candidate method output.
        def generated(selected, args, body, local_names=(), returns=False):
            local_names = list(local_names)
            if model == (3, 9) and 'BUILTINS' not in local_names:
                local_names.append('BUILTINS')  # Apple3.9 _create_fn source.
            annotation = ''
            if returns:
                variable = '_return_type' if model == (3, 9) else '__dataclass_return_type__'
                local_names.append(variable)
                annotation = '->' + variable
            text = ('def __create_fn__(' + ', '.join(local_names) + '):\n'
                + ' def ' + selected + '(' + ','.join(args) + ')' + annotation + ':\n'
                + '\n'.join('  ' + line for line in body) + '\n return ' + selected)
            compiled = compile(text, '<string>', 'exec', dont_inherit=True, optimize=sys.flags.optimize)
            return unique_code(unique_code(compiled, '__create_fn__'), selected)

        type_names = [('_type_' + selected if model == (3, 9)
                       else '__dataclass_type_' + selected + '__') for selected in field_names]
        init_locals = type_names + (['MISSING', '_HAS_DEFAULT_FACTORY'] if model == (3, 9)
                                  else ['__dataclass_HAS_DEFAULT_FACTORY__', '__dataclass_builtins_object__'])
        target = 'BUILTINS.object' if model == (3, 9) else '__dataclass_builtins_object__'
        init_code = generated('__init__', ['self'] + [selected + ':' + variable
            for selected, variable in zip(field_names, type_names)],
            [target + '.__setattr__(self,' + repr(selected) + ',' + selected + ')' for selected in field_names],
            init_locals, returns=True)
        init = function(members['__init__'], init_code, namespace, name,
            (builtins,) if model == (3, 9) else (object,), dict(field_types, **{'return': None}))
        self_tuple = '(' + ','.join('self.' + selected for selected in field_names) + ',)'
        other_tuple = '(' + ','.join('other.' + selected for selected in field_names) + ',)'
        equality = function(members['__eq__'], generated('__eq__', ('self', 'other'),
            ['if other.__class__ is self.__class__:', ' return ' + self_tuple + '==' + other_tuple,
             'return NotImplemented']), namespace, name, annotations={})
        hashing = function(members['__hash__'], generated('__hash__', ('self',),
            ['return hash(' + self_tuple + ')']), namespace, name, annotations={})
        condition = ('type(self) is cls or name in (' + ','.join(repr(selected) for selected in field_names) + ',)'
            if model == (3, 9) else 'type(self) is cls or name in {' + ', '.join(repr(selected) for selected in field_names) + '}')
        frozen = []
        for method, word in (('__setattr__', 'assign to'), ('__delattr__', 'delete')):
            expected = generated(method, ('self', 'name', 'value') if method == '__setattr__' else ('self', 'name'),
                ['if ' + condition + ':', ' raise FrozenInstanceError(f"cannot ' + word + ' field {name!r}")',
                 'super(cls, self).' + method + '(name' + (', value)' if method == '__setattr__' else ')')],
                ('cls', 'FrozenInstanceError'))
            cells = {'cls': source_class, 'FrozenInstanceError': dataclasses.FrozenInstanceError}
            frozen.append(function(members[method], expected, namespace, name,
                tuple(cells[selected] for selected in expected.co_freevars), annotations={}))
        representation = members['__repr__']
        wrapper_code = unique_code(dataclasses._recursive_repr.__code__, 'wrapper')
        if (type(representation) is not FunctionType or representation.__code__ != wrapper_code
                or representation.__globals__ is not vars(dataclasses)
                or not text(representation.__module__, name) or representation.__defaults__ is not None
                or representation.__kwdefaults__ is not None or representation.__annotations__ != {}
                or representation.__closure__ is None or len(representation.__closure__) != 2):
            refuse()
        repr_cells = dict(zip(wrapper_code.co_freevars,
                              (cell.cell_contents for cell in representation.__closure__)))
        if set(repr_cells) != {'repr_running', 'user_function'} or type(repr_cells['repr_running']) is not set:
            refuse()
        repr_names = field_names[:-2]
        raw_repr = function(repr_cells['user_function'], generated('__repr__', ('self',),
            ['return self.__class__.__qualname__ + f"(' + ', '.join(
                selected + '={self.' + selected + '!r}' for selected in repr_names) + ')"']),
            namespace, name, annotations={})
        if vars(representation).get('__wrapped__') is not raw_repr:
            refuse()

        for selected, expected in (('os', os), ('Path', Path), ('stat', stat), ('hashlib', hashlib),
                ('base64', std_base64), ('ipaddress', ipaddress), ('re', re),
                ('dataclass', dataclasses.dataclass), ('field', dataclasses.field)):
            if namespace.get(selected) is not expected:
                refuse()
        # Recheck the complete actually used namespace/object joint after all
        # validation, before releasing the original source images.
        anchors = {'source_from_known_hosts': factory, '_read_trust': read_trust,
            'verify_source_shared': shared_verify, 'ScpSource': source_class, 'ScpHold': error_class,
            'ERRORS': errors}
        if (sys.modules.get(name) is not module or any(namespace.get(key) is not value for key, value in anchors.items())
                or errors != expected_errors or vars(error_class).get('__init__') is not error_init
                or sys.modules.get('ssh_key_preparation') is not key_module
                or key_namespace.get('public_key_identity_bytes') is not key_parser
                or driver_namespace.get('_known_host_endpoint_matches') is not endpoint_parser
                or any(vars(source_class).get(key) is not members[key] for key in expected_members)):
            refuse()
        probe_refs = None
        if probe:
            # Only the finite new producer branch sees runtime leaves. In
            # particular default source19 never rejects a legacy sleep IO mock.
            runtime_modules = (json, std_base64, shlex, math, time, threading)
            if (len(_SCP_PROBE_MODULES) != 6 or len(_SCP_PROBE_LEAVES) != 10
                    or len(_SCP_PROBE_LEAF_STATE) != 10
                    or any(type(value) is not ModuleType for value in runtime_modules)
                    or any(actual is not original for actual, original in zip(runtime_modules, _SCP_PROBE_MODULES))):
                refuse()
            for selected, original in zip(('json', 'base64', 'shlex', 'math', 'time', 'threading'), runtime_modules):
                if (sys.modules.get(selected) is not original or namespace.get(selected) is not original
                        or driver_namespace.get(selected) is not original):
                    refuse()
            runtime_leaves = (json.loads, json.dumps, std_base64.b64encode, shlex.quote,
                math.isfinite, time.monotonic, time.sleep, threading.Lock, threading.Timer, threading.Event)
            if any(actual is not original for actual, original in zip(runtime_leaves, _SCP_PROBE_LEAVES)):
                refuse()
            for value, (kind, original_code, original_globals) in zip(runtime_leaves, _SCP_PROBE_LEAF_STATE):
                if (type(value) is not kind or getattr(value, '__code__', None) is not original_code
                        or getattr(value, '__globals__', None) is not original_globals):
                    refuse()
            fixed_probe = producer_function(namespace.get('_probe_source_channel'),
                unique_code(code, '_probe_source_channel'), namespace, name)
            payload = producer_function(namespace.get('launch_payload'),
                unique_code(code, 'launch_payload'), namespace, name, tuple_default=True)
            helper_bytes = producer_function(namespace.get('remote_helper_bytes'),
                unique_code(code, 'remote_helper_bytes'), namespace, name)
            python_command = producer_function(namespace.get('_python_command'),
                unique_code(code, '_python_command'), namespace, name)
            helper = namespace.get('_REMOTE_HELPER')
            expected_helper = original_data(ast.parse(provider.payload), '_REMOTE_HELPER')
            if type(helper) is not str or type(expected_helper) is not str or helper != expected_helper:
                refuse()

            observer_name = 'ibsw_upgrade_observer'
            observer = sys.modules.get(observer_name)
            observer_namespace = fixed_module(observer, observer_name, root / (observer_name + '.py'))
            observer_original, observer_code = images[observer_name + '.py']
            if (observer_namespace.get('time') is not runtime_modules[4]
                    or observer_namespace.get('threading') is not runtime_modules[5]
                    or observer_namespace.get('SharedUpgradeHold') is not SharedUpgradeHold):
                refuse()
            context, context_code, context_globals, generator_cm, context_module = _SCP_PROBE_CONTEXT
            if (type(context) is not FunctionType or context is not contextmanager
                    or context.__code__ is not context_code or context.__globals__ is not context_globals
                    or type(context_module) is not ModuleType or sys.modules.get('contextlib') is not context_module
                    or context_globals is not vars(context_module)
                    or context_globals.get('contextmanager') is not context
                    or context_globals.get('_GeneratorContextManager') is not generator_cm
                    or observer_namespace.get('contextmanager') is not context):
                refuse()
            owned = observer_namespace.get('_owned_phase')
            if type(owned) is not FunctionType or set(vars(owned)) != {'__wrapped__'}:
                refuse()
            owned_inner = producer_function(vars(owned)['__wrapped__'],
                unique_code(observer_code, '_owned_phase'), observer_namespace, observer_name)
            owned = producer_function(owned, unique_code(context_code, 'helper'),
                context_globals, observer_name, cells=(owned_inner,))
            remaining = producer_function(observer_namespace.get('_remaining'),
                unique_code(observer_code, '_remaining'), observer_namespace, observer_name)
            native_hold = observer_namespace.get('_NativeObservationHold')
            if (type(native_hold) is not type or native_hold.__bases__ != (ValueError,)
                    or not text(native_hold.__module__, observer_name)
                    or not text(native_hold.__name__, '_NativeObservationHold')
                    or not text(native_hold.__qualname__, '_NativeObservationHold')
                    or set(vars(native_hold)) != {'__module__', '__doc__', '__init__', '__weakref__'}
                    or vars(native_hold)['__doc__'] is not None):
                refuse()
            hold_init = producer_function(vars(native_hold)['__init__'],
                unique_code(unique_code(observer_code, '_NativeObservationHold'), '__init__'),
                observer_namespace, observer_name, tuple_default=True,
                native_keywords=True, cells=(native_hold,))
            hints = []
            for selected in ('READONLY_FAILURE_HINTS', 'UPGRADE_FAILURE_HINTS'):
                current_hints = observer_namespace.get(selected)
                expected_hints = original_data(ast.parse(observer_original.payload), selected)
                if (type(current_hints) is not dict or type(expected_hints) is not dict
                        or any(type(key) is not str or type(value) is not str for key, value in current_hints.items())
                        or current_hints != expected_hints):
                    refuse()
                hints.append(current_hints)
            # These are source/object references, never a source/operation grant.
            probe_refs = (fixed_probe, payload, helper_bytes, python_command, helper,
                observer, owned, owned_inner, remaining, native_hold, hold_init,
                hints[0], hints[1], context, generator_cm, context_module) + runtime_modules + runtime_leaves
            if (any(namespace.get(selected) is not original for selected, original in (
                    ('_probe_source_channel', fixed_probe), ('launch_payload', payload),
                    ('remote_helper_bytes', helper_bytes), ('_python_command', python_command), ('_REMOTE_HELPER', helper)))
                    or sys.modules.get(observer_name) is not observer
                    or any(observer_namespace.get(selected) is not original for selected, original in (
                        ('_owned_phase', owned), ('_remaining', remaining), ('_NativeObservationHold', native_hold),
                        ('READONLY_FAILURE_HINTS', hints[0]), ('UPGRADE_FAILURE_HINTS', hints[1])))
                    or vars(owned).get('__wrapped__') is not owned_inner
                    or vars(native_hold).get('__init__') is not hold_init):
                refuse()


        for original in held:
            original.verify()
        directory.verify()
        # Flat strong-reference joint; compare each item with is on reuse.
        # No secret/source instance is returned or persisted by this audit.
        result = (module, factory, source_class, shared_verify, read_trust, error_class,
                  init, source_verify, source_document, errors, endpoint_parser, key_parser,
                  error_init, equality, hashing, frozen[0], frozen[1], representation, raw_repr)
        if probe:
            result = (result, probe_refs)
    except BaseException as error:
        primary = error
    finally:
        for original in tuple(reversed(held)) + ((directory,) if directory is not None else ()):
            try:
                original.close()
            except BaseException as error:
                cleanup.append(error)
                if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                    primary = error
        if cleanup:
            scope.cleanup_issues.extend(cleanup)
            if scope._package_source_lifecycle_failure is None:
                scope._package_source_lifecycle_failure = SharedUpgradeHold(
                    'fixed SCP source provider cleanup uncertain; original parent retained')
        if primary is not None and created is not None and sys.modules.get(name) is created:
            del sys.modules[name]
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        raise SharedUpgradeHold('fixed SCP source provider audit failed') from None
    return result


def _fixed_native_scp_cpld_api(scope):
    """Finite original producer joint; no command/payload/native permission.

    Default source19/probe32 are unchanged. Templates are checked against the
    closed trusted-import original image, never this call's new baseline.
    """
    import ast
    import builtins
    import dataclasses
    import importlib.machinery
    from types import CodeType, FunctionType, ModuleType, GetSetDescriptorType
    from ibsw_upgrade_inputs import _HeldDirectory

    group = scope
    if type(scope) is not _PreparedRunScope:
        raise SharedUpgradeHold('fixed native CPLD source scope required')
    for candidate in (getattr(scope, '_package_source_parent', None),
                      getattr(scope, '_native_parent', None)):
        if (type(candidate) is _PreparedRunScope and candidate is not scope
                and type(candidate._package_source_borrowers) is set
                and scope in candidate._package_source_borrowers):
            group = candidate
            break
    held = []
    directories = []
    audited_functions = []
    primary = result = None

    def refuse():
        raise SharedUpgradeHold('fixed native CPLD producer joint changed')

    def text(value, expected):
        return type(value) is str and value == expected

    def unique_code(parent, name):
        found = [value for value in parent.co_consts if type(value) is CodeType and value.co_name == name]
        if len(found) != 1:
            refuse()
        return found[0]

    def module(name, path):
        value = sys.modules.get(name)
        if type(value) is not ModuleType:
            refuse()
        namespace = vars(value)
        spec, loader = namespace.get('__spec__'), namespace.get('__loader__')
        if (not text(namespace.get('__name__'), name) or not text(namespace.get('__file__'), str(path))
                or type(spec) is not importlib.machinery.ModuleSpec
                or type(loader) is not importlib.machinery.SourceFileLoader
                or not text(spec.name, name) or not text(spec.origin, str(path)) or spec.loader is not loader
                or not text(loader.name, name) or not text(loader.path, str(path))
                or namespace.get('__builtins__') is not builtins.__dict__):
            refuse()
        return value, namespace

    def function(value, code, namespace, name, *, qualname=None, defaults=None, keywords=None,
                 annotations=None, cells=()):
        if (type(value) is not FunctionType or value.__code__ != code or value.__globals__ is not namespace
                or not text(value.__module__, name) or not text(value.__name__, code.co_name)
                or not text(value.__qualname__, qualname or code.co_name)
                or type(value.__annotations__) is not dict):
            refuse()
        if defaults is None:
            if value.__defaults__ is not None:
                refuse()
        else:
            if (type(value.__defaults__) is not tuple or len(value.__defaults__) != len(defaults)
                    or any(type(actual) is not type(expected) or actual != expected
                           for actual, expected in zip(value.__defaults__, defaults))):
                refuse()
        actual_keywords = value.__kwdefaults__
        if keywords is None:
            if actual_keywords is not None:
                refuse()
        elif (type(actual_keywords) is not dict or any(type(key) is not str for key in actual_keywords)
                or set(actual_keywords) != set(keywords)
                or any(type(actual_keywords[key]) is not type(expected) or actual_keywords[key] != expected
                       for key, expected in keywords.items())):
            refuse()
        expected_annotations = {} if annotations is None else annotations
        actual_annotations = value.__annotations__
        if (any(type(key) is not str for key in actual_annotations)
                or set(actual_annotations) != set(expected_annotations)
                or any(type(actual_annotations[key]) is not type(expected) or actual_annotations[key] != expected
                       for key, expected in expected_annotations.items())):
            refuse()
        actual_cells = () if value.__closure__ is None else value.__closure__
        if len(actual_cells) != len(cells) or any(cell.cell_contents is not expected
                                                for cell, expected in zip(actual_cells, cells)):
            refuse()
        audited_functions.append((value, code, namespace, name, qualname, defaults, keywords,
                                  annotations, cells))
        return value

    def original_data(tree, name):
        values = [node.value for node in tree.body if isinstance(node, ast.Assign)
                  and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                  and node.targets[0].id == name]
        if len(values) != 1:
            refuse()
        return ast.literal_eval(values[0])

    def identity(info):
        return (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid,
                info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns)

    try:
        scope.verify(); group.verify()
        if (not group.manual_execution or group.parsed.method != 'scp' or group.closed
                or not group._package_source_owns or group._package_source_owner is None
                or not set(group.parsed.selected).intersection(('os', 'bios', 'cpld'))):
            refuse()
        source19, probe32 = _fixed_scp_source_api(group, probe=True)
        original_binding = group._scp_source_binding
        if (type(original_binding) is not tuple or len(original_binding) != 3
                or group._scp_source is not original_binding[0]
                or type(original_binding[1]) is not tuple or len(original_binding[1]) != 19
                or len(source19) != 19 or len(probe32) != 32
                or any(actual is not old for actual, old in zip(source19, original_binding[1]))):
            refuse()
        bootstrap = _SCP_CPLD_BOOTSTRAP
        if (type(bootstrap) is not tuple or len(bootstrap) != 5 or type(bootstrap[2]) is not tuple
                or type(bootstrap[3]) is not tuple or len(bootstrap[3]) != 2
                or type(bootstrap[4]) is not tuple or len(bootstrap[4]) != 2):
            refuse()
        root = Path(__file__).absolute().parent
        tools_directory = _HeldDirectory(root)
        directories.append(tools_directory)
        images = {}
        for filename in ('ibsw_upgrade_scp.py', 'ibsw_upgrade_component.py',
                         'ibsw_upgrade_executor.py', 'ibsw_upgrade_contract.py', Path(__file__).name):
            original = _HeldFile(root / filename, tools_directory)
            held.append(original)
            info = os.fstat(original.fd)
            if info.st_nlink != 1 or info.st_mode & 0o022:
                refuse()
            images[filename] = (original, ast.parse(original.payload),
                compile(original.payload, str(root / filename), 'exec', dont_inherit=True,
                        optimize=sys.flags.optimize))
        provider, p = module('ibsw_upgrade_scp', root / 'ibsw_upgrade_scp.py')
        component, c = module('ibsw_upgrade_component', root / 'ibsw_upgrade_component.py')
        executor, e = module('ibsw_upgrade_executor', root / 'ibsw_upgrade_executor.py')
        contract, k = module('ibsw_upgrade_contract', root / 'ibsw_upgrade_contract.py')
        driver, d = module(__name__, root / Path(__file__).name)
        if (provider is not source19[0] or component is not bootstrap[0] or d is not globals()
                or p.get('_python_command') is not probe32[3] or p.get('remote_helper_bytes') is not probe32[2]
                or p.get('_REMOTE_HELPER') is not probe32[4]):
            refuse()
        provider_code = images['ibsw_upgrade_scp.py'][2]
        command = function(p.get('_stdin_launch_command'), unique_code(provider_code, '_stdin_launch_command'),
                           p, 'ibsw_upgrade_scp')
        launcher = p.get('_STDIN_LAUNCHER')
        expected_launcher = original_data(images['ibsw_upgrade_scp.py'][1], '_STDIN_LAUNCHER')
        if type(launcher) is not str or type(expected_launcher) is not str or launcher != expected_launcher:
            refuse()
        component_code = images['ibsw_upgrade_component.py'][2]
        render = function(c.get('_render'), unique_code(component_code, '_render'), c,
            'ibsw_upgrade_component', keywords={'refresh': None, 'effect': 'REBOOT_EXPECTED'})
        declared = function(c.get('render_declared_step'), unique_code(component_code, 'render_declared_step'),
            c, 'ibsw_upgrade_component', keywords={'package_index': 0, 'switch_dir': '/home/admin'})
        validate = function(c.get('_validate_plan'), unique_code(component_code, '_validate_plan'),
                            c, 'ibsw_upgrade_component')
        url = function(c.get('_package_url'), unique_code(component_code, '_package_url'), c,
                       'ibsw_upgrade_component')
        runner = function(e.get('_owned_runner_bytes'),
            unique_code(images['ibsw_upgrade_executor.py'][2], '_owned_runner_bytes'), e,
            'ibsw_upgrade_executor')
        layout = function(k.get('_fixed_layout'), unique_code(images['ibsw_upgrade_contract.py'][2], '_fixed_layout'),
                          k, 'ibsw_upgrade_contract')
        class_code = unique_code(images[Path(__file__).name][2], '_PreparedRunScope')
        context = function(vars(_PreparedRunScope).get('_native_scp_launch_context'),
            unique_code(class_code, '_native_scp_launch_context'), d, __name__,
            qualname='_PreparedRunScope._native_scp_launch_context')
        # Missing composition is HOLD, never an optional bypass of an existing
        # foreign method. Root must combine the original fixed wrapper first.
        wrapper = function(vars(_PreparedRunScope).get('_launch_native_scp_cpld'),
            unique_code(class_code, '_launch_native_scp_cpld'), d, __name__,
            qualname='_PreparedRunScope._launch_native_scp_cpld')
        # Finite OS measurement/manager callees. Original launch_refs[0:25]
        # retain their meaning; these are actual objects from the held compiled
        # images, not matching names or caller-supplied callbacks.
        def driver_method(name):
            return function(vars(_PreparedRunScope).get(name), unique_code(class_code, name),
                d, __name__, qualname='_PreparedRunScope.' + name)
        packet_pair = function(c.get('_scp_download_pair'),
            unique_code(component_code, '_scp_download_pair'), c, 'ibsw_upgrade_component')
        packet_parser = function(c.get('parse_scp_download_results'),
            unique_code(component_code, 'parse_scp_download_results'), c, 'ibsw_upgrade_component')
        scp_ack = function(c.get('scp_download_ack_bytes'),
            unique_code(component_code, 'scp_download_ack_bytes'), c, 'ibsw_upgrade_component')
        executor_code = images['ibsw_upgrade_executor.py'][2]
        extractor = function(e.get('_scp_download_packet'),
            unique_code(executor_code, '_scp_download_packet'), e, 'ibsw_upgrade_executor')
        driver_code = images[Path(__file__).name][2]
        measurement_document = function(d.get('_scp_download_document'),
            unique_code(driver_code, '_scp_download_document'), d, __name__)
        measurement_inputs = driver_method('_scp_download_inputs_locked')
        measurement_record = driver_method('_record_scp_download_attempt')
        record_entry = driver_method('_record_download_attempt')
        component_graph = function(d.get('_validate_component_graph'),
            unique_code(driver_code, '_validate_component_graph'), d, __name__)
        scp_graph = function(d.get('_validate_scp_request_content_graph'),
            unique_code(driver_code, '_validate_scp_request_content_graph'), d, __name__)
        commit = driver_method('_commit_exclusive_binding')
        journal_writer, output_scope = d.get('_JournalWriter'), d.get('_OutputScope')
        if (type(journal_writer) is not type or type(output_scope) is not type
                or journal_writer.__bases__ != (output_scope,) or output_scope.__bases__ != (object,)
                or not text(journal_writer.__module__, __name__)
                or not text(output_scope.__module__, __name__)
                or not text(journal_writer.__qualname__, '_JournalWriter')
                or not text(output_scope.__qualname__, '_OutputScope')
                or any(name in vars(journal_writer) for name in ('__new__', 'write', 'close'))
                or '__new__' in vars(output_scope)):
            refuse()
        writer_code = unique_code(driver_code, '_JournalWriter')
        output_code = unique_code(driver_code, '_OutputScope')
        writer_init = function(vars(journal_writer).get('__init__'),
            unique_code(writer_code, '__init__'), d, __name__, qualname='_JournalWriter.__init__')
        writer_verify = function(vars(journal_writer).get('verify'),
            unique_code(writer_code, 'verify'), d, __name__,
            qualname='_JournalWriter.verify', cells=(journal_writer,))
        writer_finish = function(vars(journal_writer).get('finish'),
            unique_code(writer_code, 'finish'), d, __name__, qualname='_JournalWriter.finish')
        output_write = function(vars(output_scope).get('write'),
            unique_code(output_code, 'write'), d, __name__, qualname='_OutputScope.write')
        output_verify = function(vars(output_scope).get('verify'),
            unique_code(output_code, 'verify'), d, __name__, qualname='_OutputScope.verify')
        output_close = function(vars(output_scope).get('close'),
            unique_code(output_code, 'close'), d, __name__, qualname='_OutputScope.close')
        manager = function(e.get('_probe_component_exit_once'),
            unique_code(executor_code, '_probe_component_exit_once'), e, 'ibsw_upgrade_executor',
            keywords={'_read_only': False, '_transport': None})
        bound_consumer = function(e.get('_bound_component_postcondition_inputs'),
            unique_code(executor_code, '_bound_component_postcondition_inputs'), e, 'ibsw_upgrade_executor')
        log_reader = function(e.get('_read_component_log_prefix'),
            unique_code(executor_code, '_read_component_log_prefix'), e, 'ibsw_upgrade_executor')
        canonical_json = function(d.get('_json_bytes'), unique_code(driver_code, '_json_bytes'), d, __name__)
        packet_image = d.get('_SCP_DOWNLOAD_PAIR_IMAGE')
        if (type(packet_image) is not tuple or len(packet_image) != 3
                or packet_image[0] is not packet_pair or packet_image[1] is not packet_pair.__code__
                or packet_image[2] is not c or d.get('_SCP_DOWNLOAD_PAIR') is not packet_pair
                or c.get('math') is not math or e.get('json') is not json
                or e.get('base64') is not base64 or e.get('hashlib') is not hashlib
                or e.get('_NativeObservationHold') is not probe32[9]
                or e.get('SharedUpgradeHold') is not SharedUpgradeHold):
            refuse()
        os_refs = (packet_pair, packet_parser, scp_ack, extractor, measurement_document,
            measurement_inputs, measurement_record, record_entry, component_graph, scp_graph, commit,
            journal_writer, output_scope, writer_init, writer_verify, writer_finish,
            output_write, output_verify, output_close, manager, bound_consumer, log_reader, canonical_json,
            packet_image)
        capture = function(d.get('_capture_native_scp_cpld_bootstrap'),
            unique_code(images[Path(__file__).name][2], '_capture_native_scp_cpld_bootstrap'), d, __name__)
        if (d.get('render_declared_step') is not declared or c.get('_fixed_layout') is not layout
                or e.get('_fixed_layout') is not layout or c.get('InventoryDevice') is not k.get('InventoryDevice')
                or c.get('UpgradePolicy') is not k.get('UpgradePolicy') or c.get('dataclass') is not dataclasses.dataclass
                or any(c.get(name) is not value for name, value in (('json', json), ('re', re),
                    ('shlex', shlex), ('Path', Path)))
                or any(e.get(name) is not value for name, value in (('hashlib', hashlib), ('re', re),
                    ('posixpath', posixpath), ('shlex', shlex)))
                or c.get('_file') is not k.get('_file') or c.get('_root') is not k.get('_root')):
            refuse()
        project = sys.modules.get('project_contract')
        if type(project) is not ModuleType or any(c.get(name) is not vars(project).get(name)
                for name in ('normalize_redundancy_mac', 'validate_service_endpoint')):
            refuse()
        # Exact import-time class identity plus independent five-field original
        # generator schema. Capturing a late replacement at first audit is forbidden.
        rendered = c.get('RenderedStep')
        if type(rendered) is not type or rendered is not bootstrap[1] or rendered.__bases__ != (object,):
            refuse()
        members = dict(vars(rendered))
        if (len(bootstrap[2]) != len(members) or any(type(row) is not tuple or len(row) != 2
                or type(row[0]) is not str or members.get(row[0]) is not row[1] for row in bootstrap[2])
                or not text(rendered.__module__, 'ibsw_upgrade_component')
                or not text(rendered.__qualname__, 'RenderedStep')):
            refuse()
        names = ('script', 'target_version', 'binding', 'expected_install_effect', 'activation_state')
        types = dict(zip(names, ('str', 'str', 'tuple[str, ...]', 'str', 'str')))
        defaults = ('REBOOT_EXPECTED', 'UNKNOWN')
        allowed = {'__module__', '__annotations__', '__dict__', '__weakref__', '__doc__',
            '__dataclass_params__', '__dataclass_fields__', '__init__', '__repr__', '__eq__',
            '__setattr__', '__delattr__', '__hash__', 'expected_install_effect', 'activation_state'}
        model = sys.version_info[:2]
        if model == (3, 12):
            allowed.add('__match_args__')
        if model not in ((3, 9), (3, 12)) or set(members) != allowed:
            refuse()
        if (type(members['__annotations__']) is not dict
                or any(type(key) is not str or type(value) is not str
                       for key, value in members['__annotations__'].items())
                or members['__annotations__'] != types
                or any(not text(members[name], value) for name, value in zip(names[-2:], defaults))
                or model == (3, 12) and (type(members['__match_args__']) is not tuple
                    or any(type(value) is not str for value in members['__match_args__'])
                    or members['__match_args__'] != names)):
            refuse()
        for selected in ('__dict__', '__weakref__'):
            value = members[selected]
            if type(value) is not GetSetDescriptorType or value.__objclass__ is not rendered or value.__name__ != selected:
                refuse()
        params, fields = members['__dataclass_params__'], members['__dataclass_fields__']
        if (type(params) is not dataclasses._DataclassParams or type(fields) is not dict
                or any(type(name) is not str for name in fields) or tuple(fields) != names):
            refuse()
        for name, value in (('init', True), ('repr', True), ('eq', True), ('order', False),
                            ('unsafe_hash', False), ('frozen', True)):
            if getattr(params, name) is not value:
                refuse()
        if model == (3, 12) and any(getattr(params, name) is not value for name, value in
                (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False))):
            refuse()
        for index, name in enumerate(names):
            field = fields[name]
            expected = dataclasses.MISSING if index < 3 else defaults[index - 3]
            if (type(field) is not dataclasses.Field or not text(field.name, name) or not text(field.type, types[name])
                    or (field.default is not expected if index < 3 else not text(field.default, expected))
                    or field.default_factory is not dataclasses.MISSING or field.init is not True
                    or field.repr is not True or field.compare is not True or field.hash is not None
                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA
                    or model == (3, 12) and field.kw_only is not False):
                refuse()
        type_names = [('_type_' + name if model == (3, 9) else '__dataclass_type_' + name + '__') for name in names]
        default_names = [('_dflt_' + name if model == (3, 9) else '__dataclass_dflt_' + name + '__') for name in names[-2:]]
        local_names = type_names + (['MISSING', '_HAS_DEFAULT_FACTORY'] if model == (3, 9)
                                   else ['__dataclass_HAS_DEFAULT_FACTORY__', '__dataclass_builtins_object__'])
        local_names += default_names
        if model == (3, 9):
            local_names.append('BUILTINS')
        returns = '_return_type' if model == (3, 9) else '__dataclass_return_type__'
        local_names.append(returns)
        arguments = ['self'] + [name + ':' + variable + ('=' + default_names[index - 3] if index >= 3 else '')
                                for index, (name, variable) in enumerate(zip(names, type_names))]
        target = 'BUILTINS.object' if model == (3, 9) else '__dataclass_builtins_object__'
        body = [target + '.__setattr__(self,' + repr(name) + ',' + name + ')' for name in names]
        template = ('def __create_fn__(' + ', '.join(local_names) + '):\n def __init__(' + ','.join(arguments)
            + ')->' + returns + ':\n' + '\n'.join('  ' + line for line in body) + '\n return __init__')
        generated = unique_code(unique_code(compile(template, '<string>', 'exec', dont_inherit=True,
                                                     optimize=sys.flags.optimize), '__create_fn__'), '__init__')
        init = function(members['__init__'], generated, c, 'ibsw_upgrade_component',
            qualname='__create_fn__.<locals>.__init__' if model == (3, 9) else 'RenderedStep.__init__', defaults=defaults,
            annotations=dict(types, **{'return': None}), cells=(builtins,) if model == (3, 9) else (object,))
        # CP3.12 adjusts the Function qualname; Apple3.9 preserves the factory
        # name. Both code objects retain their modeled source-generator shape.
        fixed_layout = layout(__file__)
        actual_paths = (c.get('_TEMPLATE'), e.get('_RUNNER'))
        template_directory = _HeldDirectory(fixed_layout)
        directories.append(template_directory)
        template_images = []
        for path, saved in zip(actual_paths, bootstrap[3]):
            if (type(path) is not type(Path()) or type(saved) is not tuple or len(saved) != 3
                    or type(saved[0]) is not str or type(saved[1]) is not tuple or len(saved[1]) != 9
                    or any(type(value) is not int for value in saved[1]) or type(saved[2]) is not bytes
                    or str(path) != saved[0] or path.parent != fixed_layout):
                refuse()
            original = _HeldFile(path, template_directory)
            held.append(original)
            if identity(os.fstat(original.fd)) != saved[1] or original.payload != saved[2]:
                refuse()
            template_images.append(original)
        if actual_paths[0] is not bootstrap[4][0]:
            refuse()
        # Stable namespace/class/path objects only. Fresh compile/payload bytes
        # stay in this audit and never enter cross-audit identity comparisons.
        launch_refs = (command, launcher, context, wrapper, probe32[3], provider, component, executor, contract,
            render, declared, validate, url, rendered, init, runner, layout,
            actual_paths[0], actual_paths[1], probe32[2], probe32[4], bootstrap,
            members['__dataclass_params__'], members['__dataclass_fields__'], capture) + os_refs
        current19, current32 = _fixed_scp_source_api(group, probe=True)
        if (len(current19) != len(source19) or len(current32) != len(probe32)
                or any(a is not b for a, b in zip(source19, current19))
                or any(a is not b for a, b in zip(probe32, current32))
                or group._scp_source_binding is not original_binding or _SCP_CPLD_BOOTSTRAP is not bootstrap
                or any(sys.modules.get(name) is not value for name, value in
                    (('ibsw_upgrade_scp', provider), ('ibsw_upgrade_component', component),
                     ('ibsw_upgrade_executor', executor), ('ibsw_upgrade_contract', contract)))
                or any(p.get(name) is not value for name, value in
                    (('_stdin_launch_command', command), ('_STDIN_LAUNCHER', launcher),
                     ('remote_helper_bytes', probe32[2]), ('_REMOTE_HELPER', probe32[4])))
                or any(c.get(name) is not value for name, value in (('_render', render),
                    ('render_declared_step', declared), ('_validate_plan', validate), ('_package_url', url),
                    ('RenderedStep', rendered), ('_TEMPLATE', actual_paths[0]), ('_fixed_layout', layout)))
                or e.get('_owned_runner_bytes') is not runner or e.get('_RUNNER') is not actual_paths[1]
                or e.get('_fixed_layout') is not layout or k.get('_fixed_layout') is not layout
                or d.get('render_declared_step') is not declared
                or vars(_PreparedRunScope).get('_native_scp_launch_context') is not context
                or vars(_PreparedRunScope).get('_launch_native_scp_cpld') is not wrapper
                or any(vars(rendered).get(name) is not value for name, value in members.items())):
            refuse()
        for original in held:
            original.verify()
        for directory in directories:
            directory.verify()
        scope.verify(); group.verify()
        # Recheck actual function attributes, not only namespace is, after the
        # last original IO. The tuple is finite; do not iterate the growing log.
        for value, code, namespace, name, qualified, default, keyword, annotation, cells in tuple(audited_functions):
            function(value, code, namespace, name, qualname=qualified, defaults=default,
                     keywords=keyword, annotations=annotation, cells=cells)
        for name, value in (('ibsw_upgrade_scp', provider), ('ibsw_upgrade_component', component),
                            ('ibsw_upgrade_executor', executor), ('ibsw_upgrade_contract', contract),
                            (__name__, driver)):
            if module(name, root / (name + '.py' if name != __name__ else Path(__file__).name))[0] is not value:
                refuse()
        if (type(vars(rendered).get('__annotations__')) is not dict
                or any(type(name) is not str or type(value) is not str
                       for name, value in vars(rendered)['__annotations__'].items())
                or vars(rendered)['__annotations__'] != types
                or any(getattr(params, name) is not value for name, value in (
                    ('init', True), ('repr', True), ('eq', True), ('order', False),
                    ('unsafe_hash', False), ('frozen', True)))):
            refuse()
        if model == (3, 12) and any(getattr(params, name) is not value for name, value in
                (('match_args', True), ('kw_only', False), ('slots', False), ('weakref_slot', False))):
            refuse()
        for index, name in enumerate(names):
            field = fields[name]
            expected = dataclasses.MISSING if index < 3 else defaults[index - 3]
            if (type(field) is not dataclasses.Field or not text(field.name, name) or not text(field.type, types[name])
                    or (field.default is not expected if index < 3 else not text(field.default, expected))
                    or field.default_factory is not dataclasses.MISSING or field.init is not True
                    or field.repr is not True or field.compare is not True or field.hash is not None
                    or field._field_type is not dataclasses._FIELD or field.metadata is not dataclasses._EMPTY_METADATA
                    or model == (3, 12) and field.kw_only is not False):
                refuse()
        for namespace, name, value in (
                (c, '_scp_download_pair', packet_pair), (c, 'parse_scp_download_results', packet_parser),
                (c, 'scp_download_ack_bytes', scp_ack), (e, '_scp_download_packet', extractor),
                (d, '_scp_download_document', measurement_document),
                (d, '_validate_component_graph', component_graph),
                (d, '_validate_scp_request_content_graph', scp_graph), (d, '_json_bytes', canonical_json),
                (d, '_JournalWriter', journal_writer), (d, '_OutputScope', output_scope),
                (e, '_probe_component_exit_once', manager),
                (e, '_bound_component_postcondition_inputs', bound_consumer),
                (e, '_read_component_log_prefix', log_reader)):
            if namespace.get(name) is not value:
                refuse()
        for name, value in (('_scp_download_inputs_locked', measurement_inputs),
                ('_record_scp_download_attempt', measurement_record), ('_record_download_attempt', record_entry),
                ('_commit_exclusive_binding', commit)):
            if vars(_PreparedRunScope).get(name) is not value:
                refuse()
        for cls, name, value in ((journal_writer, '__init__', writer_init),
                (journal_writer, 'verify', writer_verify), (journal_writer, 'finish', writer_finish),
                (output_scope, 'write', output_write), (output_scope, 'verify', output_verify),
                (output_scope, 'close', output_close)):
            if vars(cls).get(name) is not value:
                refuse()
        if (journal_writer.__bases__ != (output_scope,) or output_scope.__bases__ != (object,)
                or any(name in vars(journal_writer) for name in ('__new__', 'write', 'close'))
                or '__new__' in vars(output_scope)
                or d.get('_SCP_DOWNLOAD_PAIR_IMAGE') is not packet_image
                or d.get('_SCP_DOWNLOAD_PAIR') is not packet_pair
                or packet_pair.__code__ is not packet_image[1] or packet_pair.__globals__ is not packet_image[2]
                or c.get('math') is not math
                or e.get('json') is not json or e.get('base64') is not base64
                or e.get('hashlib') is not hashlib or e.get('_NativeObservationHold') is not probe32[9]):
            refuse()
        result = source19, probe32, launch_refs
    except BaseException as error:
        primary = error
    finally:
        failures = []
        for original in tuple(reversed(held)) + tuple(reversed(directories)):
            try:
                original.close()
            except BaseException as error:
                failures.append(error)
                if primary is None or isinstance(primary, Exception) and not isinstance(error, Exception):
                    primary = error
        if failures:
            group.cleanup_issues.extend(failures)
            if group._package_source_lifecycle_failure is None:
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'fixed native CPLD producer cleanup uncertain; original group retained')
    if primary is not None:
        if group._package_source_lifecycle_failure is None:
            group._package_source_lifecycle_failure = SharedUpgradeHold(
                'fixed native CPLD producer source uncertain; original group retained')
        if not isinstance(primary, Exception) or isinstance(primary, SharedUpgradeHold):
            raise primary
        raise SharedUpgradeHold('fixed native CPLD producer audit failed') from None
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
        self._scp_source = None
        self._scp_source_binding = None
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

    @staticmethod
    def _scp_source_fields(source, source_class, expected=None):
        """Immutable, in-memory seven-field snapshot; never diagnostic DATA."""
        if type(source) is not source_class:
            raise SharedUpgradeHold('original SCP source instance class required')
        fields = object.__getattribute__(source, '__dict__')
        names = ('host', 'user', 'port', 'known_hosts_path', 'host_keys', 'password', '_identity')
        if (type(fields) is not dict or any(type(name) is not str for name in fields)
                or set(fields) != set(names)):
            raise SharedUpgradeHold('original SCP source instance fields changed')
        def typed(host, user, port, path, keys, password, identity):
            if (type(host) is not str or not host or type(user) is not str or not user
                    or type(port) is not int or not 1 <= port <= 65535
                    or type(path) is not type(Path()) or type(keys) is not bytes or not keys
                    or type(password) is not str or type(identity) is not tuple or len(identity) != 7
                    or any(type(value) is not int or value < 0 for value in identity[:6])
                    or type(identity[6]) is not str or not re.fullmatch(r'[0-9a-f]{64}', identity[6])):
                raise SharedUpgradeHold('typed original SCP source fields required')
        host, user, port, path, keys, password, identity = (fields[name] for name in names)
        typed(host, user, port, path, keys, password, identity)
        # Hold the exact concrete Path as well as an independent string value.
        # Compare that object only with is, never a replaceable Path.__eq__.
        text = str(path)
        snapshot = (host, user, port, (path, text), keys, password, identity)
        if expected is not None:
            if (type(expected) is not tuple or len(expected) != 7
                    or type(expected[3]) is not tuple or len(expected[3]) != 2
                    or type(expected[3][1]) is not str):
                raise SharedUpgradeHold('original SCP source snapshot changed')
            typed(expected[0], expected[1], expected[2], expected[3][0],
                  expected[4], expected[5], expected[6])
            if (path is not expected[3][0] or text != expected[3][1]
                    or snapshot[:3] != expected[:3] or snapshot[4:] != expected[4:]):
                raise SharedUpgradeHold('original SCP source field values changed')
        return snapshot

    def _bind_scp_source(self, source, api):
        """Bind one actual pre-schedule parent configuration, not permission."""
        try:
            if (type(self) is not _PreparedRunScope or not self.manual_execution
                    or self.parsed.method != 'scp' or self.closed or self.cleanup_issues
                    or self._native_schedule_started or self._has_native_package_source_provenance()
                    or self._package_source_parent is not None or self._package_source_owner is not None
                    or self._package_source_owner_class is not None or self._package_source_owns
                    or self._package_source_selection is not None or self._package_source_borrowers
                    or self._scp_source is not None or self._scp_source_binding is not None
                    or type(api) is not tuple or len(api) != 19):
                raise SharedUpgradeHold('single original pre-schedule SCP parent binding required')
            self.verify()
            current = _fixed_scp_source_api(self)
            if len(current) != 19 or any(left is not right for left, right in zip(api, current)):
                raise SharedUpgradeHold('original SCP source API objects changed before binding')
            snapshot = _PreparedRunScope._scp_source_fields(source, api[2])
            api[3](source)  # The audited original trust verifier, not its return value.
            current = _fixed_scp_source_api(self)
            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)
            if (len(current) != 19 or any(left is not right for left, right in zip(api, current))
                    or self._scp_source is not None or self._scp_source_binding is not None):
                raise SharedUpgradeHold('original SCP source changed during binding')
            self._scp_source_binding = (source, api, snapshot)
            self._scp_source = source
        except BaseException as error:
            if self._package_source_lifecycle_failure is None:
                self._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original SCP source binding failed; parent group retained')
            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):
                raise  # Preserve the first interruption/Shared object and preset cause.
            raise SharedUpgradeHold('original SCP source binding failed') from None

    def _native_scp_source(self, leaf, component, package_index):
        """Revalidate the same parent source for one original native borrower.

        No probe, secret wire, request, dispatch, ACK or positive permission.
        Generic scope.verify never calls this method or the source API auditor.
        """
        group = self
        try:
            parent = getattr(self, '_native_parent', None)
            # Either still-original edge can identify the registered group if
            # the other edge has drifted. Never adopt an unregistered parent.
            for original in (getattr(self, '_package_source_parent', None), parent):
                if (type(original) is _PreparedRunScope and original is not self
                        and type(original._package_source_borrowers) is set
                        and self in original._package_source_borrowers):
                    group = original
                    break
            if (type(self) is not _PreparedRunScope or group is self or parent is not group
                    or self.closed or parent.closed or self.cleanup_issues or parent.cleanup_issues
                    or type(leaf) is not _ReadonlyQueryInputs or leaf.closed
                    or leaf.scope is not self or type(leaf._original_selection) is not tuple
                    or len(leaf._original_selection) != 6 or leaf._original_selection[0] is not self
                    or leaf._original_selection[1] != leaf.node.hostname
                    or leaf._native_observation_consumed is not True
                    or type(component) is not str or type(package_index) is not int
                    or not self._is_native_package_source_child(parent, leaf.node.hostname, component)
                    or package_index not in self._native_package_indices
                    or (component, package_index) not in parent._package_source_selection[0]
                    or self._scp_source is not None or self._scp_source_binding is not None):
                raise SharedUpgradeHold('original native SCP leaf/parent/borrow/source selection required')
            self.verify()
            parent.verify()
            leaf.verify()
            binding = parent._scp_source_binding
            if type(binding) is not tuple or len(binding) != 3:
                raise SharedUpgradeHold('original parent SCP source binding missing')
            source, api, snapshot = binding
            if (type(api) is not tuple or len(api) != 19 or parent._scp_source is not source
                    or type(snapshot) is not tuple or len(snapshot) != 7):
                raise SharedUpgradeHold('original parent SCP source slot changed')
            current = _fixed_scp_source_api(parent)
            if len(current) != 19 or any(left is not right for left, right in zip(api, current)):
                raise SharedUpgradeHold('original parent SCP source API or fields changed')
            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)
            api[3](source)
            leaf.verify()
            parent.verify()
            current = _fixed_scp_source_api(parent)
            if (len(current) != 19 or any(left is not right for left, right in zip(api, current))
                    or parent._scp_source_binding is not binding or parent._scp_source is not source
                    or not self._is_native_package_source_child(parent, leaf.node.hostname, component)
                    or package_index not in self._native_package_indices):
                raise SharedUpgradeHold('original parent SCP source changed while being checked')
            _PreparedRunScope._scp_source_fields(source, api[2], snapshot)
            return source
        except BaseException as error:
            if group._package_source_lifecycle_failure is None:
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original native SCP source changed; parent group retained')
            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):
                raise
            raise SharedUpgradeHold('original native SCP source cannot be verified') from None


    def _native_scp_launch_context(self, leaf, component, package_index):
        """Derive bounded private envelope DATA from live original native inputs.

        No capture/write, package reread, wire, launch, dispatch or ACK. The
        returned bytes are not a permit and must never be logged or persisted.
        """
        group = self
        try:
            if type(self) is not _PreparedRunScope:
                raise SharedUpgradeHold('original native SCP DATA scope required')
            # Either still-original edge can identify the registered group even
            # when the child's owner slot or its other parent edge has drifted.
            for original in (getattr(self, '_package_source_parent', None),
                             getattr(self, '_native_parent', None)):
                if (type(original) is _PreparedRunScope and original is not self
                        and type(original._package_source_borrowers) is set
                        and self in original._package_source_borrowers):
                    group = original
                    break
            lease = self._active_request_lease
            if group is self or type(lease) is not _ManualJournalTransaction:
                raise SharedUpgradeHold('active original native SCP DATA lease required')
            lease.verify()
            source = self._native_scp_source(leaf, component, package_index)
            owner = group._package_source_owner
            binding_joint = group._scp_source_binding
            fields = _PreparedRunScope._scp_source_fields(
                source, binding_joint[1][2], binding_joint[2])
            # No path discovery/adoption: all six artifact originals must
            # already be held by this same native child before this call.
            stage_name = declared_step_key(self.policy, component, package_index)
            stage_path = self.run_directory / leaf.node.hostname / stage_name
            directory = self.session._directories.get(str(stage_path))
            if directory is None:
                raise SharedUpgradeHold('original SCP request stage is not held')
            self._private_directory(directory)
            names = ('request.json', 'step.sh', 'step-binding.json',
                     'runner.sh', 'runner-binding.json', 'scp-source-request.json')
            held, payloads = {}, {}
            for name in names:
                original = self.files.get((str(stage_path), name))
                if (type(original) is not _HeldFile or original.directory is not directory
                        or original.name != name or original.cleanup_issues):
                    raise SharedUpgradeHold('complete held SCP request originals required')
                original.verify()
                metadata = os.fstat(original.fd)
                if (metadata.st_uid != os.geteuid() or metadata.st_nlink != 1
                        or stat.S_IMODE(metadata.st_mode) != 0o600):
                    raise SharedUpgradeHold('private original SCP request artifact required')
                held[name], payloads[name] = original, original.payload
            script, binding = self._candidate(leaf.node.hostname, component, package_index, stage_name)
            if payloads['step.sh'] != script or payloads['step-binding.json'] != _json_bytes(binding):
                raise SharedUpgradeHold('original SCP stage declaration changed')
            _validate_scp_request_content_graph(set(payloads), binding, payloads.__getitem__)
            companion = json.loads(payloads['scp-source-request.json'])
            request = json.loads(payloads['request.json'])
            runner_binding = json.loads(payloads['runner-binding.json'])
            remote = runner_binding.get('remote_script') if type(runner_binding) is dict else None
            prefix = '.ibsw-' + self.run_id + '-' + leaf.node.hostname + '-' + stage_name + '-'
            from ibsw_upgrade_executor import _owned_runner_bytes
            if (type(remote) is not str or posixpath.normpath(remote) != remote
                    or posixpath.basename(remote) != 'step.sh'
                    or posixpath.dirname(posixpath.dirname(remote)) != self.parsed.switch_dir
                    or not re.fullmatch(re.escape(prefix) + '[0-9a-f]{32}',
                                        posixpath.basename(posixpath.dirname(remote)))
                    or payloads['runner.sh'] != _owned_runner_bytes(binding, remote)
                    or payloads['runner-binding.json'] != _json_bytes(
                        _owned_runner_binding(binding, remote, payloads['runner.sh']))):
                raise SharedUpgradeHold('original SCP runner binding changed')
            self._verify_package_source_owner()
            packages, original_rows = {}, []
            for package in self._package_source_packages(component, package_index):
                path = Path(package.path)
                row = owner._files.get(path)
                if (type(row) is not tuple or len(row) != 5
                        or type(row[3]) is not tuple or len(row[3]) != 9
                        or type(row[3][6]) is not int or row[3][6] <= 0
                        or type(row[4]) is not str or not re.fullmatch('[0-9a-f]{64}', row[4])):
                    raise SharedUpgradeHold('original SCP package digest rows required')
                packages[package.path] = dict(size=row[3][6], sha256=row[4])
                original_rows.append((path, row))
            if companion['packages'] != packages:
                raise SharedUpgradeHold('SCP companion differs from live original packages')
            content = dict(version=1,
                binding_sha256=hashlib.sha256(payloads['step-binding.json']).hexdigest(),
                request_id=request['request_id'],
                request_sha256=hashlib.sha256(payloads['request.json']).hexdigest(),
                companion_sha256=hashlib.sha256(payloads['scp-source-request.json']).hexdigest(),
                packages=packages)
            document = dict(host=fields[0], user=fields[1], port=fields[2],
                host_keys=fields[4].decode('ascii'), password=fields[5],
                paths={path: row['size'] for path, row in packages.items()},
                timeout_seconds=600 if component == 'os' else 300, content_binding=content)
            payload = (json.dumps(document, ensure_ascii=True, sort_keys=True,
                                  separators=(',', ':')) + '\n').encode('utf-8')
            if not 1 <= len(payload) <= 65536 or payload.count(b'\n') != 1:
                raise SharedUpgradeHold('bounded single-frame SCP context DATA required')
            # Recheck the SAME source/group/lease/artifact owners after all
            # derivation. No fresh baseline or package digest is acquired.
            if self._native_scp_source(leaf, component, package_index) is not source:
                raise SharedUpgradeHold('original SCP source changed at DATA tail')
            if (self._active_request_lease is not lease
                    or group._scp_source_binding is not binding_joint
                    or group._scp_source is not source
                    or self._package_source_owner is not owner
                    or group._package_source_owner is not owner
                    or self.session._directories.get(str(stage_path)) is not directory):
                raise SharedUpgradeHold('original SCP context owners changed at DATA tail')
            lease.verify()
            _PreparedRunScope._scp_source_fields(source, binding_joint[1][2], binding_joint[2])
            self._verify_package_source_owner()
            for path, row in original_rows:
                if owner._files.get(path) is not row:
                    raise SharedUpgradeHold('original SCP package digest row changed at DATA tail')
            for name, original in held.items():
                if (self.files.get((str(stage_path), name)) is not original
                        or original.payload != payloads[name]):
                    raise SharedUpgradeHold('original SCP request artifact changed at DATA tail')
                original.verify()
            self.verify(); leaf.verify(); group.verify()
            _validate_scp_request_content_graph(set(payloads), binding, payloads.__getitem__)
            return payload
        except BaseException as error:
            if (type(group) is _PreparedRunScope
                    and group._package_source_lifecycle_failure is None):
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original native SCP context DATA uncertain; shared group retained')
            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):
                raise  # Keep the original NI/Shared object and preset cause.
            raise SharedUpgradeHold('original native SCP context DATA could not be verified') from None

    def _launch_native_scp_cpld(self, leaf, component, package_index, transport, deadline):
        """Fixed native CPLD/index0 or actual selected OS stdin launch; no caller wire."""
        primary = None
        channel = None
        source = joint = payload = command = None
        lease = source_binding = package_owner = None
        fields_check = None
        originals = ()
        function_states = ()
        parent = getattr(self, '_native_parent', None)
        group = parent if type(parent) is _PreparedRunScope else self
        output, errors = bytearray(), bytearray()
        complete, status = False, None
        closed = False
        close_error = None
        lock = threading.Lock()

        def remember(error):
            nonlocal primary
            if (primary is None or isinstance(primary, Exception) and not isinstance(error, Exception)
                    or isinstance(primary, Exception) and not isinstance(primary, SharedUpgradeHold)
                    and isinstance(error, SharedUpgradeHold)):
                primary = error

        class OwnedChannel:
            def close(owner):
                nonlocal closed, close_error
                with lock:
                    if closed:
                        if close_error is not None:
                            raise close_error
                        return
                    closed = True
                try:
                    channel.close()
                except BaseException as error:
                    close_error = error
                    raise

        owner = OwnedChannel()

        def require_new_send():
            stop = getattr(self, '_pipeline_stop_event', None)
            if stop is not None and stop.is_set():
                raise SharedUpgradeHold('shared stop forbids another native CPLD stdin fragment')

        def verify_current(*, full=True):
            # Same live child/parent/source, original six held files and fixed
            # producers. A new source/companion or caller envelope is not adopted.
            current = _fixed_native_scp_cpld_api(parent) if full else joint
            if (type(current) is not tuple or len(current) != 3
                    or any(type(old) is not tuple or type(new) is not tuple
                        or len(old) != len(new)
                        or any(left is not right for left, right in zip(old, new))
                        for old, new in zip(joint, current))):
                raise SharedUpgradeHold('fixed native CPLD launch producers changed')
            if (self._native_parent is not parent or self._active_request_lease is not lease
                    or parent._scp_source is not source or parent._scp_source_binding is not source_binding
                    or self._package_source_owner is not package_owner
                    or parent._package_source_owner is not package_owner):
                raise SharedUpgradeHold('original native CPLD request/source changed before wire')
            lease.verify()
            for name, original, image in originals:
                if self.files.get((str(directory), name)) is not original or original.payload is not image:
                    raise SharedUpgradeHold('original native CPLD held request changed')
                original.verify()
            for function, code, namespace, defaults, keywords, keyword_items in function_states:
                actual = function.__kwdefaults__
                if (function.__code__ is not code or function.__globals__ is not namespace
                        or function.__defaults__ is not defaults or actual is not keywords
                        or keywords is not None and (set(actual) != set(keyword_items)
                            or any(actual[name] is not value for name, value in keyword_items.items()))):
                    raise SharedUpgradeHold('native CPLD producer code/default joint changed')
            source_namespace = vars(current[0][0])
            if (source_namespace.get('ScpSource') is not current[0][2]
                    or source_namespace.get('verify_source_shared') is not current[0][3]
                    or source_namespace.get('_read_trust') is not current[0][4]
                    or source_namespace.get('ScpHold') is not current[0][5]
                    or source_namespace.get('ERRORS') is not current[0][9]
                    or vars(current[0][2]).get('verify') is not current[0][7]
                    or vars(current[0][5]).get('__init__') is not current[0][12]
                    or _PreparedRunScope._scp_source_fields is not fields_check):
                raise SharedUpgradeHold('native CPLD source verifier slots changed before send')
            fields_check(source, current[0][2], source_binding[2])
            current[0][3](source)
            self._verify_package_source_owner()
            leaf.verify_io_identity()
            if full and (self._native_scp_source(leaf, component, package_index) is not source
                    or current[2][2](self, leaf, component, package_index) != payload):
                raise SharedUpgradeHold('original native CPLD context changed at full wire gate')
            current[1][8](deadline)

        try:
            if (type(self) is not _PreparedRunScope or type(parent) is not _PreparedRunScope
                    or type(leaf) is not _ReadonlyQueryInputs
                    or type(component) is not str or component not in ('os', 'bios', 'cpld')
                    or type(package_index) is not int
                    or (component in ('bios', 'cpld') and package_index != 0)
                    or (component == 'os' and package_index not in self._native_package_indices)
                    or self.parsed.method != 'scp' or self._active_request_lease is None
                    or type(deadline) not in (int, float) or not math.isfinite(deadline)):
                raise SharedUpgradeHold('original native CPLD launch scope/lease required')
            # One bounded launch-response budget, independent of the receiver's
            # per-package firmware budget. Never extend the caller deadline.
            deadline = min(deadline, time.monotonic() + 25.0)
            source = self._native_scp_source(leaf, component, package_index)
            joint = _fixed_native_scp_cpld_api(parent)
            if type(joint) is not tuple or len(joint) != 3 or len(joint[2]) < 3:
                raise SharedUpgradeHold('fixed native CPLD producer joint required')
            remaining, owned_phase = joint[1][8], joint[1][6]
            remaining(deadline)
            payload = joint[2][2](self, leaf, component, package_index)
            stage = declared_step_key(self.policy, component, package_index)
            directory = self.run_directory / leaf.node.hostname / stage
            lease = self._active_request_lease
            source_binding = parent._scp_source_binding
            package_owner = self._package_source_owner
            fields_check = _PreparedRunScope._scp_source_fields
            names = ('request.json', 'step.sh', 'step-binding.json',
                     'runner.sh', 'runner-binding.json', 'scp-source-request.json')
            originals = tuple((name, self.files[(str(directory), name)],
                               self.files[(str(directory), name)].payload) for name in names)
            from types import FunctionType
            function_states = tuple((function, function.__code__, function.__globals__,
                    function.__defaults__, function.__kwdefaults__,
                    {} if function.__kwdefaults__ is None else dict(function.__kwdefaults__))
                for group_refs in joint + ((fields_check,),)
                for function in group_refs if type(function) is FunctionType)
            step = self.files[(str(directory), 'step.sh')]
            runner = self.files[(str(directory), 'runner.sh')]
            binding = self.files[(str(directory), 'runner-binding.json')]
            binding.verify(); step.verify(); runner.verify()
            remote = json.loads(binding.payload)['remote_script']
            command = joint[2][0](remote, hashlib.sha256(runner.payload).hexdigest(),
                                     hashlib.sha256(step.payload).hexdigest())
            verify_current()
            require_new_send()
            channel = transport.open_session(timeout=remaining(deadline))
            channel.settimeout(remaining(deadline))
            with owned_phase((owner,), deadline):
                try:
                    verify_current()
                    require_new_send()
                    channel.exec_command(command)
                    position = 0
                    while position < len(payload):
                        # No recompiling/refreezing per tiny partial send. Full
                        # source/context gates bracket the wire; each fragment
                        # still checks the same six held files/source/lease/
                        # package owner plus code/default object anchors.
                        verify_current(full=False)
                        require_new_send()
                        channel.settimeout(remaining(deadline))
                        count = channel.send(payload[position:])
                        if type(count) is not int or not 0 < count <= len(payload) - position:
                            raise SharedUpgradeHold('native CPLD stdin delivery uncertain')
                        position += count
                    verify_current(full=False)
                    channel.settimeout(remaining(deadline))
                    channel.shutdown_write()
                    while True:
                        leaf.verify_io_identity()
                        remaining(deadline)
                        for ready, receive, target in (
                                (channel.recv_ready, channel.recv, output),
                                (channel.recv_stderr_ready, channel.recv_stderr, errors)):
                            if ready():
                                channel.settimeout(remaining(deadline))
                                part = receive(65536)
                                if type(part) is not bytes:
                                    raise SharedUpgradeHold('native CPLD launch response uncertain')
                                target.extend(part)
                                if len(output) + len(errors) > 65536:
                                    raise SharedUpgradeHold('bounded native CPLD launch response required')
                        if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                            if channel.exit_status_ready():
                                status = channel.recv_exit_status()
                            complete = channel.eof_received is True and type(status) is int and status == 0
                            break
                        if not transport.is_active():
                            break
                        time.sleep(min(.005, remaining(deadline)))
                except BaseException as error:
                    remember(error)
                finally:
                    try:
                        owner.close()
                    except BaseException as error:
                        remember(error)
                    try:
                        verify_current()
                    except BaseException as error:
                        remember(error)
        except BaseException as error:
            remember(error)
        finally:
            if channel is not None and not closed:
                try:
                    owner.close()
                except BaseException as error:
                    remember(error)
            if joint is not None and payload is not None:
                try:
                    verify_current()
                except BaseException as error:
                    remember(error)
            for verify in ((leaf.verify,) if type(leaf) is _ReadonlyQueryInputs else ()):
                try:
                    verify()
                except BaseException as error:
                    remember(error)
        if (primary is not None or not complete or bytes(output) != b'IBSW_LAUNCH_REQUESTED\n'
                or errors or time.monotonic() >= deadline):
            if type(group) is _PreparedRunScope and group._package_source_lifecycle_failure is None:
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'native CPLD launch uncertain; retain original request and shared parent')
            if primary is not None and (not isinstance(primary, Exception)
                                        or isinstance(primary, SharedUpgradeHold)):
                raise primary
            raise SharedUpgradeHold('native CPLD launch uncertain; no automatic retry') from None
        # Public asynchronous raw launch fact only. Never return payload/secret,
        # installer success, an ACK or a caller-created dispatch grant.
        return command, (b'IBSW_LAUNCH_REQUESTED\n', b'', 0, True)

    def _preflight_native_scp_source(self, leaf, component, package_index, transport, deadline):
        """Fixed signed-session probe fact only; backend remains unsupported."""
        parent, group = None, self
        source = audited = refs = primary = binding = None

        def remember(error):
            nonlocal primary
            if (primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception))
                    or (isinstance(primary, Exception) and not isinstance(primary, SharedUpgradeHold)
                        and isinstance(error, SharedUpgradeHold))):
                primary = error

        try:
            parent = getattr(self, '_native_parent', None)
            for original in (getattr(self, '_package_source_parent', None), parent):
                if (type(original) is _PreparedRunScope and original is not self
                        and type(original._package_source_borrowers) is set
                        and self in original._package_source_borrowers):
                    group = original
                    break
            source = self._native_scp_source(leaf, component, package_index)
            if (type(parent) is not _PreparedRunScope or parent is not self._native_parent
                    or type(deadline) not in (int, float) or not _SCP_PROBE_LEAVES[4](deadline)):
                raise SharedUpgradeHold('fixed native source probe original parent/deadline required')
            binding = parent._scp_source_binding
            audited, refs = _fixed_scp_source_api(parent, probe=True)
            if (len(audited) != 19 or any(actual is not original for actual, original
                    in zip(audited, parent._scp_source_binding[1]))):
                raise SharedUpgradeHold('fixed native source probe binding/API differs')
            refs[8](deadline)  # Audited original _remaining; no deadline extension.
            result = refs[0](leaf, transport, deadline, source)
            if result is not None:
                raise SharedUpgradeHold('fixed native source probe returned unknown DATA')
        except BaseException as error:
            remember(error)
        finally:
            # These are fresh read-only tail checks, not a producer/factory
            # retry. An ordinary wire error must not hide shared-source drift;
            # a pending body NI must remain the same object/cause over any tail.
            if source is not None:
                try:
                    if self._native_scp_source(leaf, component, package_index) is not source:
                        raise SharedUpgradeHold('fixed native source original instance changed at tail')
                except BaseException as error:
                    remember(error)
            try:
                leaf.verify()
            except BaseException as error:
                remember(error)
            if audited is not None and refs is not None:
                try:
                    current, current_refs = _fixed_scp_source_api(parent, probe=True)
                    if (len(current) != len(audited) or len(current_refs) != len(refs)
                            or any(actual is not original for actual, original in zip(current, audited))
                            or any(actual is not original for actual, original in zip(current_refs, refs))):
                        raise SharedUpgradeHold('fixed native source producer objects changed at tail')
                    if parent._scp_source_binding is not binding or parent._scp_source is not source:
                        raise SharedUpgradeHold('fixed native source binding changed at producer tail')
                    _PreparedRunScope._scp_source_fields(source, audited[2], binding[2])
                    current_refs[8](deadline)
                except BaseException as error:
                    remember(error)
        if primary is not None:
            if group._package_source_lifecycle_failure is None:
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'fixed native source probe failed; original parent group retained')
            # Same original body/first-tail NI/cause and batch Shared object.
            # A genuine audited ordinary wire failure remains only a failure.
            if (not isinstance(primary, Exception) or isinstance(primary, SharedUpgradeHold)
                    or audited is not None and type(primary) is audited[5]
                    or refs is not None and type(primary) is refs[9]):
                raise primary
            raise SharedUpgradeHold('fixed native source probe could not be verified') from None
        return None

    def _native_scp_needed_indices(self, node, component):
        """Select from this parent's real startup rows, not dispatch permission."""
        from ibsw_upgrade_contract import select_os_path
        if (not self.manual_execution or self.parsed.method != 'scp'
                or node not in self.devices or component not in self.parsed.selected):
            raise SharedUpgradeHold('original native SCP node/component required')
        rows = [row for row in getattr(self, '_version_plan', ())
                if row.get('hostname') == node and row.get('component') == component]
        if len(rows) != 1:
            raise SharedUpgradeHold('unique original startup component row required')
        row = rows[0]
        if any(issue.get('hostname') == node and issue.get('component') == component
               for issue in getattr(self, '_component_readiness_issues', ())):
            return ()  # No source acquisition for a startup-blocked component.
        if component == 'os':
            path = row.get('path')
            if (type(path) not in (list, tuple) or not path
                    or path[0] != row.get('current') or path[-1] != self.policy.final_os
                    or row.get('target') != self.policy.final_os):
                raise SharedUpgradeHold('original native OS route is incomplete')
            available = frozenset(package.path for package in self.policy.os
                                  if package.version in path[1:])
            selected = select_os_path(self.policy, row['current'], available=available)
            if (tuple(path[1:]) != tuple(package.version for package in selected)
                    or row.get('action') != ('UPGRADE_REQUIRED' if selected else 'AT_TARGET_NO_FLASH')):
                raise SharedUpgradeHold('native OS route differs from original approved path')
            return tuple(next(index for index, original in enumerate(self.policy.os)
                              if original is package) for package in selected)
        target = (self.policy.bios.version if component == 'bios' else
                  '+'.join(name+'_'+version for name,version in self.policy.cpld_targets))
        if row.get('target') != target or row.get('action') not in ('UPGRADE_REQUIRED','AT_TARGET_NO_FLASH'):
            raise SharedUpgradeHold('original native firmware plan is incomplete')
        return (0,) if row['action'] == 'UPGRADE_REQUIRED' else ()

    def _has_native_package_source_provenance(self):
        # Presence, including a damaged/None value, fixes the native branch.
        # A failed native check must never fall back to readiness admission.
        return any(name in vars(self) for name in (
            '_native_parent', '_native_node', '_native_component', '_native_package_indices'))

    def _is_native_package_source_child(self, parent, node=None, component=None):
        """Fixed live native provenance, never a readiness impersonation."""
        name = getattr(self, '_native_node', None)
        selected = getattr(self, '_native_component', None)
        return (not any(name in vars(self) for name in ('_readiness_parent', '_readiness_node'))
                and type(parent) is _PreparedRunScope and parent is not self
                and getattr(self, '_native_parent', None) is parent
                and self.manual_execution and parent.manual_execution
                and self.parsed.method == parent.parsed.method == 'scp'
                and self._native_schedule_started and parent._native_schedule_started
                and name in self.devices and name in parent.devices
                and selected in self.parsed.selected and selected in parent.parsed.selected
                and (node is None or node == name) and (component is None or component == selected)
                and self in parent._package_source_borrowers
                and self._package_source_parent is parent
                and self._package_source_owner is parent._package_source_owner
                and self._package_source_selection is parent._package_source_selection
                and getattr(self, '_native_package_indices', None) ==
                    parent._native_scp_needed_indices(name, selected)
                and bool(self._native_package_indices)
                and all((selected, index) in parent._package_source_selection[0]
                        for index in self._native_package_indices))

    def fork_native_component_scope(self, node, component):
        """Borrow original frozen SCP sources after startup, never readiness."""
        self.verify()
        if (self.closed or not self._native_schedule_started
                or not self.manual_execution or self.parsed.method != 'scp'
                or self._package_source_parent is not None
                or not self._package_source_owns or self._package_source_owner is None):
            raise SharedUpgradeHold('original native SCP parent scope required')
        indices = self._native_scp_needed_indices(node, component)
        if not indices or any((component, index) not in self._package_source_selection[0] for index in indices):
            raise SharedUpgradeHold('needed native source stage was not frozen by original parent')
        child = None
        try:
            child = _PreparedRunScope(*self._open_context, self.run_directory,
                                      manual_execution=self.manual_execution)
            if (child.plan_sha256 != self.plan_sha256 or child.policy != self.policy
                    or [(p.identity,p.payload) for p in child.session._files] !=
                       [(p.identity,p.payload) for p in self.session._files]):
                raise SharedUpgradeHold('native child original inputs differ from parent')
            child._native_parent, child._native_node, child._native_component = self, node, component
            child._native_package_indices = indices
            child._native_schedule_started = True
            child._package_source_owner = self._package_source_owner
            child._package_source_owner_class = self._package_source_owner_class
            child._package_source_parent = self
            child._package_source_selection = self._package_source_selection
            self._package_source_borrowers.add(child)
            child._verify_package_source_owner()
            return child
        except BaseException as original:
            if self._package_source_lifecycle_failure is None:
                self._package_source_lifecycle_failure = SharedUpgradeHold(
                    'native source child acquisition uncertain; original parent retained')
            if child is not None:
                try:
                    child.close()
                except BaseException as cleanup:
                    if isinstance(original, Exception) and not isinstance(cleanup, Exception):
                        raise
            raise

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
                or (parent is not self and
                    (not self._is_native_package_source_child(parent)
                     if self._has_native_package_source_provenance() else
                     (getattr(self, '_readiness_parent', None) is not parent
                      or getattr(self, '_readiness_node', None) not in self.devices)))):
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
                or not (self._is_native_package_source_child(self._package_source_parent,
                                                            leaf.node.hostname, component)
                        if self._has_native_package_source_provenance() else
                        getattr(self, '_readiness_node', None) == leaf.node.hostname)
                or (self._has_native_package_source_provenance()
                    and package_index not in getattr(self, '_native_package_indices', ()))):
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
                    and ((getattr(self, '_native_parent', None) is parent
                          and self in parent._package_source_borrowers)
                         if self._has_native_package_source_provenance() else
                         getattr(self, '_readiness_parent', None) is parent)
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
            scp_companion = None
            if self.parsed.method == 'scp':
                if (component not in ('os', 'bios', 'cpld')
                        or (component in ('bios', 'cpld') and data['package_index'] != 0)):
                    raise ValueError('only original selected OS, BIOS or CPLD has an SCP dispatch backend')
                parent = self._native_parent
                self._native_scp_source(leaf, component, data['package_index'])
                joint = _fixed_native_scp_cpld_api(parent)
                if (type(joint) is not tuple or len(joint) != 3
                        or len(joint[0]) != 19
                        or any(actual is not original for actual, original in zip(joint[0], parent._scp_source_binding[1]))
                        or type(joint[2]) is not tuple or len(joint[2]) <= 3
                        or joint[2][2] is not _PreparedRunScope._native_scp_launch_context
                        or joint[2][3] is not _PreparedRunScope._launch_native_scp_cpld):
                    raise ValueError('fixed native SCP dispatch producer joint changed')
                step = self._hold(directory, 'step.sh')
                runner = self._hold(directory, 'runner.sh')
                scp_companion = self._hold(directory, 'scp-source-request.json')
                if json.loads(runner_binding.payload).get('remote_script') != remote:
                    raise ValueError('SCP dispatch differs from original runner remote')
                _validate_scp_request_content_graph(set(os.listdir(directory.fd)), data['binding'],
                    lambda name: self._hold(directory, name).payload)
                expected_command = joint[2][0](remote, hashlib.sha256(runner.payload).hexdigest(),
                                               hashlib.sha256(step.payload).hexdigest())
                if (rows[-1]['stdout_base64'] != base64.b64encode(b'IBSW_LAUNCH_REQUESTED\n').decode('ascii')
                        or rows[-1]['stderr_base64'] != '' or rows[-1]['returncode'] != 0
                        or rows[-1]['stream_complete'] is not True):
                    raise ValueError('complete fixed SCP launch delivery fact required')
            else:
                if 'scp-source-request.json' in os.listdir(directory.fd):
                    raise ValueError('SCP companion cannot authorize a V1 dispatch')
                expected_command = _owned_launch_command(remote)
            if (rows[-1]["command"] != expected_command
                    or any((r["stream_complete"] is not True or r["returncode"] != 0 or r["stderr_base64"] != "")
                           and not (self.parsed.force_health and r['command']=='nv show system health')
                           for r in rows[:-1])):
                raise ValueError("incomplete original component launch chain")
            uid = [r for r in rows if r["command"] == "id -u"]
            if len(uid) != 1 or not re.fullmatch(rb"[0-9]+\n", base64.b64decode(uid[0]["stdout_base64"], validate=True)):
                raise ValueError("one actual original uid required")
            document = {"schema_version": 2, "state": "COMPONENT_DISPATCH_DATA_ONLY",
                "binding": data["binding"], "request_sha256": hashlib.sha256(request.payload).hexdigest(),
                "remote_script": remote, "records": rows, "launch_kind": "OWNED_RUNNER_V1",
                "runner_binding_sha256": hashlib.sha256(runner_binding.payload).hexdigest()}
            if scp_companion is not None:
                document['launch_kind'] = 'SCP_STDIN_OWNED_RUNNER_V2'
                document['scp_companion_sha256'] = hashlib.sha256(scp_companion.payload).hexdigest()
            payload = _json_bytes(document)
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

    def _scp_download_inputs_locked(self, leaf, dispatch):
        """Same live OS parent/lease/seven originals; returned DATA is no permit."""
        group = self
        try:
            for candidate in (getattr(self, '_native_parent', None),
                              getattr(self, '_package_source_parent', None)):
                if (type(candidate) is _PreparedRunScope and candidate is not self
                        and type(candidate._package_source_borrowers) is set
                        and self in candidate._package_source_borrowers):
                    group = candidate
                    break
            lease = self._active_request_lease
            if (type(self) is not _PreparedRunScope or group is self
                    or type(lease) is not _ManualJournalTransaction or not self.manual_execution
                    or self.parsed.method != 'scp' or type(dispatch) is not ComponentDispatchResult
                    or dispatch.component != 'os' or dispatch.state != 'DISPATCHED_UNKNOWN'
                    or type(leaf) is not _ReadonlyQueryInputs or leaf.scope is not self
                    or not getattr(leaf, '_cooperative_completion', False)
                    or dispatch.hostname != leaf.node.hostname):
                raise SharedUpgradeHold('original leased native SCP OS measurement scope required')
            lease.verify()
            source = self._native_scp_source(leaf, 'os', dispatch.package_index)
            joint = _fixed_native_scp_cpld_api(group)
            stage_name = declared_step_key(self.policy, 'os', dispatch.package_index)
            if dispatch.stage != stage_name:
                raise SharedUpgradeHold('original native SCP OS measurement stage changed')
            stage_path = self.run_directory / leaf.node.hostname / stage_name
            directory = self.session._directories.get(str(stage_path))
            if directory is None:
                raise SharedUpgradeHold('original native SCP OS stage is not held')
            self._private_directory(directory)
            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh',
                     'runner-binding.json', 'scp-source-request.json', 'component-dispatch.json')
            originals = tuple(self.files.get((str(stage_path), name)) for name in names)
            if any(type(obj) is not _HeldFile or obj.directory is not directory
                   or obj.name != name or obj.cleanup_issues for name, obj in zip(names, originals)):
                raise SharedUpgradeHold('complete original native SCP OS measurement files required')
            for obj in originals:
                obj.verify()
            values = joint[2][45](leaf, dispatch)
            if values[0] is not self or values[1] is not directory:
                raise SharedUpgradeHold('original native SCP bound consumer changed')
            binding = values[2]
            if originals[2].payload != _json_bytes(binding):
                raise SharedUpgradeHold('original native SCP measurement binding changed')
            joint[2][34](set(names), binding,
                         lambda name: self.files[(str(stage_path), name)].payload)
            companion = json.loads(originals[5].payload)
            owner = group._package_source_owner
            self._verify_package_source_owner()
            packages = self._package_source_packages('os', dispatch.package_index)
            if len(packages) != 1 or type(companion['packages']) is not dict:
                raise SharedUpgradeHold('one actual selected native SCP OS package required')
            package = packages[0]
            row = owner._files.get(Path(package.path))
            if (type(row) is not tuple or len(row) != 5
                    or type(row[3]) is not tuple or len(row[3]) != 9
                    or type(row[3][6]) is not int or not 0 < row[3][6] < 2**63
                    or type(row[4]) is not str or re.fullmatch('[0-9a-f]{64}', row[4]) is None
                    or companion['packages'] != {package.path: dict(size=row[3][6], sha256=row[4])}):
                raise SharedUpgradeHold('native SCP measurement companion differs from original package')
            expected = dict(binding_sha256=hashlib.sha256(originals[2].payload).hexdigest(),
                            path=package.path, size=row[3][6], sha256=row[4])
            if self._native_scp_source(leaf, 'os', dispatch.package_index) is not source:
                raise SharedUpgradeHold('original native SCP measurement source changed at tail')
            current = _fixed_native_scp_cpld_api(group)
            if (any(len(a) != len(b) or any(x is not y for x, y in zip(a, b))
                    for a, b in zip(joint, current))
                    or self._active_request_lease is not lease or self._native_parent is not group
                    or self._package_source_owner is not owner or group._package_source_owner is not owner
                    or owner._files.get(Path(package.path)) is not row
                    or self.session._directories.get(str(stage_path)) is not directory):
                raise SharedUpgradeHold('original native SCP measurement owners changed at tail')
            lease.verify()
            for name, obj in zip(names, originals):
                if self.files.get((str(stage_path), name)) is not obj:
                    raise SharedUpgradeHold('original native SCP measurement file owner changed')
                obj.verify()
            self.verify(); leaf.verify(); group.verify()
            return directory, binding, expected, originals, source, owner, lease, joint, group
        except BaseException as error:
            if (type(group) is _PreparedRunScope
                    and group._package_source_lifecycle_failure is None):
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'original native SCP OS measurement inputs uncertain; group retained')
            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):
                raise
            raise SharedUpgradeHold('original native SCP OS measurement inputs unavailable') from None

    def _record_scp_download_attempt(self, leaf, dispatch, rows):
        """Record one strict original SCP pair; critical finish precedes return."""
        group = self
        try:
            for candidate in (getattr(self, '_native_parent', None),
                              getattr(self, '_package_source_parent', None)):
                if (type(candidate) is _PreparedRunScope and candidate is not self
                        and type(candidate._package_source_borrowers) is set
                        and self in candidate._package_source_borrowers):
                    group = candidate
                    break
            record = None
            with self._request_namespace_lease():
                joint = _fixed_native_scp_cpld_api(group)
                inputs = joint[2][30](self, leaf, dispatch)
                directory, binding, expected, originals, source, owner, lease, _joint, parent = inputs
                if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict
                        or type(rows[0].get('content_marker')) is not bytes
                        or type(rows[0].get('raw_line')) is not bytes):
                    raise SharedUpgradeHold('one complete original SCP measurement pair required')
                packet = rows[0]['content_marker'] + b'\n' + rows[0]['raw_line'] + b'\n'
                parsed = joint[2][26](packet, expected)
                if parsed != rows[0]:
                    raise SharedUpgradeHold('foreign SCP measurement DATA')
                read = lambda name: self._hold(directory, name).payload
                document = joint[2][29](binding, originals[6].payload, read, packet)
                payload = _json_bytes(document)
                name = 'download-attempt-01.json'
                if name in os.listdir(directory.fd):
                    self._hold(directory, name, payload)
                else:
                    if 'component-completion.json' in os.listdir(directory.fd):
                        raise SharedUpgradeHold('SCP measurement cannot be appended after completion')
                    joint[2][35](self, directory, payload, name)
                    record = dict(hostname=leaf.node.hostname, stage=dispatch.stage,
                        target_version=dispatch.target_version, measurement=document['measurement'],
                        path=str(directory.path / name))
                # The actual original writer finally/finish has already returned.
                # This second derivation cannot adopt a replacement/new package row.
                after = joint[2][30](self, leaf, dispatch)
                if (after[0] is not directory or after[4] is not source or after[5] is not owner
                        or after[6] is not lease or after[8] is not parent
                        or after[2] != expected
                        or any(a is not b for a, b in zip(after[3], originals))):
                    raise SharedUpgradeHold('original SCP measurement owners changed after commit')
                saved = self._hold(directory, name, payload)
                saved.verify(); leaf.verify()
            # All required record and lease cleanup succeeded before callbacks
            # or the observable _record_download_attempt return can occur.
            if record is not None:
                self._download_measurements = getattr(self, '_download_measurements', []) + [record]
                callback = getattr(self, '_download_callback', None)
                if callback:
                    callback(record)
            return None
        except BaseException as error:
            if (type(group) is _PreparedRunScope
                    and group._package_source_lifecycle_failure is None):
                group._package_source_lifecycle_failure = SharedUpgradeHold(
                    'native SCP OS measurement commit uncertain; shared group retained')
            if not isinstance(error, Exception) or isinstance(error, SharedUpgradeHold):
                raise
            raise SharedUpgradeHold('SCP OS measurement was not reliably committed; ACK withheld') from error

    def _record_download_attempt(self,leaf,dispatch,rows):
        """Durably save original pre-reboot numeric telemetry before remote ACK.

        Repeated polls may return identical measurements, never different bytes
        under an already committed attempt. No speed measurement admits success.
        """
        if self.parsed.method == 'scp':
            parent = self
            for candidate in (getattr(self, '_native_parent', None),
                              getattr(self, '_package_source_parent', None)):
                if (type(candidate) is _PreparedRunScope and candidate is not self
                        and type(candidate._package_source_borrowers) is set
                        and self in candidate._package_source_borrowers):
                    parent = candidate
                    break
            joint = _fixed_native_scp_cpld_api(parent)
            return joint[2][31](self, leaf, dispatch, rows)
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
