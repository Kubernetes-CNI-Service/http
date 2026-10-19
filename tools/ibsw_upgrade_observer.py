"""Fixed IB SSH reader and original-request completion observer.

The only factory source is a currently held driver input leaf. Caller-provided
connections, command vectors, parsed versions and boolean evidence cannot be
adopted. Inspection never writes devices. Explicit upgrades may restore their
original authorization through ibsw_upgrade_access after fresh authentication
and identity checks. No dependency installation, trust enrollment or installer
retry occurs here; configuration recovery retains its separate guarded path.
"""
from contextlib import contextmanager, ExitStack
from dataclasses import asdict
from importlib import metadata
import base64
import errno
import hashlib
import io
import json
import os
import re
import shlex
import socket
import threading
import time

from ibsw_upgrade_contract import (
    record_readonly_query, parse_readonly_query_data, load_global_text,
    normalize_upgrade, select_os_path, _documented_table_lines,
    _documented_firmware_fields, _version, SharedUpgradeHold,
)
from ibsw_upgrade_component import _bios_upgrade_needed, _cpld_upgrade_needed
from ibsw_upgrade_schedule import component_order


SSH_RUNTIME_PINS = (("paramiko", "5.0.0"), ("bcrypt", "5.0.0"),
                    ("cryptography", "50.0.1"), ("invoke", "2.2.1"),
                    ("PyNaCl", "1.6.2"), ("cffi", "2.0.0"),
                    ("pycparser", "2.23"), ("typing-extensions", "4.16.0"))
_QUERY_ARGV = (("nv", "show", "system", "version"),
               ("nv", "show", "platform", "firmware"))
_IDENTITY_COMMAND = "hostname; cat /sys/class/net/eth0/address"
_TOTAL_SECONDS = 25.0
_INSPECTION_SECONDS = 120.0
_CONNECT_SECONDS = 10.0
_COMPLETION_SECONDS = 1800.0
_MAX_QUERY_BYTES = 4 * 1024 * 1024

# Fixed public diagnostics only; never native exception or device-output text.
READONLY_FAILURE_HINTS = {
    "OS_PACKAGE_ROUTE_UNAVAILABLE": "No complete OS route has readable nonempty packages for every required future stage; fix the listed local paths before retrying inspection.",
    "OS_ROUTE_NOT_PREPARED": "Alternative OS stages require this run's parent preflight and frozen route before dispatch.",
    "OS_ROUTE_CHANGED": "Live OS is outside this run's frozen device route; inspect again instead of changing routes in flight.",
    "OS_VERSION_QUERY_FAILED": "OS version query failed, returned stderr or did not complete.",
    "FIRMWARE_QUERY_FAILED": "Platform firmware query failed, returned stderr or did not complete.",
    "OS_VERSION_PARSE_FAILED": "OS version table is unrecognized, incomplete or internally inconsistent.",
    "OS_UPGRADE_PATH_REJECTED": "Current OS is not an admitted node in the declared OS upgrade path.",
    "OS_FINAL_NOT_REACHED": "Firmware-only selection requires the configured final OS to be present.",
    "FIRMWARE_PARSE_FAILED": "Firmware table or required Actual FW fields are unrecognized or missing.",
    "BIOS_VERSION_CHECK_FAILED": "BIOS observation cannot satisfy the configured target/no-downgrade rule.",
    "CPLD_VERSION_CHECK_FAILED": "CPLD observations cannot satisfy target coverage or no-downgrade rules.",
}

UPGRADE_FAILURE_HINTS = {
    'INSTALLER_EXIT_NONZERO_BEFORE_REBOOT': 'The current request reported a nonzero installer exit on the original boot. Inspect the saved download/installer diagnostics; no automatic reinstall was attempted.',
    'DOWNLOAD_FAILED_BEFORE_INSTALL': 'The original child ended during package preparation before installation. The failed device remains isolated; its active slot is released. No automatic retry was attempted.',
    'DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL': 'The original child ended while awaiting its download record acknowledgement, before installation. The failed device remains isolated; its active slot is released. No automatic retry was attempted.',
    "READONLY_QUERY_TIMEOUT": "This command exhausted its independent 25-second query budget; this is not a credential rejection.",
    "READONLY_QUERY_INCOMPLETE": "The command did not provide a complete stream and exit status; no success is assumed.",
    "READONLY_QUERY_NONZERO": "The fixed read-only command returned nonzero; inspect its saved raw record and command identity.",
    "READONLY_QUERY_STDERR": "The fixed read-only command returned diagnostics on stderr; inspect its saved raw record.",
    "SSH_CONNECT_TIMEOUT": "TCP/22 connection timed out before SSH authentication.",
    "SSH_HANDSHAKE_TIMEOUT": "The SSH handshake timed out; credentials were not verified.",
    "HEALTH_PRECHECK_NOT_OK": "Pre-upgrade health is not OK/green or has active issues; installer was not dispatched. Repair the device or explicitly use --force for health only.",
    "HEALTH_STATUS_UNAVAILABLE": "The health command returned N/A; health is unknown, not healthy. Inspect the device; health-only --force must be explicit.",
    "HEALTH_DEGRADED": "New or unexplained health degradation was observed after the operation.",
    "READONLY_DEADLINE_EXCEEDED": "The bounded read-only phase budget expired; this is not evidence of an incorrect password. Check the named phase and saved evidence; no automatic installer retry is performed.",
    "OS_COVERAGE_ROUTE_CHANGED": "The live OS now requires hops outside this run's planned and canary-covered route; no new hop was dispatched. Reinspect and select coverage in a new run.",
    "OS_CANARY_ROUTE_CHANGED": "The canary's live OS path differs from its selected full coverage route; no skipped hop counts as validated. Reinspect in a new run instead of releasing peers.",
    "NVOS_CLI_NOT_READY_AFTER_5_CHECKS": "NVOS CLI still reports initialization after five readiness rounds 60 seconds apart; no installer was resent.",
    "NVUE_READINESS_CHECK_LIMIT_EXCEEDED": "The bounded readiness checks are exhausted without readiness for the current boot; manual verification is required.",
    "NVUED_NOT_RUNNING_AFTER_5_CHECKS": "nvued was not active/running after five checks 60 seconds apart; no upgrade request was resent.",
    "NVOS_CLI_INITIALIZING": "NVOS CLI still reports initialization after the nvued service gate; verification is incomplete and no installer is resent.",
    "COMPONENT_UPGRADE_PLAN_CHANGED": "A component planned for checks only now requires installation; no installer was dispatched. Reinspect and choose a real component canary.",
    "BOOT_ID_QUERY_FAILED": "The original Linux boot identity could not be read reliably; activation is not assumed.",
    "COMPONENT_FILE_UNSAFE": "An original installer file has unsafe type, ownership or mode; inspect the private safe diagnostic.",
    "COMPONENT_FILE_MISSING": "An original installer file is missing; no installer was resent.",
    "COMPONENT_FILE_CHANGED": "An original installer file changed or could not be read completely.",
    "COMPONENT_DIRECTORY_UNSAFE": "An ancestor of the original installer directory is writable or not a directory.",
    "COMPONENT_DIRECTORY_MISSING": "An original installer directory could not be found.",
    "COMPONENT_EXIT_BINDING_INVALID": "The original installer exit does not match the selected request and script.",
    "COMPONENT_SFTP_FAILED": "The original installer SFTP channel or cleanup failed.",
    "PASSWORD_PREFLIGHT_REJECTED": "The initial password-only probe was explicitly rejected; no key was imported or installer dispatched.",
    "SSH_AUTHENTICATION_REJECTED": "The server explicitly rejected this credential; no password rotation was attempted.",
    "SSH_AUTH_TRANSPORT_LOST": "The connection closed or timed out during authentication, possibly during reboot.",
    "SSH_AUTH_PROTOCOL_FAILED": "SSH authentication protocol did not complete; this is not proof of a bad password.",
    "SSH_AUTH_TIMEOUT": "Key authentication timed out; no server credential rejection was established.",
    "SSH_PASSWORD_AUTH_RESULT_UNKNOWN": "Password authentication had an ambiguous timeout/disconnect result; no repeated password guesses were made.",
    "SSH_AUTH_RESULT_UNKNOWN": "Authentication failed without explicit server rejection evidence; manual review is required.",
    "CONFIG_BACKUP_QUERY_FAILED": "Configuration export failed, returned stderr or was incomplete.",
    "CONFIG_BACKUP_EMPTY": "Configuration export was empty; no upgrade was requested.",
    "CONFIG_BACKUP_NOT_TEXT": "Configuration export was not UTF-8 text.",
    "CONFIG_PENDING_QUERY_FAILED": "Pending configuration query did not complete successfully.",
    "CONFIG_PENDING_NOT_EMPTY": "Pending device configuration exists; do not overwrite unrelated changes.",
    "HEALTH_QUERY_FAILED": "Device health query did not complete successfully.",
    "HEALTH_PARSE_FAILED": "Device health output could not be verified.",
    "CONFIG_COMPARISON_REVIEW_REQUIRED": "Post-upgrade configuration needs review; masked or unsafe missing values are not replayed.",
    "SIGNED_SESSION_CLEANUP_FAILED": "SSH session cleanup was incomplete.",
    "COMPONENT_EXIT_NOT_OBSERVED": "The original installer exit record was not observed within the bounded readback window; no installer was resent.",
    "COMPONENT_VERSION_NOT_VERIFIED": "Live versions do not establish this component's expected activation; no configuration recovery was attempted.",
}


class _NativeObservationHold(ValueError):
    def __init__(self, records=(), *, capture_raw=None, reason_code="READONLY_QUERY_FAILED"):
        super().__init__("readonly native observation HOLD; no write/current/activation permission")
        allowed = {"READONLY_QUERY_FAILED", "SSH_CONNECT_FAILED", "SSH_HANDSHAKE_FAILED",
                   "SSH_HOST_KEY_MISMATCH", "SSH_AUTHENTICATION_FAILED",
                   "DEVICE_IDENTITY_MISMATCH", "DEVICE_IDENTITY_QUERY_FAILED"} | set(READONLY_FAILURE_HINTS) | set(UPGRADE_FAILURE_HINTS)
        self.reason_code = reason_code if reason_code in allowed else "READONLY_QUERY_FAILED"
        self.records = tuple(records)
        self.capture_raw = capture_raw  # Private raw diagnostic DATA, never completion.


class _CompletionDeferred(Exception):
    """A pre-operation connection needs another bounded observation, not a write retry."""


class _CompletionBootChanged(Exception):
    """Fresh signed kernel state requires a new stabilization round, not a resend."""
    def __init__(self, boot_id):
        self.boot_id = boot_id


def _is_nvos_initializing(raw):
    """Only this complete native error is a startup wait, not a general retry."""
    expected=(b'Error: NVOS CLI is unavailable\nSystem is initializing!\n'
              b'This may take a few minutes')
    return (type(raw) is tuple and len(raw)==4 and type(raw[0]) is bytes
            and not raw[0] and type(raw[1]) is bytes and type(raw[2]) is int
            and raw[2]==1 and raw[3] is True
            and raw[1].replace(b'\r\n',b'\n').strip()==expected)


def _fixed_sdk():
    failed = False
    try:
        if any(metadata.version(name) != version for name, version in SSH_RUNTIME_PINS):
            raise ValueError("fixed optional SSH runtime unavailable")
        import paramiko
    except Exception:
        failed = True
    if failed:
        raise _NativeObservationHold()
    return paramiko


def _fingerprint(public_wire):
    return "SHA256:" + base64.b64encode(hashlib.sha256(public_wire).digest()).rstrip(b"=").decode("ascii")


def _remaining(deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise _NativeObservationHold(reason_code='READONLY_DEADLINE_EXCEEDED')
    return remaining


def _progress(leaf, component, stage):
    leaf._last_progress_stage = stage
    callback = getattr(leaf.scope, '_progress_callback', None)
    if callback is not None:
        callback(leaf.node.hostname, component, stage)


@contextmanager
def _owned_phase(owners, deadline):
    """ACK waits need an owned deadline closer; no PID/signal or retry action."""
    owners = tuple(owners)
    cleanup = []
    expired = threading.Event()
    def expire():
        expired.set()
        for owner in owners:
            if owner is None:
                continue
            try:
                owner.close()
            except BaseException as error:
                cleanup.append(error)
    timer = threading.Timer(_remaining(deadline), expire)
    original = None
    try:
        timer.daemon = True
        timer.start()
        yield expired
    except BaseException as caught:
        original = caught
    finally:
        for operation in (timer.cancel, lambda: timer.join(2)):
            try:
                operation()
            except BaseException as error:
                cleanup.append(error)
        try:
            if timer.is_alive():
                cleanup.append(ValueError("owned deadline closer did not terminate"))
                expire()  # Attempt every original owner; unknown residue HOLD.
        except BaseException as error:
            cleanup.append(error)
    interrupt = next((item for item in cleanup if not isinstance(item, Exception)), None)
    if original is not None and not isinstance(original, Exception):
        raise original
    if interrupt is not None:
        raise interrupt
    if original is not None:
        raise original
    if cleanup:
        raise ValueError("owned deadline close failed; remains HOLD")
    if expired.is_set():
        raise _NativeObservationHold(reason_code='READONLY_DEADLINE_EXCEEDED')


def _original_private_key(leaf, sdk):
    leaf.verify()
    original = leaf._identity
    expected_size = os.fstat(original.fd).st_size
    payload = os.pread(original.fd, expected_size + 1, 0)
    leaf.verify()
    if len(payload) != expected_size or os.pread(original.fd, expected_size + 1, 0) != payload:
        raise _NativeObservationHold()
    # Only the original private FD is read. SDK path reopening, default key
    # discovery and agent fallback are deliberately absent. Private material
    # stays local/in-memory, is not part of records/results/errors or repr.
    text = payload.decode("ascii")
    for key_type in (sdk.Ed25519Key, sdk.RSAKey, sdk.ECDSAKey):
        try:
            key = key_type.from_private_key(io.StringIO(text))
        except (ValueError, sdk.SSHException):
            continue
        if not key.can_sign() or _fingerprint(key.asbytes()) != leaf.management_public:
            raise _NativeObservationHold()
        leaf.verify()
        return key
    raise _NativeObservationHold()


def _read_channel(leaf, transport, command, deadline):
    """Drain raw separate streams before status; never interpret readiness EOF.

    Paramiko 5 source channel._handle_eof sets eof_received only on the remote
    protocol EOF (this reader never calls shutdown_read). Channel close or a
    dead transport alone is not complete, even if buffered reads return b''.
    """
    entered = time.monotonic()
    try:
        leaf.verify()
    except Exception as error:
        raise SharedUpgradeHold('original query inputs are no longer valid') from error
    started = time.monotonic()
    deadline = min(deadline, started + _TOTAL_SECONDS)
    budget = max(0.0, deadline-started)
    channel = None
    output, error = bytearray(), bytearray()
    status, complete, original = None, False, None
    expired = None
    def verify_stream_identity():
        try: getattr(leaf,'verify_io_identity',leaf.verify)()
        except SharedUpgradeHold: raise
        except Exception as changed:
            raise SharedUpgradeHold('original query source identity changed during collection') from changed
    try:
        channel = transport.open_session(timeout=_remaining(deadline))
        channel.settimeout(_remaining(deadline))
        with _owned_phase((channel,), deadline) as expired:
            verify_stream_identity()
            channel.exec_command(command)  # Only fixed internal literals reach here.
            verify_stream_identity()
            while True:
                verify_stream_identity()
                _remaining(deadline)
                for ready, receive, target in ((channel.recv_ready, channel.recv, output),
                                               (channel.recv_stderr_ready, channel.recv_stderr, error)):
                    if ready():
                        payload = receive(65536)
                        target.extend(payload)
                        if len(output) + len(error) > _MAX_QUERY_BYTES:
                            raise _NativeObservationHold()
                verify_stream_identity()
                if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                    raw_status = channel.recv_exit_status() if channel.exit_status_ready() else -1
                    status = raw_status if raw_status >= 0 else None
                    complete = bool(channel.eof_received) and status is not None
                    break
                if not transport.is_active() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                time.sleep(min(0.005, _remaining(deadline)))
    except BaseException as caught:
        original = caught
    finally:
        wire_finished=time.monotonic()
        if channel is not None:
            try:
                channel.close()
            except BaseException as cleanup:
                if original is None or (isinstance(original, Exception) and not isinstance(cleanup, Exception)):
                    original = cleanup
        try:
            leaf.verify()  # Full original-byte verification before accepting any received result.
        except BaseException as changed:
            original = changed if not isinstance(changed,Exception) else SharedUpgradeHold('original query inputs changed during collection')
    timed_out = bool((expired is not None and expired.is_set()) or wire_finished >= deadline
                     or getattr(original,'reason_code','') == 'READONLY_DEADLINE_EXCEEDED')
    leaf._last_query_diagnostic = dict(command=command, budget_seconds=round(budget,3),
        elapsed_seconds=round(max(0.0,wire_finished-started),3),
        precheck_seconds=round(max(0.0,started-entered),3),
        postcheck_seconds=round(max(0.0,time.monotonic()-wire_finished),3),
        stdout_bytes=len(output),stderr_bytes=len(error),returncode=status,
        stream_complete=bool(complete and original is None and not timed_out),
        native_errno=errno.errorcode.get(original.errno,'UNKNOWN') if isinstance(original,OSError) else None,
        reason_code='READONLY_QUERY_TIMEOUT' if timed_out else
                    'READONLY_QUERY_INCOMPLETE' if original is not None or not complete else 'QUERY_COMPLETE')
    if original is not None and not isinstance(original, Exception):
        raise original
    if isinstance(original, SharedUpgradeHold):
        raise original
    if isinstance(original,OSError) and original.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS):
        raise original
    # Ordinary failures preserve received bytes as incomplete data; no captured
    # numeric slot/status/timeout becomes a caller-supplied completion authority.
    return bytes(output), bytes(error), status, complete and original is None and not timed_out


def _live_plan_inputs(leaf):
    """Current ORIGINAL FD/plan-source DATA, not device-current/permission."""
    from ibsw_upgrade_driver import _ReadonlyQueryInputs, parse_prepare_args
    if type(leaf) is not _ReadonlyQueryInputs:
        raise ValueError("original live readonly input leaf required")
    leaf.verify()
    scope = leaf._original_selection[0]
    global_source = scope.session._files[1]
    run_plan = scope.files[(str(scope.directory.path), "plan.json")]
    global_source.verify(); run_plan.verify()
    declared = json.loads(run_plan.payload)
    parsed_args = parse_prepare_args(declared["entry"], declared["cwd"], declared["argv"])
    if (declared["selected"] != list(parsed_args.selected) or declared["method"] != parsed_args.method
            or asdict(leaf.node) not in declared["devices"]):
        raise ValueError("original held plan selection changed")
    document = load_global_text(global_source.payload.decode("utf-8-sig"))
    policy = normalize_upgrade(document, selected=parsed_args.selected,
                               method=parsed_args.method, package_dir=parsed_args.package_dir)
    leaf.verify()
    return scope, global_source, run_plan, declared, parsed_args, policy


def _initial_data_plan(leaf, records):
    """Pure DATA calculator; supplied records never attest device current.

    Only the fixed native factory can attribute its own captured records to a
    connection. No public native DICT/VersionDTO enters that factory.
    """
    scope, global_source, run_plan, declared, parsed_args, policy = _live_plan_inputs(leaf)
    result = {"state": "INITIAL_DATA_PLAN", "execution_state": "NOT_EXECUTED",
              "activation_state": "UNKNOWN", "attestation_state": "DATA_ONLY_UNATTESTED",
              "node": asdict(leaf.node), "run_id": declared["run_id"],
              "selected": parsed_args.selected, "method": parsed_args.method,
              "final_os_target": policy.final_os, "os_path": (), "needed_components": (), "version_rows": [],
              "order": tuple("os-to-final" if item == "os" else item for item in component_order(parsed_args.selected)),
              "canary_mode": declared["canary_mode"],
              "ordering_constraints": ("COMPONENT_CANARY_BEFORE_SAME_COMPONENT_BATCH", "PER_DEVICE_OS_FINAL_BEFORE_FIRMWARE",
                                       "FAILED_OR_UNKNOWN_NODE_STOPS_LATER_COMPONENTS",
                                       "FRESH_IDENTITY_CONFIG_HEALTH_AFTER_EACH_ACTIVATION"),
              "global_sha256": hashlib.sha256(global_source.payload).hexdigest(),
              "run_plan_sha256": hashlib.sha256(run_plan.payload).hexdigest()}
    failure_code = "READONLY_QUERY_FAILED"
    try:
        ssd_sample=(policy.ssd_version is not None and type(records) is tuple and len(records)==2)
        expected = _QUERY_ARGV if set(parsed_args.selected) & {"bios", "cpld"} or ssd_sample else _QUERY_ARGV[:1]
        if type(records) is not tuple or len(records) != len(expected):
            raise ValueError("selected fixed raw DATA records required")
        for record, argv in zip(records, expected):
            if record.argv != argv:
                raise ValueError("fixed two query order required")
            record_readonly_query(record.argv, record.stdout, record.stderr, record.returncode)
            if argv == _QUERY_ARGV[0] and (record.returncode != 0 or record.stderr):
                raise ValueError("query unfinished/nonzero/stderr")
        failure_code = "OS_VERSION_PARSE_FAILED"
        os_data = parse_readonly_query_data(records[0])
        if os_data.state != "TEXT_DATA_PARSED":
            raise ValueError("unknown OS DATA")
        observed_os = dict(os_data.fields)["image_version_text"]
        if ssd_sample and not set(parsed_args.selected)&{'bios','cpld'} and observed_os!=policy.final_os:
            raise ValueError('SSD-only startup query requires observed final OS')
        os_row = dict(component='os', current=observed_os, target=policy.final_os,
                      action='PREREQUISITE_VERIFIED', path=[])
        result['version_rows'].append(os_row)
        needed = []
        if "os" in parsed_args.selected:
            failure_code = "OS_UPGRADE_PATH_REJECTED"
            remaining = select_os_path(policy, observed_os)
            result["os_path"] = tuple(package.file for package in remaining)
            if remaining:
                needed.append("os")
            os_row.update(action='UPGRADE_REQUIRED' if remaining else 'AT_TARGET_NO_FLASH',
                          path=[observed_os]+[package.version for package in remaining])
        else:
            failure_code = "OS_FINAL_NOT_REACHED"
            if _version(observed_os) != policy.final_os:
                raise ValueError("unselected OS completion must be explicit before firmware")
        targets = (("BIOS",) if "bios" in parsed_args.selected else ())
        if "cpld" in parsed_args.selected:
            targets += ("CPLD",)
        component_issues = []
        for component, target in (("bios", "BIOS"), ("cpld", "CPLD")):
            if component not in parsed_args.selected:
                continue
            row = dict(component=component, current='UNVERIFIED', target=policy.bios.version if component=='bios'
                       else '+'.join(name+'_'+version for name,version in policy.cpld_targets), action='REVIEW_REQUIRED')
            result['version_rows'].append(row)
            try:
                if records[1].returncode != 0 or records[1].stderr:
                    raise ValueError("firmware observation incomplete")
                firmware = dict(_documented_firmware_fields(_documented_table_lines(records[1].stdout), targets=(target,)))
                if component == "bios":
                    row['current']=firmware['BIOS']
                    if _bios_upgrade_needed(policy, firmware["BIOS"]):
                        needed.append("bios")
                else:
                    slots = []
                    for slot, value in firmware.items():
                        match = re.fullmatch(r"(CPLD[0-9]+)_(REV[0-9]+)", value)
                        if match is None:
                            raise ValueError("unknown CPLD Actual FW DATA")
                        slots.append((slot, match[1], match[2]))
                    row['current']=';'.join(slot+'='+name+'_'+version for slot,name,version in slots)
                    if _cpld_upgrade_needed(policy, tuple(slots)):
                        needed.append("cpld")
                row['action']='UPGRADE_REQUIRED' if component in needed else 'AT_TARGET_NO_FLASH'
            except ValueError:
                component_issues.append({"component": component, "reason_code":
                    "FIRMWARE_QUERY_FAILED" if records[1].returncode != 0 or records[1].stderr else
                    "BIOS_VERSION_CHECK_FAILED" if component == "bios" else "CPLD_VERSION_CHECK_FAILED"})
        result["component_issues"] = component_issues
        result["needed_components"] = tuple(needed)
        if policy.ssd_version is not None and observed_os==policy.final_os:
            from ibsw_upgrade_contract import ssd_check_from_firmware
            from ibsw_upgrade_executor import _raw_record
            firmware_record=records[1] if len(records)>1 else None
            raw=(_raw_record('nv show platform firmware',(firmware_record.stdout,firmware_record.stderr,
                    firmware_record.returncode,firmware_record.returncode is not None)) if firmware_record is not None else None)
            result['ssd_check']=ssd_check_from_firmware(policy.ssd_version,raw,
                verification_basis='PREFLIGHT_OS_AT_TARGET')
            result['ssd_check']['observed_os_version']=observed_os
        result["raw_query_sha256"] = tuple((hashlib.sha256(record.stdout).hexdigest(),
                                            hashlib.sha256(record.stderr).hexdigest()) for record in records)
    except (ValueError, KeyError, TypeError, AttributeError):
        if result['version_rows']:
            result['version_rows'][0]['action']='REVIEW_REQUIRED'
        result.update(state="HOLD", os_path=(), needed_components=(),
                      reason_code=failure_code,
                      reason=READONLY_FAILURE_HINTS.get(failure_code, "initial DATA cannot establish safe ordered candidates"))
    global_source.verify(); run_plan.verify(); leaf.verify()
    return result


def _connect_for_completion(leaf, deadline):
    """Bounded TCP reconnect only, before any key/auth/command is attempted.

    Retry only boot-like connection refusal/unreachability/timeouts. Failed
    sockets must close first; identity, host-key, authentication, protocol and
    cleanup failures never enter this retry loop. No install is resent.
    """
    retryable = {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT}
    if getattr(leaf,"_cooperative_completion",False):
        connection=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        try:
            connection.settimeout(min(10.0,_remaining(deadline)))
            connection.connect((leaf.node.address,22))
            leaf.verify()
            return connection
        except BaseException:
            connection.close()
            raise
    while True:
        leaf.verify(); _remaining(deadline)
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            connection.settimeout(min(10.0, _remaining(deadline)))
            connection.connect((leaf.node.address, 22))
            leaf.verify(); _remaining(deadline)
            return connection
        except BaseException as error:
            # A close exception is never suppressed in order to retry.
            try:
                connection.close()
            except BaseException:
                if not isinstance(error, Exception):
                    raise error
                raise
            if (not isinstance(error, OSError)
                    or (not isinstance(error, TimeoutError) and error.errno not in retryable)):
                raise
            leaf.verify()
            _progress(leaf, 'ACCESS', 'WAIT_REBOOT')
            time.sleep(min(2.0, _remaining(deadline)))


@contextmanager
def _signed_session_single(leaf, *, password=None, _connection_deadline=None, _minimal=False):
    """Internal original-source authenticated lifetime, not an external provider."""
    from ibsw_upgrade_driver import _ReadonlyQueryInputs
    if type(leaf) is not _ReadonlyQueryInputs or not leaf._native_observation_consumed:
        raise _NativeObservationHold()
    if password is not None and (type(password) is not str or not password or "\x00" in password):
        raise _NativeObservationHold()
    leaf.verify()
    if leaf._identity is None and password is None:
        raise _NativeObservationHold()
    sdk = _fixed_sdk()
    leaf.verify()
    overall_deadline = (_connection_deadline if _connection_deadline is not None
                        else time.monotonic() + _INSPECTION_SECONDS)
    deadline = overall_deadline
    connection, transport, original = None, None, None
    operation_entered = False
    phase = "SSH_CONNECT_FAILED"
    try:
        leaf.verify(); _remaining(overall_deadline)
        if _connection_deadline is None:
            connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            tcp_deadline = min(overall_deadline,time.monotonic()+_CONNECT_SECONDS)
            connection.settimeout(_remaining(tcp_deadline))
            try:
                with _owned_phase((connection,),tcp_deadline):
                    connection.connect((leaf.node.address,22))
            except _NativeObservationHold as error:
                if error.reason_code=='READONLY_DEADLINE_EXCEEDED':
                    raise _NativeObservationHold(reason_code='SSH_CONNECT_TIMEOUT') from None
                raise
            except TimeoutError:
                raise _NativeObservationHold(reason_code='SSH_CONNECT_TIMEOUT') from None
        else:
            connection = _connect_for_completion(leaf,overall_deadline)
        leaf.verify(); _remaining(overall_deadline)
        phase = "SSH_HANDSHAKE_FAILED"
        transport = sdk.Transport(connection)
        handshake_deadline=min(overall_deadline,time.monotonic()+_TOTAL_SECONDS)
        connection.settimeout(_remaining(handshake_deadline))
        transport.banner_timeout = _remaining(handshake_deadline)
        try:
            with _owned_phase((transport,),handshake_deadline):
                transport.start_client(timeout=_remaining(handshake_deadline))
        except _NativeObservationHold as error:
            if error.reason_code=='READONLY_DEADLINE_EXCEEDED':
                raise _NativeObservationHold(reason_code='SSH_HANDSHAKE_TIMEOUT') from None
            raise
        except TimeoutError:
            raise _NativeObservationHold(reason_code='SSH_HANDSHAKE_TIMEOUT') from None
        leaf.verify()
        server_fingerprint = _fingerprint(transport.get_remote_server_key().asbytes())
        if server_fingerprint not in leaf.host_pins:
            raise _NativeObservationHold(reason_code="SSH_HOST_KEY_MISMATCH")
        leaf.verify(); _remaining(overall_deadline)
        phase = "SSH_AUTHENTICATION_FAILED"
        key = _original_private_key(leaf,sdk) if password is None else None
        auth_deadline=min(overall_deadline,time.monotonic()+_TOTAL_SECONDS)
        transport.auth_timeout = _remaining(auth_deadline)
        connection.settimeout(_remaining(auth_deadline))
        try:
            with _owned_phase((transport,),auth_deadline):
                if password is None:
                    transport.auth_publickey(leaf.user,key)
                    authentication="publickey"
                else:
                    transport.auth_password(leaf.user,password,fallback=False)
                    authentication="password"
        except sdk.AuthenticationException as error:
            message=str(error)
            if message=='Authentication timeout.':
                code='SSH_AUTH_TIMEOUT' if password is None else 'SSH_PASSWORD_AUTH_RESULT_UNKNOWN'
            elif message=='Authentication failed: transport shut down or saw EOF':
                code='SSH_AUTH_TRANSPORT_LOST' if password is None else 'SSH_PASSWORD_AUTH_RESULT_UNKNOWN'
            elif message=='Authentication failed.' and transport.is_active():
                code='SSH_AUTHENTICATION_REJECTED'
            else:
                code='SSH_AUTH_RESULT_UNKNOWN'
            raise _NativeObservationHold(reason_code=code) from None
        except _NativeObservationHold as error:
            if error.reason_code=='READONLY_DEADLINE_EXCEEDED':
                raise _NativeObservationHold(reason_code='SSH_AUTH_TIMEOUT' if password is None else
                                              'SSH_PASSWORD_AUTH_RESULT_UNKNOWN') from None
            raise
        except (OSError,EOFError):
            raise _NativeObservationHold(reason_code='SSH_AUTH_TRANSPORT_LOST') from None
        except sdk.SSHException:
            raise _NativeObservationHold(reason_code='SSH_AUTH_PROTOCOL_FAILED') from None
        leaf.verify(); _remaining(overall_deadline)
        if not transport.is_authenticated() or transport.get_username()!=leaf.user:
            raise _NativeObservationHold(reason_code="SSH_AUTHENTICATION_REJECTED")
        phase="DEVICE_IDENTITY_QUERY_FAILED"
        identity=None if _minimal else _read_channel(leaf,transport,_IDENTITY_COMMAND,overall_deadline)
        if not _minimal: _validate_identity(leaf,identity)
        operation_entered=True
        yield transport,overall_deadline,identity,authentication,server_fingerprint
    except BaseException as caught:
        original = caught
    finally:
        for owned in (transport, connection):
            if owned is None:
                continue
            try:
                owned.close()
            except BaseException as cleanup:
                if original is None:
                    original = (_NativeObservationHold(reason_code="SIGNED_SESSION_CLEANUP_FAILED")
                                if isinstance(cleanup, Exception) else cleanup)
                elif isinstance(original, Exception) and not isinstance(cleanup, Exception):
                    original = cleanup
        try:
            leaf.verify()
        except BaseException as cleanup:
            if original is None:
                original = (SharedUpgradeHold("original shared inputs changed during session cleanup")
                            if isinstance(cleanup, Exception) else cleanup)
            elif isinstance(original, Exception) and not isinstance(cleanup, Exception):
                original = cleanup
    if original is not None:
        if not isinstance(original, Exception):
            raise original
        if isinstance(original,SharedUpgradeHold) or (isinstance(original,OSError) and
                original.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS)):
            raise original
        if operation_entered:
            # Connection/identity already succeeded. Preserve the actual
            # business exception (especially SharedUpgradeHold), not the last
            # connection phase. The CLI emits only safe codes/source locations.
            raise original
        records = getattr(original, "records", ())
        capture_raw = getattr(original, "capture_raw", None)
        # Do not attach SDK/private-key exception chains to diagnostics.
        raise _NativeObservationHold(records, capture_raw=capture_raw,
                                     reason_code=getattr(original, "reason_code", phase))


@contextmanager
def _signed_session(leaf, *, password=None, _connection_deadline=None, _authentication=None, _initial_probe=False):
    """Key first for upgrades; password-only takeover only after explicit reject.

    Retry connection establishment only, never a yielded operation or installer.
    Trust/account/device mismatch never causes password fallback or a file write.
    """
    required = getattr(leaf.scope, '_access_required', False)
    if (required and getattr(leaf,"_cooperative_completion",False) and _connection_deadline is not None
            and _authentication is None and not _initial_probe):
        with _cooperative_signed_session(leaf,password,_connection_deadline) as session:
            yield session
        return
    if _authentication not in (None, 'key', 'password'):
        raise _NativeObservationHold()
    if not required or _authentication is not None:
        selected = None if _authentication == 'key' else password
        with _signed_session_single(leaf, password=selected, _connection_deadline=_connection_deadline) as session:
            yield session
        return
    if _initial_probe:
        # Version inspection must finish before any initial key import. This
        # password takeover is read-only; access preparation follows separately.
        with ExitStack() as initial:
            try:
                session = initial.enter_context(_signed_session_single(leaf))
            except _NativeObservationHold as error:
                if error.reason_code != 'SSH_AUTHENTICATION_REJECTED':
                    raise
                _progress(leaf, 'ACCESS', 'INITIAL_KEY_PASSWORD_FALLBACK')
                try:
                    session = initial.enter_context(_signed_session_single(leaf, password=password))
                except _NativeObservationHold as password_error:
                    if password_error.reason_code == 'SSH_AUTHENTICATION_REJECTED':
                        raise _NativeObservationHold(reason_code='PASSWORD_PREFLIGHT_REJECTED') from None
                    raise
            yield session
        return
    from ibsw_upgrade_access import restore_access, record_key_recheck
    def recheck(stack, recovery):
        # After an authorization write, reconnect ONLY; do not restart file
        # recovery or report its first transient disconnect as a final failure.
        try:
            while True:
                try:
                    return stack.enter_context(_signed_session_single(leaf, _connection_deadline=_connection_deadline))
                except _NativeObservationHold as error:
                    if error.reason_code not in {'SSH_CONNECT_FAILED','SSH_CONNECT_TIMEOUT','SSH_HANDSHAKE_FAILED','SSH_HANDSHAKE_TIMEOUT','SSH_AUTH_TRANSPORT_LOST','SSH_AUTH_TIMEOUT'}:
                        raise
                    _progress(leaf, 'ACCESS', 'WAIT_REBOOT')
                    time.sleep(min(3.0, _remaining(_connection_deadline)))
        except BaseException:
            if recovery is not None:
                record_key_recheck(leaf,recovery,verified=False)
            raise
    while True:
        stack = ExitStack()
        recovery = None
        try:
            try:
                session = stack.enter_context(_signed_session_single(leaf, _connection_deadline=_connection_deadline))
            except _NativeObservationHold as error:
                if error.reason_code != 'SSH_AUTHENTICATION_REJECTED' or _connection_deadline is None:
                    raise
                _progress(leaf, 'ACCESS', 'KEY_REJECTED_PASSWORD_FALLBACK')
                with _signed_session_single(leaf, password=password, _connection_deadline=_connection_deadline) as signed:
                    recovery = restore_access(leaf, signed[0], signed[1])
                _progress(leaf, 'ACCESS', 'KEY_LOGIN_RECHECK')
                session = recheck(stack,recovery)
                if recovery is not None:
                    record_key_recheck(leaf, recovery, verified=True)
                    _progress(leaf, 'ACCESS', 'KEY_LOGIN_VERIFIED')
            else:
                if _connection_deadline is not None:
                    # Preserve other original authorizations too, even when the
                    # management key itself survived this component's reboot.
                    recovery = restore_access(leaf, session[0], session[1])
                    if recovery is not None:
                        stack.close()
                        _progress(leaf, 'ACCESS', 'KEY_LOGIN_RECHECK')
                        session = recheck(stack,recovery)
                        record_key_recheck(leaf, recovery, verified=True)
                        _progress(leaf, 'ACCESS', 'KEY_LOGIN_VERIFIED')
            break
        except _NativeObservationHold as error:
            stack.close()
            if (_connection_deadline is None or error.reason_code not in
                    {'SSH_CONNECT_FAILED','SSH_CONNECT_TIMEOUT','SSH_HANDSHAKE_FAILED','SSH_HANDSHAKE_TIMEOUT','SSH_AUTH_TRANSPORT_LOST','SSH_AUTH_TIMEOUT'}):
                raise
            _progress(leaf, 'ACCESS', 'WAIT_REBOOT')
            time.sleep(min(3.0, _remaining(_connection_deadline)))
        except BaseException:
            stack.close()
            raise
    with stack:
        yield session


@contextmanager
def _cooperative_signed_session(leaf,password,deadline):
    """One connection/recovery turn. Never repeat an uncertain write."""
    from ibsw_upgrade_access import restore_access,record_key_recheck
    stack=ExitStack()
    recovery=getattr(leaf,"_pending_key_recovery",None)
    try:
        key_rejected=False
        try:
            session=stack.enter_context(_signed_session_single(leaf,_connection_deadline=deadline))
        except _NativeObservationHold as error:
            if error.reason_code!="SSH_AUTHENTICATION_REJECTED" or recovery is not None:
                raise
            key_rejected=True
        if key_rejected:
            _progress(leaf,"ACCESS","KEY_REJECTED_PASSWORD_FALLBACK")
            with _signed_session_single(leaf,password=password,_connection_deadline=deadline) as signed:
                recovery=restore_access(leaf,signed[0],signed[1])
            leaf._pending_key_recovery=recovery
            _progress(leaf,"ACCESS","KEY_LOGIN_RECHECK")
            session=stack.enter_context(_signed_session_single(leaf,_connection_deadline=deadline))
        else:
            if recovery is None:
                recovery=restore_access(leaf,session[0],session[1])
                if recovery is not None:
                    leaf._pending_key_recovery=recovery
                    stack.close()
                    _progress(leaf,"ACCESS","KEY_LOGIN_RECHECK")
                    session=stack.enter_context(_signed_session_single(leaf,_connection_deadline=deadline))
        if recovery is not None:
            record_key_recheck(leaf,recovery,verified=True)
            leaf._pending_key_recovery=None
            _progress(leaf,"ACCESS","KEY_LOGIN_VERIFIED")
    except _NativeObservationHold as error:
        stack.close()
        if error.reason_code in {"SSH_CONNECT_FAILED","SSH_CONNECT_TIMEOUT","SSH_HANDSHAKE_FAILED","SSH_HANDSHAKE_TIMEOUT","SSH_AUTH_TRANSPORT_LOST","SSH_AUTH_TIMEOUT"} and time.monotonic()<deadline:
            raise _CompletionDeferred() from None
        if recovery is not None:
            record_key_recheck(leaf,recovery,verified=False)
            leaf._pending_key_recovery=None
        raise
    except BaseException:
        stack.close()
        raise
    with stack:
        yield session


def _validate_identity(leaf, identity):
    stdout, stderr, status, complete = identity
    if not complete or status != 0 or stderr:
        raise _NativeObservationHold(reason_code="DEVICE_IDENTITY_QUERY_FAILED")
    lines = stdout.decode("ascii").splitlines()
    if (len(lines) != 2 or lines[0].casefold() != leaf.node.hostname.casefold()
            or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", lines[1])
            or lines[1].lower() != leaf.node.mac):
        raise _NativeObservationHold(reason_code="DEVICE_IDENTITY_MISMATCH")


def _preflight_component_on_session(leaf, component, transport, deadline, *, package_index):
    """Fresh observations on the fixed authenticated session, never a grant.

    A pending diff is an instant device fact, not proof of an exclusive
    maintenance window. The manual entry relies on the operator to exclude
    other writers and retains the backup before any write.
    """
    from ibsw_upgrade_executor import _raw_record
    _scope, _global, _plan, _declared, args, policy = _live_plan_inputs(leaf)
    if (component not in args.selected or component not in ("os", "bios", "cpld")
            or type(package_index) is not int or package_index < 0
            or (component != "os" and package_index != 0)):
        raise ValueError("original selected component and index required")
    observations = []
    def query(command):
        leaf.verify(); _remaining(deadline)
        raw = _read_channel(leaf, transport, command, deadline)
        leaf.verify(); _remaining(deadline)
        if (type(raw) is not tuple or len(raw) != 4 or type(raw[0]) is not bytes
                or type(raw[1]) is not bytes or raw[2] != 0 or raw[1]
                or raw[3] is not True):
            if command=='nv show system health':
                observations.append(_raw_record(command,raw))
                return raw
            code = {_IDENTITY_COMMAND: "DEVICE_IDENTITY_QUERY_FAILED",
                    "nv show system version": "OS_VERSION_QUERY_FAILED",
                    "nv config show -o commands": "CONFIG_BACKUP_QUERY_FAILED",
                    "nv config diff -o commands": "CONFIG_PENDING_QUERY_FAILED",
                    "nv show system health": "HEALTH_QUERY_FAILED"}[command]
            from ibsw_upgrade_contract import _ReadonlyQueryRecord
            record=_ReadonlyQueryRecord(tuple(shlex.split(command)),*raw[:3])
            diagnostic=dict(getattr(leaf,'_last_query_diagnostic',{}) or {})
            diagnostic['command']=command
            raise _NativeObservationHold((record,),reason_code=code,
                capture_raw={'safe_diagnostic':diagnostic,'query_record':_raw_record(command,raw)})
        observations.append(_raw_record(command, raw))
        return raw
    identity = query(_IDENTITY_COMMAND)
    _validate_identity(leaf, identity)
    os_raw = query("nv show system version")
    os_record = record_readonly_query(("nv", "show", "system", "version"), *os_raw[:3])
    parsed = parse_readonly_query_data(os_record)
    if parsed.state != "TEXT_DATA_PARSED":
        raise ValueError("unrecognized actual OS before component")
    os_version = dict(parsed.fields)["image_version_text"]
    if component in ("bios", "cpld") and _version(os_version) != _version(policy.final_os):
        raise _NativeObservationHold(reason_code="OS_FINAL_NOT_REACHED")
    if component == "os":
        select_os_path(policy, os_version)  # Reject versions outside the ordered chain.
        if package_index >= len(policy.os):
            raise ValueError("selected original OS index required")
    before = query("nv config show -o commands")[0]
    try:
        before.decode("utf-8")
    except UnicodeError:
        raise _NativeObservationHold(reason_code="CONFIG_BACKUP_NOT_TEXT") from None
    if not before.strip():
        raise _NativeObservationHold(reason_code="CONFIG_BACKUP_EMPTY")
    pending = query("nv config diff -o commands")[0]
    if pending.strip():
        raise _NativeObservationHold(reason_code="CONFIG_PENDING_NOT_EMPTY")
    health_raw = query("nv show system health")
    health_record = record_readonly_query(("nv", "show", "system", "health"), health_raw[0],health_raw[1],health_raw[2] if health_raw[3] else None)
    _note_health(leaf,health_record,'BEFORE_INSTALL',complete=health_raw[3],
                 component=component,stage=f'{component}-{package_index:04d}')
    leaf.verify(); _remaining(deadline)
    return {"os_version": os_version, "before_commands": before,
            "health_record": health_record, "pending_diff": pending,
            "query_records": tuple(observations),"health_override":bool(getattr(args,'force_health',False))}


def _assess_component_versions(policy, dispatch, os_record, firmware_record):
    """Actual version only; no configuration recovery until activation is proven."""
    os_data = parse_readonly_query_data(os_record)
    if os_record.argv != ("nv", "show", "system", "version") or os_data.state != "TEXT_DATA_PARSED":
        raise ValueError("complete actual OS result required")
    actual_os = dict(os_data.fields)["image_version_text"]
    if dispatch.component == "os":
        if _version(actual_os) != _version(dispatch.target_version):
            raise ValueError("actual OS does not match this ordered step")
    elif dispatch.component in ("bios", "cpld"):
        if _version(actual_os) != _version(policy.final_os):
            raise ValueError("actual final OS required before firmware completion")
        if (firmware_record is None or firmware_record.argv != ("nv", "show", "platform", "firmware")
                or firmware_record.returncode != 0 or firmware_record.stderr):
            raise ValueError("complete actual firmware query required")
        targets = ("BIOS",) if dispatch.component == "bios" else ("CPLD",)
        actual = dict(_documented_firmware_fields(_documented_table_lines(firmware_record.stdout), targets=targets))
        if dispatch.component == "bios":
            if actual["BIOS"] != dispatch.target_version:
                raise ValueError("actual BIOS does not match target")
        else:
            expected = {}
            for value in dispatch.target_version.split("+"):
                match = re.fullmatch(r"(CPLD[0-9]+)_(REV[0-9]+)", value)
                if match is None or match[1] in expected:
                    raise ValueError("unknown or duplicate CPLD target")
                expected[match[1]] = match[2]
            seen = set()
            for slot in actual:
                match = re.fullmatch(r"(CPLD[0-9]+)_(REV[0-9]+)", actual[slot])
                if match is None:
                    raise ValueError("unknown actual CPLD slot")
                if match[1] in expected:
                    if match[2] != expected[match[1]]:
                        raise ValueError("actual target CPLD revision differs")
                    seen.add(match[1])
            if seen != set(expected):
                raise ValueError("actual target CPLD observations incomplete")
    else:
        raise ValueError("fixed supported component required")
    return actual_os


def _require_upgrade_health(record, *, force=False, complete=True):
    """Health-only gate; force never changes the underlying observation."""
    parsed=parse_readonly_query_data(record)
    code=None
    if complete is not True or record.returncode!=0 or record.stderr:
        code='HEALTH_QUERY_FAILED'
    elif parsed.state!='TEXT_HEALTH_DATA_PARSED':
        code=('HEALTH_STATUS_UNAVAILABLE' if re.search(rb'(?m)^ *status +N/A *$',record.stdout)
              else 'HEALTH_PARSE_FAILED')
    else:
        fields=dict(parsed.fields)
        if fields['global_status']!='OK' or fields['status_led']!='green' or json.loads(fields['issues_json']):
            code='HEALTH_PRECHECK_NOT_OK'
    if code and not force:
        raise _NativeObservationHold((record,),reason_code=code)
    fields=dict(parsed.fields)
    return dict(state='FORCED' if code else 'PASS',reason_code=code,
        status=fields.get('global_status','UNAVAILABLE'),status_led=fields.get('status_led','UNAVAILABLE'),
        issue_count=len(json.loads(fields.get('issues_json','[]'))))


def _note_health(leaf,record,phase,*,complete=True,gate=True,component=None,stage=None):
    """Retain actual facts before applying an optional health-only write gate.

    Even a passing or non-gating/no-flash observation is reported. Force changes
    admission only, never observed_state, the command or its captured bytes.
    """
    from ibsw_upgrade_executor import _raw_record
    force=gate and bool(getattr(leaf.scope.parsed,'force_health',False))
    result=_require_upgrade_health(record,force=True,complete=complete)
    code=result['reason_code']
    observed=('PASS' if not code else 'FAIL' if code=='HEALTH_PRECHECK_NOT_OK' else 'UNAVAILABLE')
    result.update(hostname=leaf.node.hostname,phase=phase,component=component,stage=stage,
        observed_state=observed,state='FORCED' if code and force else observed,
        forced=bool(code and force),gate_applied=bool(gate),
        observation_id=os.urandom(16).hex(),
        raw_record=_raw_record('nv show system health',
            (record.stdout,record.stderr,record.returncode,complete)))
    if not hasattr(leaf.scope,'_health_checks'): leaf.scope._health_checks=[]
    leaf.scope._health_checks.append(result)
    if result['state']=='FORCED':
        if not hasattr(leaf.scope,'_health_overrides'): leaf.scope._health_overrides=[]
        leaf.scope._health_overrides.append(result)
        _progress(leaf,'ACCESS','HEALTH_OVERRIDE_USED')
    if code and gate and not force:
        raise _NativeObservationHold((record,),reason_code=code)
    return result


def _assess_component_health(baseline_health, health_record, *, force=False):
    health_values = []
    for record in (baseline_health, health_record):
        parsed = parse_readonly_query_data(record)
        if record.argv != ("nv", "show", "system", "health") or parsed.state != "TEXT_HEALTH_DATA_PARSED":
            _require_upgrade_health(record,force=force)
            if force: return
            raise _NativeObservationHold(reason_code='HEALTH_PARSE_FAILED')
        health_values.append(dict(parsed.fields))
    old, new = health_values
    old_issues = {tuple(item) for item in json.loads(old["issues_json"])}
    new_issues = {tuple(item) for item in json.loads(new["issues_json"])}
    if (not new_issues.issubset(old_issues)
            or (new["status_led"] != "green" and new["status_led"] != old["status_led"])):
        if not force: raise _NativeObservationHold(reason_code='HEALTH_DEGRADED')


def _assess_component_postconditions(policy, dispatch, before, after, baseline_health,
                                    os_record, firmware_record, health_record, *, force_health=False):
    """Conservative comparison only; this pure result is not native authority."""
    from ibsw_upgrade_contract import compare_commands
    actual_os = _assess_component_versions(policy, dispatch, os_record, firmware_record)
    if (type(before) is not bytes or type(after) is not bytes or not before.strip() or not after.strip()
            or compare_commands(before.decode("utf-8"), after.decode("utf-8")).state != "PASS"):
        raise ValueError("configuration incomplete, changed, masked or requires missing-only recovery")
    _assess_component_health(baseline_health, health_record,force=force_health)
    return actual_os


def _original_component_baseline(leaf, dispatch):
    """Read only original held preflight/backup bound to this selected step."""
    from ibsw_upgrade_contract import ComponentDispatchResult, SharedUpgradeHold
    from ibsw_upgrade_driver import _before_commands_binding, _json_bytes
    try:
        if type(dispatch) is not ComponentDispatchResult or dispatch.hostname != leaf.node.hostname:
            raise ValueError("original fixed dispatch required")
        scope, _global, _plan, _declared, args, policy = _live_plan_inputs(leaf)
        if dispatch.component not in args.selected:
            raise ValueError("unselected completion")
        target = (policy.os[dispatch.package_index].version if dispatch.component == "os"
                  else policy.bios.version if dispatch.component == "bios"
                  else "+".join(identifier + "_" + revision for identifier, revision in policy.cpld_targets))
        if target != dispatch.target_version:
            raise ValueError("original policy target differs")
        with scope._request_namespace_lease():
            directory = scope.session._directory(scope.run_directory / dispatch.hostname / dispatch.stage)
            scope._private_directory(directory)
            step = scope._hold(directory, "step-binding.json")
            binding = json.loads(step.payload)
            # Every held file is verified against the original open scope, not
            # a caller JSON/boolean or cold status-file permission.
            before = scope._hold(directory, "before.commands").payload
            before_binding = _json_bytes(_before_commands_binding(binding, before))
            scope._hold(directory, "before-binding.json", before_binding)
            original = json.loads(scope._hold(directory, "component-preflight.json").payload)
            if (original["schema_version"] != 2 or original["state"] != "COMPONENT_PREFLIGHT_DATA_ONLY"
                    or original["component"] != dispatch.component
                    or original["package_index"] != dispatch.package_index
                    or original["binding"] != binding
                    or original["before_sha256"] != hashlib.sha256(before).hexdigest()
                    or original["before_binding_sha256"] != hashlib.sha256(before_binding).hexdigest()
                    or base64.b64decode(original["pending_diff_base64"], validate=True).strip()):
                raise ValueError("original component preflight differs")
            health = original["health_record"]
            forced=bool(getattr(args,'force_health',False))
            if bool(original.get('health_override',False))!=forced:
                raise ValueError('health override differs from the original plan')
            if (health["command"] != "nv show system health" or (not forced and
                    (health["stream_complete"] is not True or health["returncode"] != 0))):
                raise ValueError("original actual baseline health incomplete")
            baseline = record_readonly_query(("nv", "show", "system", "health"),
                base64.b64decode(health["stdout_base64"], validate=True),
                base64.b64decode(health["stderr_base64"], validate=True),health["returncode"])
            if not forced and parse_readonly_query_data(baseline).state != "TEXT_HEALTH_DATA_PARSED":
                raise ValueError("unknown original health baseline")
            leaf.verify()
        return scope, policy, before, baseline
    except Exception as error:
        raise SharedUpgradeHold("original completion baseline cannot be verified") from error


def _repair_missing_component_on_session(leaf, dispatch, transport, deadline, before, after, records):
    """Apply only original pure missing NVUE text, never execute it as shell.

    This runs inside the fixed completion's authenticated session. A durable
    REQUESTED repair plan precedes remote transfer or configuration writes.
    Neither a saved repair result nor this helper grants overall completion.
    """
    from ibsw_upgrade_contract import compare_commands, SharedUpgradeHold
    from ibsw_upgrade_executor import _raw_record
    if type(before) is not bytes or type(after) is not bytes:
        raise ValueError("original configuration bytes required")
    difference = compare_commands(before.decode("utf-8"), after.decode("utf-8"))
    if difference.state == "PASS":
        return after
    if difference.state != "REPAIR_REQUIRED" or dispatch.state != "DISPATCHED_UNKNOWN":
        raise _NativeObservationHold(reason_code="CONFIG_COMPARISON_REVIEW_REQUIRED")
    from ibsw_upgrade_executor import _upload_component_missing_once
    scope, _global, _plan, declared, _args, _policy = _live_plan_inputs(leaf)
    if not scope.manual_execution and "--exclusive-config-window" not in declared["argv"]:
        raise SharedUpgradeHold("actual exclusive configuration window declaration required")
    missing = ("\n".join(difference.missing) + "\n").encode("utf-8")
    started, repaired, repair_records = False, b"", []
    def query(command):
        leaf.verify(); _remaining(deadline)
        raw = _read_channel(leaf, transport, command, deadline)
        row = _raw_record(command, raw)
        records.append(row); repair_records.append(row)
        leaf.verify(); _remaining(deadline)
        if raw[2] != 0 or raw[1] or raw[3] is not True:
            raise ValueError("configuration repair query/write incomplete; never resend automatically")
        return raw
    try:
        _validate_identity(leaf, query(_IDENTITY_COMMAND))
        if query("nv config show -o commands")[0] != after:
            raise ValueError("actual after.commands changed before repair; do not apply stale missing text")
        if query("nv config diff -o commands")[0].strip():
            raise ValueError("foreign pending before repair; no patch")
        original = scope._prepare_component_repair_data(leaf, dispatch, after, missing, tuple(repair_records))
        started = True
        remote, transfer_records = _upload_component_missing_once(leaf, dispatch, original, transport, deadline)
        records.extend(transfer_records)
        repair_records.extend(transfer_records)
        original.verify(); leaf.verify(); _remaining(deadline)
        if query("nv config diff -o commands")[0].strip():
            raise ValueError("foreign pending after repair transfer; no patch")
        query("nv config patch " + shlex.quote(remote))
        pending = query("nv config diff -o commands")[0]
        actual_patch = compare_commands(missing.decode("utf-8"), pending.decode("utf-8"))
        if actual_patch.state != "PASS" or actual_patch.added:
            raise ValueError("pending diff differs from original pure missing patch; do not apply")
        _validate_identity(leaf, query(_IDENTITY_COMMAND))
        original.verify(); leaf.verify()
        query("nv config apply -y")
        query("nv config save")
        repaired = query("nv config show -o commands")[0]
        if (query("nv config diff -o commands")[0].strip()
                or compare_commands(before.decode("utf-8"), repaired.decode("utf-8")).state != "PASS"):
            raise ValueError("configuration repair did not restore original applied baseline")
        _validate_identity(leaf, query(_IDENTITY_COMMAND))
        scope._record_component_repair_result(leaf, dispatch, repaired=repaired,
                                            records=tuple(repair_records), state="REPAIRED")
        leaf.verify(); _remaining(deadline)
        return repaired
    except BaseException as original_error:
        captured = getattr(original_error,"capture_raw",None)
        if type(captured) is dict and type(captured.get("component_missing_upload")) is str:
            if os.path.basename(captured["component_missing_upload"]) == "missing.commands":
                diagnostics = []
                uid = captured.get("uid_record")
                if (type(uid) is dict and set(uid) == {"command","stdout_base64","stderr_base64","returncode","stream_complete"}
                        and uid["command"] == "id -u" and uid["returncode"] == 0
                        and uid["stream_complete"] is True and uid["stderr_base64"] == ""):
                    # This is the original completed UID read, not invented
                    # status for a failed SFTP operation.
                    diagnostics.append(dict(uid))
                readback = captured.get("readback")
                if type(readback) is bytes and len(readback) <= _MAX_QUERY_BYTES:
                    diagnostics.append(_raw_record("SFTP_PARTIAL missing.commands readback",(readback,b"",None,False)))
                partial = captured.get("partial_readback")
                if type(partial) is dict and type(partial.get("stable_reads")) is tuple:
                    for index,payload in enumerate(partial["stable_reads"][:2]):
                        if type(payload) is bytes and len(payload) <= _MAX_QUERY_BYTES:
                            diagnostics.append(_raw_record("SFTP_PARTIAL missing.commands read-"+str(index+1),
                                                           (payload,b"",None,False)))
                cleanup_types = captured.get("cleanup_error_types")
                if (type(cleanup_types) is tuple and len(cleanup_types) <= 8
                        and all(type(item) is str and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}",item)
                                for item in cleanup_types)):
                    diagnostics.append(_raw_record("SFTP_CLEANUP_DIAGNOSTIC missing.commands",
                        (json.dumps(cleanup_types,ensure_ascii=True).encode("ascii"),b"",None,False)))
                records.extend(diagnostics); repair_records.extend(diagnostics)
        if started:
            try:
                scope._record_component_repair_result(leaf, dispatch, repaired=repaired,
                                                    records=tuple(repair_records), state="UNKNOWN")
            except BaseException as record_error:
                if not isinstance(original_error, Exception):
                    raise original_error
                if not isinstance(record_error, Exception):
                    raise
                raise SharedUpgradeHold("repair record uncertain; whole batch HOLD") from record_error
        raise


def _validate_component_execution_log(leaf, scope, dispatch, stdout, stderr):
    """Check original fixed script framing, not a universal vendor grammar.

    Owned child rc0 without its bound header and complete footer is not a
    completion. Known documented error outputs also prevent verification.
    Native version/config/health checks remain separately mandatory.
    """
    if (type(stdout) is not bytes or type(stderr) is not bytes
            or not stdout or len(stdout) + len(stderr) > 2 * _MAX_QUERY_BYTES):
        raise ValueError("original complete component log required")
    binding = (scope.run_id, leaf.node.hostname, leaf.node.address, leaf.node.mac,
               dispatch.component, dispatch.target_version)
    header = json.dumps(binding,ensure_ascii=True,separators=(",",":")).encode("ascii") + b"\n"
    footer = (b"IBSW_EXECUTION_RC=0 IBSW_ACTIVATION_STATE=UNKNOWN\nIBSW_EXPECTED_EFFECT="
              + dispatch.expected_effect.encode("ascii") + b"\n")
    if not stdout.startswith(header) or not stdout.endswith(footer):
        raise ValueError("component log binding/footer incomplete")
    pattern = rb"(?im)^[ \t]*(?:ERROR:|Action failed\b|Failed to (?:install|enable|disable|update)\b|Invalid file:|WARNING: Interrupted\b)"
    if re.search(pattern,stdout) or re.search(pattern,stderr):
        raise ValueError("documented installer error in original component log")


def _record_component_probe_failure(leaf,dispatch,error):
    """Native negative diagnostic bound to this original live request only."""
    from ibsw_upgrade_contract import ComponentCompletionResult
    from ibsw_upgrade_executor import _raw_record
    from ibsw_upgrade_schedule import _native_failure_reason
    scope,_policy,_before,_health=_original_component_baseline(leaf,dispatch)
    safe=error.capture_raw.get("safe_diagnostic",{})
    rows=list(dispatch.raw_records)
    query=error.capture_raw.get('query_record')
    if type(query) is dict:
        from ibsw_upgrade_driver import _component_raw_records
        rows.extend(_component_raw_records([query]))
    if type(safe) is dict:
        rows.append(_raw_record("COMPONENT_SAFE_DIAGNOSTIC",(json.dumps(safe,sort_keys=True).encode(),b"",None,False)))
    files=error.capture_raw.get('component_owned_files',{})
    if type(files) is dict:
        for name in ('owned-exit.record','execution.stdout','execution.stderr'):
            value=files.get(name)
            if type(value) is bytes and len(value)<=_MAX_QUERY_BYTES:
                rows.append(_raw_record('SFTP_DIAGNOSTIC '+name,(value,b'',None,False)))
    before_install=(type(safe) is dict and error.reason_code in ('DOWNLOAD_FAILED_BEFORE_INSTALL','DOWNLOAD_RECORD_FAILED_BEFORE_INSTALL')
        and safe.get('installation_started') is False and safe.get('original_boot_unchanged') is True)
    completion=ComponentCompletionResult(dispatch.component,dispatch.hostname,dispatch.package_index,
        dispatch.target_version,"FAIL" if before_install else "UNKNOWN",tuple(rows),
        (dispatch.hostname+"/"+dispatch.stage+"/component-completion.json",),
        reason="original installer evidence probe failed: "+_native_failure_reason(error))
    scope._record_component_completion_data(leaf,dispatch,completion)
    return completion


def _observe_component_completion_once(leaf, dispatch, *, password=None, _deadline=None, _skip_exit_wait=False):
    """One fixed fresh authenticated readback; never redispatch an installer.

    The manual two-pool path uses independently verified post-reboot state,
    not remote installer files. Legacy callers retain their original exit
    collection contract. Neither path can resend an installation here.
    """
    from ibsw_upgrade_contract import ComponentCompletionResult, SharedUpgradeHold
    from ibsw_upgrade_executor import _raw_record, _collect_component_exit_and_logs
    scope, policy, before, baseline = _original_component_baseline(leaf, dispatch)
    live_reboot = bool(scope.manual_execution and getattr(leaf, '_cooperative_completion', False))
    records = list(dispatch.raw_records)+list(getattr(leaf,"_post_boot_records",[]))
    state, reason, actual_os = "UNKNOWN", "actual completion could not be established", None
    interrupt = None
    try:
        completion_deadline = time.monotonic() + _COMPLETION_SECONDS if _deadline is None else _deadline
        if dispatch.state == "DISPATCHED_UNKNOWN" and not live_reboot and not _skip_exit_wait:
            from ibsw_upgrade_executor import _await_component_exit
            try:
                _await_component_exit(leaf, dispatch, password=password, deadline=completion_deadline)
            except _NativeObservationHold:
                if time.monotonic() >= completion_deadline:
                    raise _NativeObservationHold(reason_code="COMPONENT_EXIT_NOT_OBSERVED") from None
                raise
        with _signed_session(leaf, password=password,
                             _connection_deadline=completion_deadline) as (transport, deadline, _identity, _auth, _pin):
            def query(command):
                leaf.verify(); _remaining(deadline)
                raw = _read_channel(leaf, transport, command, deadline)
                records.append(_raw_record(command, raw))
                leaf.verify(); _remaining(deadline)
                if raw[2] != 0 or raw[1] or raw[3] is not True:
                    if command=='nv show system health':
                        return raw
                    code={_IDENTITY_COMMAND:'DEVICE_IDENTITY_QUERY_FAILED',
                        'cat /proc/sys/kernel/random/boot_id':'BOOT_ID_QUERY_FAILED',
                        'nv show system version':'OS_VERSION_QUERY_FAILED',
                        'nv show platform firmware':'FIRMWARE_QUERY_FAILED',
                        'nv config show -o commands':'CONFIG_BACKUP_QUERY_FAILED',
                        'nv config diff -o commands':'CONFIG_PENDING_QUERY_FAILED',
                        'nv show system health':'HEALTH_QUERY_FAILED'}.get(command,'READONLY_QUERY_FAILED')
                    if command.startswith('nv ') and _is_nvos_initializing(raw):
                        code='NVOS_CLI_INITIALIZING'
                    raise _NativeObservationHold(reason_code=code)
                return raw
            _validate_identity(leaf, query(_IDENTITY_COMMAND))
            original_exit = None if live_reboot and dispatch.state == "DISPATCHED_UNKNOWN" else 0
            if live_reboot and dispatch.state == 'DISPATCHED_UNKNOWN':
                from ibsw_upgrade_pipeline import _BOOT_COMMAND
                _validate_stable_post_boot(leaf, dispatch, query(_BOOT_COMMAND))
            if dispatch.state == "DISPATCHED_UNKNOWN" and not live_reboot:
                logs = _collect_component_exit_and_logs(leaf, dispatch, transport, deadline)
                records.extend(logs["raw_records"])
                original_exit = logs["exit_code"]
                if original_exit == 0:
                    _validate_component_execution_log(leaf, scope, dispatch, logs["stdout"], logs["stderr"])
            os_raw = query("nv show system version")
            os_record = record_readonly_query(("nv","show","system","version"),*os_raw[:3])
            firmware = None
            if dispatch.component != "os":
                fw_raw = query("nv show platform firmware")
                firmware = record_readonly_query(("nv","show","platform","firmware"),*fw_raw[:3])
            after = query("nv config show -o commands")[0]
            _progress(leaf, dispatch.component, 'POSTCHECK_CONFIGURATION')
            # The helper is a no-op for unchanged configuration. It refuses
            # unsafe missing values/scalar conflicts rather than a full replace.
            if live_reboot or original_exit == 0:
                try:
                    _assess_component_versions(policy, dispatch, os_record, firmware)
                except ValueError:
                    raise _NativeObservationHold(reason_code="COMPONENT_VERSION_NOT_VERIFIED") from None
                if query("nv config diff -o commands")[0].strip():
                    raise _NativeObservationHold(reason_code="CONFIG_PENDING_NOT_EMPTY")
                pre_repair_health = query("nv show system health")
                pre_health_record=record_readonly_query(("nv","show","system","health"),pre_repair_health[0],pre_repair_health[1],pre_repair_health[2] if pre_repair_health[3] else None)
                _progress(leaf,dispatch.component,'POSTCHECK_HEALTH')
                _note_health(leaf,pre_health_record,'POST_INSTALL',complete=pre_repair_health[3],
                             component=dispatch.component,stage=dispatch.stage)
                _assess_component_health(baseline,pre_health_record,force=getattr(scope.parsed,'force_health',False))
                after = _repair_missing_component_on_session(leaf, dispatch, transport, deadline,
                                                            before, after, records)
            pending = query("nv config diff -o commands")[0]
            if pending.strip():
                raise ValueError("foreign pending configuration after component")
            health_raw = query("nv show system health")
            health = record_readonly_query(("nv","show","system","health"),health_raw[0],health_raw[1],health_raw[2] if health_raw[3] else None)
            _note_health(leaf,health,'FINAL_HEALTH',complete=health_raw[3],
                         component=dispatch.component,stage=dispatch.stage)
            if original_exit is not None and original_exit != 0:
                state, reason = "FAIL", "original component installer returned exit=" + str(original_exit)
            else:
                actual_os = _assess_component_postconditions(policy, dispatch, before, after, baseline,
                    os_record, firmware, health,force_health=getattr(scope.parsed,'force_health',False))
                state, reason = "VERIFIED", None
                if (dispatch.component == "os" and dispatch.target_version == policy.final_os
                        and policy.ssd_version is not None):
                    # Only the final OS verifier samples SSD; it never changes
                    # the native OS outcome, repairs SSD or dispatches a package.
                    # Shared ownership/input failures and cancellation still
                    # propagate. Ordinary query failure remains private DATA.
                    _progress(leaf, dispatch.component, 'POSTCHECK_SSD')
                    leaf.verify(); _remaining(deadline)
                    try:
                        ssd_raw = _read_channel(leaf, transport, "nv show platform firmware",
                                               min(deadline, time.monotonic() + 10.0))
                    except (_NativeObservationHold, OSError, EOFError) as error:
                        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
                        ssd_raw = (b"", b"", None, False)
                    records.append(_raw_record("nv show platform firmware", ssd_raw))
                    leaf.verify(); _remaining(deadline)
            leaf.verify(); _remaining(deadline)
        leaf.verify()  # signed connection and every owned channel have closed.
        if state=='VERIFIED' and getattr(scope,'_access_required',False):
            # NVUE missing-only repair may itself regenerate user files. Check
            # access again AFTER patch/apply/save/readback, on a fresh session.
            _progress(leaf,dispatch.component,'FINAL_KEY_ACCESS_CHECK')
            with _signed_session(leaf,password=password,_connection_deadline=completion_deadline) as final_session:
                if live_reboot and dispatch.state == 'DISPATCHED_UNKNOWN':
                    from ibsw_upgrade_pipeline import _BOOT_COMMAND
                    raw = _read_channel(leaf, final_session[0], _BOOT_COMMAND, completion_deadline)
                    records.append(_raw_record(_BOOT_COMMAND, raw))
                    _validate_stable_post_boot(leaf, dispatch, raw)
            leaf.verify()
    except _CompletionDeferred:
        raise
    except _CompletionBootChanged:
        raise
    except SharedUpgradeHold:
        raise
    except BaseException as error:
        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
        if not isinstance(error, Exception):
            interrupt = error
        captured = getattr(error, "capture_raw", None)
        if type(captured) is dict:
            safe=captured.get("safe_diagnostic")
            if type(safe) is dict:
                records.append(_raw_record("COMPONENT_SAFE_DIAGNOSTIC",
                    (json.dumps(safe,sort_keys=True).encode(),b"",None,False)))
            # Fixed collector diagnostic bytes are incomplete observations,
            # never child-exit/EOF facts. Keep binary originals on failure.
            files = captured.get("component_owned_files")
            if type(files) is dict:
                for name in ("owned-exit.record", "execution.stdout", "execution.stderr"):
                    payload = files.get(name)
                    if type(payload) is bytes and len(payload) <= _MAX_QUERY_BYTES:
                        records.append(_raw_record("SFTP_PARTIAL " + name,(payload,b"",None,False)))
            partial = captured.get("partial_file")
            if type(partial) is dict:
                path = partial.get("component_file", "")
                name = os.path.basename(path) if type(path) is str else ""
                reads = partial.get("stable_reads")
                if name in ("owned-exit.record", "execution.stdout", "execution.stderr") and type(reads) is tuple:
                    for index, payload in enumerate(reads[:2]):
                        if type(payload) is bytes and len(payload) <= _MAX_QUERY_BYTES:
                            records.append(_raw_record("SFTP_PARTIAL " + name + " read-" + str(index + 1),
                                                       (payload,b"",None,False)))
        from ibsw_upgrade_schedule import _native_failure_reason
        state, reason, actual_os = "UNKNOWN", "post-upgrade verification incomplete: " + _native_failure_reason(error), None
    completion_path = dispatch.hostname + "/" + dispatch.stage + "/component-completion.json"
    evidence = (completion_path,)
    completion = ComponentCompletionResult(dispatch.component, dispatch.hostname, dispatch.package_index,
        dispatch.target_version, state, tuple(records), evidence, observed_os_version=actual_os, reason=reason)
    try:
        scope._record_component_completion_data(leaf, dispatch, completion)
        leaf.verify()
    except BaseException as error:
        if interrupt is not None:
            raise interrupt
        if not isinstance(error, Exception):
            raise
        raise SharedUpgradeHold("completion record uncertain; whole batch HOLD") from error
    if interrupt is not None:
        raise interrupt
    if completion.state == 'VERIFIED':
        _progress(leaf, dispatch.component, 'POSTCHECK_VERIFIED')
    return completion


def _validate_stable_post_boot(leaf, dispatch, raw):
    """Fresh kernel epoch must match the live service gate, not a fixed timer."""
    from ibsw_upgrade_pipeline import _BOOT_COMMAND, _BOOT_RE
    before = [r for r in dispatch.raw_records if r['command'] == _BOOT_COMMAND]
    if (not before or raw[1] or raw[2] != 0 or raw[3] is not True
            or any(r['returncode'] != 0 or r['stderr_base64'] or r['stream_complete'] is not True for r in before)):
        raise _NativeObservationHold(reason_code='BOOT_ID_QUERY_FAILED')
    initial = base64.b64decode(before[-1]['stdout_base64'], validate=True).decode('ascii').strip()
    current = raw[0].decode('ascii').strip()
    if not _BOOT_RE.fullmatch(current) or not _BOOT_RE.fullmatch(initial) or current == initial:
        raise _NativeObservationHold(reason_code='BOOT_ID_QUERY_FAILED')
    if current != getattr(leaf, '_verification_boot_epoch', None):
        raise _CompletionBootChanged(current)
    if current != getattr(leaf, '_verification_nvued_epoch', None):
        raise _NativeObservationHold(reason_code='BOOT_ID_QUERY_FAILED')


def _observe_live_inputs_once(leaf, *, password=None, initial_plan=False, commands_capture=None, pending_diff=None):
    from ibsw_upgrade_driver import _ReadonlyQueryInputs
    if type(leaf) is not _ReadonlyQueryInputs or not leaf._native_observation_consumed:
        raise _NativeObservationHold()
    leaf.verify()
    if pending_diff is not None:
        if type(pending_diff) is not tuple or len(pending_diff) != 2 or initial_plan or commands_capture is not None:
            raise _NativeObservationHold()
        leaf._original_selection[0]._commands_capture_stage(leaf, "pending-diff", *pending_diff)
    if commands_capture is not None:
        if type(commands_capture) is not tuple or len(commands_capture) != 3 or initial_plan:
            raise _NativeObservationHold()
        leaf._original_selection[0]._commands_capture_stage(leaf, *commands_capture)
    records, capture_raw, result = [], None, None
    try:
        with _signed_session(leaf, password=password, _initial_probe=initial_plan) as (transport, deadline, identity, authentication, server_fingerprint):
            if pending_diff is not None or commands_capture is not None:
                argv = (("nv", "config", "diff", "-o", "commands") if pending_diff is not None
                        else ("nv", "config", "show", "-o", "commands"))
                stdout, stderr, status, complete = _read_channel(leaf, transport, " ".join(argv), deadline)
                capture_raw = (argv, stdout, stderr, status)
                if not complete or status != 0 or stderr or (pending_diff is None and not stdout):
                    raise _NativeObservationHold(capture_raw=capture_raw)
                scope = leaf._original_selection[0]
                result = (scope._write_pending_diff_data(leaf, *pending_diff, stdout, stderr, status)
                          if pending_diff is not None else
                          scope._write_commands_phase_data(leaf, *commands_capture, stdout, stderr, status))
            else:
                selected = leaf.scope.parsed.selected
                queries = (_QUERY_ARGV[:1] if initial_plan and not (set(selected) & {"bios", "cpld"})
                           else _QUERY_ARGV)
                for argv in queries:
                    stdout, stderr, status, complete = _read_channel(leaf, transport, " ".join(argv), deadline)
                    records.append(record_readonly_query(argv, stdout, stderr, status if complete else None))
                    if not complete or status != 0 or stderr:
                        if initial_plan and argv == _QUERY_ARGV[1]:
                            # Retain the failed firmware fact for that component;
                            # it cannot cancel an independently eligible OS step.
                            continue
                        diagnostic=getattr(leaf,'_last_query_diagnostic',{})
                        if diagnostic.get('command')!=' '.join(argv):
                            diagnostic=dict(command=' '.join(argv),stdout_bytes=len(stdout),stderr_bytes=len(stderr),
                                returncode=status,stream_complete=complete)
                        code=(diagnostic.get('reason_code') if not complete else None)
                        if initial_plan and _is_nvos_initializing((stdout,stderr,status,complete)):
                            code='NVOS_CLI_INITIALIZING'
                        elif code not in ('READONLY_QUERY_TIMEOUT','READONLY_QUERY_INCOMPLETE'):
                            code='OS_VERSION_QUERY_FAILED' if argv==_QUERY_ARGV[0] else 'FIRMWARE_QUERY_FAILED'
                        raise _NativeObservationHold(records,reason_code=code,capture_raw={'safe_diagnostic':diagnostic})
                if initial_plan and len(records)==1 and leaf.scope.policy.ssd_version is not None:
                    os_data=parse_readonly_query_data(records[0])
                    if (os_data.state=='TEXT_DATA_PARSED' and
                            dict(os_data.fields)['image_version_text']==leaf.scope.policy.final_os):
                        try:
                            fw=_read_channel(leaf,transport,'nv show platform firmware',
                                min(deadline,time.monotonic()+10.0))
                        except (_NativeObservationHold,OSError,EOFError) as error:
                            if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS): raise
                            fw=(b'',b'',None,False)
                        records.append(record_readonly_query(_QUERY_ARGV[1],fw[0],fw[1],fw[2] if fw[3] else None))
                leaf.verify()
                if initial_plan:
                    leaf._initial_os_record=records[0]  # This native collector only; not a caller result DTO.
                    data_plan = _initial_data_plan(leaf, tuple(records))
                    data_plan["state"] = "INITIAL_NATIVE_DATA_PLAN" if data_plan["state"] == "INITIAL_DATA_PLAN" else "HOLD"
                    if data_plan['state']=='INITIAL_NATIVE_DATA_PLAN' and data_plan.get('ssd_check'):
                        check=data_plan['ssd_check']
                        evidence=leaf.scope._record_startup_ssd(leaf.node.hostname,tuple(records),check)
                        check['evidence_file']=evidence
                        leaf.scope._startup_ssd_check=dict(check)
                    parsed = ()
                    if data_plan['state']=='INITIAL_NATIVE_DATA_PLAN':
                        health_raw=_read_channel(leaf,transport,'nv show system health',deadline)
                        health=record_readonly_query(('nv','show','system','health'),health_raw[0],health_raw[1],health_raw[2] if health_raw[3] else None)
                        gate=bool(getattr(leaf.scope,'_access_required',False) and any(
                            row['action']=='UPGRADE_REQUIRED' for row in data_plan.get('version_rows',[])))
                        try: _note_health(leaf,health,'STARTUP',complete=health_raw[3],gate=gate)
                        except _NativeObservationHold as error:
                            raise _NativeObservationHold(tuple(records)+(health,),reason_code=error.reason_code) from None
                else:
                    parsed = tuple(parse_readonly_query_data(record) for record in records)
                    if any(value.state != "TEXT_DATA_PARSED" for value in parsed):
                        raise _NativeObservationHold(records)
                result = {"state": "READONLY_NATIVE_DATA", "execution_state": "NOT_EXECUTED",
                    "activation_state": "UNKNOWN", "node": asdict(leaf.node),
                    "server_host_key_fingerprint": server_fingerprint, "authentication": authentication,
                    "identity_raw": identity[:3], "records": tuple(records), "parsed": parsed}
                if initial_plan:
                    result["initial_plan"] = data_plan
            leaf.verify()
    except SharedUpgradeHold:
        raise
    except Exception as error:
        # Raw diagnostics, not transport/parser completion authority.
        if isinstance(error,OSError) and error.errno in (errno.EMFILE,errno.ENFILE,errno.ENOMEM,errno.ENOBUFS):
            raise
        raise _NativeObservationHold(getattr(error,'records',None) or records,
            capture_raw=getattr(error,'capture_raw',None) or capture_raw,
            reason_code=getattr(error, "reason_code", "READONLY_QUERY_FAILED")) from None
    return result


def _capture_live_health_queries_once(leaf, *, password=None):
    """One explicit fixed triple -> original schema2 DATA while still live.

    Does not parse health or version facts, use caller records, admit a device,
    reset pending or certify activation. Incomplete capture retains diagnostic
    bytes/status/actual EOF result, never a fabricated full round. Default
    readonly and initial-plan factories above remain the original two queries.
    """
    from ibsw_upgrade_driver import _ReadonlyQueryInputs
    if type(leaf) is not _ReadonlyQueryInputs or not leaf._native_observation_consumed:
        raise _NativeObservationHold()
    leaf.verify()
    records, wire, result = [], [], None
    try:
        with _signed_session(leaf, password=password) as (transport, deadline, identity, authentication, server_fingerprint):
            for argv in _QUERY_ARGV + (("nv", "show", "system", "health"),):
                stdout, stderr, status, complete = _read_channel(leaf, transport, " ".join(argv), deadline)
                records.append(record_readonly_query(argv, stdout, stderr, status))
                wire.append((argv, stdout, stderr, status, complete))
                if not complete or status != 0 or stderr:
                    raise _NativeObservationHold(records, capture_raw=tuple(wire))
            leaf.verify()
            scope = leaf._original_selection[0]
            evidence = scope.prepare_readonly_health_query_data(leaf.node.hostname, tuple(records))
            leaf.verify()
            result = {"state": "READONLY_HEALTH_RAW_DATA", "execution_state": "NOT_EXECUTED",
                "attestation_state": "DATA_ONLY_UNATTESTED", "activation_state": "UNKNOWN",
                "node": asdict(leaf.node), "server_host_key_fingerprint": server_fingerprint,
                "authentication": authentication, "identity_raw": identity[:3],
                "records": tuple(records), "stream_complete": tuple(item[4] for item in wire),
                "evidence": evidence}
        leaf.verify()
    except Exception:
        # Preserve actual partial bytes/EOF/status, not SDK exception secrets.
        raise _NativeObservationHold(records, capture_raw=tuple(wire)) from None
    return result
