"""Explicit fresh-only enrollment orchestration, never an automatic worker path.

An interrupted attempt is retained, never repaired, adopted or retried here.
Local nonce durability and remote observations do not enable automatic sending.
"""
from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import time

from monitor.issue_tracker_attempt_supervision import supervise_owned_attempt, AttemptHold


class EnrollmentInitializeHold(ValueError):
    def __init__(self):
        super().__init__('req7_explicit_enrollment_denied')


def _initializer_close_original(fd, identity):
    """Close only our captured inode, and never hide an uncertain close."""
    current = os.fstat(fd)
    if identity is None or (current.st_dev, current.st_ino) != identity[:2]:
        raise EnrollmentInitializeHold()
    os.close(fd)


def _close_initialization_images(graph, parent, parent_identity, primary):
    # Preserve the first body interrupt (including its existing cause), else
    # the first cleanup interrupt. A failed slot cannot skip the remaining
    # independently captured originals. No numeric FD adoption or rescue.
    slots = [(row[2], row[3]) for row in reversed(graph.files)]
    slots += [(row[2], row[3]) for row in reversed(graph.directories)]
    if parent is not None:
        slots.append((parent, parent_identity))
    for fd, identity in slots:
        try:
            _initializer_close_original(fd, identity)
        except BaseException as error:
            if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                primary = error
    return primary


def _fresh_namespace(owner, binding):
    from monitor import issue_tracker_spreadsheet_owner as ownership
    actual = ownership._validated_owner(owner, binding)
    parent = actual.directories[-1][0]
    stem = actual.lock_name[:-5]
    if ({name for name in os.listdir(parent) if name.startswith(stem + '.')}
            != {actual.lock_name} or 'enrollment-init-' + stem in os.listdir(parent)):
        raise EnrollmentInitializeHold()
    return parent, stem


def initialize_current_project(project):
    """Manual one-shot entry: current fixed project only, no recovery options.

    Existing project/tracker roots and fixed root-owned credential/allowlist/CA
    must already exist. No initial K/COUNT state or missing owners are created.
    A whole empty metadata observation is required, not merely missing markers.
    Every ambiguous outcome leaves the first-attempt evidence and nonce images.
    """
    from monitor import issue_tracker_enrollment_journal as enrollment
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_spreadsheet_owner as ownership
    from monitor import issue_tracker_unit_catalog as catalog
    from monitor import issue_tracker_attempt_journal as journal_files
    from monitor import issue_tracker_online_target as targets
    from monitor import issue_tracker_token_launcher as auth
    from monitor import issue_tracker_history_read_launcher as reads
    from monitor import issue_tracker_sheets_read_decode as decode
    from monitor import issue_tracker_enrollment_protocol as protocol
    graph = catalog._Originals()
    parent_copy = None
    parent_identity = None
    primary = None
    folder = None
    appended = set()
    try:
        project = Path(project)
        if not project.is_absolute():
            raise EnrollmentInitializeHold()
        with local.try_writer_owner(project, project / '99-output-monitor') as writer:
            with targets._hold_current_project_online_target(writer) as binding:
                with ownership.spreadsheet_owner(binding) as owner:
                    parent, stem = _fresh_namespace(owner, binding)
                    parent_identity = journal_files._identity(os.fstat(parent))
                    parent_copy = os.dup(parent)
                    # This distinct evidence directory is not an enrollment or
                    # a business catalog. Its presence forbids another attempt.
                    name = 'enrollment-init-' + stem
                    os.mkdir(name, 0o700, dir_fd=parent_copy)
                    os.fsync(parent_copy)
                    folder = graph.directory(parent_copy, name)
                    graph.namespace = (parent_copy, stem + '.', {stem + '.lock'})

                    def verify():
                        graph.verify(appended_to=(folder, appended),
                            parent_additions=additions)
                        if journal_files._identity(os.fstat(parent_copy))[:5] != parent_identity[:5]:
                            raise EnrollmentInitializeHold()

                    def evidence(name, raw):
                        verify()
                        local._write_new(folder, name, raw)
                        appended.add(name)
                        graph.file(folder, name, 2 * 1024 * 1024)
                        verify()

                    additions = frozenset()
                    evidence('INTENT', local._canonical({'schema_version': 1,
                        'state': 'UNKNOWN_UNTIL_OBSERVED', 'spreadsheet_id': binding.spreadsheet_id,
                        'policy_sha256': binding.policy_sha256,
                        'allowlist_sha256': binding.allowlist_sha256}))
                    authentication = auth.OwnedProjectTokenRefreshUnit(owner, binding).refresh_once()
                    cohort = reads.OwnedProjectTemplateReadCohort(writer, owner, binding, authentication).read_once()
                    kinds = ('template_identity', 'template_headers', 'whitelist', 'metadata')
                    if type(cohort) is not tuple or len(cohort) != 4:
                        raise EnrollmentInitializeHold()
                    group = tuple((kind, None, None, value) for kind, value in zip(kinds, cohort))

                    def originals():
                        verify()
                        return reads._require_current_owned_project_read_group(
                            writer, owner, binding, authentication, group)

                    plans = originals()
                    for kind, observed in zip(kinds, cohort):
                        evidence('PREFLIGHT-' + kind, observed.data)
                    identity = decode.decode_template_identity(plans[0][0], cohort[0])
                    decode.decode_template_headers(plans[1][0], cohort[1], identity)
                    # Whitelist bytes are retained DATA, not a local-rule match
                    # or sending permission. Normal admission still owes C-24.
                    prior = protocol._document(cohort[3])
                    if prior not in ({}, {'matchedDeveloperMetadata': []}):
                        raise EnrollmentInitializeHold()
                    originals()
                    # Recheck after network/decoding; never adopt a newly
                    # appearing local family, including loss witnesses.
                    if {n for n in os.listdir(parent_copy) if n.startswith(stem + '.')} != {stem + '.lock'}:
                        raise EnrollmentInitializeHold()
                    nonces = enrollment.prepare_enrollment_journal(owner, binding, identity)
                    additions = frozenset((stem + '.enrollment',))
                    nonce_folder = graph.directory(parent_copy, stem + '.enrollment')
                    held = []
                    for filename, limit in (('HEADER', 16384), ('NONCES', 16384), ('INITIALIZED', 4096)):
                        graph.file(nonce_folder, filename, limit)
                        held.append(graph.files[-1][2])
                    prepared = protocol.prepare_enrollment_mutation(binding, authentication.token, identity, nonces)
                    evidence('WIRE', prepared.body)
                    wire_fd = graph.files[-1][2]
                    originals()
                    transport = _send_initialize_once(writer, owner, binding, authentication,
                        identity, nonces, *held, wire_fd, _template_reads=cohort)
                    response = transport.response
                    evidence('RESPONSE', response.data)
                    evidence('RESPONSE-STATUS', local._canonical({'status': response.status}))
                    reply = protocol.decode_enrollment_reply(prepared, response)
                    observed = reads.OwnedProjectSheetsReadUnit(writer, owner, binding,
                        authentication, read_kind='metadata').read_once()
                    read_plan, _project_id, _digest = reads.require_current_owned_project_read(
                        writer, owner, binding, observed, authentication, read_kind='metadata')
                    evidence('READBACK', observed.data)
                    data = protocol.decode_enrollment_metadata(prepared, read_plan, observed, reply)
                    originals()
                    if nonces != enrollment.inspect_enrollment_journal(owner, binding, identity):
                        raise EnrollmentInitializeHold()
                    reads.require_current_owned_project_read(writer, owner, binding,
                        observed, authentication, read_kind='metadata')
                    evidence('OBSERVED-DATA', local._canonical({'schema_version': 1,
                        'outcome': data.outcome, 'metadata_sha256': data.metadata_sha256,
                        'wire_sha256': prepared.wire_sha256,
                        'automatic_sending_enabled': False}))
                    originals()
        # All three original owner contexts have completed before success.
        verify()
    except BaseException as error:
        primary = error
    finally:
        primary = _close_initialization_images(graph, parent_copy, parent_identity, primary)
    if primary is not None:
        if not isinstance(primary, Exception):
            raise primary
        raise EnrollmentInitializeHold() from None

_SOURCE_ROOT = Path(__file__).resolve().parents[1]
_INITIALIZE_CHILD_PROGRAM = '''import sys
sys.path[:0]=[sys.argv[1],sys.argv[1]+"/tools"]
from monitor.issue_tracker_enrollment_initialize import _initialize_child
raise SystemExit(_initialize_child(sys.argv[2],*(int(value) for value in sys.argv[3:7])))
'''


class InitializeTransportHold(ValueError):
    def __init__(self, termination_confirmed=False):
        super().__init__("req7_initialize_transport_denied")
        self.termination_confirmed = termination_confirmed


@dataclass(frozen=True)
class InitializeTransportCompletion:
    response: object = field(repr=False)
    wire_sha256: str
    response_sha256: str
    termination_confirmed: bool


def _canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                       allow_nan=False) + "\n").encode("utf-8")


def _digest(value):
    if type(value) is not str or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise InitializeTransportHold()
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result: raise InitializeTransportHold()
        result[key] = value
    return result


def _invalid_constant(_value):
    raise InitializeTransportHold()


def _json(raw):
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_invalid_constant)
    if _canonical(value) != raw: raise InitializeTransportHold()
    return value


def _fd_image(fd, limit):
    from monitor import issue_tracker_local_commit as local
    if type(fd) is not int or fd < 3: raise InitializeTransportHold()
    before = local._check(fd, directory=False)
    if not 1 <= before.st_size <= limit: raise InitializeTransportHold()
    key = lambda s: (s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid, s.st_nlink,
                     s.st_size, s.st_mtime_ns, s.st_ctime_ns)
    chunks = []; cursor = 0
    while cursor < before.st_size:
        chunk = os.pread(fd, min(4096, before.st_size - cursor), cursor)
        if not chunk: raise InitializeTransportHold()
        chunks.append(chunk); cursor += len(chunk)
    if key(local._check(fd, directory=False)) != key(before): raise InitializeTransportHold()
    return key(before), b"".join(chunks)


def _originals(binding, token, header_fd, nonces_fd, marker_fd, wire_fd):
    """Borrow four distinct original regular files; never close or seek them."""
    from monitor.issue_tracker_sheets_read_decode import ObservedTemplateIdentity
    from monitor.issue_tracker_enrollment_journal import JournaledEnrollments
    from monitor.issue_tracker_enrollment_protocol import prepare_enrollment_mutation
    fds = (header_fd, nonces_fd, marker_fd, wire_fd)
    if len(set(fds)) != 4: raise InitializeTransportHold()
    images = tuple(_fd_image(fd, size) for fd, size in zip(fds, (16384, 16384, 4096, 32768)))
    if len({image[0][:2] for image in images}) != 4: raise InitializeTransportHold()
    header_raw, nonce_raw, marker_raw, wire = (image[1] for image in images)
    header, rows, marker = _json(header_raw), _json(nonce_raw), _json(marker_raw)
    if (type(header) is not dict or set(header) != {"schema_version", "spreadsheet_id", "sheet_ids", "nonces_sha256"}
            or type(header["schema_version"]) is not int or header["schema_version"] != 1
            or header["spreadsheet_id"] != binding.spreadsheet_id
            or header["nonces_sha256"] != hashlib.sha256(nonce_raw).hexdigest()
            or type(header["sheet_ids"]) is not list or type(rows) is not list
            or any(type(row) is not list for row in header["sheet_ids"] + rows)
            or marker != {"schema_version": 1, "state": "INITIALIZED",
                          "header_sha256": hashlib.sha256(header_raw).hexdigest()}
            or type(marker) is not dict or type(marker.get("schema_version")) is not int):
        raise InitializeTransportHold()
    identity = ObservedTemplateIdentity(binding.spreadsheet_id, tuple(tuple(row) for row in header["sheet_ids"]),
                                        hashlib.sha256(header_raw).hexdigest())
    journal = JournaledEnrollments(tuple(tuple(row) for row in rows), hashlib.sha256(header_raw).hexdigest())
    prepared = prepare_enrollment_mutation(binding, token, identity, journal)
    if wire != prepared.body: raise InitializeTransportHold()
    return images, identity, journal, prepared


def _private(raw, nonce):
    from monitor.issue_tracker_online_target import OnlineTargetBinding
    from monitor.issue_tracker_sdk_authentication import AuthenticatedToken
    from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read
    _digest(nonce)
    if type(raw) is not bytes or not 1 <= len(raw) <= 32768: raise InitializeTransportHold()
    value = _json(raw)
    if (type(value) is not dict or set(value) != {"schema_version", "nonce", "spreadsheet_id",
            "allowlist_sha256", "policy_sha256", "token", "expires_at"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["nonce"] != nonce): raise InitializeTransportHold()
    binding = OnlineTargetBinding(value["spreadsheet_id"], value["allowlist_sha256"], value["policy_sha256"])
    token = AuthenticatedToken(value["token"], value["expires_at"])
    prepare_template_identity_read(binding, token)
    return binding, token


def _frame(nonce, prepared, response):
    _digest(nonce)
    if (type(response.status) is not int or not 200 <= response.status <= 599 or response.complete is not True
            or type(response.data) is not bytes or not 1 <= len(response.data) <= 2 * 1024 * 1024 - 4096):
        raise InitializeTransportHold()
    header = _canonical({"schema_version": 1, "nonce": nonce, "wire_sha256": prepared.wire_sha256,
        "status": response.status, "size": len(response.data),
        "response_sha256": hashlib.sha256(response.data).hexdigest()})
    if len(header) > 4096: raise InitializeTransportHold()
    return header + response.data


def _decode_initialize_completion(raw, nonce, prepared):
    from monitor.issue_tracker_enrollment_protocol import validate_prepared_enrollment_mutation
    from monitor.issue_tracker_tls_inputs import CompleteTokenResponse
    validate_prepared_enrollment_mutation(prepared); _digest(nonce)
    if type(raw) is not bytes or not 1 <= len(raw) <= 2 * 1024 * 1024: raise InitializeTransportHold(True)
    line, separator, data = raw.partition(b"\n")
    if not separator or len(line) >= 4096: raise InitializeTransportHold(True)
    value = _json(line + b"\n")
    if (type(value) is not dict or set(value) != {"schema_version", "nonce", "wire_sha256", "status", "size", "response_sha256"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["nonce"] != nonce or value["wire_sha256"] != prepared.wire_sha256
            or type(value["status"]) is not int or not 200 <= value["status"] <= 599
            or type(value["size"]) is not int or not 1 <= value["size"] == len(data) <= 2 * 1024 * 1024 - 4096
            or value["response_sha256"] != hashlib.sha256(data).hexdigest()):
        raise InitializeTransportHold(True)
    return InitializeTransportCompletion(CompleteTokenResponse(value["status"], (), data),
        prepared.wire_sha256, value["response_sha256"], True)


def _initialize_child(nonce, header_fd, nonces_fd, marker_fd, wire_fd):
    """Internal fixed child: no arguments for endpoint, CA, body or budget."""
    try:
        _digest(nonce)
        if os.geteuid() != 0: raise InitializeTransportHold()
        raw = bytearray()
        while True:
            chunk = os.read(0, min(4096, 32769 - len(raw)))
            if not chunk: break
            raw.extend(chunk)
            if len(raw) > 32768: raise InitializeTransportHold()
        binding, token = _private(bytes(raw), nonce)
        before, _identity, _journal, prepared = _originals(binding, token, header_fd, nonces_fd, marker_fd, wire_fd)
        from monitor.issue_tracker_tls_inputs import _native_complete_read
        response = _native_complete_read(prepared)
        after, _identity, _journal, _prepared = _originals(binding, token, header_fd, nonces_fd, marker_fd, wire_fd)
        if before != after: raise InitializeTransportHold()
        output = _frame(nonce, prepared, response)
        cursor = 0
        while cursor < len(output):
            written = os.write(1, output[cursor:])
            if written <= 0: raise InitializeTransportHold()
            cursor += written
    except BaseException:
        return 1
    return 0


def _parent_originals(writer, owner, binding, authentication, identity, journal, fds):
    from monitor import issue_tracker_local_commit as local
    from monitor import issue_tracker_enrollment_journal as enrollment
    from monitor.issue_tracker_spreadsheet_owner import owner_lock_fd
    from monitor.issue_tracker_online_target import inspect_project_online_target
    from monitor.issue_tracker_token_launcher import require_current_owned_project_token
    project = local._owner(writer); lock = owner_lock_fd(owner, binding)
    require_current_owned_project_token(owner, binding, authentication)
    inspect_project_online_target(writer, binding)
    if enrollment.inspect_enrollment_journal(owner, binding, identity) != journal: raise InitializeTransportHold()
    images, rebuilt, original, prepared = _originals(binding, authentication.token, *fds)
    if rebuilt.sheet_ids != identity.sheet_ids or original != journal: raise InitializeTransportHold()
    _sheet, parent, name, _header = enrollment._inputs(owner, binding, identity)
    folder = local._directory(parent, name)
    folder_identity = None
    primary = None
    try:
        info = os.fstat(folder)
        folder_identity = (info.st_dev, info.st_ino)
        for leaf, fd in zip(("HEADER", "NONCES", "INITIALIZED"), fds[:3]):
            named = os.stat(leaf, dir_fd=folder, follow_symlinks=False)
            held = os.fstat(fd)
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino): raise InitializeTransportHold()
    except BaseException as error:
        primary = error
    finally:
        try:
            _initializer_close_original(folder, folder_identity)
        except BaseException as error:
            if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                primary = error
    if primary is not None:
        raise primary
    inspect_project_online_target(writer, binding)
    require_current_owned_project_token(owner, binding, authentication)
    if local._owner(writer) is not project or owner_lock_fd(owner, binding) != lock: raise InitializeTransportHold()
    return project, lock, images, prepared


def _send_initialize_once(writer, owner, binding, authentication, identity, journal,
                          header_fd, nonces_fd, marker_fd, wire_fd, *, _template_reads):
    """One owned launch under the original 60s total, including final cleanup.

    This is not durable one-use admission. The explicit manual orchestrator must
    retain its original attempt on UNKNOWN and must never invoke this to replay.
    Borrowed original files and both owner locks are NEVER closed/unlocked here.
    """
    started = time.monotonic(); process = None; primary = None; confirmed = False
    fds = (header_fd, nonces_fd, marker_fd, wire_fd)
    try:
        original = _parent_originals(writer, owner, binding, authentication, identity, journal, fds)
        project, sheet_lock, images, prepared = original
        inherited = (project.lock_fd, sheet_lock, *fds)
        if len(set(inherited)) != 6: raise InitializeTransportHold()
        nonce = secrets.token_hex(32)
        raw = _canonical({"schema_version": 1, "nonce": nonce, "spreadsheet_id": binding.spreadsheet_id,
            "allowlist_sha256": binding.allowlist_sha256, "policy_sha256": binding.policy_sha256,
            "token": authentication.token.value, "expires_at": authentication.token.expires_at})
        _private(raw, nonce)
        if time.monotonic() >= started + 60.0: raise InitializeTransportHold()
        executable = str(Path(sys.executable).resolve(strict=True))
        # Original reads must still be current AFTER all launch preparation,
        # not only before potentially slow credential/journal/source checks.
        # This API checks the actual issued objects, owners and original fixed
        # deadlines; a tuple or caller-created completion cannot issue a PASS.
        from monitor.issue_tracker_history_read_launcher import _require_current_owned_project_read_group
        if type(_template_reads) is not tuple or len(_template_reads) != 4:
            raise InitializeTransportHold()
        _require_current_owned_project_read_group(writer, owner, binding, authentication,
            tuple((kind, None, None, response) for kind, response in zip(
                ('template_identity', 'template_headers', 'whitelist', 'metadata'), _template_reads)))
        if time.monotonic() >= started + 60.0: raise InitializeTransportHold()
        process = subprocess.Popen([executable, "-I", "-B", "-c", _INITIALIZE_CHILD_PROGRAM,
            str(_SOURCE_ROOT), nonce, *(str(fd) for fd in fds)], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, start_new_session=True, close_fds=True, pass_fds=inherited,
            cwd=str(_SOURCE_ROOT), env={"LC_ALL": "C"})
        completion = supervise_owned_attempt(process, started_monotonic=started, kind="mutation", request_bytes=raw)
        confirmed = completion.termination_confirmed
        if confirmed is not True: raise InitializeTransportHold()
        result = _decode_initialize_completion(completion.data, nonce, prepared)
    except BaseException as error:
        primary = error
        if isinstance(error, AttemptHold): confirmed = error.termination_confirmed
    finally:
        if process is not None:
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is None: continue
                try: stream.close()
                except BaseException as error:
                    if primary is None or (isinstance(primary, Exception) and not isinstance(error, Exception)):
                        primary = error
    if primary is not None:
        if not isinstance(primary, Exception): raise primary
        raise InitializeTransportHold(confirmed)
    failed = False
    try:
        after = _parent_originals(writer, owner, binding, authentication, identity, journal, fds)
        if (after[0] is not project or after[1] != sheet_lock or after[2] != images
                or after[3] != prepared or time.monotonic() >= started + 60.0):
            raise InitializeTransportHold(True)
    except Exception:
        failed = True
    if failed: raise InitializeTransportHold(confirmed)
    return result
