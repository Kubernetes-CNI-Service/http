"""Uninstalled C-12/C-14 TLS inputs and native prototype, not online authority.

The Ubuntu image already declares ca-certificates. Only its fixed aggregate
file is considered here, read through held, root-owned non-writable FDs. No
default/system-directory/environment trust is loaded. Local owned-file tests
do not prove deployment Python/SSL/CA identity or any handshake/deadline.
"""
from dataclasses import dataclass, field
import fcntl
import hashlib
import http.client
import math
import os
import re
import ssl
import stat
import threading

CA_PATH = "/etc/ssl/certs/ca-certificates.crt"
_MAX_CA_BYTES = 2 * 1024 * 1024
_CERTIFICATES = re.compile(
    r"(?:-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----\n\s*)+\Z"
)


class TlsInputHold(ValueError):
    def __init__(self): super().__init__("req7_tls_input_denied")


@dataclass(frozen=True)
class CaIdentity:
    path: str
    sha256: str
    size: int
    device: int
    inode: int
    openssl_version: str


def _directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _file_identity(value):
    return (_directory_identity(value), value.st_nlink, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _directory(value):
    if not stat.S_ISDIR(value.st_mode) or value.st_uid != 0 or value.st_mode & 0o022:
        raise TlsInputHold()


def _fixed_ca():
    """One bounded read; no pathname repair, second read or trust fallback."""
    descriptors, directories, edges = [], [], []
    failed = False
    try:
        if os.geteuid() != 0 or any(not hasattr(os, flag) for flag in (
            "O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK",
        )):
            raise TlsInputHold()
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        parent = os.open("/", directory_flags); descriptors.append(parent)
        metadata = os.fstat(parent); _directory(metadata); directories.append((parent, metadata))
        for name in ("etc", "ssl", "certs"):
            child = os.open(name, directory_flags, dir_fd=parent); descriptors.append(child)
            metadata = os.fstat(child); _directory(metadata)
            directories.append((child, metadata)); edges.append((parent, name, metadata)); parent = child
        leaf = "ca-certificates.crt"
        fd = os.open(leaf, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=parent)
        descriptors.append(fd); before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o022
                or before.st_nlink != 1 or not 1 <= before.st_size <= _MAX_CA_BYTES):
            raise TlsInputHold()
        source = os.read(fd, _MAX_CA_BYTES + 1)
        if (type(source) is not bytes or len(source) != before.st_size
                or _file_identity(os.fstat(fd)) != _file_identity(before)
                or _file_identity(os.stat(leaf, dir_fd=parent, follow_symlinks=False)) != _file_identity(before)):
            raise TlsInputHold()
        for directory, previous in directories:
            current = os.fstat(directory); _directory(current)
            if _directory_identity(current) != _directory_identity(previous): raise TlsInputHold()
        for ancestor, name, previous in edges:
            if _directory_identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False)) != _directory_identity(previous):
                raise TlsInputHold()
    except Exception:
        failed = True
    finally:
        for descriptor in reversed(descriptors):
            try: os.close(descriptor)
            except OSError: failed = True
    if failed: raise TlsInputHold()
    return source, before


def stdlib_header_bounds():
    """Observe the actual parser contract, never change its process globals."""
    if (type(http.client._MAXLINE) is not int or http.client._MAXLINE != 65536
            or type(http.client._MAXHEADERS) is not int or http.client._MAXHEADERS != 100):
        raise TlsInputHold()
    return (65536, 100)


def controlled_tls_context():
    """Fresh TLS-client context anchored only in one verified CA byte image."""
    failed = False
    try:
        stdlib_header_bounds()
        source, metadata = _fixed_ca()
        pem = source.decode("ascii", "strict")
        if _CERTIFICATES.fullmatch(pem) is None: raise TlsInputHold()
        # SSLContext does not load default CA directories or environment trust.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cadata=pem)
        context.set_alpn_protocols(["http/1.1"])
        if context.verify_mode != ssl.CERT_REQUIRED or context.check_hostname is not True:
            raise TlsInputHold()
        if context.cert_store_stats()["x509_ca"] < 1: raise TlsInputHold()
        identity = CaIdentity(CA_PATH, hashlib.sha256(source).hexdigest(), len(source),
                              metadata.st_dev, metadata.st_ino, ssl.OPENSSL_VERSION)
    except Exception:
        failed = True
    if failed: raise TlsInputHold()
    return context, identity


@dataclass(frozen=True)
class PreparedTokenRequest:
    host: str
    path: str
    method: str
    body: bytes = field(repr=False)
    headers: tuple = field(repr=False)
    budget_seconds: float = 30.0


def prepare_token_request(wire):
    """Strict immutable token-only wire shape; this grants no sending right."""
    from monitor.issue_tracker_sdk_authentication import TokenWireRequest
    if (type(wire) is not TokenWireRequest or type(wire.url) is not str
            or wire.url != "https://oauth2.googleapis.com/token" or type(wire.method) is not str
            or wire.method != "POST" or type(wire.body) is not bytes or not 1 <= len(wire.body) <= 65536
            or type(wire.budget_seconds) not in (int, float) or not 0 < wire.budget_seconds <= 30
            or not math.isfinite(wire.budget_seconds) or type(wire.headers) is not tuple):
        raise TlsInputHold()
    headers = {}
    for pair in wire.headers:
        if type(pair) is not tuple or len(pair) != 2: raise TlsInputHold()
        name, value = pair
        if (type(name) is not str or name not in ("Content-Type", "x-goog-api-client") or name in headers
                or type(value) is not str or not 1 <= len(value) <= 1024
                or any(not 32 <= ord(character) <= 126 for character in value)):
            raise TlsInputHold()
        headers[name] = value
    if headers.get("Content-Type") != "application/x-www-form-urlencoded": raise TlsInputHold()
    return PreparedTokenRequest("oauth2.googleapis.com", "/token", "POST", wire.body,
                                tuple(sorted(headers.items())), float(wire.budget_seconds))


@dataclass(frozen=True)
class CompleteTokenResponse:
    status: int
    headers: tuple = field(repr=False)
    data: bytes = field(repr=False)
    complete: bool = True


def _native_complete_read(prepared):
    """One fixed OAuth POST, Sheets GET, metadata search or typed whole batch.

    Internal only: this is not a URL-taking transport API or target authority.
    Uninstalled callers construct their immutable fixed shapes themselves.
    Complete here means intact bounded HTTP, not a valid Sheets observation.
    """
    connection = response = None; failed = False; mutation = False; interruption = None
    try:
        from monitor.issue_tracker_sheets_read_plan import PreparedSheetsMutation
        if type(prepared) is PreparedSheetsMutation:
            # Check type FIRST: tampered host/method must not select the GET
            # or OAuth branch and escape the immutable mutation contract.
            from monitor.issue_tracker_send_unit import _validate_mutation_request
            _validate_mutation_request(prepared); mutation = True
        elif (prepared.host, prepared.method) == ("sheets.googleapis.com", "POST"):
            # Every other Sheets POST must satisfy the separate exact typed
            # read-only search contract, never a generic mutation allowance.
            from monitor.issue_tracker_metadata_capacity import _validate_plan
            _validate_plan(prepared)
        elif (prepared.host, prepared.method) not in (("oauth2.googleapis.com", "POST"), ("sheets.googleapis.com", "GET")):
            raise TlsInputHold()
        context, _identity = controlled_tls_context()
        connection = http.client.HTTPSConnection(prepared.host, timeout=prepared.budget_seconds, context=context)
        # Fresh native connection, never a proxy/tunnel, redirect or resend loop.
        connection.set_debuglevel(0)
        connection.request(prepared.method, prepared.path, body=prepared.body, headers=dict(prepared.headers))
        response = connection.getresponse()
        status = response.status; pairs = tuple(response.getheaders())
        if (type(status) is not int or (not mutation and status != 200)
                or (mutation and not 200 <= status <= 599) or len(pairs) > 100): raise TlsInputHold()
        total = 0; unique = {}
        for name, value in pairs:
            if (type(name) is not str or re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,256}", name) is None
                    or name.lower() in unique or type(value) is not str or len(value) > 8192
                    or any(not 32 <= ord(character) <= 126 for character in value)):
                raise TlsInputHold()
            unique[name.lower()] = value; total += len(name) + len(value)
        if total > 65536: raise TlsInputHold()
        length = unique.get("content-length"); transfer = unique.get("transfer-encoding")
        # A connection-close EOF supplies no independently bounded intended
        # body length. Native TLS can suppress a ragged EOF; even a valid JSON
        # prefix must not be certified complete. Require explicit HTTP framing.
        if length is None and transfer is None: raise TlsInputHold()
        if transfer is not None and (transfer.lower() != "chunked" or length is not None): raise TlsInputHold()
        expected = None
        if length is not None:
            if re.fullmatch(r"[0-9]{1,10}", length) is None: raise TlsInputHold()
            expected = int(length)
            if expected > 2 * 1024 * 1024: raise TlsInputHold()
        data = response.read(2 * 1024 * 1024 + 1)
        if (type(data) is not bytes or len(data) > 2 * 1024 * 1024
                or (expected is not None and len(data) != expected)):
            raise TlsInputHold()
        result = CompleteTokenResponse(status, pairs, data)
    except Exception:
        failed = True
    except BaseException as error:
        interruption = error
    finally:
        # A Connection: close response may own a detached socket makefile.
        # Release it even when a caller retains the denial's traceback; the
        # connection alone no longer necessarily owns that descriptor.
        for resource in (response, connection):
            if resource is None: continue
            try: resource.close()
            except Exception: failed = True
            except BaseException as error:
                if interruption is None: interruption = error
    if interruption is not None: raise interruption
    if failed: raise TlsInputHold()
    return result


@dataclass(frozen=True)
class NativeMutationObservation:
    """Intact same-connection syntax only; no APPLIED/COMPLETE or retry right."""
    status: int
    wire_sha256: str
    response_sha256: object
    outcome: str


class NativeSheetsMutationUnit:
    """Uninstalled native whole-batch prototype, NOT an online entry/permit.

    One object consumes at most one request, even after error. The fixed
    supervised launcher must separately enforce 60 seconds TOTAL, original
    held WIRE and durable one-use count, actual dual ownership, fresh gates,
    shared cadence and capacity. No CLI, refresh, resend or override ships.
    Socket timeout alone is NOT a total budget or durable attempt proof.
    """
    def __init__(self,binding,token,unit):
        from monitor.issue_tracker_send_unit import prepare_mutation_request
        failed = False
        try: self._prepared = prepare_mutation_request(binding,token,unit)
        except Exception: failed = True
        if failed: raise TlsInputHold()
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        failed = False
        try:
            from monitor.issue_tracker_send_unit import _validate_mutation_request
            from monitor.issue_tracker_mutation_rejection import observe_rejection
            _validate_mutation_request(self._prepared)
            response = _native_complete_read(self._prepared)
            observed = observe_rejection(response.status,response.data,complete=response.complete)
            result = NativeMutationObservation(response.status,self._prepared.wire_sha256,
                observed.body_sha256,observed.outcome)
        except Exception: failed = True
        if failed: raise TlsInputHold()
        return result


class NativeOriginalSheetsMutationUnit(NativeSheetsMutationUnit):
    """Uninstalled borrowed original FD boundary, NOT an admission entry.

    Original read-only private ACTION/WIRE <=1 MiB each; one held pread per
    image, no source/path reopening, no body input/URL/CA/budget override.
    The fixed parent still must supervise TOTAL 60 seconds, retain both locks
    and consume a fresh governed opportunity plus original count once. This
    boundary alone establishes neither provenance nor a durable send permit.
    """
    def __init__(self,binding,token,action_fd,wire_fd):
        failed = False
        try:
            if (os.geteuid() != 0 or any(type(fd) is not int or fd < 3 for fd in (action_fd,wire_fd))
                    or action_fd == wire_fd): raise TlsInputHold()
            originals = []; images = []
            for fd in (action_fd,wire_fd):
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0 or before.st_mode & 0o777 != 0o600
                        or before.st_nlink != 1 or not 1 <= before.st_size <= 1024*1024
                        or fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE != os.O_RDONLY): raise TlsInputHold()
                raw = os.pread(fd,1024*1024+1,0)
                if len(raw) != before.st_size or _file_identity(os.fstat(fd)) != _file_identity(before): raise TlsInputHold()
                originals.append((fd,_file_identity(before))); images.append(raw)
            from monitor.issue_tracker_send_unit import _original_unit
            super().__init__(binding,token,_original_unit(*images))
            self._originals = tuple(originals); self._original_guard = threading.Lock(); self._original_used = False
        except Exception: failed = True
        if failed: raise TlsInputHold()

    def send_once(self):
        with self._original_guard:
            used = self._original_used; self._original_used = True
        if used: raise TlsInputHold()
        failed = False
        try:
            for fd,identity in self._originals:
                if _file_identity(os.fstat(fd)) != identity: raise TlsInputHold()
            result = super().send_once()
            for fd,identity in self._originals:
                if _file_identity(os.fstat(fd)) != identity: raise TlsInputHold()
        except Exception: failed = True
        if failed: raise TlsInputHold()
        return result


class NativeTokenHttpsUnit:
    """Uninstalled token-only native unit, NOT a supervised total-budget proof.

    This has no CLI, worker activation or arbitrary destination. Socket timeouts
    are only per operation, so this unit must not become an online entry until a
    supervised process, orphan/lock and fresh admission contract dominates it.
    Local tests exercise negative paths and a separate whole fake-unit boundary;
    real TLS/header/read/termination behaviour remains a REAL_ENV obligation.
    """
    def __init__(self):
        self._called = False; self._lock = threading.Lock()

    def send_once(self, wire):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        failed = False
        try:
            prepared = prepare_token_request(wire)
            result = _native_complete_read(prepared)
        except Exception:
            failed = True
        if failed: raise TlsInputHold()
        return result


class NativeSheetsReadUnit:
    """Uninstalled single GET; no arbitrary URL, mutation, refresh or retry API.

    This is a local native-wire prototype only. Typed inputs confer no live
    permission. A fixed audited launcher, total-budget supervision, fresh target
    authority and complete discovery/template/continuity checks remain required
    before any online use. No response is interpreted as APPLIED or a permit.
    """
    def __init__(self, binding, token, *, mode, sheet, first_row, last_row=None):
        from monitor.issue_tracker_sheets_read_plan import prepare_sheets_read
        self._prepared = prepare_sheets_read(binding, token, mode=mode, sheet=sheet,
                                             first_row=first_row, last_row=last_row)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeActivitySheetReadUnit:
    """One capacity-bearing business discovery GET; no allocation or mutation."""
    def __init__(self, binding, token, *, sheet):
        from monitor.issue_tracker_sheets_read_plan import prepare_activity_sheet_read
        self._prepared = prepare_activity_sheet_read(binding, token, sheet=sheet)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeInsertionSheetReadUnit:
    """One fixed occupancy GET; no insertion, ID or reservation authority."""
    def __init__(self, binding, token, *, sheet):
        from monitor.issue_tracker_sheets_read_plan import prepare_insertion_sheet_read
        self._prepared = prepare_insertion_sheet_read(binding, token, sheet=sheet)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeHistoryReadUnit:
    """One bounded five-column GET, uninstalled and without COMPLETE authority."""
    def __init__(self, binding, token, *, first_row, last_row):
        from monitor.issue_tracker_sheets_read_plan import prepare_history_read
        self._prepared = prepare_history_read(binding, token, first_row=first_row, last_row=last_row)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeHistoryTailReadUnit:
    """One fixed same-response capacity/raw-tail GET; no mutation authority."""
    def __init__(self, binding, token):
        from monitor.issue_tracker_sheets_read_plan import prepare_history_tail_read
        self._prepared = prepare_history_tail_read(binding, token)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeOnlineWhitelistReadUnit:
    """Uninstalled fixed read, no activation, write, refresh or retry authority."""
    def __init__(self, binding, token):
        from monitor.issue_tracker_sheets_read_plan import prepare_online_whitelist_read
        self._prepared = prepare_online_whitelist_read(binding, token)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeTemplateIdentityReadUnit:
    """Uninstalled one metadata GET, no grid read, enrollment or write permit."""
    def __init__(self, binding, token):
        from monitor.issue_tracker_sheets_read_plan import prepare_template_identity_read
        self._prepared = prepare_template_identity_read(binding, token)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)


class NativeTemplateHeaderReadUnit:
    """Uninstalled one four-range header GET, not complete live continuity."""
    def __init__(self, binding, token):
        from monitor.issue_tracker_sheets_read_plan import prepare_template_header_read
        self._prepared = prepare_template_header_read(binding, token)
        self._called = False; self._lock = threading.Lock()

    def send_once(self):
        with self._lock:
            used = self._called; self._called = True
        if used: raise TlsInputHold()
        return _native_complete_read(self._prepared)
