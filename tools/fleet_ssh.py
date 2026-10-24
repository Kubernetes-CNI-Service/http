"""SSH sessions for switch fleet jobs (IB upgrade v2 first; nvl-sw later; owner 2026-10-23).

The IB v1 signed sessions only accept v1 leaf/scope objects and their evidence lock, so
fleet jobs have their own small layer on the same pinned paramiko runtime (the pins equal
ibsw_upgrade_observer.SSH_RUNTIME_PINS; a test keeps them equal): host keys pinned from
known_hosts (literal or OpenSSH-hashed entries, never trust on first use), the
management key first and the switch password only when the key is rejected, commands
bounded from the moment they are sent. Passwords and private keys never appear in a
repr, an error or a result. A rejected key is AUTH_REJECTED (the cue for the password
fallback); a password the switch refuses is PASSWORD_REJECTED, so a mistyped password
can stop a run before it is tried on other switches (field 2026-10-24).
"""
from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass, field
import errno
import hashlib
import hmac
from importlib import metadata
import io
import os
from pathlib import Path
import socket
import stat
import time

from ssh_key_preparation import public_key_identity_bytes

SSH_RUNTIME_PINS = (("paramiko", "5.0.0"), ("bcrypt", "5.0.0"),
                    ("cryptography", "50.0.1"), ("invoke", "2.2.1"),
                    ("PyNaCl", "1.6.2"), ("cffi", "2.0.0"),
                    ("pycparser", "2.23"), ("typing-extensions", "4.16.0"))

CONNECT_SECONDS = 10.0
HANDSHAKE_SECONDS = 25.0
COMMAND_SECONDS = 25.0
OUTPUT_LIMIT = 16 * 1024 * 1024
POLL_SECONDS = 0.05
RETRYABLE_ERRNOS = {errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ETIMEDOUT,
                    errno.ECONNRESET, errno.EHOSTDOWN}


class SshError(Exception):
    """Fixed reason codes only; never device text, secrets or SDK messages."""

    CODES = {"CONNECT_FAILED", "CONNECT_TIMEOUT", "HANDSHAKE_FAILED", "HOST_KEY_UNKNOWN", "HOST_KEY_MISMATCH",
             "AUTH_REJECTED", "PASSWORD_REJECTED", "AUTH_TIMEOUT", "AUTH_TRANSPORT_LOST", "AUTH_UNKNOWN", "COMMAND_TIMEOUT",
             "COMMAND_INCOMPLETE", "OUTPUT_LIMIT", "CHANNEL_FAILED", "KEY_INVALID", "SDK_UNAVAILABLE"}

    def __init__(self, code):
        super().__init__(code)
        self.code = code if code in self.CODES else "CHANNEL_FAILED"

    @property
    def reboot_like(self):
        """Failures a rebooting switch produces; probing retries these."""
        return self.code in {"CONNECT_FAILED", "CONNECT_TIMEOUT", "HANDSHAKE_FAILED", "AUTH_TIMEOUT",
                             "AUTH_TRANSPORT_LOST", "COMMAND_INCOMPLETE"}


def endpoint_matches(field: bytes, endpoints) -> bool:
    """Exact endpoint text or an OpenSSH |1| HMAC-SHA1 hashed host (same rule as IB v1)."""
    if b"|" not in field:
        return bool(set(endpoints).intersection(field.decode("ascii").split(",")))
    parts = field.split(b"|")
    if len(parts) != 4 or parts[0] != b"" or parts[1] != b"1":
        raise ValueError("unsupported known_hosts host field")
    try:
        salt, digest = (base64.b64decode(value, validate=True) for value in parts[2:])
    except (ValueError, binascii.Error):
        raise ValueError("invalid hashed known_hosts host") from None
    if len(salt) != 20 or len(digest) != 20:
        raise ValueError("invalid hashed known_hosts host")
    return any(hmac.compare_digest(hmac.new(salt, endpoint.encode("ascii"), hashlib.sha1).digest(), digest)
               for endpoint in endpoints)


def fingerprint(wire: bytes) -> str:
    return "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b"=").decode("ascii")


class HostPins:
    """known_hosts read once; keys per switch address on port 22."""

    def __init__(self, payload: bytes):
        self.lines = payload.splitlines()

    @classmethod
    def load(cls, path):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            item = os.fstat(fd)
            if not stat.S_ISREG(item.st_mode) or not 0 < item.st_size <= 16 * 1024 * 1024:
                raise ValueError("known_hosts must be a non-empty regular file")
            payload = os.read(fd, item.st_size + 1)
        finally:
            os.close(fd)
        if len(payload) != item.st_size:
            raise ValueError("known_hosts changed while reading")
        return cls(payload)

    def keys(self, address, port=22):
        """[(key type, base64 blob)] pinned for address; a matching @marker line refuses the host."""
        endpoints = {address, f"[{address}]:22"} if port == 22 else {f"[{address}]:{port}"}
        found = []
        for line in self.lines:
            if not line.strip() or line.lstrip().startswith(b"#"):
                continue
            fields = line.split()
            try:
                if fields[0].startswith(b"@"):
                    if len(fields) > 1 and endpoint_matches(fields[1], endpoints):
                        raise SshError("HOST_KEY_MISMATCH")
                    continue
                if len(fields) < 3 or not endpoint_matches(fields[0], endpoints):
                    continue
                public_key_identity_bytes(fields[1] + b" " + fields[2] + b"\n")
            except (ValueError, UnicodeError):
                continue                       # unrelated malformed line; other hosts' entries are not ours
            entry = (fields[1].decode("ascii"), fields[2].decode("ascii"))
            if entry not in found:
                found.append(entry)
        return found

    def fingerprints(self, address):
        return {fingerprint(base64.b64decode(blob)) for _kind, blob in self.keys(address)}

    def known_hosts_text(self, address, port=22):
        """Literal-address lines for a receiver switch's temporary known_hosts (review 15.13)."""
        host = address if port == 22 else f"[{address}]:{port}"
        return "".join(f"{host} {kind} {blob}\n" for kind, blob in self.keys(address, port))


@dataclass(frozen=True)
class Credentials:
    user: str
    key: object = field(default=None, repr=False)
    key_fingerprint: str | None = None
    password: str | None = field(default=None, repr=False)


def load_private_key(private_path, public_path):
    """Management key pair: the private key must match the public key file."""
    sdk = _sdk()
    path = Path(private_path)
    item = path.lstat()
    if not stat.S_ISREG(item.st_mode) or item.st_uid != os.geteuid() or item.st_mode & 0o077 or item.st_size > 1 << 20:
        raise SshError("KEY_INVALID")
    text = path.read_text(encoding="ascii")
    _kind, blob = public_key_identity_bytes(Path(public_path).read_bytes())
    expected = fingerprint(blob)
    for key_type in (sdk.Ed25519Key, sdk.RSAKey, sdk.ECDSAKey):
        try:
            key = key_type.from_private_key(io.StringIO(text))
        except (ValueError, sdk.SSHException):
            continue
        if not key.can_sign() or fingerprint(key.asbytes()) != expected:
            raise SshError("KEY_INVALID")
        return key, expected
    raise SshError("KEY_INVALID")


def _sdk():
    try:
        if any(metadata.version(name) != version for name, version in SSH_RUNTIME_PINS):
            raise ValueError("SSH runtime differs from the pinned versions")
        import paramiko
        return paramiko
    except Exception:
        raise SshError("SDK_UNAVAILABLE") from None


@dataclass
class Result:
    rc: int | None
    stdout: bytes
    stderr: bytes
    complete: bool
    seconds: float

    @property
    def ok(self):
        return self.complete and self.rc == 0 and not self.stderr


class Session:
    def __init__(self, transport, sock, address, authentication, server_fingerprint):
        self.transport, self.sock, self.address = transport, sock, address
        self.authentication, self.server_fingerprint = authentication, server_fingerprint
        self._sftp = None

    def __enter__(self):
        return self

    def __exit__(self, *_exc):
        self.close()

    def close(self):
        for owned in (self._sftp, self.transport, self.sock):
            try:
                if owned is not None:
                    owned.close()
            except Exception:
                pass
        self._sftp = None

    def run(self, command, *, timeout=COMMAND_SECONDS, stdin=None, limit=OUTPUT_LIMIT):
        """Run one command; the deadline starts when it is sent. Raises SshError on timeout/limit."""
        started = time.monotonic()
        deadline = started + timeout
        out, err = bytearray(), bytearray()
        try:
            channel = self.transport.open_session(timeout=max(0.1, deadline - time.monotonic()))
        except Exception:
            raise SshError("CHANNEL_FAILED") from None
        try:
            channel.settimeout(max(0.1, deadline - time.monotonic()))
            channel.exec_command(command)
            if stdin is not None:
                channel.sendall(stdin)
                channel.shutdown_write()
            while True:
                progressed = False
                while channel.recv_ready():
                    out += channel.recv(65536)
                    progressed = True
                while channel.recv_stderr_ready():
                    err += channel.recv_stderr(65536)
                    progressed = True
                if len(out) + len(err) > limit:
                    raise SshError("OUTPUT_LIMIT")
                if channel.closed and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if not self.transport.is_active() and not channel.recv_ready() and not channel.recv_stderr_ready():
                    break
                if time.monotonic() >= deadline:
                    raise SshError("COMMAND_TIMEOUT")
                if not progressed:
                    time.sleep(POLL_SECONDS)
            status = channel.recv_exit_status() if channel.exit_status_ready() else None
            complete = bool(channel.eof_received) and status is not None and status >= 0
            return Result(status if status is not None and status >= 0 else None, bytes(out), bytes(err),
                          complete, time.monotonic() - started)
        except SshError:
            raise
        except (OSError, EOFError, socket.timeout):
            raise SshError("COMMAND_INCOMPLETE") from None
        finally:
            try:
                channel.close()
            except Exception:
                pass

    def sftp(self):
        if self._sftp is None:
            try:
                self._sftp = _sdk().SFTPClient.from_transport(self.transport)
                self._sftp.get_channel().settimeout(COMMAND_SECONDS)
            except SshError:
                raise
            except Exception:
                raise SshError("CHANNEL_FAILED") from None
        return self._sftp


def _connect_socket(address, timeout):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(timeout)
        sock.connect((address, 22))
        return sock
    except socket.timeout:
        sock.close()
        raise SshError("CONNECT_TIMEOUT") from None
    except OSError as error:
        sock.close()
        if error.errno in (errno.EMFILE, errno.ENFILE, errno.ENOMEM, errno.ENOBUFS):
            raise
        raise SshError("CONNECT_FAILED") from None


def connect(address, pins, credentials, *, method="key", sock_factory=None):
    """One authenticated session. method is 'key' or 'password'."""
    sdk = _sdk()
    expected = pins.fingerprints(address)
    if not expected:
        raise SshError("HOST_KEY_UNKNOWN")
    sock = (sock_factory or _connect_socket)(address, CONNECT_SECONDS)
    transport = None
    try:
        transport = sdk.Transport(sock)
        transport.banner_timeout = HANDSHAKE_SECONDS
        transport.handshake_timeout = HANDSHAKE_SECONDS
        try:
            transport.start_client(timeout=HANDSHAKE_SECONDS)
        except Exception:
            raise SshError("HANDSHAKE_FAILED") from None
        server = fingerprint(transport.get_remote_server_key().asbytes())
        if server not in expected:
            raise SshError("HOST_KEY_MISMATCH")
        transport.auth_timeout = HANDSHAKE_SECONDS
        try:
            if method == "key":
                if credentials.key is None:
                    raise SshError("AUTH_REJECTED")
                transport.auth_publickey(credentials.user, credentials.key)
            elif method == "password":
                if not credentials.password:
                    raise SshError("AUTH_REJECTED")
                transport.auth_password(credentials.user, credentials.password, fallback=False)
            else:
                raise ValueError("authentication method must be key or password")
        except sdk.AuthenticationException as error:
            message = str(error)
            if message == "Authentication timeout.":
                raise SshError("AUTH_TIMEOUT") from None
            if message == "Authentication failed: transport shut down or saw EOF":
                raise SshError("AUTH_TRANSPORT_LOST") from None
            if message == "Authentication failed." and transport.is_active():
                raise SshError("PASSWORD_REJECTED" if method == "password" else "AUTH_REJECTED") from None
            raise SshError("AUTH_UNKNOWN") from None
        except (OSError, EOFError):
            raise SshError("AUTH_TRANSPORT_LOST") from None
        except sdk.SSHException:
            raise SshError("AUTH_UNKNOWN") from None
        if not transport.is_authenticated() or transport.get_username() != credentials.user:
            raise SshError("AUTH_REJECTED")
        transport.set_keepalive(30)             # long package transfers keep an otherwise idle session
        return Session(transport, sock, address, method, server)
    except BaseException:
        for owned in (transport, sock):
            try:
                if owned is not None:
                    owned.close()
            except Exception:
                pass
        raise


def connect_any(address, pins, credentials, *, sock_factory=None):
    """Key first; the password only after the key is explicitly rejected. Returns (session, key_rejected)."""
    try:
        return connect(address, pins, credentials, method="key", sock_factory=sock_factory), False
    except SshError as error:
        if error.code != "AUTH_REJECTED" or not credentials.password:
            raise
    return connect(address, pins, credentials, method="password", sock_factory=sock_factory), True


__all__ = ["SSH_RUNTIME_PINS", "Credentials", "HostPins", "Result", "Session", "SshError", "connect",
           "connect_any", "fingerprint", "load_private_key"]
