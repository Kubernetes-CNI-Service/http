"""Fake-only candidate for REQ7 fixed-path private inputs and info shape.

The parser alone proves no FD authority. The fixed-path reader below is only
fake-tested here, not native-root/RO-bind verified. Neither imports google-auth,
interprets/signs private keys, refreshes a token, opens network, or grants send
authority. The governed public SDK must separately validate/consume the mapping;
native/container identity and authentication remain separate proof obligations.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import json
import os
import stat
from types import MappingProxyType
from typing import Mapping


TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"
SHEETS_SCOPE = "https://www.googleapis.com/auth/spreadsheets"
_MAX_BYTES = 65536
_REQUIRED = frozenset(("type", "private_key", "client_email", "token_uri"))
_ALLOWED = _REQUIRED | frozenset((
    "project_id", "private_key_id", "client_id", "auth_uri",
    "auth_provider_x509_cert_url", "client_x509_cert_url", "universe_domain",
))


class CredentialShapeHold(ValueError):
    """Only a sanitized reason, never source bytes, fields or parser context."""

    def __init__(self):
        super().__init__("credential_shape_invalid")


class CredentialFileHold(ValueError):
    def __init__(self):
        super().__init__("credential_file_authority_invalid")


@dataclass(frozen=True)
class ParsedServiceAccountInfo:
    mapping: Mapping[str, str] = field(repr=False)
    scope: str = SHEETS_SCOPE


def _pairs(pairs):
    mapping = {}
    for key, value in pairs:
        if key in mapping:
            raise CredentialShapeHold()
        mapping[key] = value
    return mapping


def _constant(_value):
    raise CredentialShapeHold()


def parse_service_account_info(source_bytes):
    """Preserve the original mapping; no path reopen, claims or ADC fallback."""
    if type(source_bytes) is not bytes or not 1 <= len(source_bytes) <= _MAX_BYTES:
        raise CredentialShapeHold()
    try:
        mapping = json.loads(source_bytes.decode("utf-8", errors="strict"),
                             object_pairs_hook=_pairs, parse_constant=_constant)
    except (ValueError, UnicodeError, RecursionError):
        raise CredentialShapeHold() from None
    if (type(mapping) is not dict or not _REQUIRED <= set(mapping)
            or not set(mapping) <= _ALLOWED
            or any(type(value) is not str or not value.strip() for value in mapping.values())
            or mapping["type"] != "service_account"
            or mapping["token_uri"] != TOKEN_ENDPOINT
            or mapping.get("universe_domain", "googleapis.com") != "googleapis.com"):
        raise CredentialShapeHold()
    return ParsedServiceAccountInfo(MappingProxyType(mapping))


def _directory_identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_uid, value.st_gid)


def _file_identity(value):
    return (_directory_identity(value), value.st_nlink, value.st_size,
            value.st_mtime_ns, value.st_ctime_ns)


def _root_directory(value, *, private=False):
    if (not stat.S_ISDIR(value.st_mode) or value.st_uid != 0
            or value.st_mode & 0o022
            or (private and stat.S_IMODE(value.st_mode) != 0o700)):
        raise CredentialFileHold()


def _read_private_file(basename):
    """Read one of the two fixed C-1 names, never an argv/env override.

    Every ancestor remains held and name-bound through readback. One bounded
    read of the verified file FD precedes fresh fstat/name identity checks;
    no recovery, ownership/mode repair, second read or path reopen is allowed.
    CGI must not call this function. It is not a network/send entrypoint.
    """
    with _hold_private_file(basename) as (source, verify):
        verify()
    return source


@contextmanager
def _hold_private_file(basename):
    """Private continuous original scope; the same fixed names and one read.

    No replacement name is adopted during this scope. Rechecks use the held
    file/ancestor metadata, including file ctime, not a new read or reopen.
    """
    if (type(basename) is not str
            or basename not in ("cre.json", "issue-tracker-spreadsheet-whitelist.json")
            or os.geteuid() != 0):
        raise CredentialFileHold()
    if any(not hasattr(os, flag) for flag in ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")):
        raise CredentialFileHold()
    directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    file_flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    descriptors, directories, edges = [], [], []
    close_failed = False
    try:
        parent = os.open("/", directory_flags)
        descriptors.append(parent)
        meta = os.fstat(parent)
        _root_directory(meta)
        directories.append((parent, meta, False))
        components = ("var", "lib", "http-ztp-container", "service-account")
        for name in components:
            child = os.open(name, directory_flags, dir_fd=parent)
            descriptors.append(child)
            meta = os.fstat(child)
            private = name == "service-account"
            _root_directory(meta, private=private)
            directories.append((child, meta, private))
            edges.append((parent, name, child, meta))
            parent = child
        file_fd = os.open(basename, file_flags, dir_fd=parent)
        descriptors.append(file_fd)
        file_meta = os.fstat(file_fd)
        if (not stat.S_ISREG(file_meta.st_mode) or file_meta.st_uid != 0
                or stat.S_IMODE(file_meta.st_mode) != 0o600 or file_meta.st_nlink != 1
                or not 1 <= file_meta.st_size <= _MAX_BYTES):
            raise CredentialFileHold()
        source = os.read(file_fd, _MAX_BYTES + 1)
        if len(source) != file_meta.st_size:
            raise CredentialFileHold()
        def verify():
            if (os.geteuid() != 0
                    or _file_identity(os.fstat(file_fd)) != _file_identity(file_meta)
                    or _file_identity(os.stat(basename, dir_fd=parent, follow_symlinks=False))
                    != _file_identity(file_meta)):
                raise CredentialFileHold()
            for fd, before, private in directories:
                after = os.fstat(fd)
                _root_directory(after, private=private)
                if _directory_identity(after) != _directory_identity(before):
                    raise CredentialFileHold()
            for ancestor, name, child, before in edges:
                if (_directory_identity(os.stat(name, dir_fd=ancestor, follow_symlinks=False))
                        != _directory_identity(before)):
                    raise CredentialFileHold()
        verify()
        yield source, verify
        verify()
    except (OSError, ValueError, TypeError, OverflowError):
        raise CredentialFileHold() from None
    finally:
        for fd in reversed(descriptors):
            try:
                os.close(fd)
            except OSError:
                close_failed = True
    if close_failed:
        raise CredentialFileHold()


def read_service_account_info():
    """Root-only fixed cre.json reader; parsing consumes the single FD read."""
    return parse_service_account_info(_read_private_file("cre.json"))


def read_target_allowlist():
    """Root-only fixed whitelist reader; no config-derived entries or path input."""
    from monitor.issue_tracker_online_target import freeze_target_allowlist

    return freeze_target_allowlist(
        _read_private_file("issue-tracker-spreadsheet-whitelist.json"))
