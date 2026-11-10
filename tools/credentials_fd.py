"""Read one JSON credential object from an inherited pipe fd (R-012 design §8.3, --credentials-fd).

A caller (initial-setup today; upgrade2 and ufm-setup-upgrade in L1) reads the fd once at its entry:
``read_credentials(fd, required=..., optional=...)`` reads to EOF (at most ``MAX_BYTES``), closes the
fd on every path, decodes one UTF-8 JSON object, keeps only the requested keys (other keys are
ignored) and checks their types.  A missing required key, a wrong type, a non-object, an oversize or
non-UTF-8 input and an unreadable fd all raise ``CredentialsError``; its message names at most the
key, never a value, and it carries no exception chain.  The caller exits 2 on it.

Keys (a caller may only request keys listed here; L1 adds keys and never changes these):

``jump_passwords``
    JSON object: jump switch host name -> password.  The jump switches of R-012 design §8.1:
    ``eth_jump`` rows and ``eth`` OOB Leafs; Spine jumps use the same table.  Index it with
    ``host_passwords(table, key=...)``, where ``key`` is the caller's host-name comparison
    (initial-setup passes ``tools.device_identity.short_key``, I-007 rule 6).
``nvos_initial_password``
    String: NVOS initial password.  When absent initial-setup uses ``admin`` (I14).
``ib_target_password``
    String: IB target password; the caller still checks it against the project global's hash.

Values are non-empty strings.  Standard library only, and no other ``tools`` module is imported, so
the module works both from the repository root and from a Leaf directory that carries
``tools/credentials_fd.py`` next to ``initial-setup.py`` (guide O5).
"""

from __future__ import annotations

import json
import os
from typing import Callable, Iterable

MAX_BYTES = 64 * 1024

_STRING = "string"
_HOST_TABLE = "host table"
KEY_TYPES = {
    "jump_passwords": _HOST_TABLE,
    "nvos_initial_password": _STRING,
    "ib_target_password": _STRING,
}


class CredentialsError(Exception):
    """The one refusal type of this module; its text never contains a credential value."""


def _fail(message: str) -> CredentialsError:
    # Built outside any except block so no decoder error (which holds the input) is chained.
    error = CredentialsError(message)
    error.__cause__ = None
    error.__context__ = None
    error.__suppress_context__ = True
    return error


def _read_all(fd: int) -> bytes:
    chunks = []
    total = 0
    failed = False
    try:
        while total <= MAX_BYTES:
            try:
                chunk = os.read(fd, MAX_BYTES + 1 - total)
            except OSError:
                failed = True
                break
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
    finally:
        try:
            os.close(fd)
        except OSError:
            failed = True
    if failed:
        raise _fail("credential fd is not readable")
    if total > MAX_BYTES:
        raise _fail(f"credential input exceeds {MAX_BYTES} bytes")
    return b"".join(chunks)


def _valid(kind: str, value: object) -> bool:
    if kind == _STRING:
        return type(value) is str and value != ""
    return (type(value) is dict and all(
        type(name) is str and name.strip() != "" and type(secret) is str and secret != ""
        for name, secret in value.items()))


def read_credentials(fd: int, *, required: Iterable[str], optional: Iterable[str]) -> dict:
    """Read, close and check the credential object; return only the requested keys present."""
    required, optional = tuple(required), tuple(optional)
    unknown = [key for key in required + optional if key not in KEY_TYPES]
    if unknown:
        raise ValueError(f"unregistered credential keys: {unknown}")
    raw = _read_all(fd)
    text = None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    if text is None:
        raise _fail("credential input is not UTF-8")
    document = None
    parsed = False
    try:
        document = json.loads(text)
        parsed = True
    except (ValueError, RecursionError):
        pass
    if not parsed:
        raise _fail("credential input is not one JSON value")
    if type(document) is not dict:
        raise _fail("credential input is not a JSON object")
    values = {}
    for key in required + optional:
        if key not in document:
            if key in required:
                raise _fail(f"credential key {key} is required")
            continue
        if not _valid(KEY_TYPES[key], document[key]):
            raise _fail(f"credential key {key} must be a non-empty {KEY_TYPES[key]}")
        values[key] = document[key]
    return values


def host_passwords(table: dict, *, key: Callable[[str], str]) -> dict:
    """Index a host table by the caller's comparison key; two hosts with one key are ambiguous."""
    indexed = {}
    for name, secret in table.items():
        comparable = key(name)
        if comparable in indexed:
            raise _fail("credential host table names one host twice")
        indexed[comparable] = secret
    return indexed
