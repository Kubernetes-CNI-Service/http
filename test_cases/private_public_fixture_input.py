"""Test-only private fixture reader with source-pinned original content proof.

Canonical destination proposed: test_cases/private_public_fixture_input.py.
No private input is opened at import. The environment supplies only a locator;
the canonical payload length/digest come from independently fixed source bytes.
This is not the external three-field KAT ABI or a same-UID sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import sys
import threading

INPUT_ENV = "HTTP_TEST_PUBLIC_FIXTURE_INPUT_BINDING"
LOCATOR_ENV = "HTTP_TEST_PUBLIC_FIXTURE_INPUT_PATH"
ORIGINAL_PAYLOAD_BYTES = 507
ORIGINAL_PAYLOAD_SHA256 = "3dbf3ead249c15db03371d1e7db9758d14978a22778d34193c084a14d0677453"
INPUT_SCHEMA = "http-test.private-public-fixture-input/v1"
VALUE_KEYS = (
    "handoff_transport_password",
    "pending_diff_password",
    "collector_prefix_secret",
    "cache_admission_key_0",
    "cache_admission_key_1",
)
ROOT_BINDING = None
_UNKNOWN = False
_SECONDARY = []
_CALL_LOCK = threading.Lock()
_NINE_FIELDS = (
    "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
    "st_size", "st_mtime_ns", "st_ctime_ns",
)


class PrivateFixtureInputError(RuntimeError):
    """Readiness/custody failure; never a business-test success or skip."""


def _need(condition, message):
    if not condition:
        raise PrivateFixtureInputError(message)


def _nine(info):
    return tuple(str(getattr(info, field)) for field in _NINE_FIELDS)


def _valid9(value):
    return (
        type(value) is list and len(value) == 9
        and all(type(part) is str and part.isascii() and part.isdecimal()
                for part in value)
    )


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        _need(type(key) is str and key not in result,
              "private fixture JSON keys are invalid or duplicated")
        result[key] = value
    return result


def _json(data):
    # All parser failures are translated after leaving the except suite:
    # no raw decoder exception, duplicate key or input value in args/context.
    failure = None
    if type(data) is bytes:
        try:
            data = data.decode("utf-8", "strict")
        except UnicodeDecodeError:
            failure = "private fixture UTF-8 is invalid"
    if failure is None and type(data) is str:
        depth, quoted, escaped = 0, False, False
        for character in data:
            if quoted:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    quoted = False
            elif character == '"':
                quoted = True
            elif character in "[{":
                depth += 1
                if depth > 16:
                    failure = "private fixture JSON is invalid"
                    break
            elif character in "]}":
                depth -= 1
    if failure is None:
        try:
            result = json.loads(data, object_pairs_hook=_pairs,
                                parse_constant=lambda unused: _invalid_constant())
        except (PrivateFixtureInputError, UnicodeError, ValueError,
                TypeError, RecursionError, OverflowError):
            failure = "private fixture JSON is invalid"
    if failure is not None:
        data = None
        raise PrivateFixtureInputError(failure) from None
    return result


def _invalid_constant():
    raise PrivateFixtureInputError("private fixture JSON is invalid")


def _digest(value):
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _binding():
    # The old self-certifying JSON environment route remains forbidden. The
    # new environment item is an untrusted absolute path, never a content pin.
    environment = os.environ.get(INPUT_ENV)
    locator = os.environ.get(LOCATOR_ENV)
    _need(environment is None,
          "private fixture environment cannot establish original input identity")
    _need(locator is None or type(locator) is str,
          "private fixture locator environment is invalid")
    _need(not (ROOT_BINDING is not None and locator is not None),
          "private fixture metadata has two binding sources")
    _need(type(ORIGINAL_PAYLOAD_BYTES) is int
          and 0 < ORIGINAL_PAYLOAD_BYTES <= 65536
          and _digest(ORIGINAL_PAYLOAD_SHA256),
          "private fixture fixed original proof is invalid")
    if ROOT_BINDING is None:
        _need(locator is not None,
              "private fixture independent binding or locator is absent")
        value = {
            "path": locator, "bytes": ORIGINAL_PAYLOAD_BYTES,
            "SHA256": ORIGINAL_PAYLOAD_SHA256,
            "native9": None, "parent_native9": None,
            "original_input": {
                "bytes": ORIGINAL_PAYLOAD_BYTES,
                "SHA256": ORIGINAL_PAYLOAD_SHA256,
            },
        }
    else:
        value = ROOT_BINDING
    _need(type(value) is dict and set(value) == {
        "path", "bytes", "SHA256", "native9", "parent_native9", "original_input",
    }, "private fixture independent Root binding is absent or unsupported")
    original = value["original_input"]
    _need(type(original) is dict and set(original) == {"bytes", "SHA256"}
          and type(original["bytes"]) is int
          and 0 < original["bytes"] <= 65536 and _digest(original["SHA256"]),
          "private fixture original input proof is absent or unsupported")
    _need(original["bytes"] == ORIGINAL_PAYLOAD_BYTES
          and original["SHA256"] == ORIGINAL_PAYLOAD_SHA256,
          "private fixture original proof differs from fixed source anchor")
    path = value["path"]
    _need(type(path) is str and path.startswith("/") and "\0" not in path
          and os.path.normpath(path) == path
          and all(part not in ("", ".", "..") for part in path.split("/")[1:])
          and len(path.split("/")) >= 3,
          "private fixture input path is not canonical absolute metadata")
    _need(type(value["bytes"]) is int and 0 < value["bytes"] <= 65536,
          "private fixture input byte count is invalid")
    _need(_digest(value["SHA256"]),
          "private fixture input SHA256 is invalid")
    _need(value["bytes"] == original["bytes"]
          and value["SHA256"] == original["SHA256"],
          "private fixture pin differs from independent original input proof")
    if ROOT_BINDING is None:
        _need(value["native9"] is None and value["parent_native9"] is None,
              "locator cannot carry native identity authority")
        file9 = parent9 = None
    else:
        _need(_valid9(value["native9"]) and _valid9(value["parent_native9"]),
              "private fixture native identities are invalid")
        file9, parent9 = tuple(value["native9"]), tuple(value["parent_native9"])
    # Per-call snapshot; locator-route identities are established under held
    # directory FDs and checked against the same fixed original digest.
    return {"path": path, "bytes": value["bytes"], "SHA256": value["SHA256"],
            "native9": file9, "parent_native9": parent9}


def _file_identity(info, expected):
    _need(stat.S_ISREG(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o600
          and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
          and info.st_nlink == 1 and _nine(info) == tuple(expected),
          "private fixture input file identity or permission differs")


def _parent_identity(info, expected):
    _need(stat.S_ISDIR(info.st_mode) and stat.S_IMODE(info.st_mode) == 0o700
          and info.st_uid == os.geteuid() and info.st_gid == os.getegid()
          and info.st_nlink >= 1 and _nine(info) == tuple(expected),
          "private fixture input parent identity or permission differs")


def _pending_owner(descriptor):
    return {"fd": descriptor, "birth": None, "state": "pending"}


def _establish_owner(owner, expected, validator):
    try:
        current = os.fstat(owner["fd"])
        validator(current, expected)
    except BaseException:
        owner["state"] = "unknown"
        raise
    owner["birth"] = _nine(current)
    owner["state"] = "verified"
    return current


def _verified_owner(owner):
    _need(owner["state"] == "verified" and owner["birth"] is not None,
          "private fixture FD has no verified ownership")
    try:
        current = os.fstat(owner["fd"])
        _need(_nine(current) == owner["birth"],
              "private fixture held FD identity changed")
    except BaseException:
        owner["state"] = "unknown"
        raise
    return current


def _read_owned(owner, amount):
    _verified_owner(owner)
    result = os.read(owner["fd"], amount)
    _verified_owner(owner)
    return result


def _rewind_owned(owner):
    _verified_owner(owner)
    os.lseek(owner["fd"], 0, os.SEEK_SET)
    _verified_owner(owner)


def _directory_identity(info, expected):
    _need(stat.S_ISDIR(info.st_mode) and _nine(info) == tuple(expected),
          "private fixture ancestor directory identity differs")


def _open_owned(name, flags, expected, validator, owned, *, directory=None):
    if directory is None:
        descriptor = os.open(name, flags)
    else:
        _verified_owner(directory)
        descriptor = os.open(name, flags, dir_fd=directory["fd"])
    # The very next operation registers a returned number, before any fstat.
    owner = _pending_owner(descriptor)
    owned.append(owner)
    _establish_owner(owner, expected, validator)
    return owner


def _walk_parent(path, binding, owned):
    parent, leaf = os.path.split(path)
    flags = (os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
             | os.O_CLOEXEC | os.O_NONBLOCK)
    root_info = os.lstat("/")
    root9 = _nine(root_info)
    _directory_identity(root_info, root9)
    current = _open_owned("/", flags, root9, _directory_identity, owned)
    root = current
    edges = []
    components = parent.split("/")[1:]
    for index, name in enumerate(components):
        _verified_owner(current)
        named = os.stat(name, dir_fd=current["fd"], follow_symlinks=False)
        expected = (_nine(named) if index < len(components) - 1
                    or binding["parent_native9"] is None
                    else binding["parent_native9"])
        validator = (_directory_identity if index < len(components) - 1
                     else _parent_identity)
        if index == len(components) - 1 and binding["parent_native9"] is None:
            # Locator-only: acquire the parent identity under the held ancestor.
            validator(named, expected)
            binding["parent_native9"] = tuple(expected)
        validator(named, expected)
        child = _open_owned(name, flags, expected, validator, owned,
                            directory=current)
        edges.append((current, name, child, validator, expected))
        current = child
    return root, root9, edges, current, parent, leaf


def _check_path(root, root9, edges, parent_owner, parent, binding):
    _directory_identity(_verified_owner(root), root9)
    _directory_identity(os.lstat("/"), root9)
    for ancestor, name, child, validator, expected in edges:
        _verified_owner(ancestor)
        validator(os.stat(name, dir_fd=ancestor["fd"], follow_symlinks=False),
                  expected)
        validator(_verified_owner(child), expected)
    # Absolute lstat is an additional check, never the path used for open/read.
    _parent_identity(os.lstat(parent), binding["parent_native9"])
    _parent_identity(_verified_owner(parent_owner), binding["parent_native9"])


def require_fixture_value(key):
    """One main-thread call at a time; any contention/failure sticks UNKNOWN.

    This is a finite source-input reader, not a same-process hostile-code sandbox.
    Root must qualify the independent original_input digest before binding it.
    """
    global _UNKNOWN
    _need(not _UNKNOWN, "private fixture reader has sticky UNKNOWN custody")
    if threading.current_thread() is not threading.main_thread():
        _UNKNOWN = True
        raise PrivateFixtureInputError("private fixture reader requires the main thread")
    if not _CALL_LOCK.acquire(blocking=False):
        _UNKNOWN = True
        raise PrivateFixtureInputError("private fixture reader rejects concurrent entry")
    try:
        return _require_fixture_value_locked(key)
    finally:
        _CALL_LOCK.release()


def _require_fixture_value_locked(key):
    global _UNKNOWN
    _need(not _UNKNOWN, "private fixture reader has sticky UNKNOWN custody")
    primary = None
    owned = []
    answer = None
    try:
        _need(type(key) is str and key in VALUE_KEYS,
              "private fixture value key is unsupported")
        binding = _binding()
        path = binding["path"]
        root, root9, edges, parent_owner, parent, leaf = _walk_parent(
            path, binding, owned)
        parent_fd = parent_owner["fd"]
        named_leaf = os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False)
        if binding["native9"] is None:
            # Locator-only: discover the leaf identity under the held parent.
            _file_identity(named_leaf, _nine(named_leaf))
            binding["native9"] = tuple(_nine(named_leaf))
        _file_identity(named_leaf, binding["native9"])
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        file_owner = _open_owned(leaf, flags, binding["native9"], _file_identity,
                                 owned, directory=parent_owner)
        reads = []
        for _ in range(2):
            _file_identity(_verified_owner(file_owner), binding["native9"])
            chunks = []
            total = 0
            while True:
                chunk = _read_owned(file_owner, min(131072, binding["bytes"] + 1 - total))
                if not chunk:
                    break
                chunks.append(chunk)
                total += len(chunk)
                _need(total <= binding["bytes"], "private fixture input exceeds its pin")
            _need(_read_owned(file_owner, 1) == b"", "private fixture explicit EOF differs")
            raw = b"".join(chunks)
            _need(len(raw) == binding["bytes"]
                  and hashlib.sha256(raw).hexdigest() == binding["SHA256"],
                  "private fixture complete content pin differs")
            _file_identity(_verified_owner(file_owner), binding["native9"])
            _file_identity(os.stat(leaf, dir_fd=parent_fd, follow_symlinks=False),
                           binding["native9"])
            _check_path(root, root9, edges, parent_owner, parent, binding)
            reads.append(raw)
            _rewind_owned(file_owner)
        _need(reads[0] == reads[1], "private fixture complete reads differ")
        data = _json(reads[0])
        _need(type(data) is dict and set(data) == {"schema", "values"}
              and type(data["schema"]) is str and data["schema"] == INPUT_SCHEMA,
              "private fixture payload schema differs")
        values = data["values"]
        _need(type(values) is dict and set(values) == set(VALUE_KEYS)
              and all(type(value) is str and value and "\0" not in value
                      for value in values.values()),
              "private fixture value set differs")
        answer = values[key]
    except BaseException:
        primary = sys.exc_info()
        _UNKNOWN = True
    while owned:
        owner = owned.pop()
        if owner["state"] != "verified" or owner["birth"] is None:
            _UNKNOWN = True
            continue
        try:
            _verified_owner(owner)
        except BaseException:
            _UNKNOWN = True
            if primary is None:
                primary = sys.exc_info()
            else:
                _SECONDARY.append(sys.exc_info()[1])
            continue
        owner["state"] = "consumed"
        try:
            os.close(owner["fd"])
        except BaseException:
            owner["state"] = "unknown"
            _UNKNOWN = True
            if primary is None:
                primary = sys.exc_info()
            else:
                _SECONDARY.append(sys.exc_info()[1])
    if primary is not None:
        raise primary[1].with_traceback(primary[2])
    _need(not _UNKNOWN, "private fixture reader has unresolved FD custody")
    return answer


if __name__ == "__main__":
    raise SystemExit("STOPPED: never run this reader as a script")
