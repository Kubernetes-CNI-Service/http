"""Exact local F01 SSH execution-environment identity; never install or permit.

The runner supplies its own source-snapshot lock digest. That digest is an
integrity comparison, not caller authority or a way to waive any check. Imports
occur only after fixed versions, unique metadata and all twelve RECORD-owned
files have been checked. Held originals are rechecked after the imports. No
socket, subprocess, credential, deployment or approval-ledger operation exists.
"""
from __future__ import annotations

import base64
import csv
from email.parser import BytesHeaderParser, BytesParser, HeaderParser
import hashlib
import importlib
import importlib.machinery
from importlib import metadata
import io
import os
from pathlib import Path
import re
import stat
import sys
import threading
import types


_PINS = {
    "paramiko": ("5.0.0", ("paramiko",)),
    "bcrypt": ("5.0.0", ("bcrypt", "bcrypt._bcrypt")),
    "cryptography": ("50.0.1", ("cryptography", "cryptography.hazmat.bindings._rust")),
    "invoke": ("2.2.1", ("invoke",)),
    "pynacl": ("1.6.2", ("nacl", "nacl._sodium")),
    "cffi": ("2.0.0", ("cffi", "_cffi_backend")),
    "pycparser": ("2.23", ("pycparser",)),
    "typing-extensions": ("4.16.0", ("typing_extensions",)),
}
_NATIVE = {"bcrypt._bcrypt", "cryptography.hazmat.bindings._rust", "nacl._sodium", "_cffi_backend"}
_LOCK = "requirements-f01-ssh.lock"


class F01DependencyError(ValueError):
    """Missing or ambiguous environment identity, never a downgrade or SKIP."""

    def __init__(self):
        super().__init__("unproved_f01_ssh_dependency_environment")


def _name(value):
    if type(value) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", value):
        raise F01DependencyError()
    return re.sub(r"[-_.]+", "-", value).lower()


def _absolute(value):
    if not isinstance(value, (str, Path)) or not str(value):
        raise F01DependencyError()
    path = Path(value)
    if not path.is_absolute() or str(path) != str(value) or ".." in path.parts:
        raise F01DependencyError()
    return path


def _within(path, parent):
    if path == parent or parent not in path.parents:
        raise F01DependencyError()


def _file_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_gid, info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def _directory_identity(info):
    return (info.st_dev, info.st_ino, info.st_mode)


class _OriginalReads:
    """One-call held FD graph; no persistent cache or resolved-path shortcut."""

    def __init__(self):
        self.directories = {}
        self.files = {}

    def directory(self, path):
        if path in self.directories:
            return self.directories[path][0]
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK | os.O_DIRECTORY
        parent = None if path == Path("/") else self.directory(path.parent)
        expected = (os.stat(str(path), follow_symlinks=False) if parent is None
                    else os.stat(path.name, dir_fd=parent, follow_symlinks=False))
        descriptor = os.open(str(path) if parent is None else path.name, flags, dir_fd=parent)
        actual = None
        try:
            actual = os.fstat(descriptor)
            named = (os.stat(str(path), follow_symlinks=False) if parent is None
                     else os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            if (_directory_identity(expected) != _directory_identity(actual)
                    or _directory_identity(named) != _directory_identity(actual)):
                raise F01DependencyError()
        except BaseException:
            # First-stat failure admits nothing. The named original is only
            # a cleanup fallback; it cannot authorize a recycled foreign slot.
            original = expected if actual is None else actual
            try:
                current = os.fstat(descriptor)
                if (current.st_dev, current.st_ino) == (original.st_dev, original.st_ino):
                    os.close(descriptor)
                else:
                    self.cleanup_unconfirmed = True
            except BaseException:
                self.cleanup_unconfirmed = True
            raise
        self.directories[path] = (descriptor, parent, actual)
        return descriptor

    @staticmethod
    def bytes(descriptor, maximum):
        os.lseek(descriptor, 0, os.SEEK_SET)
        chunks, remaining = [], maximum + 1
        while remaining:
            part = os.read(descriptor, min(remaining, 1024 * 1024))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if not raw or len(raw) > maximum:
            raise F01DependencyError()
        return raw

    def read(self, path, maximum):
        if path in self.files:
            return self.files[path][3]
        parent = self.directory(path.parent)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
        descriptor = os.open(path.name, flags, dir_fd=parent)
        try:
            info = os.fstat(descriptor)
            if (_file_identity(info) != _file_identity(named)
                    or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                    or not 0 < info.st_size <= maximum):
                raise F01DependencyError()
            raw = self.bytes(descriptor, maximum)
            if len(raw) != info.st_size or _file_identity(os.fstat(descriptor)) != _file_identity(info):
                raise F01DependencyError()
        except BaseException:
            try:
                current = os.fstat(descriptor)
                if (current.st_dev,current.st_ino)==(named.st_dev,named.st_ino):
                    os.close(descriptor)
                else:
                    self.cleanup_unconfirmed = True
            except BaseException:
                self.cleanup_unconfirmed = True
            raise
        self.files[path] = (descriptor, parent, info, raw, maximum)
        return raw

    def binding(self, path):
        return list(_file_identity(self.files[path][2]))

    def verify(self):
        for path, (descriptor, parent, info, raw, maximum) in self.files.items():
            named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
            if (_file_identity(named) != _file_identity(info)
                    or _file_identity(os.fstat(descriptor)) != _file_identity(info)
                    or self.bytes(descriptor, maximum) != raw):
                raise F01DependencyError()
        for path, (descriptor, parent, info) in self.directories.items():
            named = (os.stat("/", follow_symlinks=False) if parent is None
                     else os.stat(path.name, dir_fd=parent, follow_symlinks=False))
            if (_directory_identity(named) != _directory_identity(info)
                    or _directory_identity(os.fstat(descriptor)) != _directory_identity(info)):
                raise F01DependencyError()

    def close(self):
        for descriptor, *_ in self.files.values():
            os.close(descriptor)
        for descriptor, *_ in reversed(list(self.directories.values())):
            os.close(descriptor)


class _LexicalOriginals(_OriginalReads):
    """Private source FD pool; logical role releases never claim physical close."""
    def __init__(self):
        super().__init__()
        self.context = (os.getpid(), threading.get_ident())
        self.active = True

    def _check(self):
        if not self.active or self.context != (os.getpid(), threading.get_ident()):
            raise F01DependencyError()

    def view(self, role):
        self._check()
        if role not in {"ENV", "FACTORY", "CHANNEL"}:
            raise F01DependencyError()
        return _LexicalView(self, role)

    def read(self, path, maximum):
        self._check()
        if path not in self.files:
            return super().read(path, maximum)
        descriptor, parent, info, raw, _maximum = self.files[path]
        before = os.fstat(descriptor)
        named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (_file_identity(before) != _file_identity(info)
                or _file_identity(named) != _file_identity(info)
                or len(raw) > maximum):
            raise F01DependencyError()
        current = self.bytes(descriptor, maximum)
        if (_file_identity(os.fstat(descriptor)) != _file_identity(info)
                or _file_identity(os.stat(path.name, dir_fd=parent, follow_symlinks=False)) != _file_identity(info)
                or current != raw):
            raise F01DependencyError()
        return current

    def close(self):
        # Revoke before every physical release; all other originals are tried.
        self.active = False
        errors = []
        for table in (self.files, dict(reversed(list(self.directories.items())))):
            for descriptor, _parent, info, *_rest in table.values():
                try:
                    current = os.fstat(descriptor)
                    if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
                        raise F01DependencyError()
                    os.close(descriptor)
                except BaseException as error:
                    errors.append(error)
        self.files.clear(); self.directories.clear()
        if getattr(self, "cleanup_unconfirmed", False):
            errors.append(F01DependencyError())
        if errors:
            hold = F01DependencyError()
            hold.cleanup_errors = tuple(errors)
            operator = next((e for e in errors if not isinstance(e, Exception)), None)
            if operator is not None:
                raise operator from hold
            raise hold from errors[0]


class _LexicalView(_OriginalReads):
    """Per-role/checkpoint members; actual reads and verify points stay distinct."""
    def __init__(self, pool, role):
        self.pool, self.role, self.active = pool, role, True
        self.files = {}; self.directories = {}

    def _check(self):
        if not self.active or type(self.pool) is not _LexicalOriginals:
            raise F01DependencyError()
        self.pool._check()

    def read(self, path, maximum):
        self._check()
        if path in self.files:
            return self.files[path][3] # original intra-checkpoint cache only
        current = self.pool.read(path, maximum) # actual reread on every new view
        original = self.pool.files[path]
        self.files[path] = (original[0], original[1], original[2], current, maximum)
        parent = path.parent
        ancestors = []
        while True:
            ancestors.append(parent)
            if parent == Path("/"):
                break
            parent = parent.parent
        for parent in reversed(ancestors):
            self.directories[parent] = self.pool.directories[parent]
        return current

    def verify(self):
        self._check()
        super().verify() # exact original per-role name/FD/bytes/ancestor checks

    def close(self):
        self.active = False # physical pool originals remain owned until scope exit


def _lock_pins(raw):
    pins = {}
    for line in raw.decode("ascii").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        match = re.fullmatch(r"([A-Za-z0-9][A-Za-z0-9._-]*)==([0-9]+(?:\.[0-9]+)+)", line)
        if match is None:
            raise F01DependencyError()
        name = _name(match[1])
        if name in pins:
            raise F01DependencyError()
        pins[name] = match[2]
    if pins != {name: value[0] for name, value in _PINS.items()}:
        raise F01DependencyError()


def _config(raw):
    pairs = {}
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        if "=" not in line:
            raise F01DependencyError()
        key, value = (part.strip() for part in line.split("=", 1))
        if not key or key in pairs:
            raise F01DependencyError()
        pairs[key] = value
    if pairs.get("include-system-site-packages") != "false":
        raise F01DependencyError()


def _inventory_headers(distribution):
    """One full fresh exact-distribution text; inventory uses headers only.

    This private parsed copy is not an original/approval. Later owned
    METADATA/RECORD byte hashes and every verify still consume full bytes.
    """
    if type(distribution) is not metadata.PathDistribution:
        raise F01DependencyError()
    text = (distribution.read_text("METADATA")
            or distribution.read_text("PKG-INFO") or distribution.read_text(""))
    if type(text) is not str:
        raise F01DependencyError()
    parsed = HeaderParser().parsestr(text)
    parsed.set_payload(None)  # opaque body is not inventory identity
    return metadata._adapters.Message(parsed)  # original standard header repair


def _visible_distributions(prefix):
    found = {}
    for distribution in metadata.distributions():
        if not isinstance(distribution, metadata.PathDistribution):
            raise F01DependencyError()
        # One actual fresh metadata view, not a cache across discovery/checks.
        # PathDistribution.version otherwise parses the SAME METADATA again.
        fields = (_inventory_headers(distribution)
                  if type(distribution) is metadata.PathDistribution
                  else distribution.metadata)
        name = _name(fields["Name"])
        if name not in _PINS:
            continue
        path = _absolute(distribution._path)
        _within(path, prefix)
        if (name in found or not path.name.endswith(".dist-info")
                or fields["Version"] != _PINS[name][0]):
            raise F01DependencyError()
        found[name] = path
    if set(found) != set(_PINS):
        raise F01DependencyError()
    return found


def _metadata_record(raw, name, version):
    fields = BytesHeaderParser().parsebytes(raw)
    if (len(fields.get_all("Name", [])) != 1 or len(fields.get_all("Version", [])) != 1
            or _name(fields["Name"]) != name or fields["Version"] != version):
        raise F01DependencyError()


def _record(raw):
    records = {}
    for row in csv.reader(io.StringIO(raw.decode("utf-8"), newline=""), strict=True):
        if len(row) != 3 or not row[0] or row[0] in records:
            raise F01DependencyError()
        records[row[0]] = (row[1], row[2])
    return records


def _record_file(reads, site, records, relative, maximum):
    path, raw, _digest = _record_file_digest(reads, site, records, relative, maximum)
    return path, raw


def _record_file_digest(reads, site, records, relative, maximum):
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts or str(relative_path) != relative:
        raise F01DependencyError()
    path = site / relative_path
    _within(path, site)
    raw = reads.read(path, maximum)
    digest = hashlib.sha256(raw).digest()
    expected = ("sha256=" + base64.urlsafe_b64encode(digest).decode("ascii").rstrip("="), str(len(raw)))
    if records.get(relative) != expected:
        raise F01DependencyError()
    return path, raw, digest.hex()


def f01_ssh_dependency_environment(repo_root, *, expected_lock_sha256):
    """Return JSON-safe identity; uncertainty closes before approval or permit."""
    reads = _OriginalReads()
    return _environment_on_original_reads(repo_root, expected_lock_sha256=expected_lock_sha256, reads=reads)


def _environment_on_original_reads(repo_root, *, expected_lock_sha256, reads):
    if type(reads) not in {_OriginalReads, _LexicalView}:
        raise F01DependencyError()
    try:
        if (type(expected_lock_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", expected_lock_sha256) is None):
            raise F01DependencyError()
        root = _absolute(repo_root)
        prefix, base = _absolute(sys.prefix), _absolute(sys.base_prefix)
        executable = _absolute(sys.executable)
        _within(executable, prefix)
        if prefix == base:
            raise F01DependencyError()
        runtime = (str(prefix), str(base), str(executable))
        lock = reads.read(root / _LOCK, 65536)
        lock_sha = hashlib.sha256(lock).hexdigest()
        if lock_sha != expected_lock_sha256:
            raise F01DependencyError()
        _lock_pins(lock)
        config_path = prefix / "pyvenv.cfg"
        config = reads.read(config_path, 65536)
        _config(config)
        visible = _visible_distributions(prefix)
        result, imports = [], []
        # Hold and validate every original before any optional/native import.
        for name in sorted(_PINS):
            version, module_names = _PINS[name]
            info, sources = visible[name], []
            metadata_path, record_path = info / "METADATA", info / "RECORD"
            meta = reads.read(metadata_path, 65536)
            record_bytes = reads.read(record_path, 8 * 1024 * 1024)
            _metadata_record(meta, name, version)
            records = _record(record_bytes)
            _metadata_path, _metadata_raw, metadata_digest = _record_file_digest(
                reads, info.parent, records, info.name + "/METADATA", 65536)
            for module_name in module_names:
                stem = module_name.replace(".", "/")
                candidates = ([stem + suffix for suffix in importlib.machinery.EXTENSION_SUFFIXES]
                              if module_name in _NATIVE else [stem + ".py", stem + "/__init__.py"])
                matches = [path for path in candidates if path in records]
                if len(matches) != 1:
                    raise F01DependencyError()
                path, raw, module_digest = _record_file_digest(
                    reads, info.parent, records, matches[0], 128 * 1024 * 1024)
                sources.append({"name": module_name, "origin": str(path),
                                "sha256": module_digest, "size_bytes": len(raw),
                                "file_identity": reads.binding(path)})
                imports.append((module_name, path))
            result.append({"name": name, "version": version, "metadata_path": str(info),
                           "metadata_sha256": metadata_digest,
                           "record_sha256": hashlib.sha256(record_bytes).hexdigest(),
                           "metadata_identity": reads.binding(metadata_path),
                           "record_identity": reads.binding(record_path), "modules": sources})
        reads.verify()
        imported = []
        for name, path in imports:
            module = importlib.import_module(name)
            spec = getattr(module, "__spec__", None)
            expected_loader = (importlib.machinery.ExtensionFileLoader if name in _NATIVE
                               else importlib.machinery.SourceFileLoader)
            if (not isinstance(module, types.ModuleType) or spec is None or spec.name != name
                    or not isinstance(spec.loader, expected_loader)
                    or getattr(module, "__file__", None) != str(path) or spec.origin != str(path)
                    or spec.loader.get_filename(name) != str(path)):
                raise F01DependencyError()
            imported.append((name, path, module))
        if visible != _visible_distributions(prefix):
            raise F01DependencyError()
        for name, path, module in imported:
            spec = getattr(module, "__spec__", None)
            expected_loader = (importlib.machinery.ExtensionFileLoader if name in _NATIVE
                               else importlib.machinery.SourceFileLoader)
            if (spec is None or spec.name != name or spec.origin != str(path)
                    or getattr(module, "__file__", None) != str(path)
                    or not isinstance(spec.loader, expected_loader)
                    or spec.loader.get_filename(name) != str(path)):
                raise F01DependencyError()
        if (str(sys.prefix), str(sys.base_prefix), str(sys.executable)) != runtime:
            raise F01DependencyError()
        reads.verify()
        return {"schema_version": 1, "lock_sha256": lock_sha,
                "python_executable": str(executable), "environment_prefix": str(prefix),
                "base_prefix": str(base), "pyvenv_cfg_sha256": hashlib.sha256(config).hexdigest(),
                "pyvenv_cfg_identity": reads.binding(config_path), "distributions": result}
    except F01DependencyError:
        raise
    except (OSError, ValueError, TypeError, AttributeError, KeyError, UnicodeError,
            ImportError, csv.Error, RecursionError):
        raise F01DependencyError() from None
    finally:
        reads.close()
