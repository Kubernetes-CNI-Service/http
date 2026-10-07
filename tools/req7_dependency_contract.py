"""REQ7 C-14 public dependency contracts; no SDK import, install or network.

Policy/lock hashes bind source identity, not deployment approval. Linux wheel
artifacts cover CPython 3.12 aarch64/x86_64 only. Development metadata identity
is separate and does not claim those Linux binaries ran on the local machine.
"""

from dataclasses import dataclass
from importlib import metadata
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


POLICY_PATH = "infra/docker/req7-dependency-policy.json"
LOCK_PATH = "infra/docker/requirements-req7-online.txt"
PINS = (("google-auth", "2.50.0"), ("pyasn1-modules", "0.4.2"),
        ("pyasn1", "0.6.4"), ("cryptography", "50.0.1"),
        ("cffi", "2.0.0"), ("pycparser", "2.23"))
_POLICY_KEYS = {"schema_version", "contract", "python", "platform", "architectures",
                "extras", "distributions", "artifacts", "development_conditional", "forbidden_transports"}
_LOCK_HEADER = "# REQ7 C-14: CPython 3.12 Linux aarch64/x86_64; wheels only; no extras; pip --no-deps --require-hashes."


class DependencyContractError(ValueError):
    def __init__(self): super().__init__("invalid_req7_dependency_contract")


@dataclass(frozen=True)
class DependencyContract:
    policy_sha256: str
    lock_sha256: str
    distributions: tuple
    artifacts: tuple


@dataclass(frozen=True)
class DependencyIdentity:
    policy_sha256: str
    lock_sha256: str
    versions: tuple


def _identity(value):
    return (value.st_dev, value.st_ino, value.st_mode, value.st_nlink,
            value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def _read(root, relative):
    """Hold each directory and a bounded single-link leaf; never follow links."""
    held = []
    bindings = []
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        root = Path(root)
        directory = os.open(root, flags | os.O_DIRECTORY); held.append(directory)
        original = os.fstat(directory)
        for part in Path(relative).parts[:-1]:
            parent = directory
            directory = os.open(part, flags | os.O_DIRECTORY, dir_fd=parent)
            held.append(directory); bindings.append((parent, part, os.fstat(directory)))
        name = Path(relative).name
        leaf = os.open(name, flags, dir_fd=directory); held.append(leaf)
        before = os.fstat(leaf)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= 65536:
            raise DependencyContractError()
        data = os.read(leaf, 65537)
        if len(data) != before.st_size or _identity(before) != _identity(os.fstat(leaf)):
            raise DependencyContractError()
        if _identity(before) != _identity(os.stat(name, dir_fd=directory, follow_symlinks=False)):
            raise DependencyContractError()
        for parent, part, expected in bindings:
            named = os.stat(part, dir_fd=parent, follow_symlinks=False)
            if (named.st_dev, named.st_ino, named.st_mode) != (expected.st_dev, expected.st_ino, expected.st_mode):
                raise DependencyContractError()
        named = root.lstat()
        if (named.st_dev, named.st_ino, named.st_mode) != (original.st_dev, original.st_ino, original.st_mode):
            raise DependencyContractError()
        return data, _identity(before)
    except (OSError, ValueError, TypeError):
        raise DependencyContractError() from None
    finally:
        for descriptor in reversed(held): os.close(descriptor)


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value: raise DependencyContractError()
        value[key] = item
    return value


def _constant(_): raise DependencyContractError()


def _filename(name, version, arch):
    if name == "cryptography":
        return f"cryptography-{version}-cp39-abi3-manylinux_2_28_{arch}.whl"
    if name == "cffi":
        return f"cffi-{version}-cp312-cp312-manylinux2014_{arch}.manylinux_2_17_{arch}.whl"
    return f"{name.replace('-', '_')}-{version}-py3-none-any.whl"


def load_dependency_contract(root):
    """Load fixed source-relative contracts; reject extras and foreign artifacts."""
    policy_read = _read(root, POLICY_PATH)
    lock_read = _read(root, LOCK_PATH)
    # These are public source files, not a writer-locked private authority.
    # Reobserve both byte and inode identities across the pair; the outer
    # runner still freezes/revalidates the complete source snapshot.
    if policy_read != _read(root, POLICY_PATH) or lock_read != _read(root, LOCK_PATH):
        raise DependencyContractError()
    raw, _ = policy_read; lock, _ = lock_read
    try:
        value = json.loads(raw.decode("ascii"), object_pairs_hook=_pairs, parse_constant=_constant)
        canonical = (json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
        if (type(value) is not dict or set(value) != _POLICY_KEYS or raw != canonical
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["contract"] != "REQ7-C14-T6-A" or value["python"] != "CPython-3.12"
                or value["platform"] != "linux" or value["architectures"] != ["aarch64", "x86_64"]
                or value["extras"] != []
                or value["distributions"] != [{"name": n, "version": v} for n, v in PINS]
                or value["development_conditional"] != {"name": "typing_extensions", "version": "4.16.0",
                                                        "marker": "python_full_version < '3.11'"}
                or value["forbidden_transports"] != ["google-api-python-client", "httplib2", "requests", "AuthorizedSession"]):
            raise DependencyContractError()
        expected = [(n, a, _filename(n, v, a)) for n, v in PINS
                    for a in (("aarch64", "x86_64") if n in ("cryptography", "cffi") else ("any",))]
        artifacts = value["artifacts"]
        if type(artifacts) is not list or len(artifacts) != 8: raise DependencyContractError()
        records = []
        for item, (n, a, filename) in zip(artifacts, expected):
            if (type(item) is not dict or set(item) != {"name", "architecture", "filename", "sha256"}
                    or (item["name"], item["architecture"], item["filename"]) != (n, a, filename)
                    or type(item["sha256"]) is not str or re.fullmatch(r"[0-9a-f]{64}", item["sha256"]) is None):
                raise DependencyContractError()
            records.append((n, a, filename, item["sha256"]))
        if len({item[3] for item in records}) != 8: raise DependencyContractError()
        lines = [_LOCK_HEADER]
        for n, v in PINS:
            selected = [item for item in records if item[0] == n]
            lines.extend(f"# wheel: {item[2]} sha256:{item[3]}" for item in selected)
            lines.append(n + "==" + v + " \\")
            hashes = sorted(item[3] for item in selected)
            lines.extend("    --hash=sha256:" + h + (" \\" if i < len(hashes) - 1 else "")
                         for i, h in enumerate(hashes))
        if lock != ("\n".join(lines) + "\n").encode("ascii"): raise DependencyContractError()
        return DependencyContract(hashlib.sha256(raw).hexdigest(), hashlib.sha256(lock).hexdigest(), PINS, tuple(records))
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        raise DependencyContractError() from None


def architecture_artifacts(contract, architecture):
    if type(contract) is not DependencyContract or type(architecture) is not str or architecture not in ("aarch64", "x86_64"):
        raise DependencyContractError()
    return tuple((n, f, h) for n, a, f, h in contract.artifacts if a in ("any", architecture))


def installed_dependency_identity(contract, *, python_version=None, version_getter=None):
    """Check metadata only, before any corresponding SDK import; no auth proof."""
    py = sys.version_info[:2] if python_version is None else python_version
    if (type(contract) is not DependencyContract or type(py) is not tuple or len(py) != 2
            or any(type(v) is not int for v in py) or py[0] != 3 or py[1] < 9):
        raise DependencyContractError()
    getter = (lambda name: metadata.distribution(name).version) if version_getter is None else version_getter
    pins = PINS + ((("typing_extensions", "4.16.0"),) if py < (3, 11) else ())
    try:
        for name, version in pins:
            if getter(name) != version: raise DependencyContractError()
    except (metadata.PackageNotFoundError, KeyError, ValueError, TypeError):
        raise DependencyContractError() from None
    return DependencyIdentity(contract.policy_sha256, contract.lock_sha256, pins)
