#!/usr/bin/env python3
"""Check and install the project's dependencies from the unified table infra/dependencies.json.

check    Compare one or more targets with the table and print one line per item; exit 1 when
         anything is missing or differs. --json prints the same result as JSON.
           files              existing requirement lists and hard-coded copies agree with the table
                              (repository/development check: run it in the git worktree)
           local-test         the CLT /usr/bin/python3 user site used by the formal macOS tests
           container          the image venv /opt/http-ztp/venv (run inside the container)
           native             apt packages, system python3 modules and commands of a native server
           venv-ibsw-upgrade  ~/.venvs/http/ibsw-upgrade of the current user
           venv-cabletracker  ~/.venvs/http/cabletracker of the current user
           ci                 the CI interpreter (requirements-dev.txt)
         Without --target: darwin -> files + local-test; inside the container -> container;
         other Linux -> native plus each venv that exists for the current user.
install  Create ~/.venvs/http/<name> for venv-ibsw-upgrade or venv-cabletracker of the current user
         from the table's hashed requirements (pip -I --isolated --no-cache-dir --only-binary=:all:
         --no-deps --require-hashes), then check it. Run it as the user who runs the consumer:
         11-load.py (its worker runs cron.sh) for venv-cabletracker, upgrade.py for venv-ibsw-upgrade.
         The base interpreter's platform selects the hashed list: a target's variant for that platform
         (venv-ibsw-upgrade on macOS cp39 arm64, the CLT /usr/bin/python3 of the formal full proof,
         whose F01 SDK identity tests run in this venv), otherwise the target's own list. An existing
         venv is reused only when its interpreter is that same platform; check likewise requires the
         venv's interpreter platform to be the target's and pyvenv.cfg to carry that variant's python.
         Neither binds the venv to one base interpreter (a pyenv or Homebrew 3.9 arm64 venv passes):
         the F01 SDK identity tests enforce that binding at test time (test_cases/f01_sdk_venv.py
         requires the child's base_prefix, version, cache tag and machine to be the proof interpreter's).
         Root installs only into its own home (HOME must be root's home: plain sudo, not sudo -E).
         A half-built venv is reported with the directory to remove; nothing is deleted.
bundle   Phase 2 (offline apt + wheel bundle); not implemented yet.
fmt      Rewrite infra/dependencies.json in its canonical JSON form.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import json
import os
from pathlib import Path
import pwd
import re
import shutil
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[1]
TABLE_RELATIVE = "infra/dependencies.json"
EXIT_OK = 0
EXIT_PROBLEM = 1
EXIT_USAGE = 2
CONTAINER_MARKER = Path("/opt/http-ztp/venv/bin/python")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
REQUIREMENT_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
VENV_BASE_DISTRIBUTIONS = frozenset({"pip", "setuptools", "wheel"})
TARGET_KINDS = frozenset({"container-venv", "apt", "venv", "user-site", "ci"})
FILE_FORMATS = frozenset({"hashed", "pins", "lower-bounds"})
COPY_KINDS = frozenset({"pins", "import-map", "names", "requirement-path", "apt",
                        "dockerfile-apt", "venv-path"})
IDENTITY_PROBE = (
    "# deps-identity\n"
    "import json, platform, sys\n"
    "print(json.dumps({'implementation': platform.python_implementation(), 'system': sys.platform,"
    " 'machine': platform.machine(), 'version': '%d.%d' % sys.version_info[:2]}))\n"
)
IMPORT_PROBE = (
    "# deps-import-probe\n"
    "import importlib, sys\n"
    "for name in sys.argv[1:]:\n"
    "    importlib.import_module(name)\n"
)


class TableError(ValueError):
    """The dependency table itself is invalid; nothing can be checked."""


def canonical(name: str) -> str:
    """PEP 503 normalized distribution name."""
    return re.sub(r"[-_.]+", "-", name).lower()


def canonical_bytes(table: dict) -> bytes:
    return (json.dumps(table, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")


# --------------------------------------------------------------------------- table


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise TableError(message)


def _string_list(value: object, label: str) -> list:
    _require(isinstance(value, list) and all(isinstance(item, str) and item for item in value),
             f"{label} must be a list of non-empty strings")
    _require(len(value) == len(set(value)), f"{label} has duplicates")
    return value


def _validate_venv_variants(target_name: str, row: dict, files: dict) -> None:
    """Every platform of a venv target has one hashed list covering it and a matching cpXY python.

    `variants` maps a platform to {python, requirements} that replace the target's own pair there, and the
    variant lists pin the same set. The platform (system, cpXY, machine) selects the variant, so one python
    may serve several platforms (for example linux-cp312 and a future macos-cp312 variant).
    """
    _require(isinstance(row.get("python"), str) and row["python"], f"venv target {target_name} needs a python")
    target_platforms = row.get("platforms", [])
    variants = row.get("variants", {})
    _require(isinstance(variants, dict), f"venv target {target_name} variants must be an object")
    own_set = files[row["requirements"]]["set"]
    for platform_name, variant in variants.items():
        label = f"venv target {target_name} variant {platform_name}"
        _require(platform_name in target_platforms, f"{label} is not one of its platforms")
        _require(isinstance(variant, dict) and set(variant) == {"python", "requirements"}
                 and isinstance(variant["python"], str) and variant["python"], f"{label} needs python and requirements")
        _require(variant["requirements"] in files and files[variant["requirements"]]["format"] == "hashed",
                 f"{label} needs a hashed requirements file from requirement_files")
        _require(files[variant["requirements"]]["set"] == own_set,
                 f"{label} list has set {files[variant['requirements']]['set']}, the target's list has set {own_set}")
    for platform_name in target_platforms:
        python, requirements = venv_variant(row, platform_name)
        _require(platform_name in files[requirements].get("platforms", []),
                 f"venv target {target_name}: {requirements} does not cover platform {platform_name}")
        _require(f"-cp{python.replace('.', '')}-" in f"-{platform_name}-",
                 f"venv target {target_name}: python {python} does not match platform {platform_name}")


def venv_variant(target: dict, platform_name: str) -> tuple:
    """(python, requirements) of a venv target on one platform: its variant there, else its own pair."""
    variant = target.get("variants", {}).get(platform_name)
    if variant:
        return variant["python"], variant["requirements"]
    return target["python"], target["requirements"]


def interpreter_problem(python: Path) -> str:
    """Why a venv's bin/python cannot run; a broken symlink names the base interpreter that is gone."""
    if os.path.islink(python) and not python.exists():
        return f"a broken symlink to {os.readlink(python)} (its base interpreter is gone)"
    if not python.exists():
        return "missing"
    return "not executable"


def validate_table(table: object) -> dict:
    _require(isinstance(table, dict), "table must be an object")
    _require(table.get("schema_version") == 1, "schema_version must be 1")
    distributions = table.get("python_distributions")
    _require(isinstance(distributions, dict) and distributions, "python_distributions missing")
    for name, row in distributions.items():
        _require(name == canonical(name), f"distribution {name} is not a canonical name")
        _require(isinstance(row, dict) and isinstance(row.get("version"), str) and row["version"],
                 f"distribution {name} lacks a version")
        _string_list(row.get("import_names"), f"distribution {name} import_names")
        _require(isinstance(row.get("used_by"), str) and row["used_by"], f"distribution {name} lacks used_by")
    sets = table.get("python_sets")
    _require(isinstance(sets, dict) and sets, "python_sets missing")
    for set_name, row in sets.items():
        _require(isinstance(row, dict), f"python set {set_name} must be an object")
        for member in _string_list(row.get("distributions"), f"python set {set_name}"):
            _require(member in distributions, f"python set {set_name} names unknown distribution {member}")
        if "import_probe" in row:
            _string_list(row["import_probe"], f"python set {set_name} import_probe")
    apt_sets = table.get("apt_sets")
    _require(isinstance(apt_sets, dict) and apt_sets, "apt_sets missing")
    for set_name, row in apt_sets.items():
        _require(isinstance(row, dict), f"apt set {set_name} must be an object")
        _string_list(row.get("packages"), f"apt set {set_name}")
    commands = table.get("commands")
    _require(isinstance(commands, dict) and all(isinstance(v, str) for v in commands.values()),
             "commands must map command -> apt package")
    platforms = table.get("platforms")
    _require(isinstance(platforms, dict) and platforms, "platforms missing")
    files = table.get("requirement_files")
    _require(isinstance(files, dict) and files, "requirement_files missing")
    for path, row in files.items():
        _require(isinstance(row, dict) and row.get("set") in sets, f"requirement file {path} names an unknown set")
        _require(row.get("format") in FILE_FORMATS, f"requirement file {path} has an unknown format")
        for name in _string_list(row.get("unpinned", []), f"requirement file {path} unpinned"):
            _require(name in sets[row["set"]]["distributions"], f"requirement file {path} unpinned {name} not in its set")
        if row["format"] == "hashed" or "platforms" in row:
            # A hashed list pins the wheels of exactly these platforms; lists are compared per platform.
            covered = _string_list(row.get("platforms"), f"requirement file {path} platforms")
            _require(bool(covered), f"requirement file {path} platforms must not be empty")
            for platform_name in covered:
                _require(platform_name in platforms, f"requirement file {path} names unknown platform {platform_name}")
    _require(isinstance(table.get("not_dependency_lists", {}), dict), "not_dependency_lists must be an object")
    targets = table.get("targets")
    _require(isinstance(targets, dict) and targets, "targets missing")
    for target_name, row in targets.items():
        _require(isinstance(row, dict) and row.get("kind") in TARGET_KINDS, f"target {target_name} has an unknown kind")
        for set_name in _string_list(row.get("python_sets", []), f"target {target_name} python_sets"):
            _require(set_name in sets, f"target {target_name} names unknown python set {set_name}")
        for key in ("apt_sets", "optional_apt_sets"):
            for set_name in _string_list(row.get(key, []), f"target {target_name} {key}"):
                _require(set_name in apt_sets, f"target {target_name} names unknown apt set {set_name}")
        for key in ("commands", "optional_commands"):
            for command in _string_list(row.get(key, []), f"target {target_name} {key}"):
                _require(command in commands, f"target {target_name} names unknown command {command}")
        for platform_name in _string_list(row.get("platforms", []), f"target {target_name} platforms"):
            _require(platform_name in platforms, f"target {target_name} names unknown platform {platform_name}")
        for name in row.get("omit", {}):
            _require(name in distributions, f"target {target_name} omits unknown distribution {name}")
        if row["kind"] == "venv":
            _require(isinstance(row.get("path"), str) and row["path"].startswith("~/"),
                     f"venv target {target_name} needs a ~/ path")
            _require(row.get("requirements") in files and files[row["requirements"]]["format"] == "hashed",
                     f"venv target {target_name} needs a hashed requirements file from requirement_files")
            _require(isinstance(row.get("system_site_packages"), bool),
                     f"venv target {target_name} needs system_site_packages")
            _validate_venv_variants(target_name, row, files)
    copies = table.get("code_copies")
    _require(isinstance(copies, list), "code_copies must be a list")
    for index, row in enumerate(copies):
        _require(isinstance(row, dict) and row.get("kind") in COPY_KINDS
                 and isinstance(row.get("path"), str) and isinstance(row.get("symbol"), str),
                 f"code_copies[{index}] is invalid")
        if "set" in row:
            _require(row["set"] in sets, f"code_copies[{index}] names unknown set")
        for set_name in row.get("apt_sets", []):
            _require(set_name in apt_sets, f"code_copies[{index}] names unknown apt set")
        if "target" in row:
            _require(row["target"] in targets, f"code_copies[{index}] names unknown target")
    return table


def load_table(root: Path = ROOT) -> dict:
    path = root / TABLE_RELATIVE
    try:
        raw = path.read_bytes()
        table = json.loads(raw.decode("ascii"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise TableError(f"cannot read {TABLE_RELATIVE}: {exc}") from None
    validate_table(table)
    if raw != canonical_bytes(table):
        raise TableError(f"{TABLE_RELATIVE} is not canonical JSON; run: python3 infra/deps.py fmt")
    return table


def set_distributions(table: dict, set_names) -> list:
    members = []
    for set_name in set_names:
        for name in table["python_sets"][set_name]["distributions"]:
            if name not in members:
                members.append(name)
    return members


def target_distributions(table: dict, target: dict) -> list:
    omitted = set(target.get("omit", {}))
    return [name for name in set_distributions(table, target.get("python_sets", [])) if name not in omitted]


def apt_packages(table: dict, set_names) -> list:
    packages = []
    for set_name in set_names:
        for package in table["apt_sets"][set_name]["packages"]:
            if package not in packages:
                packages.append(package)
    return packages


# --------------------------------------------------------------------------- results


class Report:
    """Per-target result lines: status is ok, missing, mismatch, unexpected, error or info."""

    def __init__(self) -> None:
        self.targets: dict = {}

    def add(self, target: str, status: str, item: str, detail: str = "", fix: str = "") -> None:
        self.targets.setdefault(target, []).append(
            {"status": status, "item": item, "detail": detail, "fix": fix})

    def target_ok(self, target: str) -> bool:
        return all(row["status"] in ("ok", "info") for row in self.targets.get(target, []))

    @property
    def ok(self) -> bool:
        return all(self.target_ok(name) for name in self.targets)

    def as_json(self) -> dict:
        return {"ok": self.ok, "targets": {name: {"ok": self.target_ok(name), "items": rows}
                                           for name, rows in self.targets.items()}}

    def render(self) -> str:
        lines = []
        for name, rows in self.targets.items():
            lines.append(f"== {name}: {'OK' if self.target_ok(name) else 'PROBLEMS'}")
            for row in rows:
                text = f"  {row['status'].upper():<10} {row['item']}"
                if row["detail"]:
                    text += f" — {row['detail']}"
                if row["fix"]:
                    text += f" (fix: {row['fix']})"
                lines.append(text)
        return "\n".join(lines)


# --------------------------------------------------------------------------- requirement files


def _logical_lines(text: str) -> list:
    logical, pending = [], []
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        continuation = stripped.endswith("\\")
        pending.append(stripped[:-1].strip() if continuation else stripped)
        if not continuation:
            logical.append(" ".join(pending))
            pending = []
    if pending:
        raise ValueError("unterminated line continuation")
    return logical


def parse_hashed(text: str) -> tuple:
    """({name: (version, frozenset(sha256))}, {wheel filename: sha256}) of a hash-locked list."""
    records: dict = {}
    for line in _logical_lines(text):
        tokens = line.split()
        if "==" not in tokens[0]:
            raise ValueError(f"not an exact pin: {tokens[0]}")
        name, version = tokens[0].split("==", 1)
        if not REQUIREMENT_NAME.match(name) or not version:
            raise ValueError(f"invalid requirement {tokens[0]}")
        hashes = []
        for token in tokens[1:]:
            if not token.startswith("--hash=sha256:") or not HEX64.match(token[len("--hash=sha256:"):]):
                raise ValueError(f"{name}: only --hash=sha256:<64 hex> options are allowed")
            hashes.append(token[len("--hash=sha256:"):])
        if not hashes:
            raise ValueError(f"{name}: no hash")
        if canonical(name) in records:
            raise ValueError(f"{name}: duplicate record")
        records[canonical(name)] = (version, frozenset(hashes))
    wheels = {}
    for raw in text.splitlines():
        match = re.match(r"^# wheel: (\S+\.whl) sha256:([0-9a-f]{64})$", raw.strip())
        if match:
            # One wheel file is one PyPI upload: its filename names exactly one digest.
            if match.group(1) in wheels:
                problem = "has two digests" if wheels[match.group(1)] != match.group(2) else "is listed twice"
                raise ValueError(f"wheel {match.group(1)} {problem}")
            wheels[match.group(1)] = match.group(2)
    return records, wheels


def parse_simple(text: str, operator: str) -> dict:
    """{name: version or None} of a list of `name<operator>version` or bare `name` lines."""
    pins: dict = {}
    for line in _logical_lines(text):
        if operator in line:
            name, version = line.split(operator, 1)
            name, version = name.strip(), version.strip()
        else:
            name, version = line, None
        if not REQUIREMENT_NAME.match(name) or (version is not None and not re.match(r"^[0-9][0-9A-Za-z.+!]*$", version)):
            raise ValueError(f"unsupported requirement line: {line}")
        pins[canonical(name)] = version
    return pins


def _version_key(version: str) -> tuple:
    return tuple(int(part) if part.isdigit() else part for part in re.split(r"[.]", version))


def check_requirement_file(root: Path, table: dict, relative: str, report: Report, target: str) -> tuple:
    """Report one list against the table; return its hashed (records, wheel comments), empty otherwise."""
    row = table["requirement_files"][relative]
    expected = table["python_sets"][row["set"]]["distributions"]
    versions = table["python_distributions"]
    path = root / relative
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        report.add(target, "missing", relative, f"cannot read: {exc.__class__.__name__}")
        return {}, {}
    try:
        if row["format"] == "hashed":
            records, wheels = parse_hashed(text)
            found = {name: version for name, (version, _hashes) in records.items()}
        else:
            records, wheels = {}, {}
            found = parse_simple(text, "==" if row["format"] == "pins" else ">=")
    except ValueError as exc:
        report.add(target, "error", relative, f"cannot parse: {exc}")
        return {}, {}
    problems = 0
    for name in sorted(set(expected) - set(found)):
        problems += 1
        report.add(target, "missing", f"{relative}: {name}", f"set {row['set']} lists it; the file does not")
    for name in sorted(set(found) - set(expected)):
        problems += 1
        report.add(target, "unexpected", f"{relative}: {name}", f"not in set {row['set']}")
    for name in sorted(set(found) & set(expected)):
        version = found[name]
        table_version = versions[name]["version"]
        if row["format"] == "lower-bounds":
            if version is None or _version_key(table_version) < _version_key(version):
                problems += 1
                report.add(target, "mismatch", f"{relative}: {name}", f"table {table_version} does not satisfy >={version}")
        elif version is None:
            if name not in row.get("unpinned", []):
                problems += 1
                report.add(target, "mismatch", f"{relative}: {name}", "unpinned but not declared unpinned in the table")
        elif version != table_version:
            problems += 1
            report.add(target, "mismatch", f"{relative}: {name}", f"file {version}, table {table_version}")
    commented: dict = {}
    for filename, digest in sorted(wheels.items()):
        name = canonical(filename.split("-", 1)[0])
        commented.setdefault(name, set()).add(digest)
        if name not in records or digest not in records[name][1]:
            problems += 1
            report.add(target, "mismatch", f"{relative}: {filename}", "wheel comment digest is not a hash of its record")
        elif filename.split("-")[1] != records[name][0]:
            problems += 1
            report.add(target, "mismatch", f"{relative}: {filename}",
                       f"wheel version differs from its record {name}=={records[name][0]}")
    # The reverse direction: every hash of a record names its wheel file, so the per-file digest rule of
    # check_files sees every pinned wheel.
    for name, (_version, hashes) in sorted(records.items()):
        uncommented = len(set(hashes) - commented.get(name, set()))
        if uncommented:
            problems += 1
            report.add(target, "mismatch", f"{relative}: {name}",
                       f"{uncommented} hash(es) without a '# wheel: <filename> sha256:<digest>' comment")
    if not problems:
        report.add(target, "ok", relative, f"{len(found)} distributions agree with set {row['set']}")
    return records, wheels


# --------------------------------------------------------------------------- code copies


def _literal(node: ast.AST, env: dict) -> object:
    if isinstance(node, ast.Name):
        if node.id not in env:
            raise ValueError(f"unresolved name {node.id}")
        return env[node.id]
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return _literal(node.left, env) + _literal(node.right, env)
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
            and node.func.id in {"frozenset", "set", "tuple"} and len(node.args) <= 1 and not node.keywords):
        value = _literal(node.args[0], env) if node.args else ()
        return {"frozenset": frozenset, "set": set, "tuple": tuple}[node.func.id](value)
    if isinstance(node, (ast.Tuple, ast.List)):
        return [_literal(item, env) for item in node.elts]
    if isinstance(node, ast.Set):
        return {_literal(item, env) for item in node.elts}
    if isinstance(node, ast.Dict):
        return {_literal(key, env): _literal(value, env) for key, value in zip(node.keys, node.values)}
    return ast.literal_eval(node)


def module_constant(path: Path, symbol: str) -> object:
    """Evaluate one module-level constant without importing the module."""
    tree = ast.parse(path.read_bytes(), filename=str(path))
    env: dict = {}
    for node in tree.body:
        targets = []
        if isinstance(node, ast.Assign):
            targets = [target.id for target in node.targets if isinstance(target, ast.Name)]
            value = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.value is not None:
            targets = [node.target.id]
            value = node.value
        if not targets:
            continue
        try:
            evaluated = _literal(value, env)
        except (ValueError, TypeError, SyntaxError):
            if symbol in targets:
                raise
            continue
        for name in targets:
            env[name] = evaluated
    if symbol not in env:
        raise ValueError(f"{symbol} is not a literal module constant")
    return env[symbol]


def dockerfile_apt_packages(text: str) -> list:
    block = text.split("apt-get install -y --no-install-recommends", 1)[1].split("&&", 1)[0]
    return [token for token in block.replace("\\", " ").split() if token]


def _pairs(value: object) -> dict:
    if isinstance(value, dict):
        return {canonical(name): (item[0] if isinstance(item, (list, tuple)) else item)
                for name, item in value.items()}
    return {canonical(name): version for name, version in value}


def _field(table: dict, dotted: str, section: str) -> list:
    owner, field = dotted.split(".", 1)
    value = table[section][owner][field]
    return sorted(value) if isinstance(value, dict) else list(value)


def check_code_copy(root: Path, table: dict, row: dict, report: Report, target: str) -> None:
    label = f"{row['path']}::{row['symbol']}"
    path = root / row["path"]
    try:
        if row["kind"] == "dockerfile-apt":
            value = dockerfile_apt_packages(path.read_text(encoding="utf-8"))
        else:
            value = module_constant(path, row["symbol"])
    except (OSError, UnicodeError, SyntaxError, ValueError, IndexError) as exc:
        report.add(target, "error", label, f"cannot read the constant: {exc}")
        return
    distributions = table["python_distributions"]
    kind = row["kind"]
    problems = []
    if kind == "pins":
        expected = {name: distributions[name]["version"] for name in table["python_sets"][row["set"]]["distributions"]}
        actual = _pairs(value)
        if actual != expected:
            differing = sorted(name for name in set(actual) | set(expected) if actual.get(name) != expected.get(name))
            problems.append("differs for " + ", ".join(
                f"{name} (code {actual.get(name)}, table {expected.get(name)})" for name in differing))
    elif kind == "import-map":
        members = table["python_sets"][row["set"]]["distributions"]
        actual = _pairs(value)
        for name, module in sorted(actual.items()):
            if name not in members:
                problems.append(f"{name} is not in set {row['set']}")
            elif module not in distributions[name]["import_names"]:
                problems.append(f"{name} imports as {module}, table says {distributions[name]['import_names']}")
        if row.get("exact") and set(actual) != set(members):
            problems.append(f"covers {sorted(actual)}, set {row['set']} is {sorted(members)}")
    elif kind == "names":
        expected = (_field(table, row["target_field"], "targets") if "target_field" in row
                    else _field(table, row["set_field"], "python_sets"))
        if sorted(value) != sorted(expected):
            problems.append(f"code {sorted(value)}, table {sorted(expected)}")
    elif kind == "requirement-path":
        if table["requirement_files"].get(value, {}).get("set") != row["set"]:
            problems.append(f"{value!r} is not the table's requirements file of set {row['set']}")
    elif kind in ("apt", "dockerfile-apt"):
        expected = set(apt_packages(table, row["apt_sets"])) - set(row.get("known_missing", []))
        if set(value) != expected:
            problems.append(f"extra {sorted(set(value) - expected)}, missing {sorted(expected - set(value))}")
    elif kind == "venv-path":
        expected = table["targets"][row["target"]]["path"]
        if not value or value[0] != expected:
            problems.append(f"first path {value[0] if value else None!r}, table {expected!r}")
    if problems:
        report.add(target, "mismatch", label, "; ".join(problems))
    else:
        report.add(target, "ok", label)


def check_files(root: Path, table: dict, report: Report, target: str = "files") -> None:
    """Every referenced list and hard-coded copy agrees with the table; hashed lists agree with each other.

    Two hashed lists that share a platform pin the same wheel hashes for the same name==version; lists of
    disjoint platforms (Linux cp312 and macOS cp39) pin different wheels, but one wheel file (for example a
    py3-none-any wheel) carries one digest in every list.
    """
    hashed: dict = {}
    for relative in table["requirement_files"]:
        records, wheels = check_requirement_file(root, table, relative, report, target)
        row = table["requirement_files"][relative]
        if row["format"] == "hashed":
            hashed[relative] = (records, wheels, set(row["platforms"]))
    seen: dict = {}
    seen_wheels: dict = {}
    for relative, (records, wheels, platforms) in hashed.items():
        for name, (version, hashes) in records.items():
            key = (name, version)
            other = next((first for first, first_platforms, first_hashes in seen.get(key, [])
                          if first_platforms & platforms and first_hashes != hashes), None)
            if other is not None:
                report.add(target, "mismatch", f"{name}=={version}",
                           f"{relative} and {other} pin different wheel hashes")
            seen.setdefault(key, []).append((relative, platforms, hashes))
        for filename, digest in sorted(wheels.items()):
            first, first_digest = seen_wheels.setdefault(filename, (relative, digest))
            if first_digest != digest:
                report.add(target, "mismatch", filename,
                           f"wheel digest differs between {first} and {relative}")
    for row in table["code_copies"]:
        check_code_copy(root, table, row, report, target)


# --------------------------------------------------------------------------- environments


def installed_distributions() -> dict:
    """{canonical name: version} visible to the current interpreter (first one wins)."""
    from importlib import metadata

    found: dict = {}
    for distribution in metadata.distributions():
        name = distribution.metadata["Name"]
        if name:
            found.setdefault(canonical(name), distribution.version)
    return found


def _find_spec(module: str) -> bool:
    try:
        return importlib.util.find_spec(module) is not None
    except (ImportError, AttributeError, ValueError):
        return False


def _check_python(table: dict, target_name: str, target: dict, report: Report) -> None:
    installed = installed_distributions()
    for name in target_distributions(table, target):
        row = table["python_distributions"][name]
        actual = installed.get(name)
        fix = "install it as listed in infra/dependencies.json"
        if actual is None:
            report.add(target_name, "missing", f"python {name}=={row['version']}", "not installed", fix)
        elif actual != row["version"]:
            report.add(target_name, "mismatch", f"python {name}", f"installed {actual}, table {row['version']}", fix)
        else:
            missing = [module for module in row["import_names"] if not _find_spec(module)]
            if missing:
                report.add(target_name, "missing", f"python {name}", f"cannot find module(s) {', '.join(missing)}")
            else:
                report.add(target_name, "ok", f"python {name}=={actual}")
    for name, version in sorted(target.get("clt_provided", {}).items()):
        actual = installed.get(name)
        if actual is None:
            report.add(target_name, "missing", f"python {name}", "CLT-provided distribution is absent")
        else:
            detail = "CLT-provided" + ("" if actual == version else f"; observed {actual}, table records {version}")
            report.add(target_name, "ok" if actual == version else "info", f"python {name}=={actual}", detail)


def _check_interpreter(target_name: str, target: dict, report: Report) -> None:
    version = "%d.%d" % sys.version_info[:2]
    wanted = target.get("python")
    allowed = wanted if isinstance(wanted, list) else [wanted]
    if wanted and version not in allowed:
        report.add(target_name, "mismatch", "python version", f"running {version}, target needs {' or '.join(allowed)}")
    interpreter = target.get("interpreter")
    # Only the container venv has a fixed path; /usr/bin/python3 is a shim on macOS whose
    # sys.executable names the selected toolchain, so the other kinds check "not a venv".
    if target["kind"] == "container-venv" and os.path.abspath(sys.executable) != interpreter:
        report.add(target_name, "mismatch", "interpreter", f"running {sys.executable}, target is {interpreter}",
                   f"run: {interpreter} infra/deps.py check --target {target_name}")
    if target["kind"] in ("apt", "user-site") and sys.prefix != getattr(sys, "base_prefix", sys.prefix):
        report.add(target_name, "mismatch", "interpreter", "running inside a venv; the target's modules cannot be checked",
                   f"run it with {interpreter or 'the system python3'}")
    elif target["kind"] in ("apt", "user-site"):
        report.add(target_name, "info", "interpreter", f"{sys.executable} (Python {version})")


def _check_commands(table: dict, target_name: str, target: dict, report: Report) -> None:
    for command in target.get("commands", []):
        package = table["commands"][command]
        if shutil.which(command):
            report.add(target_name, "ok", f"command {command}")
        else:
            report.add(target_name, "missing", f"command {command}", f"apt package {package}", f"sudo apt-get install {package}")
    for command in target.get("optional_commands", []):
        state = "present" if shutil.which(command) else "absent"
        report.add(target_name, "info", f"command {command}", f"optional, {state}")


def dpkg_state(package: str) -> object:
    """Installed version of a Debian package, None when not installed; raises OSError without dpkg."""
    result = subprocess.run(["dpkg-query", "-W", "-f=${Status}\t${Version}", package],
                            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            text=True, timeout=30, check=False)
    if result.returncode != 0:
        return None
    status, _tab, version = result.stdout.partition("\t")
    return version.strip() if status.strip() == "install ok installed" else None


def _check_apt(table: dict, target_name: str, target: dict, report: Report) -> None:
    if shutil.which("dpkg-query") is None:
        report.add(target_name, "error", "dpkg-query", "not found; this is not a Debian/Ubuntu host")
        return
    for package in apt_packages(table, target.get("apt_sets", [])):
        version = dpkg_state(package)
        if version is None:
            report.add(target_name, "missing", f"apt {package}", "not installed", f"sudo apt-get install {package}")
        else:
            report.add(target_name, "ok", f"apt {package}={version}")
    for package in apt_packages(table, target.get("optional_apt_sets", [])):
        version = dpkg_state(package)
        report.add(target_name, "info", f"apt {package}", f"optional, {'installed ' + version if version else 'not installed'}")


def _check_system_modules(target_name: str, modules: dict, report: Report, label: str) -> None:
    for module, package in sorted(modules.items()):
        if _find_spec(module):
            report.add(target_name, "ok", f"{label} {module}")
        else:
            report.add(target_name, "missing", f"{label} {module}", f"apt package {package}", f"sudo apt-get install {package}")


def check_current_interpreter_target(table: dict, target_name: str, report: Report) -> None:
    target = table["targets"][target_name]
    _check_interpreter(target_name, target, report)
    if target["kind"] == "apt":
        _check_apt(table, target_name, target, report)
        _check_system_modules(target_name, target.get("python_modules", {}), report, "python module")
    else:
        _check_python(table, target_name, target, report)
        if target["kind"] == "container-venv":
            _check_apt(table, target_name, target, report)
            _check_system_modules(target_name, target.get("apt_python_modules", {}), report, "apt python module")
    _check_commands(table, target_name, target, report)


def venv_path(target: dict) -> Path:
    return Path(os.path.expanduser(target["path"]))


def read_pyvenv_cfg(venv: Path) -> dict:
    values = {}
    for line in (venv / "pyvenv.cfg").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key.strip()] = value.strip()
    return values


def venv_site_packages(venv: Path, python: str) -> Path:
    return venv / "lib" / f"python{python}" / "site-packages"


def venv_distributions(site_packages: Path) -> dict:
    """{canonical name: version} from *.dist-info/METADATA, without running the venv."""
    found: dict = {}
    for entry in sorted(site_packages.glob("*.dist-info")):
        name = version = None
        try:
            for line in (entry / "METADATA").read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("Name:") and name is None:
                    name = line.split(":", 1)[1].strip()
                elif line.startswith("Version:") and version is None:
                    version = line.split(":", 1)[1].strip()
                elif not line.strip():
                    break
        except OSError:
            continue
        if name and version:
            found.setdefault(canonical(name), version)
    return found


def check_venv_target(table: dict, target_name: str, report: Report, *, import_probe: bool = True) -> None:
    target = table["targets"][target_name]
    venv = venv_path(target)
    fix = f"python3 infra/deps.py install --target {target_name}"
    if not (venv / "pyvenv.cfg").is_file():
        report.add(target_name, "missing", f"venv {venv}", "not created", fix)
        return
    cfg = read_pyvenv_cfg(venv)
    wanted_system = "true" if target["system_site_packages"] else "false"
    if cfg.get("include-system-site-packages", "false").lower() != wanted_system:
        report.add(target_name, "mismatch", "include-system-site-packages",
                   f"{cfg.get('include-system-site-packages')}, table {wanted_system}", f"recreate the venv: {fix}")
    version = cfg.get("version") or cfg.get("version_info") or ""
    python = venv / "bin" / "python"
    if not (python.exists() and os.access(python, os.X_OK)):
        report.add(target_name, "missing", f"{python}", interpreter_problem(python), f"recreate the venv: {fix}")
        return
    # The venv's own interpreter names the host platform (system, machine) and its version; that platform
    # must be one of the target's, and pyvenv.cfg must carry the python of that platform's variant.
    try:
        venv_platform = probe_platform(str(python))
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError) as exc:
        report.add(target_name, "error", "venv python", f"cannot identify {python}: {exc}", f"recreate the venv: {fix}")
        return
    site_python = ".".join(version.split(".")[:2]) or target["python"]
    if venv_platform not in target["platforms"]:
        report.add(target_name, "mismatch", "venv python",
                   f"its interpreter is {venv_platform} (pyvenv.cfg version {version or 'unknown'}), not a platform "
                   f"of this target: {', '.join(target['platforms'])}", f"recreate the venv: {fix}")
    else:
        wanted = venv_variant(target, venv_platform)[0]
        if not (version == wanted or version.startswith(wanted + ".")):
            report.add(target_name, "mismatch", "venv python",
                       f"pyvenv.cfg version {version or 'unknown'}, but {venv_platform} needs python {wanted}",
                       f"recreate the venv: {fix}")
        else:
            site_python = wanted
    installed = venv_distributions(venv_site_packages(venv, site_python))
    problems = 0
    for name in target_distributions(table, target):
        expected = table["python_distributions"][name]["version"]
        actual = installed.get(name)
        if actual is None:
            problems += 1
            report.add(target_name, "missing", f"python {name}=={expected}", "not installed in the venv", fix)
        elif actual != expected:
            problems += 1
            report.add(target_name, "mismatch", f"python {name}", f"venv {actual}, table {expected}", fix)
        else:
            report.add(target_name, "ok", f"python {name}=={actual}")
    allowed = set(target_distributions(table, target)) | VENV_BASE_DISTRIBUTIONS
    for name in sorted(set(installed) - allowed):
        problems += 1
        report.add(target_name, "unexpected", f"python {name}=={installed[name]}", "not in the table for this venv",
                   f"recreate the venv: {fix}")
    modules = []
    for set_name in target.get("python_sets", []):
        modules.extend(table["python_sets"][set_name].get("import_probe", []))
    if import_probe and modules and not problems:
        result = subprocess.run([str(python), "-I", "-c", IMPORT_PROBE, *modules], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=120, check=False)
        if result.returncode:
            tail = result.stdout.strip().splitlines()[-1:] or ["no output"]
            report.add(target_name, "error", "import probe", tail[0][:300], fix)
        else:
            report.add(target_name, "ok", "import probe", ", ".join(modules))


def default_targets(table: dict) -> list:
    if sys.platform == "darwin":
        return ["files", "local-test"]
    if sys.platform.startswith("linux") and os.path.abspath(sys.executable) == str(CONTAINER_MARKER):
        return ["container"]
    selected = ["native"]
    for name, target in table["targets"].items():
        if target["kind"] == "venv" and (venv_path(target) / "pyvenv.cfg").exists():
            selected.append(name)
    return selected


def run_check(root: Path, table: dict, targets: list) -> Report:
    report = Report()
    for name in targets:
        if name == "files":
            check_files(root, table, report)
        elif table["targets"][name]["kind"] == "venv":
            check_venv_target(table, name, report)
        else:
            check_current_interpreter_target(table, name, report)
    return report


# --------------------------------------------------------------------------- install


def probe_platform(python: str) -> str:
    """Table platform name (e.g. linux-cp312-x86_64, macos-cp39-arm64) of an interpreter, by running it."""
    # -I -B: no PYTHON* environment, user site or cwd, and no .pyc written (also in a dry run).
    result = subprocess.run([python, "-I", "-B", "-c", IDENTITY_PROBE], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=60, check=False)
    if result.returncode:
        raise RuntimeError(f"cannot run {python}")
    identity = json.loads(result.stdout)
    machine = identity["machine"].lower()
    if identity["implementation"] != "CPython":
        raise RuntimeError(f"{python} is {identity['implementation']}, not CPython")
    system = "linux" if identity["system"].startswith("linux") else ("macos" if identity["system"] == "darwin" else identity["system"])
    # Linux names ARM aarch64 (wheel tags manylinux_*_aarch64); macOS names it arm64 (macosx_*_arm64).
    machine = {"amd64": "x86_64"}.get(machine, machine)
    if system == "linux":
        machine = {"arm64": "aarch64"}.get(machine, machine)
    return f"{system}-cp{identity['version'].replace('.', '')}-{machine}"


def root_home_problem() -> object:
    """None, or why root must not install here: root installs only into its own home directory.

    With sudo -E (or a kept HOME) root would create root-owned files under another user's home,
    and cron.sh running as root would then refuse that venv anyway.
    """
    if os.geteuid() != 0:
        return None
    home = os.environ.get("HOME", "")
    root_home = pwd.getpwuid(os.geteuid()).pw_dir
    if home and os.path.realpath(home) == os.path.realpath(root_home):
        return None
    return (f"running as root with HOME={home or '(unset)'}: root installs only into its own home {root_home}. "
            f"Run it as the user who runs 11-load.py (for venv-cabletracker) or upgrade.py (for "
            f"venv-ibsw-upgrade); if that user is root, run it with HOME={root_home} (plain sudo, not sudo -E)")


def half_built(venv: Path, target_name: str, problem: str) -> int:
    print(f"[ERROR] {venv} is an incomplete venv: {problem}. Nothing was deleted. Remove it and rerun:\n"
          f"  rm -rf {venv}\n"
          f"  python3 infra/deps.py install --target {target_name}", file=sys.stderr)
    return EXIT_PROBLEM


def install(root: Path, table: dict, target_name: str, python: str, dry_run: bool) -> int:
    target = table["targets"][target_name]
    problem = root_home_problem()
    if problem:
        print(f"[ERROR] {problem}", file=sys.stderr)
        return EXIT_USAGE
    try:
        platform_name = probe_platform(python)
    except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError) as exc:
        print(f"[ERROR] cannot identify the base interpreter {python}: {exc}", file=sys.stderr)
        return EXIT_USAGE
    if platform_name not in target["platforms"]:
        status = table["platforms"].get(platform_name, {}).get("status", "unsupported")
        detail = "planned for phase 2 (no hashed list yet)" if status == "planned" else "not supported"
        print(f"[ERROR] {target_name}: platform {platform_name} is {detail}; supported: "
              f"{', '.join(target['platforms'])}", file=sys.stderr)
        return EXIT_USAGE
    venv = venv_path(target)
    venv_python = venv / "bin" / "python"
    _python_version, requirements_relative = venv_variant(target, platform_name)
    requirements = root / requirements_relative
    # -I: no PYTHON* environment, user site or cwd shadowing; --isolated: no PIP_* environment and no
    # pip.conf; --no-cache-dir: nothing written to ~/.cache/pip. The hashes decide what is installed.
    pip = [str(venv_python), "-I", "-m", "pip", "--isolated"]
    create = None
    if (venv / "pyvenv.cfg").is_file():
        if not (venv_python.exists() and os.access(venv_python, os.X_OK)):
            return half_built(venv, target_name, f"{venv_python} is {interpreter_problem(venv_python)}")
        # Never reuse a venv of another platform or python: its interpreter must be the selected variant's.
        try:
            existing = probe_platform(str(venv_python))
        except (OSError, ValueError, KeyError, TypeError, AttributeError, RuntimeError, subprocess.SubprocessError) as exc:
            return half_built(venv, target_name, f"its interpreter {venv_python} cannot be identified ({exc})")
        if existing != platform_name:
            print(f"[ERROR] {venv} holds a {existing} interpreter, but {python} is {platform_name}, which selects "
                  f"{requirements_relative}; nothing was changed. Remove it and rerun with the interpreter you "
                  f"want the venv built from:\n"
                  f"  rm -rf {venv}\n"
                  f"  python3 infra/deps.py install --target {target_name}", file=sys.stderr)
            return EXIT_USAGE
        if not dry_run:
            try:
                probe = subprocess.run(pip + ["--version"], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, text=True, timeout=120, check=False)
                detail = (probe.stdout.strip().splitlines() or [""])[-1][:200]
                usable = probe.returncode == 0
            except (OSError, subprocess.SubprocessError) as exc:
                detail, usable = exc.__class__.__name__, False
            if not usable:
                return half_built(venv, target_name, f"pip does not run in it ({detail})")
    elif venv.exists():
        print(f"[ERROR] {venv} exists but is not a venv; move it away first", file=sys.stderr)
        return EXIT_USAGE
    else:
        create = [python, "-I", "-m", "venv"]
        if target["system_site_packages"]:
            create.append("--system-site-packages")
        create.append(str(venv))
    install_command = pip + ["install", "--no-cache-dir", "--disable-pip-version-check", "--only-binary=:all:",
                             "--no-deps", "--require-hashes", "-r", str(requirements)]
    for command in ([create] if create else []) + [install_command]:
        print("[RUN] " + " ".join(command))
        if dry_run:
            continue
        if command is create:
            venv.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            code = subprocess.run(command, stdin=subprocess.DEVNULL, check=False).returncode
        except OSError as exc:
            code = exc.__class__.__name__
        if not code:
            continue
        if command is create:
            reason = (f"python -m venv failed ({code}); on Ubuntu install python3-venv first "
                      f"(sudo apt-get install python3-venv)")
            if venv.exists():
                return half_built(venv, target_name, reason)
            print(f"[ERROR] {reason}; then rerun: python3 infra/deps.py install --target {target_name}",
                  file=sys.stderr)
            return EXIT_PROBLEM
        print(f"[ERROR] pip install into {venv} failed ({code}); the venv was kept. Fix the cause shown above "
              f"(for example PyPI access) and rerun: python3 infra/deps.py install --target {target_name}",
              file=sys.stderr)
        return EXIT_PROBLEM
    if dry_run:
        return EXIT_OK
    report = Report()
    check_venv_target(table, target_name, report)
    print(report.render())
    return EXIT_OK if report.ok else EXIT_PROBLEM


# --------------------------------------------------------------------------- CLI


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = result.add_subparsers(dest="action")
    check = sub.add_parser("check", help="compare targets with the table")
    check.add_argument("--target", action="append", default=[],
                       help="files, a target name from the table, or all (repeatable)")
    check.add_argument("--json", action="store_true", help="print the result as JSON")
    install_parser = sub.add_parser("install", help="create one of the two venvs from hashed requirements")
    install_parser.add_argument("--target", required=True, choices=("venv-ibsw-upgrade", "venv-cabletracker"),
                                help="the venv to create under ~/.venvs/http/<name>")
    install_parser.add_argument("--python", default=sys.executable,
                                help="base interpreter for python3 -m venv (default: this interpreter)")
    install_parser.add_argument("--dry-run", action="store_true", help="print the commands only")
    sub.add_parser("bundle", help="phase 2: offline bundle (not implemented)")
    sub.add_parser("fmt", help="rewrite the table in canonical JSON")
    return result


def main(argv=None) -> int:
    args = parser().parse_args(argv)
    if args.action is None:
        parser().print_help()
        return EXIT_USAGE
    if args.action == "bundle":
        print("[ERROR] bundle is phase 2 and not implemented yet: no offline apt/wheel bundle is produced. "
              "Use 'check' and 'install' (online) for now.", file=sys.stderr)
        return EXIT_USAGE
    if args.action == "fmt":
        path = ROOT / TABLE_RELATIVE
        try:
            table = validate_table(json.loads(path.read_text(encoding="ascii")))
        except (OSError, UnicodeError, ValueError) as exc:
            print(f"[ERROR] {exc}", file=sys.stderr)
            return EXIT_USAGE
        path.write_bytes(canonical_bytes(table))
        print(f"[OK] {TABLE_RELATIVE} is canonical")
        return EXIT_OK
    try:
        table = load_table(ROOT)
    except TableError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_USAGE
    if args.action == "install":
        return install(ROOT, table, args.target, args.python, args.dry_run)
    known = ["files", *table["targets"]]
    targets = []
    for name in args.target or default_targets(table):
        for expanded in (known if name == "all" else [name]):
            if expanded not in known:
                print(f"[ERROR] unknown target {expanded}; choose from {', '.join(known)} or all", file=sys.stderr)
                return EXIT_USAGE
            if expanded not in targets:
                targets.append(expanded)
    report = run_check(ROOT, table, targets)
    if args.json:
        print(json.dumps(report.as_json(), indent=2, sort_keys=True))
    else:
        print(report.render())
    return EXIT_OK if report.ok else EXIT_PROBLEM


if __name__ == "__main__":
    sys.exit(main())
