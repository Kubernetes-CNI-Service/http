"""Unified dependency table: direct contract of infra/deps.py, infra/dependencies.json and the hashed lists.

The expected closure, versions and owner decisions below are written out independently of
the implementation; the engine list and the container lock are parsed here with a parser
of this module, never with infra/deps.py. Environment checks run against a temporary HOME,
fake dpkg-query/commands and a fake base python; nothing is installed and no network is used.
"""

from __future__ import annotations

import ast
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
DEPS_PATH = ROOT / "infra/deps.py"
TABLE_PATH = ROOT / "infra/dependencies.json"
ENGINE = "infra/docker/requirements-issue-tracker-engine.txt"
IBSW = "infra/requirements-ibsw-upgrade.txt"
# Owner 2026-10-24: the formal full proof runs on the CLT /usr/bin/python3 (CPython 3.9, macOS arm64); its F01 SDK
# identity tests need venv-ibsw-upgrade there, so the ibsw set also has a macOS cp39 arm64 hashed list.
IBSW_MACOS = "infra/requirements-ibsw-upgrade-macos-cp39.txt"
LINUX_CP312 = ["linux-cp312-x86_64", "linux-cp312-aarch64"]
# Retired in REQ7 retirement step 3b (2026-10-24) with requirements-req7-online.txt; the image installs only
# the engine list now, which keeps the retired lock's 20 distributions byte for byte.
RETIRED_LISTS = ("infra/docker/requirements-req7-cable-sync.txt", "infra/docker/requirements-req7-online.txt")
# The 20 distributions of the retired cable lock (read from it at 7d5518d; unchanged until step 3b removed it).
EXPECTED_ENGINE_BASE = {
    "certifi": "2026.7.22",
    "cffi": "2.0.0",
    "charset-normalizer": "3.5.1",
    "cryptography": "50.0.1",
    "google-api-core": "2.30.3",
    "google-api-python-client": "2.198.0",
    "google-auth": "2.50.0",
    "google-auth-httplib2": "0.3.1",
    "googleapis-common-protos": "1.75.0",
    "httplib2": "0.32.0",
    "idna": "3.19",
    "proto-plus": "1.27.2",
    "protobuf": "6.33.6",
    "pyasn1": "0.6.4",
    "pyasn1-modules": "0.4.2",
    "pycparser": "2.23",
    "pyparsing": "3.3.2",
    "requests": "2.32.5",
    "uritemplate": "4.2.0",
    "urllib3": "2.6.3",
}
# sha256 over those 20 records (name==version and sorted hashes) and their wheel comments, computed from the
# retired lock by req7-batch2-3b/edit_deps_test_b3.py; see engine_base_records_sha256.
EXPECTED_ENGINE_BASE_RECORDS_SHA256 = "73173aa17b78436e3684308e0898a07ccdb7e571ca555c929eae7a3ac3c673a7"
CONTAINER_LOCK = "requirements-container-top-level.lock"
XDR = "infiniband/bringup/xdr-upgrade/requirements.txt"
# Measured by a cp312 resolve (pip download with dependencies, Ubuntu 24.04, 2026-10-23) of the
# engine's imports plus httpx[socks]/openai/PySocks; versions are the CLT user-site versions.
EXPECTED_ENGINE_EXTRAS = {
    "annotated-types": "0.7.0", "anyio": "4.12.1", "distro": "1.9.0", "h11": "0.16.0",
    "httpcore": "1.0.9", "httpx": "0.28.1", "jiter": "0.16.0", "openai": "2.48.0",
    "pydantic": "2.13.5", "pydantic-core": "2.46.5", "pysocks": "1.7.1", "sniffio": "1.3.1",
    "socksio": "1.0.0", "tqdm": "4.70.1", "typing-extensions": "4.16.0", "typing-inspection": "0.4.2",
}
# The 51 user-site distributions of the formal local test runtime (CLT /usr/bin/python3 3.9).
EXPECTED_LOCAL_TEST = {
    "annotated-types", "anyio", "bcrypt", "certifi", "cffi", "charset-normalizer", "cryptography",
    "distro", "et-xmlfile", "exceptiongroup", "google-api-core", "google-api-python-client",
    "google-auth", "google-auth-httplib2", "googleapis-common-protos", "h11", "httpcore", "httplib2",
    "httpx", "idna", "invoke", "jinja2", "jiter", "markupsafe", "numpy", "openai", "openpyxl", "pandas",
    "paramiko", "proto-plus", "protobuf", "pyasn1", "pyasn1-modules", "pycparser", "pydantic",
    "pydantic-core", "pynacl", "pyparsing", "python-dateutil", "pytz", "pyyaml", "requests", "sniffio",
    "socksio", "tqdm", "typing-extensions", "typing-inspection", "tzdata", "uritemplate", "urllib3",
    "xlsxwriter",
}
FORBIDDEN_TOKENS = ("://", "file:", "git+", " @ ", ";", "--index-url", "--extra-index-url",
                    "--find-links", "--editable", "-e ")


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_lock(path: Path) -> tuple:
    """Test-owned parser: ({name: (version, [hashes])}, {wheel: sha256}, header)."""
    text = path.read_text(encoding="ascii")
    records, wheels, pending = {}, {}, []
    for raw in text.splitlines():
        stripped = raw.strip()
        match = re.fullmatch(r"# wheel: (\S+\.whl) sha256:([0-9a-f]{64})", stripped)
        if match:
            wheels[match.group(1)] = match.group(2)
            continue
        if not stripped or stripped.startswith("#"):
            continue
        pending.append(stripped.rstrip("\\").strip())
        if stripped.endswith("\\"):
            continue
        tokens = " ".join(pending).split()
        pending = []
        name, version = tokens[0].split("==")
        records[norm(name)] = (version, [token.split(":", 1)[1] for token in tokens[1:]])
    assert not pending, path
    return records, wheels, text.splitlines()[0]


def engine_base_records_sha256(records: dict, wheels: dict, names) -> str:
    lines = [f"{name}=={records[name][0]} {' '.join(sorted(records[name][1]))}" for name in sorted(names)]
    lines += [f"{wheel} {digest}" for wheel, digest in sorted(wheels.items())
              if norm(wheel.split("-", 1)[0]) in names]
    return hashlib.sha256("\n".join(lines).encode("ascii")).hexdigest()


def parse_pins(path: Path) -> dict:
    pins = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            name, _sep, version = line.partition("==")
            pins[norm(name)] = version or None
    return pins


def load_deps():
    return load_script("deps_table_under_test", DEPS_PATH)


FAKE_PYTHON = r'''#!{python}
import json, os, sys
from pathlib import Path
args = sys.argv[1:]
log = os.environ.get("FAKE_PY_LOG")
if log:
    with open(log, "a") as handle:
        handle.write(json.dumps([str(Path(__file__))] + args) + "\n")
while args and args[0] in ("-I", "-B", "-s", "-E"):
    args = args[1:]
if args[:1] == ["-c"]:
    if args[1].startswith("# deps-identity"):
        # A venv interpreter keeps the identity of the base it was created from (fake-identity.json beside
        # its pyvenv.cfg); a base interpreter reports FAKE_PY_IDENTITY.
        own = Path(__file__).resolve().parents[1] / "fake-identity.json"
        print(own.read_text() if (own.parent / "pyvenv.cfg").is_file() and own.is_file()
              else os.environ["FAKE_PY_IDENTITY"])
        sys.exit(0)
    if args[1].startswith("# deps-import-probe"):
        broken = [name for name in args[2:] if name in os.environ.get("FAKE_PY_IMPORT_FAIL", "").split()]
        if broken:
            print("ModuleNotFoundError: No module named %r" % broken[0])
            sys.exit(1)
        sys.exit(0)
    sys.exit(3)
if args[:2] == ["-m", "venv"]:
    target = Path(args[-1])
    # The created venv follows the identity this fake base interpreter reports (Linux 3.12 unless told otherwise).
    identity = os.environ.get("FAKE_PY_IDENTITY") or json.dumps(
        {"implementation": "CPython", "system": "linux", "machine": "x86_64", "version": "3.12"})
    version = json.loads(identity)["version"]
    site = target / ("lib/python%s/site-packages" % version)
    (target / "bin").mkdir(parents=True)
    site.mkdir(parents=True)
    system = "true" if "--system-site-packages" in args else "false"
    full = {"3.12": "3.12.3", "3.9": "3.9.6"}.get(version, version + ".0")
    (target / "pyvenv.cfg").write_text("home = /usr/bin\ninclude-system-site-packages = %s\nversion = %s\n" % (system, full))
    (target / "fake-identity.json").write_text(identity)
    me = target / "bin/python"
    me.write_bytes(Path(__file__).read_bytes())
    me.chmod(0o755)
    if os.environ.get("FAKE_PY_VENV_FAIL"):
        # Debian/Ubuntu without python3-venv: pyvenv.cfg and bin/python exist, ensurepip failed.
        print("The virtual environment was not created successfully because ensurepip is not available.")
        sys.exit(1)
    info = site / "pip-24.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Name: pip\nVersion: 24.0\n\n")
    sys.exit(0)
if args[:2] == ["-m", "pip"]:
    venv = Path(__file__).resolve().parents[1]
    sites = sorted(venv.glob("lib/python*/site-packages"))
    site = sites[0] if len(sites) == 1 else venv / "lib/python3.12/site-packages"
    rest = [arg for arg in args[2:] if arg != "--isolated"]
    if not (site / "pip-24.0.dist-info").is_dir():
        print("%s: No module named pip" % __file__)
        sys.exit(1)
    if rest[:1] == ["--version"]:
        print("pip 24.0 from %s" % site)
        sys.exit(0)
    if rest[:1] == ["install"]:
        requirements = Path(rest[rest.index("-r") + 1])
        for raw in requirements.read_text().splitlines():
            line = raw.strip()
            if line and not line.startswith(("#", "--")) and "==" in line:
                name, version = line.split()[0].split("==")
                info = site / ("%s-%s.dist-info" % (name.replace("-", "_"), version))
                info.mkdir(exist_ok=True)
                (info / "METADATA").write_text("Metadata-Version: 2.1\nName: %s\nVersion: %s\n\n" % (name, version))
        sys.exit(0)
sys.exit(4)
'''

LINUX_312 = json.dumps({"implementation": "CPython", "system": "linux", "machine": "x86_64", "version": "3.12"})
MACOS_39_ARM64 = json.dumps({"implementation": "CPython", "system": "darwin", "machine": "arm64", "version": "3.9"})


def write_fake_python(directory: Path) -> Path:
    path = directory / "fakepython"
    path.write_text(FAKE_PYTHON.replace("{python}", sys.executable), encoding="utf-8")
    path.chmod(0o755)
    return path


def run_deps(*args: str, env: dict = None) -> subprocess.CompletedProcess:
    environment = dict(os.environ)
    environment.update(env or {})
    return subprocess.run([sys.executable, "-B", str(DEPS_PATH), *args], cwd=ROOT, env=environment,
                          stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120)


class TableContractTests(unittest.TestCase):
    def setUp(self):
        self.deps = load_deps()
        self.table = self.deps.load_table(ROOT)

    def test_table_is_canonical_ascii_json_with_one_version_per_distribution(self):
        raw = TABLE_PATH.read_bytes()
        value = json.loads(raw.decode("ascii"))
        self.assertEqual(raw, (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii"))
        self.assertEqual(1, value["schema_version"])
        for name, row in value["python_distributions"].items():
            with self.subTest(distribution=name):
                self.assertEqual(norm(name), name)
                self.assertRegex(row["version"], r"^[0-9][0-9A-Za-z.]*$")
                self.assertTrue(row["import_names"])
                self.assertTrue(row["used_by"].strip())

    def test_owner_decisions_are_recorded(self):
        targets = self.table["targets"]
        self.assertEqual("~/.venvs/http/ibsw-upgrade", targets["venv-ibsw-upgrade"]["path"])
        self.assertEqual("~/.venvs/http/cabletracker", targets["venv-cabletracker"]["path"])
        for name in ("venv-ibsw-upgrade", "venv-cabletracker"):
            self.assertIs(False, targets[name]["system_site_packages"])
            self.assertEqual("3.12", targets[name]["python"])
        self.assertEqual(LINUX_CP312, targets["venv-cabletracker"]["platforms"])
        self.assertNotIn("variants", targets["venv-cabletracker"])
        # Owner 2026-10-24: the formal proof interpreter is the CLT /usr/bin/python3 (3.9, macOS arm64); the F01
        # SDK identity tests run in venv-ibsw-upgrade there, built from its own macOS cp39 hashed list. Only
        # arm64: no Intel Mac can verify an x86_64 list.
        ibsw = targets["venv-ibsw-upgrade"]
        self.assertEqual(LINUX_CP312 + ["macos-cp39-arm64"], ibsw["platforms"])
        self.assertEqual(IBSW, ibsw["requirements"])
        self.assertEqual({"macos-cp39-arm64": {"python": "3.9", "requirements": IBSW_MACOS}}, ibsw["variants"])
        self.assertNotIn("macos-cp39-x86_64", self.table["platforms"])
        self.assertEqual("supported", self.table["platforms"]["macos-cp39-arm64"]["status"])
        files = self.table["requirement_files"]
        self.assertEqual({"format": "hashed", "set": "ibsw-upgrade", "platforms": ["macos-cp39-arm64"]}, files[IBSW_MACOS])
        for relative in (IBSW, ENGINE, CONTAINER_LOCK):
            self.assertEqual(LINUX_CP312, files[relative]["platforms"], relative)
        self.assertEqual({ENGINE, IBSW, IBSW_MACOS, CONTAINER_LOCK},
                         {path for path, row in files.items() if row["format"] == "hashed"})
        # F01 reuses the ibsw-upgrade venv, which therefore carries PyYAML.
        self.assertIn("tools/ufm_bootstrap_auth_adapter.py", targets["venv-ibsw-upgrade"]["consumers"])
        self.assertIn("pyyaml", self.table["python_sets"]["ibsw-upgrade"]["distributions"])
        self.assertEqual("1.7.1", self.table["python_distributions"]["pysocks"]["version"])
        self.assertIn("pysocks", self.table["python_sets"]["issue-tracker-engine"]["distributions"])
        for platform_name in ("linux-cp310-x86_64", "linux-cp310-aarch64"):
            self.assertEqual("planned", self.table["platforms"][platform_name]["status"])
        self.assertEqual("6.0.1-2build2", targets["native"]["observed_versions"]["python3-yaml"])
        self.assertEqual("ci", targets["ci"]["kind"])
        self.assertEqual("requirements-dev.txt", targets["ci"]["requirements"])
        self.assertEqual("/opt/http-ztp/venv/bin/python", targets["container"]["interpreter"])
        self.assertEqual("3.9", targets["local-test"]["python"])
        self.assertIn("python3-venv", self.deps.apt_packages(self.table, targets["native"]["apt_sets"]))

    def test_local_test_target_is_the_measured_clt_user_site(self):
        target = self.table["targets"]["local-test"]
        self.assertEqual(EXPECTED_LOCAL_TEST, set(self.deps.target_distributions(self.table, target)))
        self.assertEqual({"pysocks"}, set(target["omit"]))
        self.assertEqual({"altgraph", "future", "macholib", "pip", "setuptools", "six", "wheel"},
                         set(target["clt_provided"]))

    def test_engine_set_is_the_retired_cable_closure_plus_the_measured_extras(self):
        self.assertEqual(20, len(EXPECTED_ENGINE_BASE))
        engine = set(self.table["python_sets"]["issue-tracker-engine"]["distributions"])
        self.assertEqual(set(EXPECTED_ENGINE_BASE) | set(EXPECTED_ENGINE_EXTRAS), engine)
        self.assertEqual(36, len(engine))
        for name, version in {**EXPECTED_ENGINE_BASE, **EXPECTED_ENGINE_EXTRAS}.items():
            self.assertEqual(version, self.table["python_distributions"][name]["version"], name)
        # The two retired REQ7 sets are gone; every target that had them still gets their distributions.
        self.assertEqual(set(), {"req7-online", "req7-cable"} & set(self.table["python_sets"]))
        for target in ("container", "local-test"):
            with self.subTest(target=target):
                self.assertIn("issue-tracker-engine", self.table["targets"][target]["python_sets"])

    def test_every_third_party_import_of_a_production_script_is_in_the_table(self):
        if str(ROOT) not in sys.path:
            sys.path.insert(0, str(ROOT))
        from test_cases import run_related_tests as runner

        # The runner's own source frame: production paths only (no outputs/, .git, venvs or
        # reference-only trees), so a stray venv cannot hide a third-party import.
        scripts = runner.discover_source_scripts(ROOT)
        local = set()
        for relative in scripts:
            path = Path(relative)
            if path.suffix == ".py":
                local.add(path.stem)
            local.update(parent.name for parent in path.parents if parent.name)
        stdlib_names = getattr(sys, "stdlib_module_names", None)
        stdlib_root = os.path.realpath(os.path.dirname(os.__file__))

        def is_stdlib(name: str) -> bool:
            if name in sys.builtin_module_names or (stdlib_names is not None and name in stdlib_names):
                return True
            if stdlib_names is not None:
                return False
            try:
                spec = importlib.util.find_spec(name)
            except (ImportError, ValueError):
                return False
            origin = getattr(spec, "origin", None) if spec is not None else None
            if origin in ("built-in", "frozen"):
                return True
            return bool(origin) and os.path.realpath(origin).startswith(stdlib_root + os.sep) \
                and "site-packages" not in os.path.realpath(origin)

        third_party = {}
        for relative in scripts:
            if not relative.endswith((".py", ".cgi")):
                continue
            for node in ast.walk(ast.parse((ROOT / relative).read_bytes(), filename=relative)):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    if top != "__future__" and top not in local and not is_stdlib(top):
                        third_party.setdefault(top, set()).add(relative)
        registered = {module.split(".")[0] for row in self.table["python_distributions"].values()
                      for module in row["import_names"]}
        self.assertEqual({}, {name: sorted(paths)[:3] for name, paths in third_party.items() if name not in registered})
        # The scan is not vacuous: these are the third-party roots the review counted (2026-10-23).
        self.assertTrue({"yaml", "jinja2", "openpyxl", "pandas", "xlsxwriter", "paramiko", "google",
                         "googleapiclient", "google_auth_httplib2", "httplib2", "httpx", "requests",
                         "openai"} <= set(third_party), sorted(third_party))

    def test_every_tracked_dependency_list_is_registered(self):
        sys.path.insert(0, str(ROOT / "tools"))
        try:
            from project_contract import path_disposition
        finally:
            sys.path.remove(str(ROOT / "tools"))
        listing = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
                                 cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True, check=True)
        pattern = re.compile(r"(?:^|/)[^/]*(?:requirements|constraints)[^/]*\.(?:txt|in|lock)$|\.lock(?:\.json)?$"
                             r"|(?:^|/)(?:Pipfile|pyproject\.toml|setup\.cfg)$", re.IGNORECASE)
        found = sorted(path for path in listing.stdout.decode("utf-8").split("\0")
                       if path and pattern.search(path) and path_disposition(path) == "production")
        registered = set(self.table["requirement_files"]) | set(self.table["not_dependency_lists"])
        self.assertEqual([], [path for path in found if path not in registered])
        self.assertTrue({ENGINE, IBSW, IBSW_MACOS, CONTAINER_LOCK, XDR} <= set(found))
        self.assertEqual(set(), set(RETIRED_LISTS) & (set(found) | registered))


class HashedListTests(unittest.TestCase):
    def assert_hash_locked(self, relative: str) -> dict:
        path = ROOT / relative
        self.assertEqual(".txt", path.suffix)
        raw = path.read_bytes()
        raw.decode("ascii")
        self.assertTrue(raw.endswith(b"\n"))
        text = raw.decode("ascii")
        requirement_lines = [line.casefold() for line in text.splitlines() if not line.lstrip().startswith("#")]
        for token in FORBIDDEN_TOKENS:
            offending = [line for line in requirement_lines if token in line]
            self.assertEqual([], offending, f"{relative}: forbidden {token!r} (markers/URLs/options)")
        records, wheels, header = parse_lock(path)
        self.assertTrue(header.startswith("# ") and "--require-hashes" in header and "infra/dependencies.json" in header)
        all_hashes = set()
        for name, (version, hashes) in records.items():
            with self.subTest(list=relative, distribution=name):
                self.assertTrue(hashes)
                self.assertEqual(sorted(hashes), hashes)
                for digest in hashes:
                    self.assertRegex(digest, r"^[0-9a-f]{64}$")
                    self.assertNotIn(digest, all_hashes)
                    all_hashes.add(digest)
                commented = {digest for wheel, digest in wheels.items() if norm(wheel.split("-", 1)[0]) == name}
                self.assertEqual(set(hashes), commented)
                for wheel in wheels:
                    if norm(wheel.split("-", 1)[0]) == name:
                        self.assertEqual(version, wheel.split("-")[1])
        self.assertEqual(sorted(records), list(records))
        return records

    def test_engine_list_keeps_the_retired_cable_wheels_byte_for_byte(self):
        engine = self.assert_hash_locked(ENGINE)
        self.assertEqual(36, len(engine))
        for name, version in EXPECTED_ENGINE_BASE.items():
            with self.subTest(distribution=name):
                self.assertIn(name, engine)
                self.assertEqual(version, engine[name][0])
        _engine_records, engine_wheels, _header = parse_lock(ROOT / ENGINE)
        self.assertEqual(EXPECTED_ENGINE_BASE_RECORDS_SHA256,
                         engine_base_records_sha256(engine, engine_wheels, set(EXPECTED_ENGINE_BASE)),
                         "the image's former cable-lock wheels changed")
        for name, version in EXPECTED_ENGINE_EXTRAS.items():
            self.assertEqual(version, engine[name][0], name)

    def test_ibsw_list_is_the_xdr_pins_plus_pyyaml_with_shared_hashes(self):
        ibsw = self.assert_hash_locked(IBSW)
        xdr = parse_pins(ROOT / XDR)
        container, _wheels, _header = parse_lock(ROOT / CONTAINER_LOCK)
        engine, _engine_wheels, _header = parse_lock(ROOT / ENGINE)
        self.assertEqual(set(xdr), set(ibsw))
        for name, version in xdr.items():
            self.assertEqual(version or container[name][0], ibsw[name][0], name)
        self.assertEqual(set(container["pyyaml"][1]), set(ibsw["pyyaml"][1]))
        for name in ("cryptography", "cffi", "pycparser"):
            self.assertEqual(set(engine[name][1]), set(ibsw[name][1]), name)
        self.assertEqual(set(engine["typing-extensions"][1]), set(ibsw["typing-extensions"][1]))
        self.assertEqual({"paramiko", "bcrypt", "invoke", "pynacl", "pyyaml", "cryptography", "cffi",
                          "pycparser", "typing-extensions"}, set(ibsw))

    def test_ibsw_macos_list_pins_the_linux_versions_with_cp39_arm64_wheels(self):
        """One wheel per distribution, installable by CPython 3.9 on every Apple Silicon macOS (11+); the
        versions are the Linux list's, and a pure wheel is the same PyPI file in both lists."""
        macos = self.assert_hash_locked(IBSW_MACOS)
        linux = self.assert_hash_locked(IBSW)
        _records, macos_wheels, header = parse_lock(ROOT / IBSW_MACOS)
        _records, linux_wheels, _header = parse_lock(ROOT / IBSW)
        self.assertIn("CPython 3.9 macOS arm64", header)
        self.assertEqual({name: record[0] for name, record in linux.items()},
                         {name: record[0] for name, record in macos.items()})
        self.assertEqual(len(macos), len(macos_wheels))
        self.assertEqual({name: 1 for name in macos},
                         {name: len(record[1]) for name, record in macos.items()})
        platform_specific = 0
        for wheel, digest in sorted(macos_wheels.items()):
            with self.subTest(wheel=wheel):
                _name, _version, python_tag, abi_tag, platform_tag = wheel[:-len(".whl")].split("-")
                if platform_tag == "any":
                    self.assertEqual(("py3", "none"), (python_tag, abi_tag))
                    self.assertEqual(linux_wheels.get(wheel), digest, "a pure wheel is one file on PyPI")
                    continue
                platform_specific += 1
                if abi_tag == "abi3":
                    self.assertRegex(python_tag, r"^cp3[2-9]$")
                else:
                    self.assertEqual(("cp39", "cp39"), (python_tag, abi_tag))
                match = re.fullmatch(r"macosx_([0-9]+)_([0-9]+)_(arm64|universal2)", platform_tag)
                self.assertIsNotNone(match, platform_tag)
                release = (int(match.group(1)), int(match.group(2)))
                self.assertLessEqual(release, (11, 0), "must install on macOS 11, the first Apple Silicon release")
                if match.group(3) == "arm64":
                    self.assertEqual((11, 0), release)
                self.assertNotIn(digest, set(linux_wheels.values()))
        self.assertEqual(5, platform_specific)  # bcrypt, cffi, cryptography, pynacl, pyyaml

    def test_neither_new_list_uses_the_lock_suffix_excluded_by_transport(self):
        for relative in (ENGINE, IBSW, IBSW_MACOS):
            self.assertFalse(relative.endswith(".lock"), relative)
            self.assertTrue(relative.startswith("infra/"), relative)


class CheckFilesTests(unittest.TestCase):
    def setUp(self):
        self.deps = load_deps()
        self.table = self.deps.load_table(ROOT)

    def test_repository_lists_and_code_copies_agree_with_the_table(self):
        report = self.deps.Report()
        self.deps.check_files(ROOT, self.table, report)
        rows = report.targets["files"]
        self.assertEqual([], [row for row in rows if row["status"] != "ok"])
        items = {row["item"] for row in rows}
        self.assertTrue(set(self.table["requirement_files"]) <= items)
        for copy in self.table["code_copies"]:
            self.assertIn(f"{copy['path']}::{copy['symbol']}", items)

    def copy_tree(self, base: Path) -> Path:
        root = base / "repo"
        paths = set(self.table["requirement_files"]) | {row["path"] for row in self.table["code_copies"]}
        paths.add("infra/dependencies.json")
        for relative in paths:
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / relative, target)
        return root

    def check(self, root: Path):
        report = self.deps.Report()
        self.deps.check_files(root, self.deps.load_table(root), report)
        return [row for row in report.targets["files"] if row["status"] != "ok"]

    def test_every_drift_fails_closed_with_a_named_item(self):
        cases = {
            "engine version": (ENGINE, "httpx==0.28.1", "httpx==0.28.2", "httpx"),
            "engine record removed": (ENGINE, re.compile(r"# wheel: PySocks-1\.7\.1-[^\n]*\npysocks==1\.7\.1 \\\n"
                                                         r"    --hash=sha256:[0-9a-f]{64}\n"), "", "pysocks"),
            "dev unexpected": ("requirements-dev.txt", "XlsxWriter==3.2.9\n", "XlsxWriter==3.2.9\nrequests==2.32.5\n", "requests"),
            "f01 version": ("requirements-f01-ssh.lock", "paramiko==5.0.0", "paramiko==5.0.1", "paramiko"),
            "macos ibsw version": (IBSW_MACOS, "pyyaml==6.0.3", "pyyaml==6.0.4", "pyyaml"),
            "observer pins": ("tools/ibsw_upgrade_observer.py", '("paramiko", "5.0.0")', '("paramiko", "5.0.1")', "SSH_RUNTIME_PINS"),
            "infra-setup apt": ("infra/infra-setup.py", '"arping", "jq")', '"arping")', "COMMON_PACKAGES"),
            "upgrade venv path": ("infiniband/bringup/xdr-upgrade/upgrade.py", "'~/.venvs/http/ibsw-upgrade'", "'~/.venvs/http/other'", "_RUNTIME_VENV_PATHS"),
            "activate engine imports": ("infra/docker/activate.py", '    "openai",\n)', '    "openai",\n    "socks",\n)', "ISSUE_TRACKER_ENGINE_IMPORTS"),
            "dockerfile apt": ("infra/docker/Dockerfile", "        whois \\\n", "", "Dockerfile"),
            "lower bound": ("tools/ibdiagnet-analyze-tool/requirements.txt", "pandas>=2.0", "pandas>=9.0", "pandas"),
        }
        for label, (relative, old, new, needle) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_tree(Path(directory))
                path = root / relative
                text = path.read_text(encoding="utf-8")
                if isinstance(old, str):
                    self.assertEqual(1, text.count(old), (relative, old))
                    text = text.replace(old, new)
                else:
                    text, count = old.subn(new, text)
                    self.assertEqual(1, count, (relative, old.pattern))
                path.write_text(text, encoding="utf-8")
                problems = self.check(root)
                self.assertTrue(problems, label)
                self.assertTrue(any(needle in row["item"] or needle in row["detail"] for row in problems),
                                (label, problems))

    def test_a_different_wheel_hash_for_the_same_pin_is_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_tree(Path(directory))
            path = root / IBSW
            records, _wheels, _header = parse_lock(path)
            old = records["cryptography"][1][0]
            new = hashlib.sha256(b"foreign wheel").hexdigest()
            path.write_text(path.read_text(encoding="ascii").replace(old, new), encoding="ascii")
            problems = self.check(root)
            self.assertTrue(any(row["item"] == "cryptography==50.0.1" and "different wheel hashes" in row["detail"]
                                for row in problems), problems)

    def test_lists_of_other_platforms_differ_by_wheel_but_never_for_the_same_wheel_file(self):
        """The macOS list shares no platform with the Linux lists, so its own pyyaml/cffi/cryptography wheels are
        not a drift; but the same wheel file (a pure wheel) must carry one digest in every list."""
        report = self.deps.Report()
        self.deps.check_files(ROOT, self.table, report)
        self.assertEqual([], [row for row in report.targets["files"] if row["status"] != "ok"])
        macos, _wheels, _header = parse_lock(ROOT / IBSW_MACOS)
        linux, _wheels, _header = parse_lock(ROOT / IBSW)
        self.assertNotEqual(set(linux["pyyaml"][1]), set(macos["pyyaml"][1]))
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_tree(Path(directory))
            path = root / IBSW_MACOS
            old = macos["paramiko"][1][0]
            new = hashlib.sha256(b"foreign pure wheel").hexdigest()
            text = path.read_text(encoding="ascii")
            self.assertEqual(2, text.count(old))  # the wheel comment and the hash option
            path.write_text(text.replace(old, new), encoding="ascii")
            problems = self.check(root)
            self.assertTrue(any(row["item"] == "paramiko-5.0.0-py3-none-any.whl" and "digest" in row["detail"]
                                and IBSW in row["detail"] and IBSW_MACOS in row["detail"] for row in problems),
                            problems)

    def test_every_hash_names_one_wheel_file_and_one_file_names_one_digest(self):
        """The cross-list wheel rule sees every pinned wheel only if each record hash has its '# wheel:' comment,
        and a filename listed twice with two digests is a broken list, not a second wheel."""
        macos, wheels, _header = parse_lock(ROOT / IBSW_MACOS)
        paramiko_wheel = next(name for name in wheels if name.startswith("paramiko-"))
        pyyaml_hash = macos["pyyaml"][1][0]
        foreign = hashlib.sha256(b"uncommented foreign wheel").hexdigest()
        cases = {
            "hash without a comment": (
                f"    --hash=sha256:{pyyaml_hash}\n",
                f"    --hash=sha256:{pyyaml_hash} \\\n    --hash=sha256:{foreign}\n",
                f"{IBSW_MACOS}: pyyaml", "without a '# wheel:"),
            "one wheel file with two digests": (
                f"# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n",
                f"# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n# wheel: {paramiko_wheel} sha256:{foreign}\n",
                IBSW_MACOS, f"wheel {paramiko_wheel} has two digests"),
            # A last-wins parser silently accepted this order: the real digest overwrote the foreign one.
            "foreign digest listed before the real one": (
                f"# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n",
                f"# wheel: {paramiko_wheel} sha256:{foreign}\n# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n",
                IBSW_MACOS, f"wheel {paramiko_wheel} has two digests"),
            "the same digest listed twice": (
                f"# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n",
                f"# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n# wheel: {paramiko_wheel} sha256:{wheels[paramiko_wheel]}\n",
                IBSW_MACOS, f"wheel {paramiko_wheel} is listed twice"),
            "wheel comment of another version": (
                f"# wheel: {paramiko_wheel} sha256:",
                f"# wheel: {paramiko_wheel.replace('-5.0.0-', '-5.0.1-')} sha256:",
                f"{IBSW_MACOS}: {paramiko_wheel.replace('-5.0.0-', '-5.0.1-')}", "wheel version differs"),
        }
        for label, (old, new, item, detail) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_tree(Path(directory))
                path = root / IBSW_MACOS
                text = path.read_text(encoding="ascii")
                self.assertEqual(1, text.count(old), old)
                path.write_text(text.replace(old, new), encoding="ascii")
                problems = self.check(root)
                self.assertTrue(any(row["item"] == item and detail in row["detail"] for row in problems),
                                (label, problems))

    def write_table(self, root: Path, table: dict) -> None:
        (root / "infra/dependencies.json").write_bytes(
            (json.dumps(table, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii"))

    def test_hashed_lists_and_venv_variants_name_the_platforms_they_cover(self):
        broken = {
            "hashed list without platforms":
                (lambda t: t["requirement_files"][IBSW_MACOS].pop("platforms"),
                 "requirement file infra/requirements-ibsw-upgrade-macos-cp39.txt platforms must be a list"),
            "hashed list with an unknown platform":
                (lambda t: t["requirement_files"][IBSW_MACOS].update(platforms=["macos-cp39-x86_64"]),
                 "names unknown platform macos-cp39-x86_64"),
            "variant list does not cover its platform":
                (lambda t: t["targets"]["venv-ibsw-upgrade"]["variants"]["macos-cp39-arm64"].update(requirements=IBSW),
                 "infra/requirements-ibsw-upgrade.txt does not cover platform macos-cp39-arm64"),
            "variant python of another platform":
                (lambda t: t["targets"]["venv-ibsw-upgrade"]["variants"]["macos-cp39-arm64"].update(python="3.12"),
                 "python 3.12 does not match platform macos-cp39-arm64"),
            "variant python does not match its platform":
                (lambda t: t["targets"]["venv-ibsw-upgrade"]["variants"]["macos-cp39-arm64"].update(python="3.10"),
                 "python 3.10 does not match platform macos-cp39-arm64"),
            "variant outside the target platforms":
                (lambda t: t["targets"]["venv-ibsw-upgrade"]["platforms"].remove("macos-cp39-arm64"),
                 "variant macos-cp39-arm64 is not one of its platforms"),
            "variant list of another set":
                (lambda t: t["targets"]["venv-ibsw-upgrade"]["variants"]["macos-cp39-arm64"].update(requirements=ENGINE),
                 "list has set issue-tracker-engine, the target's list has set ibsw-upgrade"),
            "platform without a list":
                (lambda t: t["targets"]["venv-cabletracker"]["platforms"].append("macos-cp39-arm64"),
                 "requirements-issue-tracker-engine.txt does not cover platform macos-cp39-arm64"),
        }
        for label, (change, message) in broken.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = self.copy_tree(Path(directory))
                table = json.loads(TABLE_PATH.read_text(encoding="ascii"))
                change(table)
                self.write_table(root, table)
                with self.assertRaisesRegex(self.deps.TableError, message):
                    self.deps.load_table(root)

    def test_one_python_may_serve_several_platforms_through_variants(self):
        """A macos-cp312 variant next to the Linux cp312 default is valid: the platform selects the variant."""
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_tree(Path(directory))
            table = json.loads(TABLE_PATH.read_text(encoding="ascii"))
            table["platforms"]["macos-cp312-arm64"] = {"note": "test-only platform", "status": "supported"}
            table["requirement_files"][IBSW_MACOS]["platforms"].append("macos-cp312-arm64")
            target = table["targets"]["venv-ibsw-upgrade"]
            target["platforms"].append("macos-cp312-arm64")
            target["variants"]["macos-cp312-arm64"] = {"python": "3.12", "requirements": IBSW_MACOS}
            self.write_table(root, table)
            loaded = self.deps.load_table(root)
            ibsw = loaded["targets"]["venv-ibsw-upgrade"]
            self.assertEqual(("3.12", IBSW_MACOS), self.deps.venv_variant(ibsw, "macos-cp312-arm64"))
            self.assertEqual(("3.12", IBSW), self.deps.venv_variant(ibsw, "linux-cp312-x86_64"))

    def test_missing_list_and_invalid_table_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = self.copy_tree(Path(directory))
            (root / ENGINE).unlink()
            self.assertTrue(any(row["item"] == ENGINE and row["status"] == "missing" for row in self.check(root)))
            table_path = root / "infra/dependencies.json"
            table = json.loads(table_path.read_text(encoding="ascii"))
            table_path.write_text(json.dumps(table), encoding="ascii")
            with self.assertRaisesRegex(self.deps.TableError, "not canonical"):
                self.deps.load_table(root)
            table["targets"]["container"]["python_sets"].append("no-such-set")
            table_path.write_bytes((json.dumps(table, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii"))
            with self.assertRaisesRegex(self.deps.TableError, "unknown python set"):
                self.deps.load_table(root)


class EnvironmentCheckTests(unittest.TestCase):
    def setUp(self):
        self.deps = load_deps()
        self.table = self.deps.load_table(ROOT)
        self.versions = {name: row["version"] for name, row in self.table["python_distributions"].items()}

    def python_rows(self, report, target):
        return {row["item"]: row for row in report.targets[target] if row["item"].startswith("python ")}

    def test_current_interpreter_target_compares_installed_metadata(self):
        installed = {name: self.versions[name] for name in EXPECTED_LOCAL_TEST}
        installed.update(self.table["targets"]["local-test"]["clt_provided"])
        del installed["exceptiongroup"]
        installed["httpx"] = "0.27.0"
        with mock.patch.object(self.deps, "installed_distributions", return_value=installed), \
                mock.patch.object(self.deps, "_find_spec", return_value=True):
            report = self.deps.Report()
            self.deps.check_current_interpreter_target(self.table, "local-test", report)
        rows = self.python_rows(report, "local-test")
        bad = {item: row["status"] for item, row in rows.items() if row["status"] not in ("ok", "info")}
        self.assertEqual({"python exceptiongroup==1.3.1": "missing", "python httpx": "mismatch"}, bad)
        self.assertFalse(any("pysocks" in item for item in rows))

    def test_native_target_uses_dpkg_query_commands_and_system_modules(self):
        with tempfile.TemporaryDirectory() as directory:
            bin_dir = Path(directory)
            (bin_dir / "dpkg-query").write_text(
                "#!/bin/sh\npkg=\"$3\"\ncase \" $FAKE_INSTALLED \" in *\" $pkg \"*) "
                "printf 'install ok installed\\t1.0'; exit 0;; esac\nexit 1\n", encoding="utf-8")
            (bin_dir / "dpkg-query").chmod(0o755)
            native = self.table["targets"]["native"]
            for command in native["commands"]:
                (bin_dir / command).write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
                (bin_dir / command).chmod(0o755)
            required = self.deps.apt_packages(self.table, native["apt_sets"])
            installed = [package for package in required if package not in ("rsync", "whois")]
            env = {"PATH": str(bin_dir), "FAKE_INSTALLED": " ".join(installed)}
            with mock.patch.dict(os.environ, env), mock.patch.object(self.deps, "_find_spec", return_value=True):
                report = self.deps.Report()
                self.deps.check_current_interpreter_target(self.table, "native", report)
        rows = report.targets["native"]
        missing = sorted(row["item"] for row in rows if row["status"] == "missing")
        self.assertEqual(["apt rsync", "apt whois"], missing)
        optional = [row for row in rows if row["item"] == "apt apache2"]
        self.assertEqual("info", optional[0]["status"])

    def make_venv(self, home: Path, target_name: str, identity: str = LINUX_312, full: str = None) -> Path:
        """A venv whose interpreter reports `identity`; pyvenv.cfg says `full` (default: that python)."""
        target = self.table["targets"][target_name]
        venv = home / target["path"][2:]
        python_version = json.loads(identity)["version"]
        full = full or {"3.12": "3.12.3", "3.9": "3.9.6"}.get(python_version, python_version + ".0")
        site = venv / f"lib/python{'.'.join(full.split('.')[:2])}/site-packages"
        site.mkdir(parents=True)
        (venv / "bin").mkdir()
        python = venv / "bin/python"
        python.write_text(FAKE_PYTHON.replace("{python}", sys.executable), encoding="utf-8")
        python.chmod(0o755)
        (venv / "fake-identity.json").write_text(identity, encoding="utf-8")
        (venv / "pyvenv.cfg").write_text(f"home = /usr/bin\ninclude-system-site-packages = false\nversion = {full}\n",
                                         encoding="utf-8")
        for name in self.deps.target_distributions(self.table, target):
            info = site / f"{name.replace('-', '_')}-{self.versions[name]}.dist-info"
            info.mkdir()
            (info / "METADATA").write_text(f"Name: {name}\nVersion: {self.versions[name]}\n\n", encoding="utf-8")
        return venv

    def venv_report(self, home: Path, target: str, **env):
        with mock.patch.dict(os.environ, {"HOME": str(home), **env}):
            report = self.deps.Report()
            self.deps.check_venv_target(self.table, target, report)
        return report

    def test_venv_target_checks_isolation_versions_extras_and_imports(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            venv = self.make_venv(home, "venv-cabletracker")
            report = self.venv_report(home, "venv-cabletracker")
            self.assertTrue(report.ok, report.render())
            self.assertIn("import probe", {row["item"] for row in report.targets["venv-cabletracker"]})
            failing = self.venv_report(home, "venv-cabletracker", FAKE_PY_IMPORT_FAIL="openai")
            self.assertEqual(["import probe"], [row["item"] for row in failing.targets["venv-cabletracker"]
                                                if row["status"] == "error"])
            site = venv / "lib/python3.12/site-packages"
            shutil.rmtree(site / "openai-2.48.0.dist-info")
            (site / "httpx-0.28.1.dist-info/METADATA").write_text("Name: httpx\nVersion: 0.27.0\n\n")
            extra = site / "flask-3.0.0.dist-info"
            extra.mkdir()
            (extra / "METADATA").write_text("Name: Flask\nVersion: 3.0.0\n\n")
            (venv / "pyvenv.cfg").write_text("include-system-site-packages = true\nversion = 3.12.3\n")
            rows = {row["item"]: row["status"] for row in self.venv_report(home, "venv-cabletracker").targets["venv-cabletracker"]
                    if row["status"] != "ok"}
            self.assertEqual({"python openai==2.48.0": "missing", "python httpx": "mismatch",
                              "python flask==3.0.0": "unexpected", "include-system-site-packages": "mismatch"}, rows)

    def test_venv_check_selects_the_variant_by_interpreter_platform_and_pyvenv_version(self):
        """The venv interpreter's own platform (host system and machine, its python) must be a platform of the
        target, and pyvenv.cfg must carry that platform's python: 3.9 is valid for the ibsw venv only on
        macOS arm64, 3.12 only on Linux; a version alone never selects a variant."""
        def identity(system, machine, version):
            return json.dumps({"implementation": "CPython", "system": system, "machine": machine, "version": version})
        accepted = {
            "macOS arm64 3.9 ibsw": ("venv-ibsw-upgrade", MACOS_39_ARM64, None),
            "Linux x86_64 3.12 ibsw": ("venv-ibsw-upgrade", LINUX_312, None),
            "Linux aarch64 3.12 ibsw": ("venv-ibsw-upgrade", identity("linux", "aarch64", "3.12"), None),
        }
        for label, (target, value, full) in accepted.items():
            with self.subTest(accepted=label), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                self.make_venv(home, target, value, full)
                report = self.venv_report(home, target)
                self.assertTrue(report.ok, report.render())
                items = {row["item"] for row in report.targets[target]}
                self.assertIn("python paramiko==5.0.0", items)
                self.assertIn("import probe", items)
        refused = {
            # (target, interpreter identity, pyvenv.cfg version, words of the detail)
            "Linux 3.9 ibsw": ("venv-ibsw-upgrade", identity("linux", "x86_64", "3.9"), None,
                               ("linux-cp39-x86_64", "not a platform")),
            "macOS 3.12 ibsw": ("venv-ibsw-upgrade", identity("darwin", "arm64", "3.12"), None,
                                ("macos-cp312-arm64", "not a platform")),
            "macOS x86_64 3.9 ibsw": ("venv-ibsw-upgrade", identity("darwin", "x86_64", "3.9"), None,
                                      ("macos-cp39-x86_64", "not a platform")),
            "Linux 3.10 ibsw": ("venv-ibsw-upgrade", identity("linux", "x86_64", "3.10"), None,
                                ("linux-cp310-x86_64", "not a platform")),
            "macOS 3.9 cabletracker": ("venv-cabletracker", MACOS_39_ARM64, None,
                                       ("macos-cp39-arm64", "not a platform")),
            "macOS 3.9 interpreter, 3.12 pyvenv.cfg": ("venv-ibsw-upgrade", MACOS_39_ARM64, "3.12.3",
                                                       ("3.12.3", "needs python 3.9")),
            "Linux 3.12 interpreter, 3.9 pyvenv.cfg": ("venv-ibsw-upgrade", LINUX_312, "3.9.6",
                                                       ("3.9.6", "needs python 3.12")),
        }
        for label, (target, value, full, words) in refused.items():
            with self.subTest(refused=label), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                self.make_venv(home, target, value, full)
                report = self.venv_report(home, target)
                self.assertFalse(report.ok, report.render())
                mismatch = [row for row in report.targets[target] if row["item"] == "venv python"]
                self.assertEqual(["mismatch"], [row["status"] for row in mismatch], report.render())
                for word in words:
                    self.assertIn(word, mismatch[0]["detail"])
                if "not a platform" in words:
                    for platform_name in self.table["targets"][target]["platforms"]:
                        self.assertIn(platform_name, mismatch[0]["detail"])
                self.assertIn("install --target " + target, mismatch[0]["fix"])

    def test_venv_check_names_a_broken_interpreter_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            venv = self.make_venv(home, "venv-ibsw-upgrade", MACOS_39_ARM64)
            (venv / "bin/python").unlink()
            (venv / "bin/python").symlink_to(home / "vanished-base/bin/python3")
            rows = self.venv_report(home, "venv-ibsw-upgrade").targets["venv-ibsw-upgrade"]
            missing = [row for row in rows if row["item"] == str(venv / "bin/python")]
            self.assertEqual(["missing"], [row["status"] for row in missing])
            self.assertIn("broken symlink", missing[0]["detail"])
            self.assertIn(str(home / "vanished-base/bin/python3"), missing[0]["detail"])

    def test_absent_venv_is_reported_with_the_install_command(self):
        with tempfile.TemporaryDirectory() as directory:
            report = self.venv_report(Path(directory), "venv-ibsw-upgrade")
            row = report.targets["venv-ibsw-upgrade"][0]
            self.assertEqual("missing", row["status"])
            self.assertIn(str(Path(directory) / ".venvs/http/ibsw-upgrade"), row["item"])
            self.assertIn("install --target venv-ibsw-upgrade", row["fix"])


class CommandLineTests(unittest.TestCase):
    def test_help_check_json_unknown_target_and_bundle_stub(self):
        self.assertIn("usage:", run_deps("--help").stdout.casefold())
        result = run_deps("check", "--target", "files", "--json")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIs(True, json.loads(result.stdout)["ok"])
        unknown = run_deps("check", "--target", "nowhere")
        self.assertEqual(2, unknown.returncode)
        self.assertIn("unknown target", unknown.stderr)
        bundle = run_deps("bundle")
        self.assertEqual(2, bundle.returncode)
        self.assertIn("phase 2", bundle.stderr)

    def test_install_builds_the_venv_under_home_with_hash_enforcing_isolated_pip(self):
        """S5: pip runs inside the venv with -I --isolated --no-cache-dir: no PIP_* environment,
        no pip.conf, no ~/.cache/pip; hashes, no-deps and wheels-only stay."""
        real = Path(os.path.expanduser("~")) / ".venvs/http/cabletracker"
        real_before = real.exists() and sorted(os.listdir(real))
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            home.mkdir()
            fake = write_fake_python(base)
            log = base / "argv.log"
            env = {"HOME": str(home), "FAKE_PY_IDENTITY": LINUX_312, "FAKE_PY_LOG": str(log)}
            result = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake), env=env)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            venv = home / ".venvs/http/cabletracker"
            self.assertTrue((venv / "pyvenv.cfg").is_file())
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            pip = [call for call in calls if "install" in call and "-m" in call and "pip" in call]
            self.assertEqual(1, len(pip))
            self.assertEqual([str(venv / "bin/python"), "-I", "-m", "pip", "--isolated", "install", "--no-cache-dir",
                              "--disable-pip-version-check", "--only-binary=:all:", "--no-deps", "--require-hashes",
                              "-r", str(ROOT / ENGINE)], pip[0])
            create = [call for call in calls if "venv" in call[1:4]]
            self.assertEqual([[str(fake), "-I", "-m", "venv", str(venv)]], create)
            self.assertIn("== venv-cabletracker: OK", result.stdout)
            again = run_deps("check", "--target", "venv-cabletracker", env=env)
            self.assertEqual(0, again.returncode, again.stdout)
            self.assertEqual(0o700, (home / ".venvs/http").stat().st_mode & 0o777)
            # A second install into the healthy venv probes pip, then reinstalls by hash only.
            rerun = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake), env=env)
            self.assertEqual(0, rerun.returncode, rerun.stdout + rerun.stderr)
        self.assertEqual(real_before, real.exists() and sorted(os.listdir(real)))

    def test_install_refuses_planned_or_foreign_platforms_and_non_venv_paths(self):
        def identity(system, machine, version):
            return json.dumps({"implementation": "CPython", "system": system, "machine": machine, "version": version})
        identities = {
            "planned": ("venv-ibsw-upgrade", identity("linux", "aarch64", "3.10"), "phase 2"),
            # macOS cp39 arm64 is a venv-ibsw-upgrade platform only (owner 2026-10-24); Intel Macs and other
            # Python versions on macOS are not.
            "macos cabletracker": ("venv-cabletracker", MACOS_39_ARM64, "not supported"),
            "macos x86_64": ("venv-ibsw-upgrade", identity("darwin", "x86_64", "3.9"), "not supported"),
            "macos cp312": ("venv-ibsw-upgrade", identity("darwin", "arm64", "3.12"), "not supported"),
        }
        for label, (target, value, message) in identities.items():
            with self.subTest(platform=label), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                fake = write_fake_python(base)
                result = run_deps("install", "--target", target, "--python", str(fake),
                                  env={"HOME": str(base), "FAKE_PY_IDENTITY": value})
                self.assertEqual(2, result.returncode)
                self.assertIn(message, result.stderr)
                self.assertFalse((base / ".venvs").exists())
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = write_fake_python(base)
            (base / ".venvs/http/ibsw-upgrade").mkdir(parents=True)
            result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake),
                              env={"HOME": str(base), "FAKE_PY_IDENTITY": LINUX_312})
            self.assertEqual(2, result.returncode)
            self.assertIn("not a venv", result.stderr)

    def test_install_on_macos_cp39_arm64_uses_the_macos_hashed_list(self):
        """The CLT /usr/bin/python3 (CPython 3.9, darwin arm64) builds venv-ibsw-upgrade from the macOS list with
        the same isolated, hash-enforcing pip; the result checks green and a dry run names the same list."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            home = base / "home"
            home.mkdir()
            fake = write_fake_python(base)
            log = base / "argv.log"
            env = {"HOME": str(home), "FAKE_PY_IDENTITY": MACOS_39_ARM64, "FAKE_PY_LOG": str(log)}
            result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake), env=env)
            self.assertEqual(0, result.returncode, result.stdout + result.stderr)
            venv = home / ".venvs/http/ibsw-upgrade"
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            create = [call for call in calls if "venv" in call[1:4]]
            self.assertEqual([[str(fake), "-I", "-m", "venv", str(venv)]], create)
            pip = [call for call in calls if "install" in call and "-m" in call and "pip" in call]
            self.assertEqual([[str(venv / "bin/python"), "-I", "-m", "pip", "--isolated", "install", "--no-cache-dir",
                               "--disable-pip-version-check", "--only-binary=:all:", "--no-deps", "--require-hashes",
                               "-r", str(ROOT / IBSW_MACOS)]], pip)
            self.assertIn("version = 3.9.6", (venv / "pyvenv.cfg").read_text())
            site = venv / "lib/python3.9/site-packages"
            installed = {norm(path.name.split("-")[0]) for path in site.glob("*.dist-info")}
            self.assertEqual({"pip", "paramiko", "bcrypt", "invoke", "pynacl", "pyyaml", "cryptography", "cffi",
                              "pycparser", "typing-extensions"}, installed)
            self.assertIn("== venv-ibsw-upgrade: OK", result.stdout)
            again = run_deps("check", "--target", "venv-ibsw-upgrade", env=env)
            self.assertEqual(0, again.returncode, again.stdout)
            dry = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake), "--dry-run",
                           env=dict(env, HOME=str(base)))
            self.assertEqual(0, dry.returncode, dry.stderr)
            self.assertIn("--require-hashes -r " + str(ROOT / IBSW_MACOS), dry.stdout)
            self.assertFalse((base / ".venvs").exists())

    def test_install_refuses_an_existing_venv_of_another_platform_or_python(self):
        """An existing venv is reused only when its interpreter is the platform the base selects; otherwise
        install (and its dry run) stops before pip with the directory to remove, and changes nothing."""
        cases = {
            "Linux 3.12 venv, macOS 3.9 base": (LINUX_312, MACOS_39_ARM64, "linux-cp312-x86_64", "macos-cp39-arm64"),
            "macOS 3.9 venv, Linux 3.12 base": (MACOS_39_ARM64, LINUX_312, "macos-cp39-arm64", "linux-cp312-x86_64"),
        }
        for label, (built, base, existing, selected) in cases.items():
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                home = root / "home"
                home.mkdir()
                fake = write_fake_python(root)
                first = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake),
                                 env={"HOME": str(home), "FAKE_PY_IDENTITY": built})
                self.assertEqual(0, first.returncode, first.stdout + first.stderr)
                venv = home / ".venvs/http/ibsw-upgrade"
                before = {str(path.relative_to(venv)): path.read_bytes() for path in venv.rglob("*") if path.is_file()}
                log = root / "argv.log"
                for extra in ([], ["--dry-run"]):
                    result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake), *extra,
                                      env={"HOME": str(home), "FAKE_PY_IDENTITY": base, "FAKE_PY_LOG": str(log)})
                    self.assertEqual(2, result.returncode, result.stdout + result.stderr)
                    for needle in (existing, selected, "rm -rf " + str(venv),
                                   "python3 infra/deps.py install --target venv-ibsw-upgrade", "nothing was changed"):
                        self.assertIn(needle, result.stderr)
                    self.assertNotIn("[RUN]", result.stdout)
                calls = [json.loads(line) for line in log.read_text().splitlines()]
                self.assertEqual([], [call for call in calls if "pip" in call or "venv" in call[1:4]])
                after = {str(path.relative_to(venv)): path.read_bytes() for path in venv.rglob("*") if path.is_file()}
                self.assertEqual(before, after)

    def test_install_names_a_broken_interpreter_symlink_and_deletes_nothing(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = write_fake_python(root)
            env = {"HOME": str(root), "FAKE_PY_IDENTITY": LINUX_312}
            self.assertEqual(0, run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake),
                                         env=env).returncode)
            python = root / ".venvs/http/ibsw-upgrade/bin/python"
            python.unlink()
            python.symlink_to(root / "removed-base/bin/python3.12")
            result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake), env=env)
            self.assertEqual(1, result.returncode, result.stdout + result.stderr)
            self.assertIn("broken symlink to " + str(root / "removed-base/bin/python3.12"), result.stderr)
            self.assertIn("rm -rf " + str(root / ".venvs/http/ibsw-upgrade"), result.stderr)
            self.assertTrue(python.is_symlink())

    def test_probe_names_macos_machines_as_the_table_and_linux_arm64_as_aarch64(self):
        deps = load_deps()
        cases = {
            ("darwin", "arm64", "3.9"): "macos-cp39-arm64",
            ("darwin", "x86_64", "3.9"): "macos-cp39-x86_64",
            ("linux", "aarch64", "3.12"): "linux-cp312-aarch64",
            ("linux", "arm64", "3.12"): "linux-cp312-aarch64",
            ("linux", "AMD64", "3.12"): "linux-cp312-x86_64",
        }
        with tempfile.TemporaryDirectory() as directory:
            fake = write_fake_python(Path(directory))
            for (system, machine, version), expected in cases.items():
                identity = json.dumps({"implementation": "CPython", "system": system, "machine": machine,
                                       "version": version})
                with self.subTest(system=system, machine=machine), \
                        mock.patch.dict(os.environ, {"FAKE_PY_IDENTITY": identity}):
                    self.assertEqual(expected, deps.probe_platform(str(fake)))

    def test_half_built_venv_names_the_directory_to_remove_and_deletes_nothing(self):
        """S4: a venv left by a failed creation (no python3-venv), one whose pip is unusable, or one
        without bin/python fails with the directory to remove and the command to rerun."""
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = write_fake_python(base)
            log = base / "argv.log"
            env = {"HOME": str(base), "FAKE_PY_IDENTITY": LINUX_312, "FAKE_PY_LOG": str(log)}
            venv = base / ".venvs/http/cabletracker"
            rerun = "python3 infra/deps.py install --target venv-cabletracker"

            failed = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake),
                              env=dict(env, FAKE_PY_VENV_FAIL="1"))
            self.assertEqual(1, failed.returncode, failed.stdout + failed.stderr)
            for needle in (str(venv), "rm -rf " + str(venv), "python3-venv", rerun):
                self.assertIn(needle, failed.stderr)
            self.assertTrue((venv / "pyvenv.cfg").is_file())

            log.unlink()
            stuck = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake), env=env)
            self.assertEqual(1, stuck.returncode, stuck.stdout + stuck.stderr)
            for needle in ("rm -rf " + str(venv), rerun, "pip"):
                self.assertIn(needle, stuck.stderr)
            self.assertNotIn("Traceback", stuck.stderr)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertEqual([], [call for call in calls if "install" in call])
            self.assertTrue((venv / "pyvenv.cfg").is_file())

            (venv / "bin/python").unlink()
            missing = run_deps("install", "--target", "venv-cabletracker", "--python", str(fake), env=env)
            self.assertEqual(1, missing.returncode, missing.stdout + missing.stderr)
            self.assertIn("rm -rf " + str(venv), missing.stderr)
            self.assertIn(str(venv / "bin/python"), missing.stderr)
            self.assertNotIn("Traceback", missing.stderr)
            self.assertTrue((venv / "pyvenv.cfg").is_file())

    def test_root_installs_only_into_its_own_home_and_dry_run_changes_nothing(self):
        """S1: root may install only when HOME is root's own home directory (so sudo -E with another
        user's HOME is refused); a dry run never writes."""
        deps = load_deps()
        table = deps.load_table(ROOT)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fake = write_fake_python(base)
            env = {"HOME": str(base), "FAKE_PY_IDENTITY": LINUX_312}
            result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake), "--dry-run", env=env)
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertIn("--require-hashes -r " + str(ROOT / IBSW), result.stdout)
            self.assertFalse((base / ".venvs").exists())
            root_home = base / "root-home"
            account = mock.Mock(pw_dir=str(root_home))
            with mock.patch.dict(os.environ, env), mock.patch("os.geteuid", return_value=0), \
                    mock.patch("pwd.getpwuid", return_value=account), \
                    contextlib.redirect_stderr(io.StringIO()) as stderr:
                self.assertEqual(2, deps.install(ROOT, table, "venv-ibsw-upgrade", str(fake), False))
            self.assertIn(str(root_home), stderr.getvalue())
            self.assertIn("HOME", stderr.getvalue())
            self.assertFalse((base / ".venvs").exists())
            with mock.patch.dict(os.environ, dict(env, HOME=str(root_home))), mock.patch("os.geteuid", return_value=0), \
                    mock.patch("pwd.getpwuid", return_value=account), \
                    contextlib.redirect_stdout(io.StringIO()) as stdout:
                self.assertEqual(0, deps.install(ROOT, table, "venv-ibsw-upgrade", str(fake), True))
            self.assertIn(str(root_home / ".venvs/http/ibsw-upgrade"), stdout.getvalue())
            self.assertFalse(root_home.exists())


if __name__ == "__main__":
    unittest.main()
