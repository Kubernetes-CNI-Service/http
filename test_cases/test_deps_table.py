"""Unified dependency table: direct contract of infra/deps.py, infra/dependencies.json and the hashed lists.

The expected closure, versions and owner decisions below are written out independently of
the implementation; the REQ7 cable lock and the container lock are parsed here with a parser
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
CABLE = "infra/docker/requirements-req7-cable-sync.txt"
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
        print(os.environ["FAKE_PY_IDENTITY"])
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
    (target / "bin").mkdir(parents=True)
    (target / "lib/python3.12/site-packages").mkdir(parents=True)
    system = "true" if "--system-site-packages" in args else "false"
    (target / "pyvenv.cfg").write_text("home = /usr/bin\ninclude-system-site-packages = %s\nversion = 3.12.3\n" % system)
    me = target / "bin/python"
    me.write_bytes(Path(__file__).read_bytes())
    me.chmod(0o755)
    if os.environ.get("FAKE_PY_VENV_FAIL"):
        # Debian/Ubuntu without python3-venv: pyvenv.cfg and bin/python exist, ensurepip failed.
        print("The virtual environment was not created successfully because ensurepip is not available.")
        sys.exit(1)
    info = target / "lib/python3.12/site-packages/pip-24.0.dist-info"
    info.mkdir()
    (info / "METADATA").write_text("Name: pip\nVersion: 24.0\n\n")
    sys.exit(0)
if args[:2] == ["-m", "pip"]:
    venv = Path(__file__).resolve().parents[1]
    site = venv / "lib/python3.12/site-packages"
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
            self.assertEqual(["linux-cp312-x86_64", "linux-cp312-aarch64"], targets[name]["platforms"])
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

    def test_engine_set_is_the_cable_lock_plus_the_measured_extras(self):
        cable, _wheels, _header = parse_lock(ROOT / CABLE)
        self.assertEqual(20, len(cable))
        engine = set(self.table["python_sets"]["issue-tracker-engine"]["distributions"])
        self.assertEqual(set(cable) | set(EXPECTED_ENGINE_EXTRAS), engine)
        self.assertEqual(36, len(engine))
        for name, version in EXPECTED_ENGINE_EXTRAS.items():
            self.assertEqual(version, self.table["python_distributions"][name]["version"], name)
        for name, (version, _hashes) in cable.items():
            self.assertEqual(version, self.table["python_distributions"][name]["version"], name)

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
        self.assertTrue({ENGINE, IBSW, CABLE, CONTAINER_LOCK, XDR} <= set(found))


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

    def test_engine_list_shares_identical_versions_and_hashes_with_the_cable_lock(self):
        engine = self.assert_hash_locked(ENGINE)
        cable, cable_wheels, _header = parse_lock(ROOT / CABLE)
        self.assertEqual(36, len(engine))
        for name, (version, hashes) in cable.items():
            with self.subTest(distribution=name):
                self.assertIn(name, engine)
                self.assertEqual(version, engine[name][0])
                self.assertEqual(set(hashes), set(engine[name][1]))
        _engine_records, engine_wheels, _header = parse_lock(ROOT / ENGINE)
        for wheel, digest in cable_wheels.items():
            self.assertEqual(digest, engine_wheels.get(wheel), wheel)
        for name, version in EXPECTED_ENGINE_EXTRAS.items():
            self.assertEqual(version, engine[name][0], name)

    def test_ibsw_list_is_the_xdr_pins_plus_pyyaml_with_shared_hashes(self):
        ibsw = self.assert_hash_locked(IBSW)
        xdr = parse_pins(ROOT / XDR)
        container, _wheels, _header = parse_lock(ROOT / CONTAINER_LOCK)
        cable, _cable_wheels, _header = parse_lock(ROOT / CABLE)
        engine, _engine_wheels, _header = parse_lock(ROOT / ENGINE)
        self.assertEqual(set(xdr), set(ibsw))
        for name, version in xdr.items():
            self.assertEqual(version or container[name][0], ibsw[name][0], name)
        self.assertEqual(set(container["pyyaml"][1]), set(ibsw["pyyaml"][1]))
        for name in ("cryptography", "cffi", "pycparser"):
            self.assertEqual(set(cable[name][1]), set(ibsw[name][1]), name)
        self.assertEqual(set(engine["typing-extensions"][1]), set(ibsw["typing-extensions"][1]))
        self.assertEqual({"paramiko", "bcrypt", "invoke", "pynacl", "pyyaml", "cryptography", "cffi",
                          "pycparser", "typing-extensions"}, set(ibsw))

    def test_neither_new_list_uses_the_lock_suffix_excluded_by_transport(self):
        for relative in (ENGINE, IBSW):
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

    def make_venv(self, home: Path, target_name: str) -> Path:
        target = self.table["targets"][target_name]
        venv = home / target["path"][2:]
        site = venv / "lib/python3.12/site-packages"
        site.mkdir(parents=True)
        (venv / "bin").mkdir()
        python = venv / "bin/python"
        python.write_text(FAKE_PYTHON.replace("{python}", sys.executable), encoding="utf-8")
        python.chmod(0o755)
        (venv / "pyvenv.cfg").write_text("home = /usr/bin\ninclude-system-site-packages = false\nversion = 3.12.3\n",
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
        identities = {
            "planned": (json.dumps({"implementation": "CPython", "system": "linux", "machine": "aarch64", "version": "3.10"}), "phase 2"),
            "macos": (json.dumps({"implementation": "CPython", "system": "darwin", "machine": "arm64", "version": "3.9"}), "not supported"),
        }
        for label, (identity, message) in identities.items():
            with self.subTest(platform=label), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                fake = write_fake_python(base)
                result = run_deps("install", "--target", "venv-ibsw-upgrade", "--python", str(fake),
                                  env={"HOME": str(base), "FAKE_PY_IDENTITY": identity})
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
