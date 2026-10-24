"""Issue Tracker engine runtime: activate.py verify-issue-tracker-engine-runtime and cron.sh's engine choice.

activate.py runs in a cold child interpreter that models the managed Linux CPython 3.12 venv:
metadata, module specs and imports are synthetic, so no Google/OpenAI/httpx package is needed
or imported (CI installs only requirements-dev.txt). cron.sh's real issue_tracker_sync() body is
executed by bash with a fake python3; only the absolute container interpreter path is replaced
by a temporary path so that all three choices can be exercised on any host.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
ACTIVATE = ROOT / "infra/docker/activate.py"
ENGINE = "infra/docker/requirements-issue-tracker-engine.txt"
CRON = ROOT / "ethernet/monitor/cron.sh"
CONTAINER_PYTHON = "/opt/http-ztp/venv/bin/python"
EXPECTED_IMPORTS = [
    "httplib2", "httpx", "google_auth_httplib2", "google.oauth2.service_account",
    "googleapiclient.discovery", "googleapiclient.errors", "requests", "openai",
]

CHILD = r'''
import contextlib, importlib.util, io, json, pathlib, platform, sys
from importlib import metadata
from types import SimpleNamespace
script, source, venv, scenario_json = sys.argv[1:5]
scenario = json.loads(scenario_json)
spec = importlib.util.spec_from_file_location("engine_runtime_activate", script)
activate = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = activate
spec.loader.exec_module(activate)
venv = pathlib.Path(venv)
activate.DEFAULT_IMAGE_SOURCE_TREE = pathlib.Path(source)
activate.CONTAINER_VENV = venv
activate.CONTAINER_VENV_PYTHON = venv / "bin/python"
sys.executable = scenario.get("executable") or str(venv / "bin/python")
sys.platform = "linux"
sys.version_info = (3, 12, 3)
platform.python_implementation = lambda: "CPython"
versions = scenario["versions"]
def version(name):
    if name not in versions:
        raise metadata.PackageNotFoundError(name)
    return versions[name]
imported = []
def find_spec(name, package=None):
    if name in scenario.get("absent", []):
        return None
    return SimpleNamespace(origin=scenario.get("origins", {}).get(name, ""))
def import_module(name, package=None):
    if name in scenario.get("broken", []):
        raise ImportError("synthetic import failure")
    imported.append(name)
activate.importlib_metadata.version = version
activate.importlib.util.find_spec = find_spec
activate.importlib.import_module = import_module
out, err = io.StringIO(), io.StringIO()
with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
    code = activate.main(scenario.get("argv", ["verify-issue-tracker-engine-runtime"]))
print(json.dumps({"code": code, "stdout": out.getvalue(), "stderr": err.getvalue(), "imported": imported}))
'''


def engine_versions() -> dict:
    versions = {}
    for raw in (ROOT / ENGINE).read_text(encoding="ascii").splitlines():
        line = raw.strip()
        if line and not line.startswith(("#", "--")):
            name, version = line.split()[0].split("==")
            versions[name] = version
    return versions


class ActivateEngineRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="engine-runtime-")
        base = Path(self.temporary.name)
        self.source = base / "source"
        (self.source / "infra/docker").mkdir(parents=True)
        shutil.copyfile(ROOT / ENGINE, self.source / ENGINE)
        self.venv = base / "venv"
        site = self.venv / "lib/python3.12/site-packages"
        site.mkdir(parents=True)
        (self.venv / "bin").mkdir()
        self.origins = {}
        for module in EXPECTED_IMPORTS:
            path = site / (module.replace(".", "/") + ".py")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("VALUE = 1\n", encoding="utf-8")
            self.origins[module] = str(path)
        self.outside = base / "elsewhere/openai.py"
        self.outside.parent.mkdir()
        self.outside.write_text("VALUE = 1\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def run_child(self, **changes) -> dict:
        scenario = {"versions": engine_versions(), "origins": dict(self.origins)}
        scenario.update(changes)
        result = subprocess.run([sys.executable, "-B", "-c", CHILD, str(ACTIVATE), str(self.source), str(self.venv),
                                 json.dumps(scenario)], cwd=self.temporary.name, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(0, result.returncode, result.stderr)
        return json.loads(result.stdout.strip().splitlines()[-1])

    def test_complete_closure_verifies_and_imports_every_engine_module(self):
        result = self.run_child()
        self.assertEqual(0, result["code"], result["stderr"])
        payload = json.loads(result["stdout"])
        self.assertEqual({"verified": True, "contract": "ISSUE-TRACKER-ENGINE-V1", "distributions": 36,
                          "imports": EXPECTED_IMPORTS,
                          "requirements_sha256": hashlib.sha256((ROOT / ENGINE).read_bytes()).hexdigest()},
                         payload)
        self.assertEqual(EXPECTED_IMPORTS, result["imported"])

    def test_every_gap_fails_closed_before_or_during_imports(self):
        versions = engine_versions()
        missing = dict(versions)
        del missing["openai"]
        drifted = dict(versions, httpx="0.27.0")
        scenarios = {
            "missing distribution": ({"versions": missing}, "missing Issue Tracker engine distribution: openai"),
            "version drift": ({"versions": drifted}, "httpx must be 0.28.1, got 0.27.0"),
            "absent module": ({"absent": ["openai"]}, "missing Issue Tracker engine module: openai"),
            "module outside venv": ({"origins": dict(self.origins, openai=str(self.outside))}, "openai is outside"),
            "broken import": ({"broken": ["httpx"]}, "cannot import Issue Tracker engine module httpx"),
            "foreign interpreter": ({"executable": "/usr/bin/python3"}, "requires managed Linux CPython 3.12 venv"),
            "overrides": ({"argv": ["verify-issue-tracker-engine-runtime", "--source-root", "/tmp"]},
                          "takes no arguments or overrides"),
        }
        for label, (changes, message) in scenarios.items():
            with self.subTest(case=label):
                result = self.run_child(**changes)
                self.assertEqual(2, result["code"])
                self.assertIn(message, result["stderr"])
                self.assertNotIn('"verified": true', result["stdout"])
        self.assertEqual([], self.run_child(versions=missing)["imported"])

    def test_unhashed_or_empty_requirements_are_rejected(self):
        for label, payload in {"unhashed": b"openai==2.48.0\n", "empty": b"# header only\n",
                               "truncated": b"openai==2.48.0 \\\n"}.items():
            with self.subTest(case=label):
                (self.source / ENGINE).write_bytes(payload)
                result = self.run_child()
                self.assertEqual(2, result["code"])
                self.assertIn("Issue Tracker engine requirements", result["stderr"])

    def test_import_list_covers_every_third_party_import_of_the_engine_and_precheck(self):
        tree_activate = ast.parse(ACTIVATE.read_bytes())
        constant = None
        for node in tree_activate.body:
            if isinstance(node, ast.Assign) and any(getattr(t, "id", None) == "ISSUE_TRACKER_ENGINE_IMPORTS"
                                                    for t in node.targets):
                constant = ast.literal_eval(node.value)
        self.assertEqual(tuple(EXPECTED_IMPORTS), constant)
        third_party = ("google", "googleapiclient", "google_auth_httplib2", "httplib2", "httpx", "requests", "openai")
        engine_modules = set()
        for relative in ("monitor/issue-tracker/cabletracker/cabletracker_runner.py",
                         "monitor/issue-tracker/format_precheck.py"):
            for node in ast.walk(ast.parse((ROOT / relative).read_bytes())):
                if isinstance(node, ast.Import):
                    engine_modules.update(alias.name for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    engine_modules.add(node.module)
        engine_modules = {name for name in engine_modules if name.split(".")[0] in third_party}
        self.assertTrue(engine_modules)
        for module in sorted(engine_modules):
            self.assertTrue(any(entry == module or entry.startswith(module + ".") for entry in EXPECTED_IMPORTS), module)


def cron_function() -> str:
    text = CRON.read_text(encoding="utf-8")
    match = re.search(r"^issue_tracker_sync\(\) \{\n.*?^\}\n", text, re.S | re.M)
    assert match is not None
    return match.group(0)


class CronEngineSelectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="cron-engine-")
        self.base = Path(self.temporary.name)
        (self.base / "bin").mkdir()
        fake = self.base / "bin/python3"
        fake.write_text('#!/bin/sh\nprintf "%s\\n" "$@" > "$TEST_ARGS"\nexit "${FAKE_RC:-0}"\n', encoding="utf-8")
        fake.chmod(0o755)
        self.sync = self.base / "issue-tracker-sync.py"
        self.sync.write_text("# placeholder\n", encoding="utf-8")
        self.container = self.base / "image/venv/bin/python"

    def tearDown(self):
        self.temporary.cleanup()

    def run_function(self, home=None, rc=0) -> tuple:
        function = cron_function()
        self.assertEqual(2, function.count(CONTAINER_PYTHON))
        harness = "\n".join([
            'log() { printf "%s\\n" "$*" >> "$TEST_LOG"; }',
            f'ISSUE_TRACKER_SYNC="{self.sync}"',
            function.replace(CONTAINER_PYTHON, str(self.container)),
            "issue_tracker_sync eth",
        ]) + "\n"
        env = {"PATH": f"{self.base / 'bin'}:/usr/bin:/bin", "TEST_ARGS": str(self.base / "args"),
               "TEST_LOG": str(self.base / "log"), "FAKE_RC": str(rc)}
        if home is not None:
            env["HOME"] = str(home)
        result = subprocess.run(["/bin/bash", "-c", harness], env=env, stdin=subprocess.DEVNULL,
                                capture_output=True, text=True, timeout=30)
        self.assertEqual(0, result.returncode, result.stderr)
        args = (self.base / "args").read_text(encoding="utf-8").splitlines()
        log = (self.base / "log").read_text(encoding="utf-8")
        return args[args.index("--engine-python") + 1], args, log

    def make_executable(self, path: Path, mode: int = 0o755) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(mode)
        return path

    def test_container_venv_wins_then_the_users_cabletracker_venv_then_python3(self):
        home = self.base / "home"
        user_python = self.make_executable(home / ".venvs/http/cabletracker/bin/python")
        self.make_executable(self.container)
        self.assertEqual(str(self.container), self.run_function(home)[0])
        self.container.unlink()
        chosen, args, log = self.run_function(home)
        self.assertEqual(str(user_python), chosen)
        self.assertEqual([str(self.sync), "--only", "eth", "--engine-python", str(user_python)], args)
        self.assertIn("[ISSUE-TRACKER] eth: done", log)
        user_python.chmod(0o644)
        self.assertEqual("python3", self.run_function(home)[0])
        user_python.chmod(0o755)
        self.assertEqual("python3", self.run_function(None)[0])
        self.assertEqual("python3", self.run_function(self.base / "nobody")[0])

    def test_exit_codes_keep_their_log_lines(self):
        for rc, line in ((75, "another sync is running; skipped"), (1, "WARNING: eth sync exited 1")):
            with self.subTest(rc=rc):
                _chosen, _args, log = self.run_function(self.base / "home", rc=rc)
                self.assertIn(line, log)

    def test_all_cron_entry_paths_carry_the_same_function(self):
        for relative in ("ethernet/monitor/cron.sh", "infiniband/monitor/cron.sh", "nvlink/monitor/cron.sh"):
            text = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn(cron_function(), text, relative)
        self.assertIn("$HOME/.venvs/http/cabletracker/bin/python", cron_function())
        self.assertNotIn("keeps the engine's Google/OpenAI client libraries in its venv", cron_function())


if __name__ == "__main__":
    unittest.main()
