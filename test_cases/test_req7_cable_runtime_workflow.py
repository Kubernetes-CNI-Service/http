"""Real activation/FD-loader and image compatibility, not an executed image.

The Dockerfile check is textual ordering only. Cold CLI loads actual activate
from an absolute path without repository sys.path help. No SDK, Docker,
credential, service, network, runner attestation or worker is exercised.
"""
from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from test_cases import test_req7_cable_runtime as fixture


OLD_COUPLED = (
    "requirements-container-top-level.lock",
    "infra/docker/req7-dependency-policy.json", "infra/docker/requirements-req7-online.txt",
    "tools/req7_dependency_contract.py", "infra/docker/activate.py",
    "infra/docker/entrypoint.py", "infra/docker/healthcheck.py", "infra/docker/hostctl.py",
    "infra/docker/hostlock.py", "infra/docker/rsyslog-dhcp.conf",
    "infra/docker/supervisord.conf", "infra/docker/apache-ztp.conf",
    "infra/docker/logrotate-http-ztp.conf", "tools/ztp_service_runtime.py", "tools/control-auth.py",
)
# 2026-10-23 unified dependency table step 3a: the CableTracker engine list is installed into the
# image next to the Cable trio and is image-coupled on its own (it outlives the trio, step 3b).
ENGINE_COUPLED = ("infra/docker/requirements-issue-tracker-engine.txt",)

# A genuine isolated interpreter, not extraction/execution of an AST body.
# Only the already installed PyYAML package is loaded explicitly because -I
# excludes the macOS usersite. The repository is never inserted by this test.
COLD_CLI = r'''
import builtins,importlib.util,importlib.metadata as metadata,json,pathlib,sys,platform
from types import SimpleNamespace
script,source,venv,yaml_init,pins_json,blocked_json=sys.argv[1:]
script=pathlib.Path(script);source=pathlib.Path(source);venv=pathlib.Path(venv)
repo=script.resolve().parents[2]
assert all(pathlib.Path(p or '.').resolve()!=repo for p in sys.path)
assert 'tools' not in sys.modules and 'tools.req7_cable_dependency_contract' not in sys.modules
spec=importlib.util.spec_from_file_location('yaml',yaml_init,
    submodule_search_locations=[str(pathlib.Path(yaml_init).parent)])
yaml=importlib.util.module_from_spec(spec);sys.modules['yaml']=yaml;spec.loader.exec_module(yaml)
spec=importlib.util.spec_from_file_location('cold_cable_activate',script)
activate=importlib.util.module_from_spec(spec);sys.modules[spec.name]=activate;spec.loader.exec_module(activate)
assert all(pathlib.Path(p or '.').resolve()!=repo for p in sys.path)
pins=json.loads(pins_json);versions=dict(pins);blocked=set(json.loads(blocked_json));attempts=[]
def distribution(name):
    path=venv/'lib/python3.12/site-packages'/(name.replace('-','_')+'.py')
    return SimpleNamespace(version=versions[name],files=[path],locate_file=lambda item:item)
activate.DEFAULT_IMAGE_SOURCE_TREE=source;activate.CONTAINER_VENV=venv
activate.CONTAINER_VENV_PYTHON=venv/'bin/python'
sys.executable=str(venv/'bin/python');sys.version_info=(3,12,9);sys.platform='linux'
platform.python_implementation=lambda:'CPython';platform.machine=lambda:'aarch64'
metadata.distribution=distribution
original_import=builtins.__import__
def guarded(name,*args,**kwargs):
    if name.split('.',1)[0] in blocked:
        attempts.append(name);raise AssertionError('SDK import forbidden')
    return original_import(name,*args,**kwargs)
builtins.__import__=guarded
try:
    code=activate.main(['verify-req7-cable-python-runtime'])
finally:
    builtins.__import__=original_import
assert attempts==[]
assert code==0
assert all(pathlib.Path(p or '.').resolve()!=repo for p in sys.path)
'''


class CableRuntimeWorkflowTests(unittest.TestCase):
    def test_real_parser_loader_and_isolated_absolute_cli_keep_contract_fixed(self):
        activate = fixture.load(self)
        with fixture.runtime_fixture(self, activate) as control, fixture.no_sdk_imports() as attempts:
            output = io.StringIO()
            with redirect_stdout(output):
                code = activate.main(["verify-req7-cable-python-runtime"])
            self.assertEqual(code, 0)
            expected = {"verified": True, "contract": "REQ7-CABLE-SDK-V1", **fixture.expected("aarch64")}
            self.assertEqual(json.loads(output.getvalue()), expected)
            old = io.StringIO()
            with redirect_stdout(old):
                self.assertEqual(activate.main(["verify-req7-python-runtime"]), 0)
            self.assertEqual(json.loads(old.getvalue())["contract"], "REQ7-C14-T6-A")
            self.assertNotEqual(json.loads(old.getvalue())["policy_sha256"], fixture.POLICY_SHA)
            invalid = (["extra-service"], ["--source-root", str(control.root)],
                       ["--source-root=" + str(control.root)],
                       ["--manifest", str(control.root / "unused.json")],
                       ["--manifest=" + str(control.root / "unused.json")],
                       ["--source-root", "/opt/http-ztp/source-tree"],
                       ["--manifest", "/opt/http-ztp/image-source.sha256"])
            for args in invalid:
                out, err = io.StringIO(), io.StringIO()
                with self.subTest(arguments=args), redirect_stdout(out), redirect_stderr(err):
                    try:
                        code = activate.main(["verify-req7-cable-python-runtime", *args])
                    except SystemExit as refusal:
                        code = refusal.code
                self.assertEqual(code, 2)
                self.assertNotIn('"verified": true', out.getvalue())
            self.assertEqual(attempts, [])
            child_cwd = control.root / "nonrepository-cwd"
            child_cwd.mkdir()
            yaml_spec = importlib.util.find_spec("yaml")
            self.assertIsNotNone(yaml_spec)
            environment = dict(os.environ)
            environment.pop("PYTHONPATH", None)
            # The fixture temporarily models sys.executable; launch the actual
            # original host interpreter, never the synthetic managed file.
            executable = getattr(sys, "_base_executable", None)
            self.assertTrue(executable and Path(executable).is_file())
            result = subprocess.run([executable, "-I", "-B", "-c", COLD_CLI,
                str(fixture.ROOT / "infra/docker/activate.py"), str(control.root),
                str(control.venv), yaml_spec.origin, json.dumps(fixture.PINS),
                json.dumps(sorted(fixture.SDK_TOPLEVEL))], cwd=child_cwd,
                env=environment, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), expected)

    def test_docker_installs_new_lock_before_both_separate_runtime_gates(self):
        text = (fixture.ROOT / "infra/docker/Dockerfile").read_text()
        install = ("/opt/http-ztp/venv/bin/python -m pip install --only-binary=:all: "
                   "--no-deps --require-hashes -r /opt/http-ztp/source-tree/")
        old = install + "infra/docker/requirements-req7-online.txt"
        new = install + "infra/docker/requirements-req7-cable-sync.txt"
        old_gate = "/opt/http-ztp/venv/bin/python /opt/http-ztp/source-tree/infra/docker/activate.py verify-req7-python-runtime"
        new_gate = "/opt/http-ztp/venv/bin/python /opt/http-ztp/source-tree/infra/docker/activate.py verify-req7-cable-python-runtime"
        top = "/opt/http-ztp/venv/bin/python /opt/http-ztp/source-tree/infra/docker/activate.py verify-python-runtime"
        for command in (old, new, old_gate, new_gate, top):
            self.assertEqual(text.count(command), 1, command)
            self.assertIn("    && " + command + " " + chr(92), text.splitlines())
        for installed in (old, new):
            for gate in (old_gate, new_gate):
                self.assertLess(text.index(installed), text.index(gate))
        self.assertIn("python3 -m venv --system-site-packages /opt/http-ztp/venv", text)
        self.assertIn("-m pip install --no-deps --require-hashes -r /opt/http-ztp/source-tree/requirements-container-top-level.lock", text)

    def test_real_image_manifests_reject_missing_or_drifted_new_coupled_trio(self):
        activate = fixture.load(self)
        self.assertEqual(activate.IMAGE_COUPLED_SOURCE_PATHS,
                         frozenset((*OLD_COUPLED, *ENGINE_COUPLED, *fixture.TRIO)))
        with tempfile.TemporaryDirectory(prefix="cable-image-") as directory:
            base = Path(directory).resolve(strict=True)
            source = base / "source"
            for name in ("infra", "monitor", "ethernet", "infiniband", "nvlink", "ztp", "tools"):
                (source / name).mkdir(parents=True)
            for relative in (*OLD_COUPLED, *ENGINE_COUPLED, *fixture.TRIO):
                path = source / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((fixture.ROOT / relative).read_bytes() if relative in fixture.TRIO
                                 else b"PRIVATE_SOURCE_IDENTITY_FIXTURE = True\n")
            (source / "infra/docker/runtime-contract.json").write_text(
                '{"schema_version":1,"compatible_image_contracts":["3"]}\n')
            image = base / "image-source.json"
            live = source / "infra/docker/deployment-source-manifest.json"
            activate.write_image_source_manifest(source, image)
            live.write_bytes(image.read_bytes())
            records = activate.verify_compatible_live_source(source, image)
            self.assertTrue(set(fixture.TRIO) <= {row["path"] for row in records})
            old_image = json.loads(image.read_text())
            for relative in fixture.TRIO:
                missing = {"schema_version": 1, "files": [row for row in old_image["files"] if row["path"] != relative]}
                missing_path = base / "missing-trio-image.json"
                missing_path.write_text(json.dumps(missing))
                with self.subTest(missing_image_member=relative), self.assertRaises(activate.ActivationError):
                    activate.verify_compatible_live_source(source, missing_path)
                path = source / relative
                before = path.read_bytes()
                path.write_bytes(before + b"\n# FOREIGN_COUPLED_SOURCE\n")
                activate.write_image_source_manifest(source, live)
                with self.subTest(drifted_live_member=relative), self.assertRaises(activate.ActivationError):
                    activate.verify_compatible_live_source(source, image)
                path.write_bytes(before)
                activate.write_image_source_manifest(source, live)
            self.assertTrue(set(fixture.TRIO) <= {row["path"] for row in activate.verify_compatible_live_source(source, image)})
