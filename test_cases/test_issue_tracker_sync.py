"""REQ7 Issue Tracker sync wrapper: direct contract of monitor/issue-tracker/issue-tracker-sync.py.

The CableTracker engine under monitor/issue-tracker/cabletracker/ is a byte-for-byte copy of the
reference tool; this module pins those bytes and checks the wrapper's own rules: project
configuration, service-account key checks (never printing a value), newest-input selection,
the LLDP -> LLDPQ schema-v1 projection, the exact engine command, skip-when-unchanged state and
the per-project lock.
"""

from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "monitor/issue-tracker/issue-tracker-sync.py"
ENGINE = ROOT / "monitor/issue-tracker/cabletracker"
REFERENCE = ROOT / "tools/cabletracker"
UPDATE = ROOT / "monitor/issue-tracker/update-engine.py"
LOCK = ROOT / "monitor/issue-tracker/engine.lock.json"
SPREADSHEET = "1" + "A" * 43
PRECHECK = ROOT / "monitor/issue-tracker/format_precheck.py"
sys.path.insert(0, str(ROOT))
from test_cases.issue_tracker_template import TEMPLATE  # noqa: E402

SECRET_MARKER = "secret-value"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("issue_tracker_sync_under_test", WRAPPER)
    module = importlib.util.module_from_spec(spec)
    # dataclasses resolve string annotations through sys.modules[cls.__module__]
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def info_text(local_port: str, remote_host: str, remote_port: str, oper: str = "up") -> bytes:
    widths = (16, 16, 16, 12, 12, 12, 22, 16, 12)
    headers = ("Interface", "Admin Status", "Oper Status", "Speed", "MTU",
               "Type", "Remote Host", "Remote Port", "Other")
    values = (local_port, "up", oper, "100G", "9216", "swp", remote_host, remote_port, "-")
    row = lambda items: "".join(str(item).ljust(width) for item, width in zip(items, widths))
    return ("# Execute Command: nv show interface\n" + row(headers) + "\n"
            + row("-" * (width - 1) for width in widths) + "\n" + row(values) + "\n").encode()


def write_archive(path: Path, members: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(path, "w:gz") as bundle:
        for name, body in members.items():
            member = tarfile.TarInfo(name)
            member.size = len(body)
            bundle.addfile(member, io.BytesIO(body))


def record(status, a=("leaf-a", "swp1"), b=("leaf-z", "swp2"), detail="", observed=None):
    observed = observed or {}
    return {"link_type": "SW-SW", "status": status, "device_a": a[0], "interface_a": a[1],
            "device_b": b[0], "interface_b": b[1], "detail": detail, "dot_line": 1,
            "observation_a": {"admin": "up", "oper": observed.get("oper", "up"),
                              "remote_host": observed.get("host", ""),
                              "remote_port": observed.get("port", "")},
            "observation_b": {"admin": "", "oper": "", "remote_host": "", "remote_port": ""}}


def load_updater():
    spec = importlib.util.spec_from_file_location("update_engine_under_test", UPDATE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


STUBBED_PYTHON = r'''
import runpy, sys, types
for name in ("openai", "httpx"):
    try:
        __import__(name)
    except ImportError:
        stub = types.ModuleType(name)
        stub.OpenAI = stub.Client = object
        sys.modules[name] = stub
script = sys.argv[1]
sys.argv = sys.argv[1:]
runpy.run_path(script, run_name="__main__")
'''


class VendoredEngineTests(unittest.TestCase):
    def test_engine_copy_is_exactly_the_locked_version(self):
        lock = json.loads(LOCK.read_text(encoding="utf-8"))
        self.assertEqual("cabletracker-engine-lock-v1", lock["schema"])
        self.assertEqual(sorted(["cabletracker_runner.py", "mapping_v4.json", "ibdiagnet/__init__.py",
                                 "ibdiagnet/generate_report.py"]), sorted(lock["files"]))
        for relative, expected in lock["files"].items():
            with self.subTest(file=relative):
                data = (ENGINE / relative).read_bytes()
                self.assertEqual(expected, hashlib.sha256(data).hexdigest())
        self.assertNotIn("/Users/", lock["source"])

    def test_update_takes_a_new_version_only_when_it_still_accepts_the_sync_options(self):
        updater = load_updater()
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            live, source = base / "live", base / "source"
            for relative in updater.SYNC_FILES:
                for target in (live, source):
                    (target / relative).parent.mkdir(parents=True, exist_ok=True)
                    (target / relative).write_bytes((ENGINE / relative).read_bytes())
            launcher = base / "python-with-stubs"
            (base / "stubbed.py").write_text(STUBBED_PYTHON)
            launcher.write_text(f"#!/bin/sh\nexec {sys.executable} -B {base / 'stubbed.py'} \"$@\"\n")
            launcher.chmod(0o755)
            lock = base / "engine.lock.json"
            with mock.patch.multiple(updater, BASE=base, ENGINE_DIR=live, LOCK=lock, HTTP_ROOT=base):
                run = lambda *extra: updater.main(["--from", str(source), "--engine-python", str(launcher), *extra])
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(0, run(), out.getvalue())
                self.assertIn("already this version", out.getvalue())
                self.assertEqual("source", json.loads(lock.read_text())["source"])
                with redirect_stdout(io.StringIO()):
                    self.assertEqual(0, updater.main(["--check"]))

                (source / "mapping_v4.json").write_bytes(b'{"cvt_import": {}, "remediation": {}}\n')
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(0, run(), out.getvalue())
                self.assertIn("updated mapping_v4.json", out.getvalue())
                self.assertEqual((source / "mapping_v4.json").read_bytes(), (live / "mapping_v4.json").read_bytes())
                self.assertEqual(hashlib.sha256((live / "mapping_v4.json").read_bytes()).hexdigest(),
                                 json.loads(lock.read_text())["files"]["mapping_v4.json"])

                runner = source / "cabletracker_runner.py"
                runner.write_text(runner.read_text().replace('"--eth-cabling-sheet"', '"--ethernet-cabling-sheet"'))
                before = (live / "cabletracker_runner.py").read_bytes()
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(2, run(), out.getvalue())
                self.assertIn("--eth-cabling-sheet", out.getvalue())
                self.assertIn("unchanged", out.getvalue())
                self.assertEqual(before, (live / "cabletracker_runner.py").read_bytes())

                (source / "ibdiagnet/__init__.py").unlink()
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(2, run(), out.getvalue())
                (live / "mapping_v4.json").write_bytes(b"{}")
                with redirect_stdout(io.StringIO()) as out:
                    self.assertEqual(2, updater.main(["--check"]))
                self.assertIn("mapping_v4.json differs", out.getvalue())


class ConfigurationTests(unittest.TestCase):
    def setUp(self):
        self.sync = load_wrapper()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / "03-issue-tracker.json"

    def write(self, document):
        self.path.write_text(json.dumps(document), encoding="utf-8")
        return self.path

    def test_minimal_configuration_takes_the_documented_defaults(self):
        config = self.sync.load_config(self.write({"schema": "issue-tracker-sync-v1",
                                                    "spreadsheet_id": SPREADSHEET}))
        self.assertEqual(SPREADSHEET, config.spreadsheet_id)
        self.assertEqual("Asia/Shanghai", config.timezone)
        ib, eth = config.domains["ib"], config.domains["eth"]
        self.assertEqual((True, "prod", "CVT_Import_GS", "IB Cabling", False),
                         (ib.enabled, ib.environment, ib.import_sheet, ib.cabling_sheet, ib.include_warnings))
        self.assertEqual((True, "prod", "LLDPQ_Import_GS", "ETH Cabling", False),
                         (eth.enabled, eth.environment, eth.import_sheet, eth.cabling_sheet, eth.include_warnings))

    def test_invalid_configurations_are_rejected_before_anything_runs(self):
        base = {"schema": "issue-tracker-sync-v1", "spreadsheet_id": SPREADSHEET}
        cases = {
            "schema": {**base, "schema": "other"},
            "unknown key": {**base, "sheet": "x"},
            "short id": {**base, "spreadsheet_id": "abc"},
            "url instead of id": {**base, "spreadsheet_id": "https://docs.google.com/x"},
            "unknown domain key": {**base, "ib": {"sheet": "x"}},
            "environment": {**base, "eth": {"environment": "lab"}},
            "enabled not bool": {**base, "ib": {"enabled": "yes"}},
            "warnings not bool": {**base, "eth": {"include_warnings": 1}},
            "empty sheet": {**base, "ib": {"cabling_sheet": " "}},
            "same import sheet": {**base, "eth": {"import_sheet": "cvt_import_gs"}},
        }
        for label, document in cases.items():
            with self.subTest(case=label):
                with self.assertRaises(self.sync.SyncError):
                    self.sync.load_config(self.write(document))
        self.path.write_text("{not json", encoding="utf-8")
        with self.assertRaises(self.sync.SyncError):
            self.sync.load_config(self.path)
        with self.assertRaises(self.sync.SyncError):
            self.sync.load_config(self.path.with_name("missing.json"))


class CredentialTests(unittest.TestCase):
    def setUp(self):
        self.sync = load_wrapper()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.key = Path(self.directory.name) / "cre.json"

    def write_key(self, mode=0o600, **overrides):
        document = {"type": "service_account", "client_email": "sync@example.test",
                    "private_key": SECRET_MARKER, "token_uri": "https://oauth2.example.test/token"}
        document.update(overrides)
        self.key.write_text(json.dumps(document), encoding="utf-8")
        self.key.chmod(mode)

    def assert_refused(self):
        with self.assertRaises(self.sync.SyncError) as caught:
            self.sync.check_credentials(self.key)
        self.assertNotIn(SECRET_MARKER, str(caught.exception))

    def test_owner_only_service_account_key_is_accepted(self):
        self.write_key()
        self.sync.check_credentials(self.key)

    def test_unsafe_or_wrong_keys_are_refused_without_printing_values(self):
        self.write_key(mode=0o644)
        self.assert_refused()
        self.write_key(type="authorized_user")
        self.assert_refused()
        self.write_key(private_key="")
        self.assert_refused()
        self.key.write_text("not json " + SECRET_MARKER, encoding="utf-8")
        self.key.chmod(0o600)
        self.assert_refused()
        self.write_key()
        link = self.key.with_name("linked.json")
        link.symlink_to(self.key)
        with self.assertRaises(self.sync.SyncError):
            self.sync.check_credentials(link)
        with self.assertRaises(self.sync.SyncError):
            self.sync.check_credentials(self.key.with_name("absent.json"))


class InputSelectionTests(unittest.TestCase):
    def setUp(self):
        self.sync = load_wrapper()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.project = Path(self.directory.name)

    def touch(self, relative, mtime, body=b"x"):
        path = self.project / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(body)
        os.utime(path, (mtime, mtime))
        return path

    def test_newest_ib_snapshot_by_minute_environment_and_completion_record(self):
        ufm = "99-output-monitor/infiniband/ufm-ibdiagnet/"
        old = self.touch(ufm + "20261022-0644-prod-" + "a" * 16 + "_ufm01_ibdiagnet2.tgz", 5000)
        self.touch(ufm + "20261022-0700-air-" + "b" * 16 + "_ufm01_ibdiagnet2.tgz", 6000)
        self.touch(ufm + "20261022-0705-prod-" + "c" * 16 + "_ufm01_iblinkinfo.log", 7000)
        failed = self.touch(ufm + "20261022-0710-prod-" + "d" * 16 + "_ufm02_ibdiagnet2.tgz", 8000)
        self.touch(ufm + "20261022-0710-prod-" + "d" * 16 + "_ufm02_ibdiagnet2.done", 8000,
                   b"result=failed\nrc=3\n")
        self.assertEqual(old, self.sync.newest_ib_input(self.project, "prod"))
        good = self.touch(ufm + "20261022-0720-prod-" + "e" * 16 + "_ufm01_ibdiagnet2.tgz", 1000)
        self.touch(ufm + "20261022-0720-prod-" + "e" * 16 + "_ufm01_ibdiagnet2.done", 1000,
                   b"result=ok\nrc=0\n")
        # the minute in the name orders runs, not the modification time
        self.assertEqual(good, self.sync.newest_ib_input(self.project, "prod"))
        self.assertIsNone(self.sync.newest_ib_input(self.project / "absent", "prod"))
        self.assertNotEqual(failed, self.sync.newest_ib_input(self.project, "prod"))

    def test_newest_eth_archive_by_minute_and_environment(self):
        eth = "99-output-monitor/ethernet/eth-info/"
        self.touch(eth + "20260822-1728.tar.gz", 9000)
        prod = self.touch(eth + "20260831-1900-prod.tar.gz", 1000)
        self.touch(eth + "20260831-2000-air.tar.gz", 2000)
        self.touch(eth + "20260831-2100-prod.tar.gz.part", 3000)
        self.assertEqual(prod, self.sync.newest_eth_input(self.project, "prod"))
        self.assertEqual("20260831-2000-air.tar.gz",
                         self.sync.newest_eth_input(self.project, "air").name)


class LldpqProjectionTests(unittest.TestCase):
    def setUp(self):
        self.sync = load_wrapper()

    def test_every_analyzer_status_has_a_fixed_lldpq_row(self):
        payload = {
            "matching_links": [
                record("CONFIRMED_BOTH_SIDE", observed={"host": "leaf-z", "port": "swp2"}),
                record("CONFIRMED_SW_SIDE", a=("leaf-a", "swp9"), b=("gpu-01", "eth0"),
                       observed={"host": "gpu-01", "port": "eth0"}),
            ],
            "miswired_links": [
                record("WRONG_PEER", a=("leaf-b", "swp1"), b=("leaf-y", "swp1"),
                       detail="leaf-b:swp1 sees leaf-x:swp1, expected leaf-y:swp1",
                       observed={"host": "leaf-x", "port": "swp1"}),
                record("WRONG_PEER", a=("leaf-b", "swp2"), b=("leaf-y", "swp2"),
                       detail="leaf-b:swp2 sees leaf-y:swp7, expected leaf-y:swp2",
                       observed={"host": "leaf-y", "port": "swp7"}),
                record("SW_LLDP_PRESENT", a=("leaf-c", "swp3"), b=("gpu-02", "eth0"),
                       detail="leaf-c:swp3 is up and reports host-x:eth0",
                       observed={"host": "host-x", "port": "eth0"}),
                record("NO_LLDP", a=("leaf-c", "swp4"), b=("gpu-03", "eth0"),
                       detail="leaf-c:swp4 is up but has no complete LLDP Remote Host/Port"),
            ],
            "missing_links": [
                record("DOWN", a=("leaf-d", "swp5"), b=("leaf-w", "swp5"),
                       detail="leaf-d:swp5 oper=down admin=up", observed={"oper": "down"}),
                record("MISSING_INTERFACE", a=("leaf-d", "swp6"), b=("leaf-w", "swp6"),
                       detail="leaf-d has no interface swp6 in nv show interface", observed={"oper": ""}),
                record("MISSING_DEVICE", a=("leaf-e", "swp1"), b=("leaf-v", "swp1"),
                       detail="leaf-e was not collected", observed={"oper": ""}),
            ],
        }
        document = self.sync.lldpq_document(payload, 1788178680.0)
        self.assertEqual({"schema_version": 1, "domain": "lldp_results", "collection_status": "complete",
                          "generated_at": 1788178680.0, "row_count": 9},
                         {key: value for key, value in document.items() if key != "rows"})
        rows = {(row["local_device"], row["local_port"]): row for row in document["rows"]}
        expected = {
            ("leaf-a", "swp1"): ("SUCCESS", "", "leaf-z", "swp2", "up"),
            ("leaf-a", "swp9"): ("SUCCESS", "", "gpu-01", "eth0", "up"),
            ("leaf-b", "swp1"): ("FAILED", "wrong device: leaf-b:swp1 sees leaf-x:swp1, expected leaf-y:swp1",
                                 "leaf-x", "swp1", "up"),
            ("leaf-b", "swp2"): ("FAILED", "port mismatch: leaf-b:swp2 sees leaf-y:swp7, expected leaf-y:swp2",
                                 "leaf-y", "swp7", "up"),
            ("leaf-c", "swp3"): ("WARNING", "LLDP neighbor not confirmed: leaf-c:swp3 is up and reports host-x:eth0",
                                 "host-x", "eth0", "up"),
            ("leaf-c", "swp4"): ("WARNING", "No LLDP neighbor: leaf-c:swp4 is up but has no complete "
                                 "LLDP Remote Host/Port", None, None, "up"),
            ("leaf-d", "swp5"): ("FAILED", "Link Down: leaf-d:swp5 oper=down admin=up", None, None, "down"),
            ("leaf-d", "swp6"): ("FAILED", "Interface missing: leaf-d has no interface swp6 in nv show interface",
                                 None, None, None),
            ("leaf-e", "swp1"): ("NO INFO", "Switch not collected: leaf-e was not collected", None, None, None),
        }
        self.assertEqual(set(expected), set(rows))
        for key, (status, health, actual_device, actual_port, port_status) in expected.items():
            with self.subTest(link=key):
                row = rows[key]
                self.assertEqual((status, health, actual_device, actual_port, port_status),
                                 (row["status"], row["connection_health"], row["actual_device"],
                                  row["actual_port"], row["port_status"]))
        self.assertEqual(("leaf-y", "swp1"), (rows[("leaf-b", "swp1")]["expected_device"],
                                              rows[("leaf-b", "swp1")]["expected_port"]))
        # warnings never carry the engine's Mis-wiring or Link Down markers
        for key in (("leaf-c", "swp3"), ("leaf-c", "swp4")):
            text = rows[key]["connection_health"].casefold()
            for marker in ("wrong device", "port mismatch", "mismatch", "link down", "port down"):
                self.assertNotIn(marker, text)

    def test_unknown_status_missing_endpoint_or_repeated_link_is_refused(self):
        base = {"matching_links": [], "miswired_links": [], "missing_links": []}
        with self.assertRaises(self.sync.StepError):
            self.sync.lldpq_document({**base, "matching_links": [record("SOMETHING_NEW")]}, 1.0)
        with self.assertRaises(self.sync.StepError):
            self.sync.lldpq_document({**base, "matching_links": [record("CONFIRMED_BOTH_SIDE", b=("", "swp2"))]}, 1.0)
        with self.assertRaises(self.sync.StepError):
            self.sync.lldpq_document({**base, "matching_links": [record("CONFIRMED_BOTH_SIDE")],
                                      "missing_links": [record("DOWN", a=("LEAF-A", "swp1"))]}, 1.0)
        with self.assertRaises(self.sync.StepError):
            self.sync.lldpq_document({"matching_links": []}, 1.0)


class EngineCommandTests(unittest.TestCase):
    def test_exact_engine_command_per_domain(self):
        sync = load_wrapper()
        config = sync.Config(SPREADSHEET, "Asia/Shanghai", {
            "ib": sync.Domain("ib", True, "prod", "CVT_Import", "IB Cabling", False),
            "eth": sync.Domain("eth", True, "prod", "LLDPQ_Import", "ETH Cabling", True),
        })
        source, key = Path("/data/ib-cvt.json"), Path("/project/cre.json")
        self.assertEqual(
            ["/py", str(ENGINE / "cabletracker_runner.py"), "--credentials", "/project/cre.json",
             "--spreadsheet-id", SPREADSHEET, "--timezone", "Asia/Shanghai",
             "--mapping-config", str(ENGINE / "mapping_v4.json"),
             "--source-type", "cvt", "--source-transport", "file", "--source-file", "/data/ib-cvt.json",
             "--cvt-sheet", "CVT_Import", "--ib-cabling-sheet", "IB Cabling",
             "--operation", "both", "--max-runs", "1"],
            sync.engine_command("/py", config, config.domains["ib"], source, key))
        command = sync.engine_command("/py", config, config.domains["eth"], Path("/data/eth-lldpq.json"), key)
        self.assertEqual(["--source-type", "lldpq"], command[10:12])
        self.assertEqual(["--cvt-sheet", "LLDPQ_Import", "--eth-cabling-sheet", "ETH Cabling"], command[16:20])
        self.assertEqual(["--include-warnings", "true"], command[-2:])
        self.assertNotIn("--ib-cabling-sheet", command)


SHADOW_CHILD = r'''
import importlib.util, json, sys, types
from pathlib import Path
for name in ("openai", "httpx"):
    try:
        __import__(name)
    except ImportError:
        stub = types.ModuleType(name)
        stub.OpenAI = stub.Client = object
        sys.modules[name] = stub
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
root, scenario = Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text())
sys.path.insert(0, str(root))
from test_cases.issue_tracker_template import FakeSheets
spec = importlib.util.spec_from_file_location("format_precheck_shadow_child",
                                              root / "monitor/issue-tracker/format_precheck.py")
precheck = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = precheck
spec.loader.exec_module(precheck)
pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
    serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
key = Path(scenario["work"]) / "cre.json"
key.write_text(json.dumps({"type": "service_account", "client_email": "shadow@example.test",
                           "private_key": pem, "token_uri": "https://oauth2.example.test/token"}))
command = [item.replace("@KEY@", str(key)) for item in scenario["command"]]
fake = FakeSheets(scenario["document"])
report = precheck.shadow_run(command, service_factory=lambda real: fake)
report["reads"] = len(fake.reads)
print(json.dumps(report))
'''


class FormatPrecheckTests(unittest.TestCase):
    """The read-only gate: the real engine in a shadow run against the standard template."""

    def setUp(self):
        spec = importlib.util.spec_from_file_location("format_precheck_under_test", PRECHECK)
        self.precheck = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = self.precheck
        spec.loader.exec_module(self.precheck)
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.work = Path(self.directory.name)

    def shadow(self, document):
        sync = load_wrapper()
        config = sync.Config(SPREADSHEET, "Asia/Shanghai", {
            name: sync.Domain(name, True, "prod", sync.DOMAIN_DEFAULTS[name]["import_sheet"],
                              sync.DOMAIN_DEFAULTS[name]["cabling_sheet"], False) for name in ("ib", "eth")})
        source = self.work / "eth-lldpq.json"
        source.write_text(json.dumps({"schema_version": 1, "domain": "lldp_results", "collection_status": "complete",
                                      "generated_at": 1788178680.0, "row_count": 2, "rows": [
            {"status": "SUCCESS", "local_device": "leaf-a", "local_port": "swp1", "expected_device": "leaf-z",
             "expected_port": "swp2", "actual_device": "leaf-z", "actual_port": "swp2", "port_status": "up",
             "connection_health": ""},
            {"status": "FAILED", "local_device": "leaf-b", "local_port": "swp3", "expected_device": "leaf-z",
             "expected_port": "swp4", "actual_device": None, "actual_port": None, "port_status": "down",
             "connection_health": "Link Down: leaf-b:swp3 oper=down admin=up"}]}))
        command = sync.engine_command(sys.executable, config, config.domains["eth"], source, Path("@KEY@"))
        scenario = self.work / "scenario.json"
        scenario.write_text(json.dumps({"work": str(self.work), "command": command[2:], "document": document}))
        import subprocess
        completed = subprocess.run([sys.executable, "-B", "-c", SHADOW_CHILD, str(ROOT), str(scenario)],
                                   capture_output=True, text=True, timeout=300, check=False)
        self.assertEqual(0, completed.returncode, completed.stderr[-3000:])
        return json.loads(completed.stdout.strip().splitlines()[-1])

    def test_standard_template_is_only_filled(self):
        report = self.shadow(copy.deepcopy(TEMPLATE))
        self.assertEqual((True, "preparation leaves the format unchanged"), (report["ok"], report.get("verdict")),
                         report)
        self.assertEqual(["'LLDPQ_Import_GS' A1 timestamp", "'ETH Cabling' A1 timestamp"], report["allowed"])
        self.assertGreater(report["reads"], 0)

    def test_old_cabling_header_is_refused_before_any_write(self):
        document = copy.deepcopy(TEMPLATE)
        headers = document["ETH Cabling"]["headers"]
        headers[headers.index("Reported by")] = "Requested by"
        report = self.shadow(document)
        self.assertFalse(report["ok"], report)
        self.assertEqual(1, len(report["changes"]), report)
        self.assertIn("ETH Cabling", report["changes"][0])

    def test_missing_import_worksheet_is_refused(self):
        document = copy.deepcopy(TEMPLATE)
        del document["LLDPQ_Import_GS"]
        report = self.shadow(document)
        self.assertFalse(report["ok"], report)
        self.assertIn("addSheet", report["changes"][0])

    def test_old_whitelist_layout_is_refused(self):
        document = copy.deepcopy(TEMPLATE)
        document["Whitelist"]["headers"] = ["Submit Date", "Submitor", "Datahalll", "Rack", "Device Name", "Comments"]
        report = self.shadow(document)
        self.assertFalse(report["ok"], report)
        self.assertIn("Whitelist", report["changes"][0])

    def test_write_judgement_by_location_only(self):
        document = self.precheck.Document({"IB Cabling": 7, "Inventory": 8},
                                          lambda title: "Updated at: x" if title == "IB Cabling" else "Type")
        policy = self.precheck.Policy(document, ["IB Cabling"])
        self.assertEqual("allowed", policy.judge_range("'IB Cabling'!A1", [["Updated at: 2026-10-23 22:00:00"]]))
        self.assertEqual("data", policy.judge_range("'IB Cabling'!A3:AE40"))
        for text, values in (("'IB Cabling'!A1", [["not a timestamp"]]), ("'IB Cabling'!A2:AE2", [["x"]]),
                             ("'IB Cabling'!B1", [["Updated at: x"]]), ("Inventory!A2:C9", [["x"]]),
                             ("'Absent'!A5", [["x"]])):
            with self.subTest(range=text):
                with self.assertRaises(self.precheck.FormatChange):
                    policy.judge_range(text, values)
        with self.assertRaises(self.precheck.ShadowFinished):
            policy.values_write("append", {"range": "'IB Cabling'!A3", "body": {"values": [["x"]]}})
        with self.assertRaises(self.precheck.FormatChange):
            policy.values_write("batchClearByDataFilter", {})
        for request in ({"addSheet": {"properties": {"title": "New"}}},
                        {"insertDimension": {"range": {"sheetId": 7, "dimension": "COLUMNS", "startIndex": 3}}},
                        {"repeatCell": {"range": {"sheetId": 7, "startRowIndex": 1, "endRowIndex": 2}}},
                        {"updateSheetProperties": {"properties": {"sheetId": 7}}}):
            with self.subTest(request=next(iter(request))):
                with self.assertRaises(self.precheck.FormatChange):
                    policy.batch_update({"body": {"requests": [request]}})
        with self.assertRaises(self.precheck.ShadowFinished):
            policy.batch_update({"body": {"requests": [
                {"appendDimension": {"sheetId": 7, "dimension": "ROWS", "length": 100}},
                {"repeatCell": {"range": {"sheetId": 7, "startRowIndex": 2}}}]}})

    def test_range_reading_and_snapshot_comparison(self):
        self.assertEqual(("IB Cabling", 3, None, 1, 31), self.precheck.parse_range("'IB Cabling'!A3:AE"))
        self.assertEqual(("ETH&IB Switch", 1, 2, None, None), self.precheck.parse_range("'ETH&IB Switch'!1:2"))
        self.assertEqual(("It's", None, None, None, None), self.precheck.parse_range("'It''s'"))
        before = {"worksheets": ["A", "B"], "headers": {"A": [["x"]], "B": [["Updated at:"], ["h"]]}}
        self.assertEqual([], self.precheck.snapshot_changes(before, copy.deepcopy(before)))
        after = {"worksheets": ["A", "B", "C"], "headers": {"A": [["y"]], "B": [["Updated at:"], ["h"]], "C": []}}
        self.assertEqual(["worksheet added: 'C'", "header rows of 'A' changed"],
                         self.precheck.snapshot_changes(before, after))


class MainFlowTests(unittest.TestCase):
    """main() with the real LLDP analyzer and recording stand-ins for the format gate and the engine."""

    def setUp(self):
        self.sync = load_wrapper()
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        base = Path(self.directory.name)
        self.project = base / "project"
        p2p = self.project / "99-output-p2p"
        p2p.mkdir(parents=True)
        (p2p / "plan-lldpq.dot").write_bytes(b'"leaf-a":"swp1" -- "leaf-z":"swp2"\n')
        write_archive(self.project / "99-output-monitor/ethernet/eth-info/20261023-0900-prod.tar.gz", {
            "leaf-a.info": info_text("swp1", "leaf-z", "swp2"),
            "leaf-z.info": info_text("swp2", "leaf-a", "swp1"),
        })
        (self.project / "03-issue-tracker.json").write_text(json.dumps({
            "schema": "issue-tracker-sync-v1", "spreadsheet_id": SPREADSHEET,
            "ib": {"enabled": False}}), encoding="utf-8")
        key = self.project / "cre.json"
        key.write_text(json.dumps({"type": "service_account", "client_email": "sync@example.test",
                                   "private_key": SECRET_MARKER,
                                   "token_uri": "https://oauth2.example.test/token"}), encoding="utf-8")
        key.chmod(0o600)
        self.calls = base / "engine-calls.jsonl"
        self.engine = base / "fake_runner.py"
        self.engine_exit = base / "engine-exit"
        self.engine.write_text(
            "import json, os, sys\n"
            "from pathlib import Path\n"
            f"calls = Path({str(self.calls)!r})\n"
            "source = Path(sys.argv[sys.argv.index('--source-file') + 1])\n"
            "with calls.open('a') as handle:\n"
            "    handle.write(json.dumps({'argv': sys.argv[1:], 'cwd': os.getcwd(),\n"
            "                             'rows': json.loads(source.read_text())['row_count']}) + '\\n')\n"
            f"exit_file = Path({str(self.engine_exit)!r})\n"
            "raise SystemExit(int(exit_file.read_text()) if exit_file.exists() else 0)\n",
            encoding="utf-8")
        patcher = mock.patch.object(self.sync, "RUNNER", self.engine)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.gate_calls = base / "gate-calls.jsonl"
        self.gate_exit = base / "gate-exit"
        self.after_exit = base / "after-exit"
        self.after_calls = base / "after-calls.jsonl"
        gate = base / "fake_precheck.py"
        gate.write_text(
            "import json, sys\n"
            "from pathlib import Path\n"
            "argv = sys.argv\n"
            "if '--compare-snapshot' in argv:\n"
            "    snapshot = Path(argv[argv.index('--compare-snapshot') + 1])\n"
            f"    Path({str(self.after_calls)!r}).open('a').write(json.dumps([snapshot.read_text(), argv[argv.index('--spreadsheet-id') + 1]]) + '\\n')\n"
            f"    exit_file = Path({str(self.after_exit)!r})\n"
            "    code = int(exit_file.read_text()) if exit_file.exists() else 0\n"
            "    print(json.dumps({'ok': code == 0, 'changes': ['header rows of IB Cabling changed'] if code == 3 else []}))\n"
            "    raise SystemExit(code)\n"
            "command = json.loads(Path(argv[argv.index('--engine-command-json') + 1]).read_text())\n"
            "Path(argv[argv.index('--snapshot') + 1]).write_text('before-snapshot')\n"
            f"Path({str(self.gate_calls)!r}).open('a').write(json.dumps(command) + '\\n')\n"
            f"exit_file = Path({str(self.gate_exit)!r})\n"
            "code = int(exit_file.read_text()) if exit_file.exists() else 0\n"
            "print(json.dumps({'ok': code == 0, 'changes': ['IB Cabling header row 2 would be rewritten'] if code == 3 else []}))\n"
            "raise SystemExit(code)\n", encoding="utf-8")
        gate_patcher = mock.patch.object(self.sync, "FORMAT_PRECHECK", gate)
        gate_patcher.start()
        self.addCleanup(gate_patcher.stop)

    def run_main(self, *extra):
        stream = io.StringIO()
        with redirect_stdout(stream):
            code = self.sync.main(["--project-dir", str(self.project),
                                   "--engine-python", sys.executable, *extra])
        return code, stream.getvalue()

    def engine_calls(self):
        if not self.calls.exists():
            return []
        return [json.loads(line) for line in self.calls.read_text().splitlines()]

    def test_sync_once_then_skip_unchanged_then_force(self):
        output = self.project / "99-output-p2p/issue-tracker"
        code, text = self.run_main()
        self.assertEqual(0, code, text)
        calls = self.engine_calls()
        self.assertEqual(1, len(calls))
        self.assertEqual(1, calls[0]["rows"])
        self.assertIn("--eth-cabling-sheet", calls[0]["argv"])
        self.assertEqual(str((self.project / "cre.json").resolve()),
                         calls[0]["argv"][calls[0]["argv"].index("--credentials") + 1])
        self.assertEqual(output.resolve(), Path(calls[0]["cwd"]).resolve().parent)
        self.assertFalse(Path(calls[0]["cwd"]).exists())
        state = json.loads((output / "state.json").read_text())
        self.assertEqual("issue-tracker-sync-state-v1", state["schema"])
        self.assertEqual("20261023-0900-prod.tar.gz", state["eth"]["inputs"]["input"]["name"])
        self.assertNotIn("ib", state)
        self.assertNotIn(SECRET_MARKER, text + (output / "issue-tracker-sync.log").read_text())
        gate_commands = [json.loads(line) for line in self.gate_calls.read_text().splitlines()]
        self.assertEqual([calls[0]["argv"]], gate_commands)
        self.assertIn("format pre-check: document matches the engine", text)
        self.assertEqual([["before-snapshot", SPREADSHEET]],
                         [json.loads(line) for line in self.after_calls.read_text().splitlines()])

        code, text = self.run_main()
        self.assertEqual(0, code, text)
        self.assertIn("already synced", text)
        self.assertEqual(1, len(self.engine_calls()))

        code, text = self.run_main("--force")
        self.assertEqual(0, code, text)
        self.assertEqual(2, len(self.engine_calls()))

    def test_engine_failure_exits_1_and_keeps_the_input_pending(self):
        self.engine_exit.write_text("2")
        code, text = self.run_main()
        self.assertEqual(1, code, text)
        self.assertIn("cabletracker_runner.py exited 2", text)
        self.assertFalse((self.project / "99-output-p2p/issue-tracker/state.json").exists())
        self.engine_exit.unlink()
        code, text = self.run_main()
        self.assertEqual(0, code, text)
        self.assertEqual(2, len(self.engine_calls()))

    def test_a_format_change_stops_the_run_before_the_engine_writes(self):
        self.gate_exit.write_text("3")
        code, text = self.run_main()
        self.assertEqual(2, code, text)
        self.assertIn("format change refused: IB Cabling header row 2 would be rewritten", text)
        self.assertIn("nothing was written", text)
        self.assertEqual([], self.engine_calls())
        self.assertFalse((self.project / "99-output-p2p/issue-tracker/state.json").exists())
        self.gate_exit.write_text("2")
        code, text = self.run_main()
        self.assertEqual(1, code, text)
        self.assertEqual([], self.engine_calls())

    def test_a_format_change_during_the_run_fails_and_is_not_recorded_as_synced(self):
        self.after_exit.write_text("3")
        code, text = self.run_main()
        self.assertEqual(1, code, text)
        self.assertEqual(1, len(self.engine_calls()))
        self.assertIn("FORMAT CHANGED BY THE ENGINE: header rows of IB Cabling changed", text)
        self.assertIn("restore it from the document's version history", text)
        self.assertFalse((self.project / "99-output-p2p/issue-tracker/state.json").exists())

    def test_precheck_only_runs_the_gate_but_never_the_engine(self):
        code, text = self.run_main("--precheck-only")
        self.assertEqual(0, code, text)
        self.assertEqual(1, len(self.gate_calls.read_text().splitlines()))
        self.assertEqual([], self.engine_calls())
        self.assertIn("pre-check passed; nothing written", text)
        self.assertFalse((self.project / "99-output-p2p/issue-tracker/state.json").exists())
        code, text = self.run_main("--precheck-only", "--convert-only")
        self.assertEqual(2, code, text)

    def test_convert_only_needs_no_key_and_never_runs_the_engine(self):
        (self.project / "cre.json").unlink()
        code, text = self.run_main("--convert-only")
        self.assertEqual(0, code, text)
        self.assertEqual([], self.engine_calls())
        document = json.loads((self.project / "99-output-p2p/issue-tracker/eth-lldpq.json").read_text())
        self.assertEqual(1, document["row_count"])
        self.assertEqual("SUCCESS", document["rows"][0]["status"])
        code, text = self.run_main()
        self.assertEqual(2, code, text)
        self.assertIn("service account key not found", text)

    def test_only_a_domain_without_input_is_a_configuration_error(self):
        (self.project / "03-issue-tracker.json").write_text(json.dumps({
            "schema": "issue-tracker-sync-v1", "spreadsheet_id": SPREADSHEET}), encoding="utf-8")
        code, text = self.run_main("--only", "ib")
        self.assertEqual(2, code, text)
        self.assertIn("no input to sync", text)
        code, text = self.run_main()
        self.assertEqual(0, code, text)
        self.assertIn("IB: no prod ibdiagnet2.tgz", text)
        self.assertEqual(1, len(self.engine_calls()))

    def test_a_second_sync_of_the_same_project_waits_its_turn(self):
        output = self.project / "99-output-p2p/issue-tracker"
        output.mkdir()
        with (output / ".sync.lock").open("a") as holder:
            fcntl.flock(holder, fcntl.LOCK_EX)
            code, text = self.run_main()
        self.assertEqual(75, code, text)
        self.assertEqual([], self.engine_calls())

    def test_project_comes_from_the_setup_link_when_not_given(self):
        anchor = Path(self.directory.name) / "monitor-01-global.yaml"
        with mock.patch.object(self.sync, "PROJECT_ANCHOR", anchor):
            with self.assertRaises(self.sync.SyncError):
                self.sync.project_directory(None)
            (self.project / "01-global.yaml").write_text("common: {}\n")
            anchor.symlink_to(self.project / "01-global.yaml")
            self.assertEqual(self.project.resolve(), self.sync.project_directory(None))


if __name__ == "__main__":
    unittest.main()
