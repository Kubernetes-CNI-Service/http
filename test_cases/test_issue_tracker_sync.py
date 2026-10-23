"""REQ7 Issue Tracker sync wrapper: direct contract of monitor/issue-tracker/issue-tracker-sync.py.

The CableTracker engine under monitor/issue-tracker/cabletracker/ is a byte-for-byte copy of the
reference tool; this module pins those bytes and checks the wrapper's own rules: project
configuration, service-account key checks (never printing a value), newest-input selection,
the LLDP -> LLDPQ schema-v1 projection, the exact engine command, skip-when-unchanged state and
the per-project lock.
"""

from __future__ import annotations

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
import unittest
from contextlib import redirect_stdout
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "monitor/issue-tracker/issue-tracker-sync.py"
ENGINE = ROOT / "monitor/issue-tracker/cabletracker"
REFERENCE = ROOT / "tools/cabletracker-lldpq"
VENDORED_SHA256 = {
    "cabletracker_runner.py": "3ae523fa8d3cecd2af387a1b57188a036cee807e52ac12e2f7dc194a11ac8f00",
    "mapping_v4.json": "fa8ec80d39c6a968b74059cd79978fef5bee6ec823dd4a6b2321191acd4300f7",
    "ibdiagnet/__init__.py": "6f626ffc9882ef74a66a34db0979249b4d10eb102aafab264653d0d1689088ad",
    "ibdiagnet/generate_report.py": "58abe6c983d3372d26f79c3f75a04930bdb596cd0dd0f98c4aaa0df8c5978e5d",
}
SPREADSHEET = "1" + "A" * 43
SECRET_MARKER = "secret-value"


def load_wrapper():
    spec = importlib.util.spec_from_file_location("issue_tracker_sync_under_test", WRAPPER)
    module = importlib.util.module_from_spec(spec)
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


class VendoredEngineTests(unittest.TestCase):
    def test_engine_files_are_the_reference_bytes(self):
        for relative, expected in VENDORED_SHA256.items():
            with self.subTest(file=relative):
                data = (ENGINE / relative).read_bytes()
                self.assertEqual(expected, hashlib.sha256(data).hexdigest())
                reference = REFERENCE / relative
                if reference.is_file():
                    self.assertEqual(reference.read_bytes(), data)


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
        self.assertEqual((True, "prod", "CVT_Import", "IB Cabling", False),
                         (ib.enabled, ib.environment, ib.import_sheet, ib.cabling_sheet, ib.include_warnings))
        self.assertEqual((True, "prod", "LLDPQ_Import", "ETH Cabling", False),
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
            "same import sheet": {**base, "eth": {"import_sheet": "cvt_import"}},
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


class MainFlowTests(unittest.TestCase):
    """main() with the real LLDP analyzer and a recording stand-in for the engine."""

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
