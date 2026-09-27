#!/usr/bin/env python3
"""Functional cases for infra health collection and the reset wrapper."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_check_infra():
    infra_dir = ROOT / "infra"
    sys.path.insert(0, str(infra_dir))
    try:
        spec = importlib.util.spec_from_file_location(
            "functional_check_infra", infra_dir / "check_infra.py",
        )
        if spec is None or spec.loader is None:
            raise RuntimeError("cannot load check_infra.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(infra_dir))


CHECK = load_check_infra()


class InfraCheckFunctionalTests(unittest.TestCase):
    def test_public_collection_options_explain_inputs_and_output(self):
        with mock.patch.object(sys, "argv", ["check_infra.py"]):
            with mock.patch.object(CHECK.argparse.ArgumentParser, "parse_args", autospec=True) as parse:
                CHECK.parse_args()
                parser = parse.call_args.args[0]
        actions = {
            option: action
            for action in parser._actions
            for option in action.option_strings
        }
        self.assertIn("devices CSV", actions["--devices-file"].help or "")
        self.assertIn("local results", actions["--output-dir"].help or "")

    def assert_remote_result_directory_contract(self, factory):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "collected"
            output.mkdir()
            observed = {
                label: factory(output, label, "192.0.2.10")
                for label in (
                    ".", "..", "", "leaf01", "leaf/../escape", "leaf\N{SNOWMAN}",
                    "rack/a", "rack?a",
                )
            }
            self.assertEqual(len(observed), len(set(observed.values())))
            for destination in observed.values():
                self.assertEqual(output.resolve(), destination.resolve().parent)
                self.assertRegex(destination.name, r"\Aserver-[A-Za-z0-9_-]+-192-0-2-10\Z")

            first = factory(output, "same-label", "192.0.2.11")
            second = factory(output, "same-label", "192.0.2.12")
            self.assertNotEqual(first, second)

    def test_remote_result_directory_is_one_canonical_contained_component(self):
        self.assert_remote_result_directory_contract(CHECK.safe_server_output_dir)

    def test_remote_result_directory_oracle_rejects_wrong_but_present_helper(self):
        def unsafe_factory(output_dir, label, _address):
            destination = output_dir.parent / (label or "server-fallback")
            destination.mkdir(parents=True, exist_ok=True)
            return destination

        with self.assertRaises(AssertionError):
            self.assert_remote_result_directory_contract(unsafe_factory)

    def test_remote_result_directory_rejects_non_ipv4_and_preexisting_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "collected"
            output.mkdir()
            for address in ("", "../escape", "2001:db8::1", "999.1.1.1"):
                with self.subTest(address=address), self.assertRaises(CHECK.DeployError):
                    CHECK.safe_server_output_dir(output, "leaf", address)

            destination = output / "server-leaf-192-0-2-10"
            destination.symlink_to(Path(directory))
            with self.assertRaises(CHECK.DeployError):
                CHECK.safe_server_output_dir(output, "leaf", "192.0.2.10")

    def test_collect_server_keeps_status_and_log_destinations_beneath_output(self):
        probe_text = "\n".join((
            "public.status=completed",
            "public.last_action=setup",
            "public.exit_code=0",
            "system.os_id=ubuntu",
            "system.os_version=24.04",
            "run_info.status=completed",
            "packages.missing=",
            "privileged.available=true",
            "effective.dns=8.8.8.8",
            "effective.ntp=ntp.ubuntu.com",
            "effective.timezone=Etc/UTC",
            "log.file=infra-setup-20260923_010203.log",
            "log.file=logs/infra-teardown-20260923_010204.log",
            "",
        ))
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "collected" / "20260923T010200Z"
            output.mkdir(parents=True)
            copied = []

            def fake_run(command, **_kwargs):
                if command[0] == "scp":
                    destination = Path(command[-1])
                    destination.write_text("copied", encoding="utf-8")
                    copied.append(destination)
                    return subprocess.CompletedProcess(command, 0, "", "")
                if command[-1] == "printf '%s' \"$HOME\"":
                    return subprocess.CompletedProcess(command, 0, "/home/operator", "")
                return subprocess.CompletedProcess(command, 0, probe_text, "")

            with mock.patch.object(CHECK, "key_login_works", return_value=True), \
                 mock.patch.object(CHECK.subprocess, "run", side_effect=fake_run):
                result = CHECK.collect_server(
                    {"hostname": "..", "address": "192.0.2.10"},
                    "operator", None, output,
                )

            self.assertEqual(
                [
                    "infra-setup-20260923_010203.log",
                    "logs/infra-teardown-20260923_010204.log",
                ],
                result["logs"],
            )
            status_files = list(output.glob("server-*/status.txt"))
            self.assertEqual(1, len(status_files))
            self.assertEqual(2, len(copied))
            for destination in [*status_files, *copied]:
                self.assertTrue(destination.resolve().is_relative_to(output.resolve()))

    def test_probe_values_drive_success_and_failure_classification(self):
        healthy = CHECK.parse_key_values(
            "\n".join((
                "public.status=completed",
                "public.last_action=setup",
                "public.exit_code=0",
                "system.os_id=ubuntu",
                "system.os_version=24.04",
                "run_info.status=completed",
                "packages.missing=",
                "privileged.available=true",
                "effective.dns=8.8.8.8",
                "effective.ntp=ntp.ubuntu.com",
                "effective.timezone=Etc/UTC",
            ))
        )
        self.assertEqual(("OK", []), CHECK.classify(healthy))

        failed = dict(healthy)
        failed.update({
            "public.status": "failed",
            "public.exit_code": "7",
            "packages.missing": "jq chrony",
        })
        severity, issues = CHECK.classify(failed)
        self.assertEqual("ERROR", severity)
        self.assertTrue(any("exit_code=7" in issue for issue in issues))
        self.assertTrue(any("jq chrony" in issue for issue in issues))

    def test_probe_reports_and_classifies_effective_network_values(self):
        script = CHECK.remote_probe_script()
        self.assertIn("effective.dns=", script)
        self.assertIn("effective.ntp=", script)
        self.assertIn("effective.timezone=", script)
        healthy = {
            "public.status": "completed",
            "public.last_action": "setup",
            "public.exit_code": "0",
            "system.os_id": "ubuntu",
            "system.os_version": "24.04",
            "run_info.status": "completed",
            "packages.missing": "",
            "privileged.available": "true",
            "effective.dns": "8.8.8.8",
            "effective.ntp": "ntp.ubuntu.com",
            "effective.timezone": "Etc/UTC",
        }
        self.assertEqual(("OK", []), CHECK.classify(healthy))
        mismatched = dict(healthy, **{"effective.dns": "208.67.220.220"})
        severity, issues = CHECK.classify(mismatched)
        self.assertEqual("ERROR", severity)
        self.assertTrue(any("DNS" in issue for issue in issues))

    def test_main_collects_local_and_remote_results_and_writes_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "collected"
            args = mock.Mock(
                user="operator", identity=None,
                devices_file=Path(directory) / "devices.csv",
                hosts=None, output_dir=output, clients_only=False,
            )
            server = {"hostname": "client01", "address": "192.0.2.10"}
            local = {
                "hostname": "mgmt:local", "address": "local", "severity": "OK",
                "issues": [], "values": {}, "logs": [],
            }
            remote = {
                "hostname": "client01", "address": "192.0.2.10", "severity": "OK",
                "issues": [], "values": {}, "logs": [],
            }
            with mock.patch.object(CHECK, "parse_args", return_value=args), \
                 mock.patch.object(CHECK, "_validate_username", return_value="operator"), \
                 mock.patch.object(CHECK, "normalize_identity", return_value=None), \
                 mock.patch.object(CHECK, "load_servers", return_value=[server]), \
                 mock.patch.object(CHECK, "collect_local", return_value=local), \
                 mock.patch.object(
                     CHECK, "prepare_check_access",
                     return_value=("operator", False),
                 ), \
                 mock.patch.object(CHECK, "collect_server", return_value=remote):
                self.assertEqual(0, CHECK.main())
            reports = list(output.glob("*/summary.json"))
            self.assertEqual(1, len(reports))
            payload = json.loads(reports[0].read_text(encoding="utf-8"))
            self.assertEqual({"OK": 2, "WARN": 0, "ERROR": 0}, payload["summary"])
            self.assertEqual(2, len(payload["devices"]))


class ManualResetWrapperFunctionalTests(unittest.TestCase):
    def test_wrapper_forces_reset_and_forwards_arguments_and_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            wrapper = temp / "manual-reset.py"
            shutil.copy2(ROOT / "ztp/manual-reset.py", wrapper)
            captured = temp / "captured.json"
            (temp / "manual-ztp.py").write_text(
                textwrap.dedent(
                    f"""
                    import json
                    from pathlib import Path
                    def main(argv):
                        Path({str(captured)!r}).write_text(json.dumps(argv))
                        return 23
                    """
                ),
                encoding="utf-8",
            )
            result = subprocess.run(
                [sys.executable, "-B", str(wrapper), "--project", "demo", "leaf01"],
                cwd=temp, text=True, capture_output=True, timeout=20,
            )
            self.assertEqual(23, result.returncode, result.stderr)
            self.assertEqual(
                ["--operation", "reset", "--project", "demo", "leaf01"],
                json.loads(captured.read_text(encoding="utf-8")),
            )


if __name__ == "__main__":
    unittest.main()
