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
