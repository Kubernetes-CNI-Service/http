"""Explicit CWD input links are not an active/load project lookup."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures

app, driver = fixtures.app, fixtures.driver


class StandaloneLinkTests(unittest.TestCase):
    def fixture(self, root):
        project, home, entry, workspace = fixtures.ManagedDefaultWorkflowTests().fixture(root)
        (workspace / "ztp/.setup_manifest").unlink()
        for relative in ("config/cumulus/template/01-global.yaml", "config/cumulus/template/02-devices_config.csv",
                         "config/isc-dhcp-server/02-subnet_config.csv", "status"):
            (workspace / "ztp" / relative).unlink()
        return project, home, entry, workspace

    def test_real_cli_uses_cwd_links_with_no_load_manifest_or_identity_anchors(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            out, err = io.StringIO(), io.StringIO()
            with patch.object(app, "__file__", str(entry / "upgrade.py")), \
                 patch.object(app, "_fixed_driver", return_value=driver), patch.object(app.os, "getcwd", return_value=str(entry)), \
                 patch.object(socket, "socket", side_effect=AssertionError("Offline scripts only")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main(["--scripts-only", "--method", "http", "--os-only"])
            self.assertEqual(code, 0, err.getvalue())
            self.assertEqual(len(json.loads(out.getvalue())["targets"]), 2)
            self.assertEqual(len(list(project.glob("99-output-ib_nvl/bringup/xdr-upgrade-logs/*/plan.json"))), 1)
            self.assertFalse((workspace / "ztp/.setup_manifest").exists())

    def test_zero_argument_readonly_run_with_input_links_does_not_require_load(self):
        complete = fixtures.GLOBAL + """        bios:
          file: 0ACQF.cab
          version: '0ACQF_06.01.009'
        cpld:
          burn:
            file: FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
          refresh:
            file: FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
"""
        columns = ("Name", "Actual FW", "Part Number", "FW Source")
        firmware = "{:<9}  {:<23}  {:<15}  {}\n".format(*columns)
        firmware += "---------  -----------------------  ---------------  ---------\n"
        for row in (("BIOS", "0ACQF_06.01.009", "PN1", "internal"),
                    ("CPLD1", "CPLD000232_REV0900", "PN2", "internal"),
                    ("CPLD2", "CPLD000383_REV0800", "PN3", "internal"),
                    ("CPLD3", "CPLD000389_REV0600", "PN4", "internal")):
            firmware += "{:<9}  {:<23}  {:<15}  {}\n".format(*row)
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            identity = (leaf.node.hostname + "\n" + leaf.node.mac + "\n").encode()
            yield object(), 99999999999, (identity, b"", 0), "password", "synthetic-pin"
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            (project / "01-global.yaml").write_text(complete)
            out, err = io.StringIO(), io.StringIO()
            with patch.object(app, "__file__", str(entry / "upgrade.py")), patch.object(app, "_fixed_driver", return_value=driver), \
                 patch.object(app.os, "getcwd", return_value=str(entry)), patch.object(Path, "home", return_value=home), \
                 patch.object(app, "_check_runtime"), patch.object(app, "_read_password", return_value="PRIVATE"), \
                 patch.object(fixtures.observer, "_signed_session", session), \
                 patch.object(fixtures.observer, "_read_channel", side_effect=lambda _leaf,_transport,command,_deadline:
                    ({'nv show system version':fixtures.OS_TABLE,'nv show platform firmware':firmware.encode(),
                      'nv show system health':fixtures.HEALTH_TABLE}[command],b'',0,True)), \
                 patch.object(socket, "socket", side_effect=AssertionError("No network")), \
                 contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                code = app.main([])
            self.assertEqual(code, 0, err.getvalue())
            self.assertEqual(json.loads(out.getvalue())["ready_ib_count"], 2)
            self.assertFalse((workspace / "ztp/.setup_manifest").exists())

    def test_explicit_link_sources_cannot_mix_two_day0_projects(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            (workspace / "infiniband/ib.csv").unlink()
            foreign = workspace / "DAY0-Prepare/foreign"
            foreign.mkdir()
            (foreign / "02-devices_config.csv").write_bytes((project / "02-devices_config.csv").read_bytes())
            (workspace / "infiniband/ib.csv").symlink_to("../DAY0-Prepare/foreign/02-devices_config.csv")
            args = ("--standalone-inputs", "--global", str(entry / "01-global.yaml"), "--ib-csv", str(entry / "ib.csv"), "--os-only")
            with self.assertRaises(ValueError):
                driver.preflight_inventory_selection(str(entry / "upgrade.py"), str(entry), args)

    def test_alias_mutation_is_still_detected_without_a_setup_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            args = ("--standalone-inputs", "--global", str(entry / "01-global.yaml"), "--ib-csv", str(entry / "ib.csv"), "--os-only")
            plan = driver.parse_prepare_args(str(entry / "upgrade.py"), str(entry), args)
            with driver.open_standalone_inputs(plan.paths) as scope:
                (entry / "ib.csv").unlink()
                (entry / "ib.csv").symlink_to("missing.csv")
                with self.assertRaises(ValueError):
                    scope.verify()

    def test_standalone_link_cycle_is_refused_without_manifest_fallback(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            (entry / "ib.csv").unlink()
            (entry / "ib.csv").symlink_to("ib.csv")
            args = ("--standalone-inputs", "--global", str(entry / "01-global.yaml"), "--ib-csv", str(entry / "ib.csv"), "--os-only")
            plan = driver.parse_prepare_args(str(entry / "upgrade.py"), str(entry), args)
            with self.assertRaises(ValueError):
                with driver.open_standalone_inputs(plan.paths):
                    self.fail("A link cycle cannot be admitted")

    def test_output_link_cannot_publish_evidence_into_a_foreign_project(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, entry, workspace = self.fixture(Path(directory).resolve())
            output = entry / "xdr-upgrade-logs"
            output.unlink()
            output.symlink_to("../../../DAY0-Prepare/foreign/99-output-ib_nvl/bringup/xdr-upgrade-logs")
            args = ("--standalone-inputs", "--global", str(entry / "01-global.yaml"), "--ib-csv", str(entry / "ib.csv"), "--os-only")
            plan = driver.parse_prepare_args(str(entry / "upgrade.py"), str(entry), args)
            with self.assertRaisesRegex(ValueError, "output link conflicts"):
                with driver.open_standalone_inputs(plan.paths):
                    self.fail("A foreign output must not be admitted")


if __name__ == "__main__":
    unittest.main()
