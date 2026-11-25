"""WP-A3/I-016: real Engine -> LiveOps -> v1 key reader through a local SFTP failure.

OS/CPLD execute the actual component and owned-runner scripts against isolated stubs.
Only the SFTP transport boundary is faulted; business classifications are never mocked.
"""
from __future__ import annotations

import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))
import fleet_engine
import fleet_link
import fleet_probe
import fleet_ssh as ssh
import ibsw_v2_device as ib
import ibsw_upgrade_access as v1_access
import test_ibsw_upgrade_connection_drops as direct
from ibsw_upgrade_contract import load_global_text, normalize_upgrade

FAST = fleet_probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05,
                           ssh_check=0.3, dwell=8.0, ladder_budget=4.0, deadline=15.0,
                           post_ready_settle=0.05)


class UpgradeConnectionDropWorkflowTests(unittest.TestCase):
    def exercise(self, component, *, repair_fault=False):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        base = Path(temporary.name)
        item = direct.world(base)
        original_boot = item.switch.boot_id
        if component == "cpld":
            firmware = base / "http" / "firmware"
            firmware.mkdir()
            for action in ("BURN", "REFRESH"):
                (firmware / ("FUI1_" + action + "_CPLD000123_REV0400.vme")).write_bytes(b"synthetic CPLD only\n")
            item.policy = normalize_upgrade(load_global_text(f"""schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.10
      port: 8088
      http_root: {base / 'http'}
switches:
- ib:
    version: '25.02.7002'
    upgrade:
      package_dir: {base / 'http'}
      packages:
        cpld:
          sub_dir: firmware
          burn:
            file: FUI1_BURN_CPLD000123_REV0400.vme
          refresh:
            file: FUI1_REFRESH_CPLD000123_REV0400.vme
"""), selected=("cpld",), method="http")
            (item.switch.state / "cpld").write_text("CPLD000123_REV0300")
        item.ops.policy, item.ops.selected = item.policy, (component,)
        if repair_fault:
            item.switch.lose_config_line = "nv set system ntp server 192.0.2.123\n"
        original_verify = item.ops.verify
        attempts = []
        def verify(*args, **kwargs):
            attempts.append(item.switch.boot_id)
            if len(attempts) == 1:
                marker = ".ibsw-v2-repair-" if repair_fault else "authorized_keys"
                item.switch.fail_sftp("open" if repair_fault else "lstat", marker,
                                      ssh._sdk().SSHException("synthetic disconnected SFTP"), inactive=True,
                                      reboot=not repair_fault)
            return original_verify(*args, **kwargs)
        item.ops.verify = verify
        options = fleet_engine.Options(run_id="a3", selected=(component,), upgrade=True,
                                       link=fleet_link.decide(1000, source="override"), groups={}, timings=FAST,
                                       progress_seconds=0.5, later_hop_batch_seconds=0.05)
        out = io.StringIO()
        original_reader = ib._read_keys
        self.assertIs(original_reader, v1_access._read_keys, "the real frozen v1 reader is the workflow consumer")
        with mock.patch.object(ib, "_read_keys", wraps=original_reader) as reader:
            engine = fleet_engine.Engine([item.device], ib.IbFamily(item.policy), item.ops, options,
                                         item.evidence, out=out)
            report = engine.run()
        self.assertGreater(reader.call_count, 0)
        self.assertEqual(len(item.switch.sftp_fault_log), 1, "fault must reach real SFTP/v1 reader or repair")
        self.assertEqual(item.switch.sftp_fault_log[0][2:], ("SSHException", False))
        self.assertNotEqual(item.switch.boot_id, original_boot, "actual local install caused a new simulated boot")
        self.assertEqual(json.loads((item.evidence.directory("sw01") / "dispatch.json").read_text())["state"],
                         "REQUESTED")
        for path in (base / "run").rglob("*"):
            if path.is_file():
                self.assertNotIn(direct.fixtures.SENTINEL.encode(), path.read_bytes(), str(path))
        if repair_fault:
            self.assertEqual([(r["category"], r["reason"]) for r in report["devices"]],
                             [("UNKNOWN", "CONFIG_REPAIR_FAILED")], out.getvalue())
            self.assertEqual(len(attempts), 1, "once repair requested, never replay it")
            repair = json.loads((item.evidence.directory("sw01") / "repair-result.json").read_text())
            self.assertEqual((repair["state"], repair["reason"]), ("UNKNOWN", "COMMAND_INCOMPLETE"))
        else:
            self.assertEqual([(r["category"], r["reason"]) for r in report["devices"]],
                             [("UPGRADED", None)], out.getvalue())
            self.assertEqual(len(attempts), 2, "first inactive reader failure must return to probing once")
            self.assertNotEqual(attempts[0], attempts[1], "the disconnect is followed by a new simulated boot")
            if component == "cpld":
                self.assertEqual((item.switch.state / "cpld").read_text(), "CPLD000123_REV0400")
                self.assertEqual((item.switch.state / "cpld-installs").read_text().splitlines(),
                                 ["FUI1_BURN_CPLD000123_REV0400.vme", "FUI1_REFRESH_CPLD000123_REV0400.vme"])
            else:
                self.assertEqual((item.switch.state / "version").read_text(), "25.02.8008")

    def test_os_restore_disconnect_returns_to_probe_and_finishes(self):
        self.exercise("os")

    def test_cpld_restore_disconnect_returns_to_probe_and_finishes(self):
        self.exercise("cpld")

    def test_repair_upload_disconnect_is_unknown_and_not_replayed(self):
        self.exercise("os", repair_fault=True)
