"""IB upgrade v2 end to end: fleet engine + IB adapter + switch scripts on simulated switches.

Owner 2026-10-23: 1G ztp-server link, so OS images relay per OOB leaf (from P2P); the
canary (v1 route cover: the longest route) pulls directly and upgrades first through
both hops; every other switch gets each hop's image from the server once per leaf and
otherwise by scp from a holder with the switch password; nobody reboots while serving;
a switch already at target and an unreachable one are reported, not touched; the run's
evidence never contains the password.
"""
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))

import fleet_distribution as dist  # noqa: E402
import fleet_engine  # noqa: E402
import fleet_link  # noqa: E402
import fleet_probe as probe  # noqa: E402
import fleet_ssh as ssh  # noqa: E402
import ibsw_v2_device as ib  # noqa: E402
from ibsw_upgrade_contract import InventoryDevice  # noqa: E402
from ibsw_v2_switch_sim import LocalSwitch, SimFleet  # noqa: E402
from test_ibsw_v2_device import SENTINEL, policy_for  # noqa: E402

FAST = probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05, ssh_check=0.3,
                     dwell=8.0, ladder_budget=4.0, deadline=15.0)


class WorkflowTest(unittest.TestCase):
    def test_relay_fleet_upgrade_through_two_hops(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        policy = policy_for(base / "http")
        key = ssh._sdk().ECDSAKey.generate()
        versions = {"sw01": "25.02.7002", "sw02": "25.02.6077", "sw03": "25.02.7002", "sw04": "25.02.7002",
                    "sw05": "25.02.8008", "sw06": "25.02.7002"}
        switches, devices, pins = [], [], b""
        for index, (name, version) in enumerate(versions.items(), 1):
            address, mac = f"192.0.2.{20 + index}", f"02:00:00:00:00:{20 + index:02x}"
            switches.append(LocalSwitch(base / "switches", name, address, mac, version, password=SENTINEL))
            devices.append(InventoryDevice(name, address, mac))
            host_key = ssh._sdk().ECDSAKey.generate()
            pins += f"{address} {host_key.get_name()} {host_key.get_base64()}\n".encode()
        fleet = SimFleet(switches, base / "http", key.get_base64())
        original_connector = fleet.connector

        def connector(device, method):
            if device.hostname == "sw06":
                raise ssh.SshError("CONNECT_FAILED")
            return original_connector(device, method)
        fleet.connector = connector
        p2p = base / "p2p.csv"
        p2p.write_text("a-node,a-port,z-node,z-port\n" + "".join(
            f"{name},eth0,oob-leaf0{1 if index <= 3 else 2},swp{index}\n" for index, name in enumerate(versions, 1)))
        groups, warnings = dist.oob_groups(p2p, list(versions))
        self.assertEqual(warnings, [])
        creds = ssh.Credentials("admin", key, ssh.fingerprint(key.asbytes()), SENTINEL)
        ops = ib.LiveOps(pins=ssh.HostPins(pins), credentials=creds, policy=policy, selected=("os",), run_id="r1",
                         management_line=f"{key.get_name()} {key.get_base64()} mgmt\n".encode(),
                         connector=fleet.connector, ping_run=fleet.ping_run, tcp_probe=fleet.tcp,
                         dir_for=fleet.dir_for)
        options = fleet_engine.Options(run_id="r1", selected=("os",), upgrade=True,
                                       link=fleet_link.decide(1000, source="override"), groups=groups,
                                       timings=FAST, progress_seconds=0.5, later_hop_batch_seconds=0.05)
        out = io.StringIO()
        engine = fleet_engine.Engine(devices, ib.IbFamily(policy), ops, options,
                                     fleet_engine.Evidence(base / "run"), out=out)
        report = engine.run()
        results = {row["hostname"]: (row["category"], row["reason"]) for row in report["devices"]}
        self.assertEqual(results, {"sw01": ("UPGRADED", None), "sw02": ("UPGRADED", None), "sw03": ("UPGRADED", None),
                                   "sw04": ("UPGRADED", None), "sw05": ("AT_TARGET", None),
                                   "sw06": ("SKIPPED", "UNREACHABLE_CONNECT_FAILED")}, out.getvalue())
        for switch in switches[:4]:
            self.assertEqual((switch.state / "version").read_text(), "25.02.8008")
        self.assertIn("[PHASE OS] 4 switch(es); canaries: sw02", out.getvalue(),
                      "v1 route cover: sw02 has the longest route (6077 -> 7002 -> 8008)")
        scp = [(context["host"], Path(context["path"]).name) for context in fleet.contexts if context["method"] == "scp"]
        http = [Path(context["url"]).name for context in fleet.contexts if context["method"] == "http"]
        self.assertIn("nvos-amd64-25.02.8008.bin", http, "a queue's first copy comes from the ztp-server")
        self.assertTrue(scp, "other switches relay from a holder")
        self.assertTrue(all(context["password"] == SENTINEL and context["host_keys"].strip()
                            for context in fleet.contexts if context["method"] == "scp"))
        for name in versions:
            for path in (base / "run").rglob("*"):
                if path.is_file():
                    self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)
        report_file = json.loads((base / "run" / "run-report.json").read_text())
        self.assertEqual(report_file["counts"], {"UPGRADED": 4, "AT_TARGET": 1, "SKIPPED": 1})
        self.assertEqual(fleet_engine.exit_code(report), 3)


if __name__ == "__main__":
    unittest.main()
