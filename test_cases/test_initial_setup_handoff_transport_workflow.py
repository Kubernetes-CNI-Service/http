#!/usr/bin/env python3
"""PUBLIC real-reader data handoff into canonical initial-setup transport.
No full LOAD/SETUP CLI, device, real SSH, hash backend, or automatic manual helper.
"""
from __future__ import annotations
import csv
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("initial_handoff_workflow_load", ROOT / "DAY0-Prepare/11-load.py")
SETUP = load_script("initial_handoff_workflow_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
INITIAL = load_script("initial_handoff_workflow_initial",
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

DEVICE_HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)

def public_rows(*, login_ip=""):
    ib = [""] * 37
    ib[:7] = ["EXAMPLE-IB01", "ib", "NA", "198.51.100.2", "24",
              "198.51.100.1", "02:00:00:00:00:02"]
    transit = [""] * 37
    transit[:4] = ["EXAMPLE-JUMP01", "eth_jump", "", login_ip]
    return ib, transit

def write_public_inventory(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        csv.writer(stream).writerows((DEVICE_HEADER, *rows))

class InitialHandoffRealReaderTransportWorkflowTests(unittest.TestCase):
    def test_blank_inventory_survives_three_readers_but_remote_connection_refuses(self):
        self.assertEqual(37, len(DEVICE_HEADER))
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            rows = public_rows()
            self.assertEqual([37, 37], [len(row) for row in rows])
            write_public_inventory(path, rows)
            self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            ib, transit = INITIAL.load_devices(path)
            self.assertEqual({"example-ib01"}, set(ib))
            self.assertEqual({"example-jump01"}, set(transit))
            device = transit["example-jump01"]
            self.assertEqual("", device.login_ip)
            with patch.object(INITIAL, "interactive_run") as external:
                with self.assertRaisesRegex(INITIAL.SetupError, "login address"):
                    INITIAL.run_on_ethernet(device, "PUBLIC-user", "PUBLIC-ONLY",
                                            ["hostname"], 5)
            external.assert_not_called()
            self.assertEqual(["hostname"], INITIAL.outer_ssh_command(
                device, "PUBLIC-user", ["hostname"], 5, local=True))

    def test_supplied_invalid_metadata_is_rejected_by_all_three_before_dispatch(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            write_public_inventory(path, public_rows(login_ip="999.0.2.1"))
            with patch.object(INITIAL, "interactive_run") as external:
                with self.subTest(reader="LOAD"):
                    with self.assertRaises(LOAD.LoadError) as caught:
                        LOAD.load_device_types(path)
                    self.assertIn("eth0_ip", str(caught.exception))
                    self.assertIn("999.0.2.1", str(caught.exception))
                with self.subTest(reader="SETUP"):
                    errors, _warnings = SETUP._validate_eth_csv(str(path))
                    self.assertTrue(any("eth0_ip" in error and "999.0.2.1" in error
                                        for error in errors), errors)
                with self.subTest(reader="INITIAL"):
                    with self.assertRaises(INITIAL.SetupError) as caught:
                        INITIAL.load_devices(path)
                    self.assertIn("eth0_ip", str(caught.exception))
                    self.assertIn("999.0.2.1", str(caught.exception))
            external.assert_not_called()

    def test_qualified_inventory_reaches_real_carrier_and_cleans_only_prompt_lines(self):
        with tempfile.TemporaryDirectory() as name:
            path = Path(name) / "02-devices_config.csv"
            write_public_inventory(path, public_rows(login_ip="198.51.100.10"))
            self.assertEqual(frozenset({"ib", "eth_jump"}), LOAD.load_device_types(path))
            self.assertEqual(([], []), SETUP._validate_eth_csv(str(path)))
            ib, transit = INITIAL.load_devices(path)
            self.assertEqual({"example-ib01"}, set(ib))
            device = transit["example-jump01"]
            self.assertEqual("198.51.100.10", device.login_ip)
            raw = "PUBLIC-user@198.51.100.10's password:\nPUBLIC-JUMP01\n"
            with patch.object(INITIAL, "interactive_run",
                              return_value=INITIAL.SessionResult(raw, 0)) as external:
                actual = INITIAL.run_on_ethernet(
                    device, "PUBLIC-user", "PUBLIC-ONLY-NOT-A-CREDENTIAL",
                    ["hostname"], 5)
            external.assert_called_once()
            self.assertEqual("PUBLIC-JUMP01\n", actual)
            dispatched = external.call_args.args[0]
            self.assertEqual("ssh", dispatched[0])
            self.assertEqual("PUBLIC-user@198.51.100.10", dispatched[-2])
            self.assertEqual(
                "sh -c 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec hostname'",
                dispatched[-1],
            )
            self.assertIn("ControlMaster=no", dispatched)
            self.assertIn("ControlPath=none", dispatched)


if __name__ == "__main__":
    unittest.main()
