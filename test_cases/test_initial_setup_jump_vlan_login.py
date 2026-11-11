"""Direct: an eth_jump's login address comes from eth0, else from its single VLAN SVI (v15).

What: `load_devices` reads an eth_jump row and chooses its login address: eth0 first; when
eth0 is empty, the single `vlan_id`/`svi_ip` group; the SVI is transport metadata only (never
desired eth0 state, never an IB neighbor interface or VRF); multiple VLAN candidates, invalid
VLAN/mask/address values and duplicate login addresses are refused; the read-only jump transport
logs in at that address and checks the hostname.

Expectation sources (not derived from the implementation):
- v15 RUNBOOK.md:22 ("current only supports the original eth0 entry or the single SVI fallback
  when eth0 is empty; not the I20 multi-address retry"); V15-OOB-SPINE.md:23-24.
- v15 delivered test `initial-setup-test-cases/test_desktop_initial_setup.py::EthJumpVlanLoginTests`
  (:281-404; file sha256 bound by HANDOFF-SHA256SUMS:27).
- Guide v3.1.3 section 10 row T13 (:2299): the inventory is admitted without a login address and
  remote transport refuses it before any I/O; multiple VLAN candidates are refused at read
  ("multiple VLAN login addresses"); the duplicate check skips empty addresses.  The v15 test
  `test_vrr_and_evpn_addresses_are_not_svi_login_fallbacks` is rewritten as T13 says, same intent.
- Guide O3 (:256) and O14 (:267, "install_oob_management_key disappears with O3"): the v15
  sub-assertion that an SVI-only jump refuses `install_oob_management_key` is replaced by the
  retirement itself (no OOB key-install function exists).

Fixture rewrites (public audit, guide :835): synthetic host names `example-ib001`,
`example-oob-leaf01`; documentation IPv4 ranges only; MAC 02:00:00:00:00:10; the multicast case
is built at run time from its integer value.  No device or network I/O: the transport is
replaced in every test that reaches it.
"""
from __future__ import annotations

import csv
import io
import ipaddress
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_jump_vlan_login", INITIAL)

IB = "example-ib001"
JUMP = "example-oob-leaf01"
OTHER_JUMP = "example-oob-leaf02"
# First group address of the IPv4 multicast block (RFC 5771); a protocol constant, not a host.
MULTICAST = str(ipaddress.IPv4Address(0xE0000001))


class JumpVlanLoginTests(unittest.TestCase):
    HEADER = [
        "hostname", "type", "eth0_ip", "netmask", "eth0_gw", "eth0_mac",
        "eth1_ip", "netmask", "eth1_gw", "eth1_mac",
        "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
        "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
        "evpn_vrf", "evpn_l2vlan", "svi_ip", "netmask", "vlan_ports",
    ]

    def inventory(self, *, eth0="", vlan1="1000", svi1="198.51.100.10",
                  mask1="24", vrr1="", vlan2="", svi2="", evpn_svi="",
                  extra_jump=None):
        ib = [IB, "ib", "192.0.2.10", "24", "192.0.2.1",
              "02:00:00:00:00:10", "", "", "", ""] + [""] * 17
        jump = [JUMP, "eth_jump", eth0, "", "", "", "", "", "", "",
                vlan1, svi1, mask1, vrr1, "", "", vlan2, svi2, "24", "", "", "",
                "Vrf_2", "2000", evpn_svi, "24", ""]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "ib.csv"
            with source.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow(self.HEADER)
                writer.writerows([ib, jump])
                if extra_jump is not None:
                    other = jump.copy()
                    other[0] = OTHER_JUMP
                    other[11] = extra_jump
                    writer.writerow(other)
            before = source.read_bytes()
            devices = app.load_devices(source)
            self.assertEqual(source.read_bytes(), before)
        return devices

    # v15 EthJumpVlanLoginTests.test_svi_is_transport_only_and_does_not_become_eth0_configuration
    # (test_desktop_initial_setup.py:314)
    def test_svi_is_transport_only_and_does_not_become_eth0_configuration(self):
        ib, ethernet = self.inventory(vrr1="198.51.100.254")
        jump = ethernet[JUMP]
        self.assertEqual(jump.login_ip, "198.51.100.10")
        self.assertEqual(jump.login_interface, "vlan1000")
        self.assertEqual(jump.eth0_prefix, "")
        self.assertEqual(jump.eth0_mac, "")
        self.assertEqual(set(ib), {IB})
        self.assertEqual(app.Device(**app.device_to_dict(jump)), jump)
        with self.assertRaisesRegex(app.SetupError, "type=ib"):
            app.desired_commands(jump)
        # v15 also asserted that install_oob_management_key refuses this jump ("not authorized")
        # without any transport call.  Guide O3 (:256) retired --auto and O14 (:267) records that
        # install_oob_management_key disappears with it: no OOB key-install path exists at all.
        self.assertFalse(hasattr(app, "install_oob_management_key"))

    # v15 EthJumpVlanLoginTests.test_existing_eth0_keeps_priority_without_probing_other_addresses
    # (test_desktop_initial_setup.py:330)
    def test_existing_eth0_keeps_priority_without_probing_other_addresses(self):
        _, ethernet = self.inventory(eth0="203.0.113.10", vlan2="2000", svi2="198.51.100.11")
        self.assertEqual(ethernet[JUMP].login_ip, "203.0.113.10")
        self.assertEqual(ethernet[JUMP].login_interface, "eth0")

    # v15 EthJumpVlanLoginTests.test_second_vlan_block_and_na_eth0_are_supported
    # (test_desktop_initial_setup.py:335)
    def test_second_vlan_block_and_na_eth0_are_supported(self):
        _, ethernet = self.inventory(eth0="NA", vlan1="NA", svi1="NA",
                                     vlan2="2000", svi2="203.0.113.10")
        self.assertEqual(ethernet[JUMP].login_ip, "203.0.113.10")
        self.assertEqual(ethernet[JUMP].login_interface, "vlan2000")

    # v15 EthJumpVlanLoginTests.test_svi_accepts_cidr_or_bare_ip_without_mask
    # (test_desktop_initial_setup.py:341)
    def test_svi_accepts_cidr_or_bare_ip_without_mask(self):
        for address in ("198.51.100.10/24", "198.51.100.10"):
            with self.subTest(address=address):
                _, ethernet = self.inventory(svi1=address, mask1="")
                self.assertEqual(ethernet[JUMP].login_ip, "198.51.100.10")

    # v15 EthJumpVlanLoginTests.test_multiple_candidates_are_rejected_instead_of_choosing_first
    # (test_desktop_initial_setup.py:347); guide T13 (:2299) keeps this refusal at read.
    def test_multiple_candidates_are_rejected_instead_of_choosing_first(self):
        with self.assertRaisesRegex(app.SetupError, "multiple.*VLAN.*login"):
            self.inventory(vlan2="2000", svi2="203.0.113.10")

    # v15 EthJumpVlanLoginTests.test_invalid_svi_vlan_mask_and_nonhost_addresses_are_rejected
    # (test_desktop_initial_setup.py:351)
    def test_invalid_svi_vlan_mask_and_nonhost_addresses_are_rejected(self):
        for fields in (
            {"vlan1": "1000-1002"}, {"vlan1": "4095"}, {"vlan1": "0"},
            {"vlan1": ""}, {"svi1": "not-an-ip"}, {"svi1": "198.51.100.0"},
            {"svi1": "198.51.100.10/99"}, {"mask1": "invalid"},
            {"svi1": "0.0.0.0"}, {"svi1": MULTICAST},
        ):
            with self.subTest(fields=fields), self.assertRaises(app.SetupError):
                self.inventory(**fields)

    # v15 EthJumpVlanLoginTests.test_vrr_and_evpn_addresses_are_not_svi_login_fallbacks
    # (test_desktop_initial_setup.py:361), rewritten per guide T13 (:2299): "VRR and EVPN
    # addresses are not SVI fallbacks: login_ip is empty, refused before remote transport".
    def test_vrr_and_evpn_addresses_are_not_svi_login_fallbacks(self):
        _, ethernet = self.inventory(svi1="NA", vrr1="198.51.100.254", evpn_svi="203.0.113.10")
        jump = ethernet[JUMP]
        self.assertEqual(jump.login_ip, "")
        with patch.object(app, "interactive_run") as run, redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(app.SetupError, "login address"):
                app.collect_ethernet_interfaces(jump, "cumulus", "", 10)
            run.assert_not_called()

    # v15 EthJumpVlanLoginTests.test_duplicate_jump_endpoint_and_ib_address_are_rejected
    # (test_desktop_initial_setup.py:365)
    def test_duplicate_jump_endpoint_and_ib_address_are_rejected(self):
        with self.assertRaisesRegex(app.SetupError, "duplicate.*login address"):
            self.inventory(extra_jump="198.51.100.10")
        with self.assertRaisesRegex(app.SetupError, "duplicate.*login address"):
            self.inventory(svi1="192.0.2.10")

    # v15 EthJumpVlanLoginTests.test_vlan_login_builds_readonly_jump_transport_and_checks_hostname
    # (test_desktop_initial_setup.py:371)
    def test_vlan_login_builds_readonly_jump_transport_and_checks_hostname(self):
        ib, ethernet = self.inventory()
        targets = app.build_targets(
            [app.Link(IB, "eth0", JUMP, "swp1")], ib, ethernet)
        self.assertEqual(len(targets), 1)
        self.assertEqual(targets[0].ib.dev_type, "ib")
        for hostname, accepted in ((JUMP, True), ("example-wrong-leaf", False)):
            with self.subTest(hostname=hostname), patch.object(app, "interactive_run", side_effect=[
                app.SessionResult(hostname + "\n", 0),
                app.SessionResult("swp1 up up\n", 0),
            ]) as run, patch.object(app, "log"):
                if accepted:
                    app.collect_ethernet_interfaces(targets[0].ethernet, "cumulus", "", 10)
                else:
                    with self.assertRaisesRegex(app.SetupError, "identity mismatch"):
                        app.collect_ethernet_interfaces(targets[0].ethernet, "cumulus", "", 10)
                for call in run.call_args_list:
                    argv = call.args[0]
                    self.assertIn("cumulus@198.51.100.10", argv)
                    self.assertNotIn("nv set", str(argv))
                    self.assertNotIn("authorized_keys", str(argv))
                    self.assertNotIn(".bashrc", str(argv))
                    self.assertIn("StrictHostKeyChecking=accept-new", argv)

    # v15 EthJumpVlanLoginTests.test_jump_login_vlan_does_not_override_ib_neighbor_interface_or_vrf
    # (test_desktop_initial_setup.py:395)
    def test_jump_login_vlan_does_not_override_ib_neighbor_interface_or_vrf(self):
        ib, ethernet = self.inventory()
        target = app.Target(ib[IB], ethernet[JUMP], "swp1", "eth0")
        neighbor = app.Neighbor("fe80::10", "vlan2000", "02:00:00:00:00:10", "IB_VRF")
        argv = app.nested_ssh_command(target, neighbor, "cumulus", "admin", 10,
                                      ["nv", "show", "system", "ztp"], marker="ab" * 16)
        self.assertIn("cumulus@198.51.100.10", argv)
        self.assertIn("vlan2000", argv[-1])
        self.assertIn("IB_VRF", argv[-1])
        self.assertNotIn("vlan1000", argv[-1])


if __name__ == "__main__":
    unittest.main()
