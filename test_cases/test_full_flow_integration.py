#!/usr/bin/env python3
"""Cross-module integration scenarios built from real ISC/Apache log formats."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    sys.path.insert(0, str(ROOT))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


DHCP_RUNTIME = load_module(
    "full_flow_dhcp_runtime", ROOT / "ztp/dhcp_runtime_inventory.py",
)
MONITOR = load_module(
    "full_flow_ztp_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)


class FullFlowIntegrationTests(unittest.TestCase):
    @staticmethod
    def write_inventory(root: Path) -> Path:
        inventory = root / "02-devices_config.csv"
        inventory.write_text(
            "hostname,type,template,eth0_ip,netmask,eth0_mac,eth1_ip,eth1_mac\n"
            "AIR-EXAMPLE-OOB-Leaf02,air,leaf,192.0.2.34,25,"
            "02:00:00:00:00:34,,\n",
            encoding="utf-8",
        )
        return inventory

    @staticmethod
    def runtime_log(*, vendor_text: str) -> str:
        # ISC binary-to-ascii does not zero-pad MAC octets.  Keep the exact
        # variable-width form observed in the user's Ubuntu dhcpd log.
        vendor_hex = ":".join(f"{byte:x}" for byte in vendor_text.encode("utf-8"))
        return "\n".join((
            "2099-01-01T04:34:09+00:00 host dhcpd[1]: "
            "ZTP_DHCP_EVENT_V1 event=packet msg=1 mac=2:0:0:0:0:c9 "
            "ip=198.51.100.201 known=0 lease_state=observed "
            f"vendor60_hex={vendor_hex} client61_hex=- user77_hex=-",
            "2099-01-01T04:34:10+00:00 host dhcpd[1]: "
            "ZTP_DHCP_EVENT_V1 event=commit mac=2:0:0:0:0:c9 "
            "ip=198.51.100.201 known=0 lease_state=active "
            f"vendor60_hex={vendor_hex} client61_hex=- user77_hex=-",
        ))

    @staticmethod
    def dora_log() -> str:
        return "\n".join((
            "2099-01-01T04:34:09+00:00 dhcpd[1]: DHCPDISCOVER from "
            "02:00:00:00:00:c9 via swp2",
            "2099-01-01T04:34:09+00:00 dhcpd[1]: DHCPOFFER on "
            "198.51.100.201 to 02:00:00:00:00:c9 via swp2",
            "2099-01-01T04:34:10+00:00 dhcpd[1]: DHCPREQUEST for "
            "198.51.100.201 from 02:00:00:00:00:c9 via swp2",
            "2099-01-01T04:34:10+00:00 dhcpd[1]: DHCPACK on "
            "198.51.100.201 to 02:00:00:00:00:c9 via swp2",
        ))

    @staticmethod
    def apache_log(path: str) -> str:
        return (
            "198.51.100.201 - - [01/Jan/2099:04:34:13 +0000] "
            f'"GET {path} HTTP/1.1" 200 1234 "-" "curl"'
        )

    def test_front_panel_dhcp_epoch_binds_only_to_requested_eth0_yaml(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = self.write_inventory(Path(directory))
            runtime = self.runtime_log(vendor_text="cumulus-linux  x86_64")
            discovered = DHCP_RUNTIME.unknown_dhcp_devices(
                journal_text=runtime, inventory_path=inventory,
            )
            self.assertEqual(1, len(discovered))
            self.assertEqual("cumulus", discovered[0]["platform"])
            self.assertEqual("0200000000c9", discovered[0]["mac_plain"])
            self.assertEqual("198.51.100.201", discovered[0]["ip"])

            canonical = MONITOR.read_devices(
                inventory, scope="air", dhcp_leases=None,
            )
            holders = MONITOR.runtime_unknown_devices(
                inventory, runtime, scope="air", dhcp_leases=None,
            )
            self.assertEqual(1, len(canonical))
            self.assertEqual(1, len(holders))
            self.assertTrue(holders[0]["unbound_identity"])

            dhcp_events = MONITOR.parse_dhcp(self.dora_log())
            apache_events = MONITOR.parse_apache(self.apache_log(
                "/ztp/config/cumulus/latest_yaml/020000000034.yaml",
            ))
            claims = MONITOR.bind_apache_ztp_identities(
                canonical + holders, apache_events, dhcp_events, scope="air",
            )
            self.assertEqual({"198.51.100.201"}, set(claims))
            claim = claims["198.51.100.201"]
            self.assertEqual("AIR-EXAMPLE-OOB-Leaf02", claim["device"]["hostname"])
            self.assertEqual("0200000000c9", claim["holder_mac"])
            self.assertEqual(
                "2099-01-01T04:34:10+00:00", claim["epoch_started_at"],
            )

            owners = MONITOR.correlate_server_events(
                canonical,
                dhcp_events,
                apache_events,
                identity_devices=canonical + holders,
                http_identity_claims=claims,
            )
            self.assertIs(holders[0], owners["198.51.100.201"])
            device = canonical[0]
            self.assertTrue(any(
                event.get("source") == "dhcp" and event.get("kind") == "DHCPACK"
                for event in device["events"]
            ))
            self.assertTrue(any(
                event.get("source") == "apache"
                and event.get("path", "").endswith("020000000034.yaml")
                for event in device["events"]
            ))
            self.assertEqual("success", device["stages"]["dhcp"]["status"])
            self.assertEqual(
                "success", device["stages"]["config_http"]["status"],
            )
            # The transit address is evidence only.  SSH remains constrained
            # to the inventory's canonical management address and eth0 MAC.
            self.assertEqual(["192.0.2.34"], device["ssh_ips"])
            self.assertEqual(
                ("eth0", "020000000034"),
                device["candidate_identity"]["192.0.2.34"],
            )

    def test_unknown_platform_lease_cannot_claim_a_managed_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            inventory = self.write_inventory(Path(directory))
            runtime = self.runtime_log(vendor_text="unknown-box")
            holders = MONITOR.runtime_unknown_devices(
                inventory, runtime, scope="air", dhcp_leases=None,
            )
            self.assertEqual(1, len(holders))
            holder = holders[0]
            self.assertEqual("unknown", holder["platform_family"])
            self.assertFalse(holder["managed_ztp"])
            self.assertFalse(holder["ssh_collect_enabled"])
            self.assertEqual([], holder["ssh_ips"])

            canonical = MONITOR.read_devices(
                inventory, scope="air", dhcp_leases=None,
            )
            # Even a forged successful GET is not trusted when the current
            # DHCP holder has no Cumulus/NVOS fingerprint.
            apache_events = MONITOR.parse_apache(self.apache_log(
                "/ztp/config/cumulus/latest_yaml/020000000034.yaml",
            ))
            claims = MONITOR.bind_apache_ztp_identities(
                canonical + holders,
                apache_events,
                MONITOR.parse_dhcp(self.dora_log()),
                scope="air",
            )
            self.assertEqual({}, claims)


if __name__ == "__main__":
    unittest.main()
