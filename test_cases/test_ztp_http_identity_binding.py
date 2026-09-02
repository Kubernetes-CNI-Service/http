#!/usr/bin/env python3
"""Regression tests for dual-path OOB-leaf ZTP identity correlation."""

from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "DAY0-Prepare/12-ztp-monitor.py"


def load_monitor():
    spec = importlib.util.spec_from_file_location("ztp_http_identity_monitor", MODULE_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {MODULE_PATH}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


MONITOR = load_monitor()


def pending_stages():
    return {name: MONITOR.stage() for name in MONITOR.STAGE_NAMES}


class ZtpHttpIdentityBindingTests(unittest.TestCase):
    def canonical_device(
        self, *, hostname="AIR-EXAMPLE-OOB-Leaf02", mac="020000000034",
        device_type="air", environment="air", ip="192.0.2.34",
    ):
        ssh_ips = [ip] if ip else []
        return {
            "hostname": hostname, "type": device_type,
            "environment": environment, "ip": ip, "ssh_ips": ssh_ips,
            "ssh_interfaces": {ip: "eth0"} if ip else {},
            "identity_macs": {"eth0": mac}, "mac_plain": mac,
            "candidate_identity": {ip: ("eth0", mac)} if ip else {},
            "stages": pending_stages(),
            "events": [], "issues": [],
        }

    def unbound_front_panel_identity(
        self, *, mac="0200000000c9", ip="198.51.100.201",
        epoch="2099-01-01T04:34:09+00:00", environment="air",
    ):
        return {
            "hostname": f"AIR-EXAMPLE-DISCOVERED-CUMULUS-{mac.upper()}",
            "type": "pending_eth", "environment": environment,
            "ip": ip, "ssh_ips": [ip],
            "identity_macs": {"dhcp": mac}, "mac_plain": mac,
            "unbound_identity": True, "platform_family": "cumulus",
            "lease_state": "active", "runtime_last_seen": epoch,
            "stages": pending_stages(),
            "events": [],
        }

    @staticmethod
    def apache_event(
        *, ip="198.51.100.201", mac="020000000034",
        timestamp="2099-01-01T04:34:13+00:00", method="GET", status=200,
        path=None,
    ):
        return {
            "ip": ip,
            "path": path or (
                f"/ztp/config/cumulus/latest_yaml/{mac}.yaml"
            ),
            "method": method, "status": status,
            "timestamp": timestamp, "raw": "apache-event",
        }

    @staticmethod
    def dhcp_event(
        *, ip="198.51.100.201", mac="0200000000c9",
        timestamp="2099-01-01T04:34:10+00:00", kind="DHCPACK",
    ):
        return {
            "kind": kind, "mac_plain": mac, "ip": ip,
            "timestamp": timestamp, "raw": "dhcp-event",
        }

    def test_mac_yaml_get_binds_front_panel_dhcp_to_canonical_eth0_identity(self):
        canonical = self.canonical_device()
        unbound = self.unbound_front_panel_identity()
        apache = [
            {
                "ip": "198.51.100.201", "path": "/ztp/ztp-bootstrap_oob.sh",
                "method": "GET", "status": 200,
                "timestamp": "2099-01-01T04:34:11+00:00", "raw": "bootstrap",
            },
            {
                "ip": "198.51.100.201",
                "path": (
                    "/ztp/config/cumulus/latest_yaml/"
                    "020000000034.yaml?generation=current"
                ),
                "method": "GET", "status": 200,
                "timestamp": "2099-01-01T04:34:13+00:00", "raw": "config",
            },
        ]
        dhcp = [
            {
                "kind": "DHCPDISCOVER", "mac_plain": "0200000000c9",
                "ip": "198.51.100.201",
                "timestamp": "2099-01-01T04:34:10+00:00", "raw": "discover",
            },
            {
                "kind": "DHCPACK", "mac_plain": "0200000000c9",
                "ip": "198.51.100.201",
                "timestamp": "2099-01-01T04:34:10+00:00", "raw": "ack",
            },
        ]

        claims = MONITOR.bind_apache_ztp_identities(
            [canonical, unbound], apache, dhcp, scope="air",
        )
        self.assertIs(canonical, claims["198.51.100.201"]["device"])
        self.assertEqual("0200000000c9", claims["198.51.100.201"]["holder_mac"])
        self.assertEqual("AIR-EXAMPLE-OOB-Leaf02", unbound["superseded_by_hostname"])
        self.assertEqual(["198.51.100.201"], canonical["ztp_transport_ips"])

        MONITOR.correlate_server_events(
            [canonical], dhcp, apache,
            identity_devices=[canonical, unbound],
            http_identity_claims=claims,
        )
        self.assertEqual("success", canonical["stages"]["dhcp"]["status"])
        self.assertEqual("success", canonical["stages"]["bootstrap"]["status"])
        self.assertEqual("success", canonical["stages"]["config_http"]["status"])
        self.assertIn("198.51.100.201", canonical["stages"]["dhcp"]["detail"])
        self.assertEqual(
            ["192.0.2.34"], canonical["ssh_ips"],
            "transit IP is evidence only and must not replace the final SSH address",
        )

    def test_missing_eth0_ip_uses_current_transit_without_promoting_it(self):
        canonical = self.canonical_device(
            hostname="AIR-EXAMPLE-FGT-FW", mac="020000000049", ip="",
        )
        holder = self.unbound_front_panel_identity(mac="0200000000c9")
        request = self.apache_event(mac="020000000049")
        claims = MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [request], [self.dhcp_event()], scope="air",
        )

        self.assertEqual("", canonical["ip"])
        self.assertEqual(["198.51.100.201"], canonical["ssh_ips"])
        self.assertEqual(
            "ZTP transit", canonical["ssh_interfaces"]["198.51.100.201"],
        )
        self.assertEqual(
            ("eth0", "020000000049"),
            canonical["candidate_identity"]["198.51.100.201"],
        )
        self.assertEqual(
            "0200000000c9",
            canonical["ztp_transport_holders"]["198.51.100.201"],
        )
        self.assertEqual(
            ["MANAGEMENT_VIA_ZTP_TRANSIT"],
            [issue["code"] for issue in canonical["issues"]],
        )
        self.assertEqual(
            [canonical],
            MONITOR.devices_for_switch_collection(
                [canonical], {}, identity_devices=[canonical, holder],
                http_identity_claims=claims,
            ),
        )

    def test_transit_ssh_requires_canonical_eth0_and_holder_interface_macs(self):
        canonical = self.canonical_device(
            hostname="AIR-EXAMPLE-FGT-FW", mac="020000000049", ip="",
        )
        holder = self.unbound_front_panel_identity(mac="0200000000c9")
        MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [self.apache_event(mac="020000000049")],
            [self.dhcp_event()], scope="air",
        )
        result = {
            "kind": "ok", "connected_ip": "198.51.100.201",
            "attempts": [{"ip": "198.51.100.201", "status": "success"}],
            "remote_hostname": "AIR-EXAMPLE-FGT-FW",
            "remote_eth0_mac": "02:00:00:00:00:49",
            "remote_eth1_mac": "",
            "remote_interface_macs": {
                "eth0": "020000000049", "swp2": "0200000000c9",
            },
            "boot_id": "boot-1", "boot_time": "1788148800",
            "ztp_log": "", "ztp_log_mtime": "", "ifreload_log": "",
            "failed_yaml": "", "host_key_refreshed": False,
        }
        MONITOR.analyze_switch(canonical, result)
        self.assertEqual("success", canonical["stages"]["ssh"]["status"])
        self.assertEqual(
            "ZTP transit (swp2)", canonical["ip_probe"]["connected_interface"],
        )
        self.assertEqual(
            "ZTP transit (swp2)",
            canonical["ip_probe"]["interfaces"]["198.51.100.201"],
        )

        rejected = self.canonical_device(
            hostname="AIR-EXAMPLE-FGT-FW", mac="020000000049", ip="",
        )
        MONITOR.bind_apache_ztp_identities(
            [rejected, self.unbound_front_panel_identity(mac="0200000000c9")],
            [self.apache_event(mac="020000000049")], [self.dhcp_event()],
            scope="air",
        )
        wrong_result = dict(result, remote_interface_macs={
            "eth0": "020000000049", "swp2": "0200000000aa",
        })
        MONITOR.analyze_switch(rejected, wrong_result)
        self.assertEqual("failed", rejected["stages"]["ssh"]["status"])
        self.assertIn(
            "ZTP_TRANSIT_HOLDER_MAC_MISMATCH",
            [issue["code"] for issue in rejected["issues"]],
        )

    def test_failed_or_ambiguous_mac_yaml_request_does_not_claim_identity(self):
        first = self.canonical_device()
        second = self.canonical_device()
        second["hostname"] = "AIR-EXAMPLE-Duplicate-Leaf02"
        failed = [{
            "ip": "198.51.100.201",
            "path": "/ztp/config/cumulus/latest_yaml/020000000034.yaml",
            "method": "GET", "status": 404,
            "timestamp": "2099-01-01T04:34:13+00:00", "raw": "missing",
        }]
        holder = self.unbound_front_panel_identity()
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [first, holder], failed, scope="air",
        ))
        successful = [dict(failed[0], status=200)]
        self.assertEqual(
            {}, MONITOR.bind_apache_ztp_identities(
                [first, second, holder], successful, scope="air",
            ),
        )

    def test_binding_rejects_old_epoch_release_and_address_reassignment(self):
        canonical = self.canonical_device()
        old_get = self.apache_event(
            timestamp="2099-01-01T04:34:13+00:00",
        )
        reassigned_holder = self.unbound_front_panel_identity(
            mac="0200000000aa", epoch="2099-01-01T05:00:00+00:00",
        )
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [canonical, reassigned_holder], [old_get], scope="air",
        ))

        current_holder = self.unbound_front_panel_identity()
        current_get = self.apache_event()
        release = self.dhcp_event(
            timestamp="2099-01-01T04:34:14+00:00", kind="LEASE_RELEASE",
        )
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [canonical, current_holder], [current_get], [release], scope="air",
        ))

        later_holder = self.dhcp_event(
            mac="0200000000aa", timestamp="2099-01-01T04:34:15+00:00",
        )
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [canonical, current_holder], [current_get], [later_holder],
            scope="air",
        ))

    def test_binding_is_scope_get_200_and_exact_path_only(self):
        canonical = self.canonical_device()
        holder = self.unbound_front_panel_identity()
        valid = self.apache_event()
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [valid], scope="prod",
        ))
        self.assertIn("198.51.100.201", MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [valid], scope="air",
        ))

        for event in (
            self.apache_event(method="HEAD"),
            self.apache_event(status=302),
            self.apache_event(path="/ztp/latest_yaml/020000000034.yaml"),
            self.apache_event(
                path="/ztp/config/nvos/latest_yaml/020000000034.yaml",
            ),
        ):
            with self.subTest(method=event["method"], status=event["status"], path=event["path"]):
                fresh_canonical = self.canonical_device()
                fresh_holder = self.unbound_front_panel_identity()
                self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
                    [fresh_canonical, fresh_holder], [event], scope="air",
                ))

    def test_conflicting_mac_gets_in_one_epoch_do_not_claim(self):
        canonical = self.canonical_device()
        holder = self.unbound_front_panel_identity()
        requests = [
            self.apache_event(),
            self.apache_event(
                mac="0200000000aa", timestamp="2099-01-01T04:34:14+00:00",
            ),
        ]
        self.assertEqual({}, MONITOR.bind_apache_ztp_identities(
            [canonical, holder], requests, scope="air",
        ))

    def test_claim_selects_canonical_final_ip_even_when_air_prod_share_it(self):
        canonical = self.canonical_device()
        production = self.canonical_device(
            hostname="EXAMPLE-OOB-Leaf02", mac="0200000000aa",
            device_type="eth", environment="production",
        )
        holder = self.unbound_front_panel_identity()
        claims = MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [self.apache_event()],
            [self.dhcp_event()], scope="air",
        )
        selected = MONITOR.devices_for_switch_collection(
            [canonical], {}, identity_devices=[canonical, production, holder],
            http_identity_claims=claims,
        )
        self.assertEqual([canonical], selected)
        self.assertEqual(["192.0.2.34"], canonical["ssh_ips"])
        self.assertNotIn("198.51.100.201", canonical["ssh_ips"])
        self.assertEqual(
            ("eth0", "020000000034"),
            canonical["candidate_identity"]["192.0.2.34"],
        )

    def test_correlation_keeps_only_holder_epoch_events(self):
        canonical = self.canonical_device()
        holder = self.unbound_front_panel_identity()
        config_get = self.apache_event()
        claims = MONITOR.bind_apache_ztp_identities(
            [canonical, holder], [config_get], [self.dhcp_event()], scope="air",
        )
        dhcp = [
            self.dhcp_event(
                mac="0200000000aa", timestamp="2099-01-01T04:34:08+00:00",
            ),
            self.dhcp_event(),
            self.dhcp_event(
                mac="0200000000bb", timestamp="2099-01-01T04:34:15+00:00",
            ),
        ]
        apache = [
            {
                "ip": "198.51.100.201", "path": "/ztp/ztp-bootstrap_oob.sh",
                "method": "GET", "status": 200,
                "timestamp": "2099-01-01T04:34:08+00:00", "raw": "old",
            },
            {
                "ip": "198.51.100.201", "path": "/ztp/ztp-bootstrap_oob.sh",
                "method": "GET", "status": 200,
                "timestamp": "2099-01-01T04:34:11+00:00", "raw": "current",
            },
            config_get,
        ]
        MONITOR.correlate_server_events(
            [canonical], dhcp, apache,
            identity_devices=[canonical, holder],
            http_identity_claims=claims,
        )
        claimed_dhcp = [
            event for event in canonical["events"] if event["source"] == "dhcp"
        ]
        claimed_http = [
            event for event in canonical["events"] if event["source"] == "apache"
        ]
        self.assertEqual(["0200000000c9"], [
            event["mac_plain"] for event in claimed_dhcp
        ])
        self.assertEqual(["current", "apache-event"], [
            event["raw"] for event in claimed_http
        ])
        self.assertEqual("success", canonical["stages"]["dhcp"]["status"])
        self.assertEqual("success", canonical["stages"]["bootstrap"]["status"])
        self.assertEqual("success", canonical["stages"]["config_http"]["status"])


if __name__ == "__main__":
    unittest.main()
