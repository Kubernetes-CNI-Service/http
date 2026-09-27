"""Duplicate management identities must fail in both Day-0 CSV gates."""

from __future__ import annotations

import csv
import inspect
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("jump_identity_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
LOAD = load_script("jump_identity_load", ROOT / "DAY0-Prepare/11-load.py")

HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "vrf_default", "vlan_id", "svi_ip", "netmask", "vrr_ip", "vrr_mac",
    "vlan_ports", "bgp_asn", "bgp_ports", "bond_ports", "bond_type",
    "bond_mac", "peerlink_ports", "vrl", "evpn_vrf", "evpn_l3vni",
    "evpn_l3vlan", "dhcp_relay", "evpn_l2vni", "evpn_l2vlan", "svi_ip",
    "netmask", "vrr_ip", "vrr_mac", "vlan_ports",
)


def row(hostname: str, kind: str, address: str, mac: str = "NA") -> list[str]:
    values = ["NA"] * len(HEADER)
    values[:7] = [
        hostname, kind, "NA", address, "24", "192.0.2.1", mac,
    ]
    return values


class EthJumpDuplicateIdentityTests(unittest.TestCase):
    _MAC_EMIT_TEXT = 'e(row_n, hn, f"eth0_mac 重复（首次行{seen_eth0_mac[key]}）")'
    _MAC_REPORT_SITES = (
        "jump_mac_report", "server_mac_report", "air_mac_report",
        "common_mac_report",
    )
    _SETUP_SITES = {
        "census": "previous = seen_eth0_addr.setdefault(eth0_addr, [])",
        "guard_a": "and not is_jump",
        "guard_b": 'and previous[0][2] != "eth_jump"',
        "duplicate_report": 'f"eth0_ip 重复（{eth0_addr}，首次行{previous[0][0]}）",',
        "jump_branch": "if is_jump:",
    }

    def _trace_setup_sites(self, rows: list[list[str]]):
        """Identify executed guards by source text and the active function frame.

        This deliberately resolves lines anew instead of pinning stale numbers.
        A bypassed census and a suppressed duplicate report must fail at
        different named sites, even when both lose the same error message.
        """
        source, first_line = inspect.getsourcelines(SETUP._validate_eth_csv)
        site_lines = {}
        for name, text in self._SETUP_SITES.items():
            matches = [
                first_line + offset for offset, line in enumerate(source)
                if line.strip() == text
            ]
            self.assertEqual(
                1, len(matches),
                f"_validate_eth_csv::{name} source site {text!r}",
            )
            site_lines[matches[0]] = name
        mac_lines = [
            first_line + offset for offset, line in enumerate(source)
            if line.strip() == self._MAC_EMIT_TEXT
        ]
        self.assertEqual(
            4, len(mac_lines),
            f"_validate_eth_csv MAC emit sites {self._MAC_EMIT_TEXT!r}",
        )
        for name, line in zip(self._MAC_REPORT_SITES, mac_lines):
            site_lines[line] = name
        # Four emitters have identical text and one deepest function frame;
        # their enclosing branch anchors distinguish the actual emit site.
        def unique_line(text):
            matches = [
                first_line + offset for offset, line in enumerate(source)
                if line.strip() == text
            ]
            self.assertEqual(1, len(matches), text)
            return matches[0]

        self.assertLess(
            unique_line("if is_jump:"), mac_lines[0],
        )
        self.assertLess(mac_lines[0], unique_line("if is_server:"))
        self.assertLess(unique_line("if is_server:"), mac_lines[1])
        self.assertLess(mac_lines[1], unique_line("if is_air:"))
        self.assertLess(unique_line("if is_air:"), mac_lines[2])
        self.assertLess(mac_lines[2], unique_line("# eth0_mac（共有）"))
        self.assertLess(unique_line("# eth0_mac（共有）"), mac_lines[3])
        self.assertLess(
            next(line for line, name in site_lines.items() if name == "census"),
            next(line for line, name in site_lines.items() if name == "jump_branch"),
            "_validate_eth_csv::census must precede the jump branch",
        )

        events = {name: [] for name in (*self._SETUP_SITES,
                                       *self._MAC_REPORT_SITES)}
        code = SETUP._validate_eth_csv.__code__

        def trace(frame, event, _arg):
            if event == "line" and frame.f_code is code:
                name = site_lines.get(frame.f_lineno)
                if name is not None:
                    # At a line event, frame is the deepest executing frame.
                    events[name].append((frame.f_code.co_name,
                                         frame.f_locals.get("row_n"),
                                         frame.f_locals.get("row_type")))
            return trace

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows((HEADER, *rows))
            previous_trace = sys.gettrace()
            try:
                sys.settrace(trace)
                errors, _warnings = SETUP._validate_eth_csv(str(path))
            finally:
                sys.settrace(previous_trace)
        return errors, events

    def _check(self, rows: list[list[str]], duplicate: str | None) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "02-devices_config.csv"
            with path.open("w", newline="", encoding="utf-8") as stream:
                csv.writer(stream).writerows((HEADER, *rows))
            errors, warnings = SETUP._validate_eth_csv(str(path))
            if duplicate is None:
                self.assertEqual([], errors)
                self.assertEqual([], warnings)
                self.assertEqual(
                    {item[1] for item in rows},
                    set(LOAD.load_device_types(path)),
                )
            else:
                with self.subTest(gate="setup"):
                    self.assertTrue(
                        any(duplicate in error for error in errors), errors,
                    )
                with self.subTest(gate="load"):
                    with self.assertRaisesRegex(LOAD.LoadError, duplicate):
                        LOAD.load_device_types(path)

    def test_distinct_jump_and_server_identities_are_admitted(self):
        self._check([
            row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10",
                "02:00:00:00:00:10"),
            row("EXAMPLE-SERVER01", "server", "198.51.100.20/24",
                "02:00:00:00:00:20"),
        ], None)

    def test_matching_production_and_air_may_share_ip_in_both_gates(self):
        production = row("EXAMPLE-SW01", "eth", "192.0.2.10",
                         "02:00:00:00:00:11")
        production[2] = "oob-leaf"  # Production config intent is explicit.
        air = row("AIR-EXAMPLE-SW01", "air", "192.0.2.10",
                  "02:00:00:00:00:22")
        for rows in ([production, air], [air, production]):
            with self.subTest(first=rows[0][1]):
                with mock.patch.object(
                    SETUP, "_is_matching_production_air_pair",
                    wraps=SETUP._is_matching_production_air_pair,
                ) as pair_probe:
                    self._check(rows, None)
                self.assertEqual(1, pair_probe.call_count)

    def test_two_jump_rows_cannot_share_management_ip(self):
        self._check([
            row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10"),
            row("EXAMPLE-JUMP02", "eth_jump", "192.0.2.10"),
        ], "eth0_ip 重复")

    def test_jump_and_server_cannot_share_normalized_ip_in_either_order(self):
        jump = row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10")
        server = row("EXAMPLE-SERVER01", "server", "192.0.2.10/24")
        for rows in ([jump, server], [server, jump]):
            with self.subTest(first=rows[0][1]):
                self._check(rows, "eth0_ip 重复")

    def test_air_matching_name_exception_never_admits_jump(self):
        jump = row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10")
        air = row("AIR-EXAMPLE-JUMP01", "air", "192.0.2.10",
                  "02:00:00:00:00:20")
        for rows in ([jump, air], [air, jump]):
            with self.subTest(first=rows[0][1]):
                self._check(rows, "eth0_ip 重复")
                # Simulate a future widened production-type whitelist.  The
                # two in-census guards must still reject both row orders.
                with mock.patch.object(
                    SETUP, "_is_matching_production_air_pair", return_value=True,
                ) as pair_probe:
                    self._check(rows, "eth0_ip 重复")
                self.assertEqual(
                    0, pair_probe.call_count,
                    "jump exclusion must short-circuit before pair matching",
                )

    def test_census_and_report_sites_distinguish_bypass_from_suppression(self):
        jump = row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10")
        server = row("EXAMPLE-SERVER01", "server", "192.0.2.10/24")
        for rows in ([jump, server], [server, jump]):
            with self.subTest(first=rows[0][1]):
                errors, events = self._trace_setup_sites(rows)
                expected_census = [
                    ("_validate_eth_csv", row_number, item[1])
                    for row_number, item in enumerate(rows, start=2)
                ]
                self.assertEqual(
                    expected_census, events["census"],
                    "_validate_eth_csv::census was bypassed (M3)",
                )
                self.assertEqual(
                    [("_validate_eth_csv", 3, rows[1][1])],
                    events["duplicate_report"],
                    "_validate_eth_csv::duplicate_report was suppressed (M4)",
                )
                self.assertTrue(
                    any("eth0_ip 重复" in error for error in errors), errors,
                )

    def test_supplied_jump_mac_cannot_duplicate_other_row(self):
        jump = row("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10",
                   "02:00:00:00:00:AA")
        server = row("EXAMPLE-SERVER01", "server", "192.0.2.20",
                     "02-00-00-00-00-aa")
        air = row("AIR-EXAMPLE-JUMP01", "air", "192.0.2.30",
                  "02-00-00-00-00-aa")
        production = row("EXAMPLE-SW01", "eth", "192.0.2.40",
                         "02-00-00-00-00-aa")
        production[2] = "oob-leaf"
        cases = (
            ([jump, server], "server_mac_report"),
            ([server, jump], "jump_mac_report"),
            ([jump, air], "air_mac_report"),
            ([jump, production], "common_mac_report"),
        )
        for rows, expected_site in cases:
            with self.subTest(first=rows[0][1], second=rows[1][1]):
                self._check(rows, "eth0_mac 重复")
                _errors, events = self._trace_setup_sites(rows)
                for site in self._MAC_REPORT_SITES:
                    expected = (
                        [("_validate_eth_csv", 3, rows[1][1])]
                        if site == expected_site else []
                    )
                    self.assertEqual(
                        expected, events[site],
                        f"_validate_eth_csv::{site} emit-site mismatch",
                    )


if __name__ == "__main__":
    unittest.main()
