"""Independent closed NVOS argv literals; no transport, process or device call."""
from __future__ import annotations

import unittest
from pathlib import Path
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
app = load_script("initial_nvos_argv_literals", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")


class NvosArgvLiteralTests(unittest.TestCase):
    def test_fixed_nvos_vectors_are_exact_and_noninteractive(self):
        positives = [
            ["true"],
            ["nv", "config", "show"],
            ["nv", "config", "show", "-o", "commands"],
            ["nv", "config", "save"],
            ["nv", "config", "diff", "-o", "commands"],
            ["nv", "show", "system", "ztp"],
            ["nv", "config", "apply", "-y"],
            ["nv", "set", "system", "config", "auto-save", "state", "enabled"],
            ["nv", "set", "system", "ztp", "config-save", "enabled"],
        ]
        for expected in positives:
            with self.subTest(argv=expected):
                supplied = list(expected)
                actual = app.ib_command_argv(supplied)
                self.assertEqual(expected, actual)
                self.assertEqual(expected, supplied)
                self.assertIsNot(supplied, actual)

    def test_reserved_management_and_existing_typed_scalars_are_admitted(self):
        positives = [
            ["nv", "set", "interface", "eth0", "link", "state", "up"],
            ["nv", "set", "interface", "eth1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0", "type", "eth"],
            ["nv", "set", "interface", "eth1", "type", "eth"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "interface", "eth0", "ipv4", "address", "192.0.2.10/24"],
            ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.10/24"],
            ["nv", "set", "interface", "eth0-1", "ipv4", "address", "203.0.113.10/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "192.0.2.1"],
            ["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"],
            ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"],
            ["nv", "set", "system", "hostname", "ew-leaf001"],
            ["nv", "set", "system", "dns", "server", "192.0.2.53"],
            ["nv", "set", "system", "dns", "server", "2001:db8::53"],
            ["nv", "set", "system", "ntp", "server", "192.0.2.123"],
            ["nv", "set", "system", "ntp", "server", "NTP.EXAMPLE.COM."],
            ["nv", "set", "system", "date-time", "timezone", "Etc/UTC"],
            ["nv", "set", "system", "date-time", "timezone", "Etc/GMT+8"],
        ]
        for expected in positives:
            with self.subTest(argv=expected):
                supplied = list(expected)
                actual = app.ib_command_argv(supplied)
                self.assertEqual(expected, actual)
                self.assertEqual(expected, supplied)
                self.assertIsNot(supplied, actual)

    def test_near_miss_and_unowned_nvos_vectors_are_rejected(self):
        negatives = [
            ["nv", "config", "apply"],
            ["nv", "config", "apply", "-Y"],
            ["nv", "config", "apply", "-y", "--force"],
            ["nv", "config", "diff"],
            ["nv", "config", "diff", "-o", "json"],
            ["nv", "config", "diff", "-o", "commands", "extra"],
            ["nv", "show", "system"],
            ["nv", "show", "system", "ztp", "extra"],
            ["nv", "config", "reset"],
            ["nv", "config", "discard"],
            ["nv", "config", "replace", "PUBLIC"],
            ["nv", "config", "import", "PUBLIC"],
            ["nv", "unset", "interface", "eth0"],
            ["nv", "set", "system", "config", "auto-save", "state", "disabled"],
            ["nv", "set", "system", "ztp", "config-save", "disabled"],
            ["nv", "set", "system", "ztp", "state", "disabled"],
            ["nv", "set", "interface", "swp1", "link", "state", "up"],
            ["nv", "set", "interface", "vlan1000", "type", "eth"],
            ["nv", "set", "interface", "eth0-2", "link", "state", "up"],
            ["nv", "set", "interface", "eth0", "link", "state", "down"],
            ["nv", "set", "interface", "eth0", "type", "ib"],
            ["nv", "set", "interface", "eth0", "ipv4", "address", "192.0.2.10/99"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "192.0.2.1/24"],
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "2001:db8::1"],
            ["nv", "set", "system", "hostname", "bad hostname"],
            ["nv", "set", "system", "dns", "server", "resolver.example"],
            ["nv", "set", "system", "dns", "search", "example.com"],
            ["nv", "set", "system", "ntp", "server", "ntp.example;id"],
            ["nv", "set", "system", "date-time", "timezone", "UTC;id"],
            ["nv", "set", "system", "aaa", "user", "admin"],
            ["sh", "-c", "printf PUBLIC", "--", "QUFBQQ=="],
            ["scp", "PUBLIC", "remote:PUBLIC"],
        ]
        for supplied in negatives:
            with self.subTest(argv=supplied):
                with self.assertRaises(app.SetupError):
                    app.ib_command_argv(supplied)

    def test_ethernet_retains_read_only_role_and_rejects_both_apply_forms(self):
        positives = [
            ["hostname"],
            ["nv", "show", "interface"],
            ["nv", "config", "show"],
            ["ip", "-d", "link", "show"],
            ["bridge", "fdb", "show"],
            ["ip", "neighbor"],
            ["ifquery", "vlan1000"],
        ]
        for expected in positives:
            with self.subTest(read_only=expected):
                supplied = list(expected)
                self.assertEqual(expected, app.ethernet_command_argv(supplied))
                self.assertEqual(expected, supplied)
        negatives = [
            ["nv", "config", "apply"],
            ["nv", "config", "apply", "-y"],
            ["nv", "config", "save"],
            ["nv", "config", "diff", "-o", "commands"],
            ["nv", "show", "system", "ztp"],
            ["nv", "set", "system", "config", "auto-save", "state", "enabled"],
            ["nv", "set", "system", "ztp", "config-save", "enabled"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "interface", "vlan1000", "ipv4", "address", "192.0.2.10/24"],
            ["sh", "-c", "printf PUBLIC"],
            ["scp", "PUBLIC", "remote:PUBLIC"],
        ]
        for supplied in negatives:
            with self.subTest(write_or_foreign=supplied):
                with self.assertRaises(app.SetupError):
                    app.ethernet_command_argv(supplied)

    def test_scalar_control_and_nonexact_type_carriers_are_rejected(self):
        class TextSubclass(str):
            pass
        carriers = [
            None, False, (), "nv config show", [],
            ["nv", "config", ""], ["nv", "config", False],
            ["nv", "config", b"show"], ["nv", "config", TextSubclass("show")],
            ["nv", "config", "show\n"], ["nv", "config", "show\x00"],
            ["nv", "config", "show\x7f"], ["nv", "config", "show\x85"],
        ]
        for ordinal, supplied in enumerate(carriers):
            with self.subTest(carrier=ordinal, gate="typed"):
                with self.assertRaises(app.SetupError):
                    app.typed_argv(supplied, label="PUBLIC literal carrier")
            with self.subTest(carrier=ordinal, gate="ib"):
                with self.assertRaises(app.SetupError):
                    app.ib_command_argv(supplied)
            with self.subTest(carrier=ordinal, gate="ethernet"):
                with self.assertRaises(app.SetupError):
                    app.ethernet_command_argv(supplied)


if __name__ == "__main__":
    unittest.main()
