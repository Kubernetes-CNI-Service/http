"""Independent original NTP membership literals; no transport or device calls."""
import unittest
from pathlib import Path
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
app = load_script("initial_ntp_membership_literals", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")


class NtpIdempotenceTests(unittest.TestCase):
    services = {"dns": ["192.0.2.53"], "ntp": ["192.0.2.123", "ntp.example.com"],
                "timezone": "Etc/UTC"}
    common = ("nv set system dns server 192.0.2.53\n"
              "nv set system date-time timezone Etc/UTC\n")

    def test_enabled_servers_do_not_repeat(self):
        current = self.common + ("nv set system ntp server 192.0.2.123 state enabled\n"
                                 "nv set system ntp server ntp.example.com state enabled\n")
        self.assertEqual(app.desired_service_commands(self.services, current), [])

    def test_extra_server_properties_are_not_reset(self):
        current = self.common + ("nv set system ntp server 192.0.2.123 iburst enabled\n"
                                 "nv set system ntp server 192.0.2.123 state enabled\n"
                                 "nv set system ntp server ntp.example.com association-type pool\n")
        self.assertEqual(app.desired_service_commands(self.services, current), [])

    def test_server_identifier_is_not_a_substring(self):
        current = self.common + ("nv set system ntp server 192.0.2.12 state enabled\n"
                                 "nv set system ntp server ntp.example.com.evil state enabled\n")
        expected = [["nv", "set", "system", "ntp", "server", "192.0.2.123"],
                    ["nv", "set", "system", "ntp", "server", "ntp.example.com"]]
        self.assertEqual(app.desired_service_commands(self.services, current), expected)

    def test_bare_server_lines_remain_idempotent(self):
        current = self.common + ("nv set system ntp server 192.0.2.123\n"
                                 "nv set system ntp server ntp.example.com\n")
        self.assertEqual(app.desired_service_commands(self.services, current), [])

    def test_whitespace_quoting_and_dns_case(self):
        current = self.common + (" nv  set system ntp server '192.0.2.123' state enabled\n"
                                 "nv set system ntp server NTP.EXAMPLE.COM. state enabled\n")
        self.assertEqual(app.desired_service_commands(self.services, current), [])

    def test_malformed_ntp_readback_blocks_verification(self):
        current = self.common + "nv set system ntp server '192.0.2.123 state enabled\n"
        with self.assertRaises(app.SetupError):
            app.desired_service_commands(self.services, current)


if __name__ == "__main__":
    unittest.main()
