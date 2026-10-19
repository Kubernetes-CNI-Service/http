"""Real direct identity parser/transport workflow; only 3 command replies synthetic.

No socket, SDK, child, device authentication or DHCP authority is provided.
"""
import datetime as dt
import hashlib
import json
from pathlib import Path
import unittest
from infra.ufm_jump_transport import CommandResult, TransportError, direct_ipv4_read
from tools import ufm_identity_binding as binding
from test_cases.test_f01_initial_setup_entry import site

class F01DirectIpv4TransportTests(unittest.TestCase):
    def test_literal_pinned_admin_read_argv_and_write_refusal(self):
        known = Path("/private/tmp/known-hosts-fixture")
        key = Path("/private/tmp/private-identity-fixture")
        prefix = ["ssh", "-4", "-o", "BatchMode=yes", "-o", "PasswordAuthentication=no",
                  "-o", "KbdInteractiveAuthentication=no", "-o", "NumberOfPasswordPrompts=0",
                  "-o", "ConnectionAttempts=1", "-o", "ConnectTimeout=10",
                  "-o", "StrictHostKeyChecking=yes", "-o", "UpdateHostKeys=no",
                  "-o", "UserKnownHostsFile=/private/tmp/known-hosts-fixture",
                  "-i", "/private/tmp/private-identity-fixture", "admin@192.0.2.21"]
        self.assertEqual(prefix + ["hostname"], direct_ipv4_read(
            "192.0.2.21", known, key, ["hostname"], timeout=10))
        self.assertEqual(prefix + ["ip -j link show dev eno8303"], direct_ipv4_read(
            "192.0.2.21", known, key, ["ip", "-j", "link", "show", "dev", "eno8303"], timeout=10))
        for argv in (["reboot"], ["sh", "-c", "hostname"], ["ip", "address", "add", "192.0.2.99"],
                     ["ip", "-j", "link", "show", "dev", "eno8303;reboot"]):
            with self.subTest(argv=argv), self.assertRaises(TransportError):
                direct_ipv4_read("192.0.2.21", known, key, argv, timeout=10)

class F01DirectIpv4IdentityInputWorkflowTests(unittest.TestCase):
    def test_actual_project_input_pin_and_three_fixed_reads_no_lease_or_session_authority(self):
        with site() as (_http, project, logs):
            raw = b"192.0.2.21 ssh-ed25519 AAAA\n"
            pin = hashlib.sha256(raw).hexdigest()
            known = logs.parent / "known"; known.write_bytes(raw); known.chmod(0o600)
            private = logs.parent / "identity"; private.write_bytes(b"read-boundary-only"); private.chmod(0o600)
            calls = []
            outputs = [
                "factory-node\n",
                '[{"ifname":"eno8303","address":"02:00:00:00:00:21"}]',
                '[{"ifname":"eno8303","addr_info":[{"family":"inet","local":"192.0.2.21"}]}]',
            ]
            def runner(argv):
                calls.append(argv)
                return CommandResult(0, outputs[len(calls)-1], "")
            observed = binding.verify_project_direct_management_identity(
                project, "192.0.2.21", known, private, pin, phase="bootstrap",
                timeout=10, now=dt.datetime(2026,10,19,tzinfo=dt.timezone.utc), runner=runner)
            self.assertEqual(["hostname", "ip -j link show dev eno8303",
                              "ip -j address show dev eno8303"], [argv[-1] for argv in calls])
            self.assertTrue(all(argv[0:2] == ["ssh", "-4"] and argv[-2] == "admin@192.0.2.21"
                                for argv in calls))
            self.assertEqual(("factory-node", "EXAMPLE-UFM01", "192.0.2.21",
                              "02:00:00:00:00:21", "eno8303", "bootstrap"),
                             (observed.hostname, observed.expected_hostname, observed.address,
                              observed.management_mac, observed.interface, observed.phase))
            self.assertFalse(observed.license_mac_verified)
            self.assertEqual(raw, known.read_bytes())
            self.assertEqual(b"read-boundary-only", private.read_bytes())
