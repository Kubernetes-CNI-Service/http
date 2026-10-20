"""OpenSSH hashed endpoints: fixed vectors and offline real-module workflows."""

# Canonical source binding; original behavior assertions remain intact.
# Readonly IO doubles are shared by provider and explicit consumer.
import unittest as _ibsw225_unittest
from test_cases.ibsw225_fixture_support.runtime_source_support import support as _ibsw225_support
_ibsw225_runtime = _ibsw225_support(_ibsw225_unittest.TestCase())
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures as _ibsw225_install_fixed_fixtures
_ibsw225_fixed_fixture_modules = _ibsw225_install_fixed_fixtures()

import base64
import contextlib
import io
import json
from pathlib import Path
import socket
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures

app, driver, observer = fixtures.app, fixtures.driver, fixtures.observer

# HMAC-SHA1 vectors independently calculated with OpenSSL, not the tested reader.
SALT = b"MDEyMzQ1Njc4OTAxMjM0NTY3ODk="
HASH_IP = b"|1|" + SALT + b"|E/rEDh0roo9LmRthbfEwCtJ5ru0="
HASH_BRACKET = b"|1|" + SALT + b"|edCD7YS/nVagAjs4eBUl1/YTnVY="
HASH_OTHER_IP = b"|1|" + SALT + b"|eiMOEwVMKa9xxZqeS1A4EuugFMo="
HASH_HOSTNAME = b"|1|" + SALT + b"|cV5h5xPL2W/q/38IN54fDhdxNPM="
WIRE = struct.pack(">I", 11) + b"ssh-ed25519" + struct.pack(">I", 32) + b"x" * 32
PUBLIC = b"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4"
PIN = "SHA256:lA19YOwnA8sKEBzmWH//YfBfLIamgNX1CzTbbjRJ13M"


def line(endpoint, public=PUBLIC):
    return endpoint + b" " + public + b"\n"


class HostPinTests(unittest.TestCase):
    def test_hashed_ip_matches_fixed_independent_vector(self):
        self.assertEqual(driver._offline_literal_host_pins(line(HASH_IP), "192.0.2.1"), (PIN,))

    def test_hashed_bracketed_port22_endpoint_matches(self):
        self.assertEqual(driver._offline_literal_host_pins(line(HASH_BRACKET), "192.0.2.1"), (PIN,))

    def test_literal_ip_and_bracketed_records_remain_supported(self):
        for endpoint in (b"192.0.2.1", b"[192.0.2.1]:22", b"example,192.0.2.1"):
            with self.subTest(endpoint=endpoint):
                self.assertEqual(driver._offline_literal_host_pins(line(endpoint), "192.0.2.1"), (PIN,))

    def test_unrelated_hash_and_hostname_hash_never_authorize_target_ip(self):
        for endpoint in (HASH_OTHER_IP, HASH_HOSTNAME, b"192.0.2.*", b"ew-spine01.example"):
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, "no exact pre-provisioned"):
                driver._offline_literal_host_pins(line(endpoint), "192.0.2.1")

    def test_literal_and_hashed_duplicates_are_deduplicated(self):
        payload = line(b"192.0.2.1") + line(HASH_IP) + line(HASH_BRACKET)
        self.assertEqual(driver._offline_literal_host_pins(payload, "192.0.2.1"), (PIN,))

    def test_matching_hashed_markers_are_never_accepted_as_plain_pins(self):
        for marker in (b"@revoked", b"@cert-authority", b"@unknown"):
            for payload in (line(marker + b" " + HASH_IP),
                            line(b"192.0.2.1") + line(marker + b" " + HASH_IP)):
                with self.subTest(marker=marker), self.assertRaisesRegex(ValueError, "marked host trust"):
                    driver._offline_literal_host_pins(payload, "192.0.2.1")

    def test_unrelated_hashed_marker_does_not_revoke_target(self):
        payload = line(b"@revoked " + HASH_OTHER_IP) + line(HASH_IP)
        self.assertEqual(driver._offline_literal_host_pins(payload, "192.0.2.1"), (PIN,))

    def test_invalid_hash_encoding_and_lengths_fail_closed_even_with_literal_pin(self):
        invalid = (
            b"|1|bad|bad", b"|1||", b"|1|" + SALT + b"|!!!!",
            b"|1|" + SALT + b"|E/rEDh0roo9LmRthbfEwCtJ5ru0",  # missing padding
            b"|1|eHh4eHh4eHh4eHh4eHh4eHh4eA==|E/rEDh0roo9LmRthbfEwCtJ5ru0=",  # salt 19 bytes
            b"|1|" + SALT + b"|eHh4eHh4eHh4eHh4eHh4eHh4eHh4",  # digest 21 bytes
            b"|1|" + SALT + b"|E/rEDh0roo9LmRthbfEwCtJ5ru0=|extra",
            HASH_IP + b",192.0.2.1", b"192.0.2.1," + HASH_IP,
        )
        for endpoint in invalid:
            with self.subTest(endpoint=endpoint), self.assertRaisesRegex(ValueError, "hashed known_hosts"):
                driver._offline_literal_host_pins(line(b"192.0.2.1") + line(endpoint), "192.0.2.1")

    def test_unknown_hash_format_is_not_silently_trusted_or_ignored(self):
        with self.assertRaisesRegex(ValueError, "known_hosts hash format"):
            driver._offline_literal_host_pins(line(HASH_IP.replace(b"|1|", b"|2|", 1)), "192.0.2.1")

    def test_matching_hash_still_requires_valid_public_key(self):
        with self.assertRaisesRegex(ValueError, "invalid public key base64"):
            driver._offline_literal_host_pins(line(HASH_IP, b"ssh-ed25519 INVALID_KEY"), "192.0.2.1")

    def test_hashed_endpoint_works_with_rsa_public_key_type(self):
        import hashlib
        wire = (struct.pack(">I", 7) + b"ssh-rsa" + struct.pack(">I", 3) + b"\x01\x00\x01"
                + struct.pack(">I", 3) + b"\x00\x80\x01")
        expected = "SHA256:" + base64.b64encode(hashlib.sha256(wire).digest()).decode().rstrip("=")
        self.assertEqual(driver._offline_literal_host_pins(
            line(HASH_IP, b"ssh-rsa " + base64.b64encode(wire)), "192.0.2.1"), (expected,))


class HashedTrustWorkflowTests(unittest.TestCase):
    def invoke(self, project, home, server_wire=WIRE, *, connect_error=None):
        import ibsw_upgrade_executor as executor
        # Real CLI -> driver input FD binding -> real native host-key comparison;
        # sockets/SDK/channel IO only are simulated, with no real network.
        connection = SimpleNamespace(settimeout=lambda value: None, connect=lambda endpoint: None,
                                     close=lambda: None)
        if connect_error is not None:
            def failed_connect(endpoint): raise connect_error
            connection.connect=failed_connect
        transport = SimpleNamespace(
            start_client=lambda **kwargs: None,
            get_remote_server_key=lambda: SimpleNamespace(asbytes=lambda: server_wire),
            auth_password=lambda *args, **kwargs: auth.append(True),
            is_authenticated=lambda: bool(auth), get_username=lambda: "admin", close=lambda: None)
        auth, commands = [], []
        def read(leaf, actual_transport, command, deadline):
            self.assertIs(actual_transport, transport)
            commands.append(command)
            if command == "hostname; cat /sys/class/net/eth0/address":
                return b"ew-spine01.example\n02:00:00:00:00:01\n", b"", 0, True
            if command == "nv show system version":
                return fixtures.OS_TABLE, b"", 0, True
            if command == "nv show platform firmware":
                return b"unused firmware", b"", 0, True
            if command == 'nv show system health':
                return fixtures.HEALTH_TABLE,b'',0,True
            self.fail("Unexpected remote command: " + command)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(Path, "home", return_value=home), patch.object(app, "_check_runtime"), \
             patch.object(app, "_read_password", return_value="PRIVATE_TEST_PASSWORD"), \
             patch.object(socket, "socket", return_value=connection) as network, \
             patch.object(observer, "_fixed_sdk", return_value=SimpleNamespace(Transport=lambda value: transport)) as sdk_io, \
             patch.object(executor, "_fixed_sdk", sdk_io), \
             patch.object(observer, "_read_channel", side_effect=read) as read_io, \
             patch.object(executor, "_read_channel", read_io), \
             contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            self.assertIs(observer._fixed_sdk, executor._fixed_sdk)
            self.assertIs(observer._read_channel, executor._read_channel)
            code = app.main(["--project", str(project), "--os-only", "--devices", "ew-spine01*", "--password"])
        return code, json.loads(out.getvalue()) if out.getvalue() else {}, err.getvalue(), network.call_count, auth, commands

    def test_real_readonly_flow_accepts_hashed_pin_without_modifying_trust_or_upgrading(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(HASH_IP))
            before = known.read_bytes()
            code, report, err, sockets, auth, commands = self.invoke(project, home)
            self.assertEqual(code, 0, err)
            self.assertEqual(report["ready_ib_count"], 1)
            self.assertEqual(report["execution_state"], "NOT_EXECUTED")
            self.assertEqual(report["skipped_devices"], [])
            self.assertEqual((sockets, len(auth)), (1, 1))
            self.assertEqual(commands, ["hostname; cat /sys/class/net/eth0/address",
                                        "nv show system version", "nv show system health"])
            self.assertEqual(report['health_summary']['counts']['PASS'],1)
            self.assertEqual(known.read_bytes(), before)

    def test_remote_key_mismatch_still_blocks_before_any_authentication_or_query(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(HASH_IP))
            other_key = WIRE[:-32] + b"y" * 32
            code, report, err, sockets, auth, commands = self.invoke(project, home, other_key)
            self.assertEqual(code, 3, err)
            self.assertEqual(report["ready_ib_count"], 0)
            self.assertEqual(report["skipped_devices"][0]["reasons"], ["SSH_HOST_KEY_MISMATCH"])
            self.assertEqual(sockets, 1)
            self.assertEqual((auth, commands), ([], []))

    def test_unrelated_hash_only_probes_tcp_and_never_starts_untrusted_ssh(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(HASH_OTHER_IP))
            code, report, err, sockets, auth, commands = self.invoke(project, home)
            self.assertEqual(code, 3, err)
            self.assertEqual(report["skipped_devices"][0]["reasons"], ["KNOWN_HOSTS"])
            self.assertEqual((sockets, auth, commands), (1, [], []))
            self.assertEqual(report['skipped_devices'][0]['tcp_probe']['status'],'CONNECTED')

    def test_matching_hashed_marker_is_safely_reported_and_never_connects(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(b"@revoked " + HASH_IP))
            code, report, err, sockets, auth, commands = self.invoke(project, home)
            self.assertEqual(code, 2)
            self.assertIn("KNOWN_HOSTS_POLICY", err)
            self.assertEqual((sockets, auth, commands), (0, [], []))
            self.assertNotIn("PRIVATE_TEST_PASSWORD", err)
            self.assertNotIn(HASH_IP.decode(), err)

    def test_malformed_hash_has_fixed_diagnostic_without_echoing_private_data(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(b"|1|PRIVATE_TEST_PASSWORD|bad"))
            code, report, err, sockets, auth, commands = self.invoke(project, home)
            self.assertEqual(code, 2)
            self.assertIn("KNOWN_HOSTS_FORMAT", err)
            self.assertNotIn("PRIVATE_TEST_PASSWORD", err)
            self.assertEqual((sockets, auth, commands), (0, [], []))

    def test_original_hashed_trust_file_remains_bound_and_mutation_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            project, home, known = fixtures.WorkflowTests().fixture(Path(directory).resolve())
            known.write_bytes(line(HASH_IP))
            args = ("--project", str(project), "--os-only")
            prepared = driver.prepare_not_executed_run(app.__file__, str(project), args)
            opened, mutation_rejected = False, False
            with self.assertRaises(ValueError):
                with driver.open_prepared_run(app.__file__, str(project), args, prepared["run_directory"]) as scope:
                    with scope.open_readonly_query_inputs("ew-spine01.example", known_hosts_path=str(known),
                            identity_path=None, management_public_path=None, user="admin") as leaf:
                        self.assertEqual(leaf.host_pins, (PIN,))
                        opened = True
                        known.write_bytes(known.read_bytes() + b"# changed\n")
                        try:
                            leaf.verify()
                        except ValueError:
                            mutation_rejected = True
                            raise
            self.assertTrue(opened)
            self.assertTrue(mutation_rejected)


if __name__ == "__main__":
    unittest.main()
