"""Independent SFTP staging contract controls; not remote/kernel inode proof.

Initial missing-entry RED stops at subject() before fixtures or native action.
Pure input workflow only verifies wrong-node/pin refusal, not normal upload.
The separate genuine SDK/SFTP/private-filesystem workflow requires root window.
"""
import hashlib
import importlib
import importlib.util
import inspect
import struct
import types
import unittest
from unittest import mock

SUBJECT = "tools.ufm_deployment_staging_sftp"
EXPECTED_HOME_UID_ARGV = ("bash", "--noprofile", "--norc", "-p", "-c",
                          "printf '%s\\0' \"$HOME\" \"$UID\"")

def subject(test):
    test.assertIsNotNone(importlib.util.find_spec(SUBJECT),
                         "fixed original-source SFTP staging entry is absent")
    return importlib.import_module(SUBJECT)

class F01DeploymentStagingSftpDirectTests(unittest.TestCase):
    def test_fixed_home_uid_source_signature_and_status_are_not_caller_permission(self):
        api = subject(self)
        self.assertEqual(EXPECTED_HOME_UID_ARGV, api._HOME_UID_ARGV)
        self.assertEqual(("/home/admin", 1000), api._decode_home_uid(b"/home/admin\x001000\x00"))
        for raw in (b"/home/admin\n1000\n", b"/\x000\x00", b"/home/admin/../foreign\x001000\x00"):
            with self.subTest(raw=raw):
                with self.assertRaises(api.StagingSftpHold):
                    api._decode_home_uid(raw)
        self.assertEqual(("script_path", "known_hosts", "expected_known_hosts_sha256",
                          "management_identity", "timeout"),
                         tuple(inspect.signature(api.stage_readonly_project_script).parameters))
        self.assertEqual("x+", api._PART_OPEN_MODE)
        self.assertEqual(18, api._STANDARD_RENAME)
        with self.assertRaises(TypeError):
            api.stage_readonly_project_script(script_path=True, known_hosts=True,
                expected_known_hosts_sha256=True, management_identity=True,
                command="caller command", remote_path="/caller/destination")

    def test_same_class_dto_and_cached_closed_flag_cannot_substitute_native_issuance_or_close_ack(self):
        api = subject(self)
        from tools import ufm_deployment_staging_owner as owner
        live = object.__new__(owner._LiveDeploymentOwner)
        calls = []
        client = types.SimpleNamespace(open_session=lambda **kwargs: calls.append(True))
        live.__dict__.update(_active=True, _client=client, verify=lambda: True,
                             _guard=lambda: None, _fresh=lambda: True)
        with self.assertRaises(owner.StagingOwnerHold):
            owner._issued_native_deployment_owner(live)
        self.assertEqual([], calls)
        good = struct.pack(">IIII", 7, 0, 0, 0)
        self.assertTrue(api._close_status_ok(101, good, 7))
        for packet_type, raw in ((104, good), (101, struct.pack(">IIII", 8, 0, 0, 0)),
                                 (101, struct.pack(">IIII", 7, 4, 0, 0))):
            with self.subTest(packet_type=packet_type, raw=raw):
                with self.assertRaises(api.StagingSftpHold):
                    api._close_status_ok(packet_type, raw, 7)
        with self.assertRaises(api.StagingSftpHold):
            api._close_status_ok(101, {"closed": True, "status": 0}, 7)

class F01DeploymentStagingSftpInputWorkflowTests(unittest.TestCase):
    def test_actual_csv_global_builder_second_node_with_first_node_pin_stops_before_syntax_or_native(self):
        api = subject(self)
        from tools import ufm_bootstrap_auth_adapter as auth
        from tools import ufm_deployment_script_builder as builder
        from test_cases import test_f01_recovery_staging_owner as fixture
        with fixture.actual_stage(self) as (first, project, known, pin, private):
            second = builder.generate_stage_script(address="192.0.2.22",
                private_logs_root=first.script_path.parents[4])
            self.assertEqual("EXAMPLE-UFM02", second.script_path.parent.parent.name)
            original = second.script_path.read_bytes()
            calls = []
            def zero_connect(*args, **kwargs):
                calls.append(True)
                raise AssertionError("wrong target pin must be refused before transport")
            with mock.patch.object(auth, "_direct_ipv4_connected_stream", new=zero_connect):
                with self.assertRaises(api.StagingSftpHold):
                    api.stage_readonly_project_script(script_path=second.script_path,
                        known_hosts=known, expected_known_hosts_sha256=pin,
                        management_identity=private, timeout=10)
            self.assertEqual([], calls)
            self.assertEqual(original, second.script_path.read_bytes())
            self.assertEqual(hashlib.sha256(known.read_bytes()).hexdigest(), pin)
