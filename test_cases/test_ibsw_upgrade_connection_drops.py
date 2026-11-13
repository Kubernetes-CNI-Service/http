"""WP-A3/I-016: exact channel/SFTP disconnects, never authentication subclasses.

Socketpair Paramiko is real; other IO is confined to the runner-owned SimFleet.
Expectations are literal from approved r515 WP-A3, not derived from the implementation.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))
import fleet_engine
import fleet_ssh as ssh
import ibsw_v2_device as ib
import test_fleet_ssh as sockets
import test_ibsw_v2_device as fixtures
from ibsw_upgrade_contract import InventoryDevice
from ibsw_v2_switch_sim import LocalSwitch, SimFleet


class FaultSwitch(sockets.FakeSwitch):
    def _exec(self, channel, command):
        # A fault before exec sent no command. Close that owned channel silently;
        # the original server's normal command implementation remains real.
        if not command:
            channel.close()
            return
        return super()._exec(channel, command)


def world(base):
    policy = fixtures.policy_for(base / "http")
    key = ssh._sdk().ECDSAKey.generate()
    switch = LocalSwitch(base / "switches", "sw01", "192.0.2.5", "02:00:00:00:00:05",
                         "25.02.7002", password=fixtures.SENTINEL)
    fleet = SimFleet([switch], base / "http", key.get_base64())
    device = InventoryDevice("sw01", "192.0.2.5", "02:00:00:00:00:05")
    creds = ssh.Credentials("admin", key, ssh.fingerprint(key.asbytes()), fixtures.SENTINEL)
    ops = ib.LiveOps(pins=ssh.HostPins(b""), credentials=creds, policy=policy, selected=("os",), run_id="a3",
                     management_line=f"{key.get_name()} {key.get_base64()} mgmt\n".encode(),
                     connector=fleet.connector, ping_run=fleet.ping_run, tcp_probe=fleet.tcp,
                     dir_for=fleet.dir_for)
    evidence = fleet_engine.Evidence(base / "run")
    return SimpleNamespace(policy=policy, switch=switch, fleet=fleet, device=device, ops=ops,
                           key=key, evidence=evidence, journal=evidence.journal("sw01"))


class UpgradeConnectionDropTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.sdk = ssh._sdk()

    def connected(self):
        switch = FaultSwitch()
        creds = ssh.Credentials("admin", switch.client_key, ssh.fingerprint(switch.client_key.asbytes()), None)
        session = ssh.connect(sockets.ADDRESS, ssh.HostPins(switch.known_hosts()), creds,
                              sock_factory=switch.socket)
        self.addCleanup(session.close)
        return session

    def channel_error(self, error):
        session = self.connected()
        original = session.transport.open_session
        channels = []
        def open_channel(*args, **kwargs):
            channel = original(*args, **kwargs)
            channels.append(channel)
            channel.exec_command = mock.Mock(side_effect=error)
            return channel
        with mock.patch.object(session.transport, "open_session", side_effect=open_channel):
            try:
                session.run("hostname")
            except Exception as caught:
                outcome = caught
            else:
                self.fail("fault must not become success")
        self.assertEqual(len(channels), 1)
        self.assertTrue(channels[0].closed, "every failed real channel is closed")
        return outcome

    def test_exact_sdk_exception_is_incomplete_and_reboot_like(self):
        error = self.channel_error(self.sdk.SSHException("synthetic channel closed"))
        self.assertIsInstance(error, ssh.SshError, "WP-A3 exact SDK disconnect mapping")
        self.assertEqual(error.code, "COMMAND_INCOMPLETE")
        self.assertTrue(error.reboot_like)
        self.assertEqual(str(error), "COMMAND_INCOMPLETE", "SDK text is not exposed")

    def test_authentication_subclass_is_not_relaxed(self):
        original = self.sdk.AuthenticationException("synthetic authentication refused")
        self.assertIs(self.channel_error(original), original)

    def test_hostkey_subclass_is_not_relaxed(self):
        original = self.sdk.BadHostKeyException("192.0.2.5", self.sdk.ECDSAKey.generate(),
                                                self.sdk.ECDSAKey.generate())
        self.assertIs(self.channel_error(original), original)

    def test_existing_eof_mapping_and_channel_cleanup_are_preserved(self):
        error = self.channel_error(EOFError("synthetic EOF"))
        self.assertIsInstance(error, ssh.SshError)
        self.assertEqual(error.code, "COMMAND_INCOMPLETE")

    def read_fault(self, error, *, active):
        item = world(self.base)
        session = item.fleet.connector(item.device, "password")
        self.addCleanup(session.close)
        session.transport = SimpleNamespace(is_active=lambda: active)
        original = session.sftp().lstat
        def lstat(path):
            if str(path).endswith("authorized_keys"):
                raise error
            return original(path)
        with mock.patch.object(session.sftp(), "lstat", side_effect=lstat):
            try:
                ib.read_keys(session, "admin")
            except Exception as caught:
                return caught
        self.fail("fault was not observed by real v1 _read_keys")

    def test_read_keys_exact_sdk_disconnect_is_incomplete(self):
        error = self.read_fault(self.sdk.SSHException("synthetic SFTP closed"), active=True)
        self.assertIsInstance(error, ssh.SshError)
        self.assertEqual(error.code, "COMMAND_INCOMPLETE")
        self.assertTrue(error.reboot_like)

    def test_read_keys_inactive_access_hold_is_incomplete(self):
        error = self.read_fault(EOFError("synthetic SFTP EOF"), active=False)
        self.assertIsInstance(error, ssh.SshError, "only inactive AccessHold becomes retryable")
        self.assertEqual(error.code, "COMMAND_INCOMPLETE")

    def test_read_keys_active_metadata_failure_stays_device_error(self):
        error = self.read_fault(PermissionError("synthetic denied"), active=True)
        self.assertIsInstance(error, ib.DeviceError)
        self.assertEqual(error.code, "AUTHORIZED_KEYS_READ_FAILED")

    def test_read_keys_authentication_and_hostkey_subclasses_stay_original(self):
        # Separate roots because each exercise constructs a real local switch.
        for index, error in enumerate((self.sdk.AuthenticationException("synthetic refused"),
                                      self.sdk.BadHostKeyException("192.0.2.5", self.sdk.ECDSAKey.generate(),
                                                                    self.sdk.ECDSAKey.generate()))):
            self.base = Path(self.tmp.name) / str(index)
            with self.subTest(kind=type(error).__name__):
                self.assertIs(self.read_fault(error, active=False), error)

    def prepared(self):
        item = world(self.base)
        pre = item.ops.precheck(item.device, upgrade=True, staged_names=[], journal=item.journal)
        package = fleet_engine.PackageInfo.read(item.policy.os[-1])
        self.assertTrue(item.ops.fetch(item.device, package, size=package.size, sha256=package.sha256)["ok"])
        step = ib.render_step(item.policy, item.device, component="os", package_index=2, run_id="a3",
                              switch_dir=str(item.switch.home))
        return item, pre, package, step

    def test_requested_launch_disconnect_stays_dispatched_and_uncertain(self):
        item, pre, package, step = self.prepared()
        real_session = self.connected()
        with mock.patch.object(self.sdk.Channel, "exec_command", side_effect=self.sdk.SSHException("synthetic close")), \
                mock.patch.object(ib, "launch", side_effect=lambda *a: real_session.run("owned launch")):
            try:
                result = item.ops.dispatch(item.device, step, backup=pre["backup"],
                                           staged={package.file: (package.size, package.sha256)}, journal=item.journal)
            except Exception as error:
                self.fail("after REQUESTED must return DISPATCHED, not " + type(error).__name__)
        self.assertEqual((result["state"], result["confirmed"]), ("DISPATCHED", None))
        record = json.loads((item.evidence.directory("sw01") / "dispatch.json").read_text())
        self.assertEqual(record["state"], "REQUESTED")

    def test_before_requested_read_disconnect_never_records_dispatch(self):
        item, pre, package, step = self.prepared()
        original = ib._read_keys
        with mock.patch.object(ib, "_read_keys", side_effect=self.sdk.SSHException("synthetic prewrite close")):
            try:
                item.ops.dispatch(item.device, step, backup=pre["backup"],
                                  staged={package.file: (package.size, package.sha256)}, journal=item.journal)
            except Exception as error:
                outcome = error
            else:
                self.fail("pre-REQUESTED disconnect cannot be dispatched")
        self.assertIsNotNone(original, "the real reader is only faulted at its boundary")
        self.assertIsInstance(outcome, ssh.SshError)
        self.assertEqual(outcome.code, "COMMAND_INCOMPLETE")
        self.assertFalse((item.evidence.directory("sw01") / "dispatch.json").exists())

    def test_upload_step_failure_before_requested_preserves_original_error(self):
        item, pre, package, step = self.prepared()
        original = self.sdk.SSHException("synthetic step upload failed")
        with mock.patch.object(ib, "_upload", side_effect=original):
            with self.assertRaises(self.sdk.SSHException) as caught:
                item.ops.dispatch(item.device, step, backup=pre["backup"],
                                  staged={package.file: (package.size, package.sha256)}, journal=item.journal)
        self.assertIs(caught.exception, original)
        self.assertFalse((item.evidence.directory("sw01") / "dispatch.json").exists())

    def test_repair_sftp_exact_exception_is_fixed_error_and_never_replayed(self):
        item = world(self.base)
        with item.fleet.connector(item.device, "password") as session:
            before = (item.switch.state / "config").read_bytes()
            missing = "nv set system ntp server 192.0.2.123"
            after = before.replace((missing + "\n").encode(), b"")
            (item.switch.state / "config").write_bytes(after)
            difference = SimpleNamespace(missing=(missing,))
            with mock.patch.object(ib, "_upload", side_effect=self.sdk.SSHException("synthetic upload close")) as upload:
                try:
                    ib.repair(session, item.device, before, after, difference, uid=__import__("os").getuid(),
                              switch_dir=str(item.switch.home), record=lambda *a: None)
                except Exception as error:
                    outcome = error
                else:
                    self.fail("failed upload must not report repaired")
            self.assertEqual(upload.call_count, 1)
            self.assertIsInstance(outcome, ssh.SshError)
            self.assertEqual(outcome.code, "COMMAND_INCOMPLETE")
            self.assertEqual((item.switch.state / "config").read_bytes(), after)
            self.assertEqual((item.switch.state / "pending").read_bytes(), b"")

    def test_repair_sftp_authentication_and_hostkey_subclasses_stay_original(self):
        item = world(self.base)
        with item.fleet.connector(item.device, "password") as session:
            before = (item.switch.state / "config").read_bytes()
            missing = "nv set system ntp server 192.0.2.123"
            after = before.replace((missing + "\n").encode(), b"")
            (item.switch.state / "config").write_bytes(after)
            errors = (self.sdk.AuthenticationException("synthetic refused"),
                      self.sdk.BadHostKeyException("192.0.2.5", self.sdk.ECDSAKey.generate(),
                                                   self.sdk.ECDSAKey.generate()))
            for error in errors:
                with self.subTest(kind=type(error).__name__), \
                        mock.patch.object(ib, "_upload", side_effect=error) as upload:
                    try:
                        ib.repair(session, item.device, before, after, SimpleNamespace(missing=(missing,)),
                                  uid=__import__("os").getuid(), switch_dir=str(item.switch.home), record=lambda *a: None)
                    except Exception as caught:
                        outcome = caught
                    else:
                        self.fail("failed repair upload must not return success")
                    self.assertIs(outcome, error)
                    self.assertEqual(upload.call_count, 1)
            self.assertEqual((item.switch.state / "config").read_bytes(), after)
            self.assertEqual((item.switch.state / "pending").read_bytes(), b"")
