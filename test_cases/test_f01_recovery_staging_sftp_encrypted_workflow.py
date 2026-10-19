"""Genuine local SDK/SFTP file protocol, not UFM server conformance.

Only fixed TCP connect is substituted by an owned AF_UNIX stream. The actual
source holder, syntax child, signed KEX/admin key-auth, identity reads, SFTP
packets and native cleanup are production. The local filesystem backend uses
atomic no-overwrite link/unlink, never exists+overwrite rename. No script body.
Prepared only: this method needs the root's exclusive crypto/child window.
"""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import queue
import shlex
import socket
import stat
import tempfile
import threading
import unittest
from unittest import mock

from tools import ufm_deployment_staging_sftp as api
from tools import ufm_deployment_staging_owner as owner
from tools import ufm_deployment_script_builder as builder
from tools import ufm_bootstrap_auth_adapter as auth
from test_cases import test_f01_recovery_stage_script_builder as site_fixture
import paramiko

IDENTITY = ["hostname", "ip -j link show dev eno8303", "ip -j address show dev eno8303"]
HOME_PROBE = "bash --noprofile --norc -p -c 'printf '\"'\"'%s\\0'\"'\"' \"$HOME\" \"$UID\"'"

@contextlib.contextmanager
def local_sftp_peer(test, host_key, management_key, home, scenario):
    left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    stop, requests = threading.Event(), queue.Queue()
    clients, channels, server_channels, workers, handles, subsystems = [], [], [], [], [], []
    commands, attempts, errors, acks, operations = [], [], [], {}, []
    facts = {"scenario": scenario}
    foreign = None
    original_thread_start = threading.Thread.start
    def observe_original_start(thread, *args, **kwargs):
        target_code = getattr(getattr(thread, "_target", None), "__code__", None)
        if (target_code is not None and target_code.co_filename in {auth.__file__, api.__file__}
                and target_code.co_name in {"execute", "invoke"} and thread not in workers):
            # Retain the ACTUAL object before it can finish/disappear from
            # enumerate; observe only, delegate the original start exactly once.
            workers.append(thread)
        if isinstance(thread, paramiko.SFTPServer) and thread.get_server() is interface:
            subsystems.append(thread)
        return original_thread_start(thread, *args, **kwargs)

    def capture():
        for thread in threading.enumerate():
            if type(thread) is paramiko.Transport and thread.sock is left and not thread.server_mode:
                if thread not in clients:
                    clients.append(thread)
            code = getattr(getattr(thread, "_target", None), "__code__", None)
            if (code is not None and code.co_filename in {auth.__file__, api.__file__}
                    and code.co_name in {"execute", "invoke"} and thread not in workers):
                workers.append(thread)
        for client in clients:
            for channel in list(client._channels.values()):
                if channel not in channels:
                    channels.append(channel)

    class FileHandle(paramiko.SFTPHandle):
        def __init__(self, fd, path):
            super().__init__()
            self.fd, self.path = fd, path
            value = os.fstat(fd)
            self.original = (value.st_dev, value.st_ino)
            self.closed_original = False
            handles.append(self)
        def stat(self):
            capture()
            return paramiko.SFTPAttributes.from_stat(os.fstat(self.fd))
        def read(self, offset, length):
            capture()
            return os.pread(self.fd, length, offset)
        def write(self, offset, raw):
            capture()
            if scenario == "interrupted":
                test.assertEqual(0, offset)
                test.assertEqual(3, os.pwrite(self.fd, raw[:3], offset))
                operations.append("interrupted_write")
                return paramiko.SFTP_FAILURE
            test.assertEqual(len(raw), os.pwrite(self.fd, raw, offset))
            operations.append("write")
            return paramiko.SFTP_OK
        def close(self):
            if not self.closed_original:
                value = os.fstat(self.fd)
                test.assertEqual(self.original, (value.st_dev, value.st_ino))
                os.close(self.fd)
                self.closed_original = True

    class Backend(paramiko.SFTPServerInterface):
        def checked(self, path):
            value = Path(path)
            if not value.is_absolute() or ".." in value.parts or (value != home and home not in value.parents):
                raise AssertionError("fixture SFTP foreign path")
            return value
        def lstat(self, path):
            capture()
            try:
                return paramiko.SFTPAttributes.from_stat(self.checked(path).lstat())
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)
        def mkdir(self, path, attr):
            nonlocal foreign
            value = self.checked(path)
            test.assertEqual(home, value.parent)
            test.assertTrue(value.name.startswith(".xdr-stage-"))
            test.assertEqual(0o700, attr.st_mode)
            os.mkdir(value, 0o700)
            operations.append("mkdir")
            if scenario == "existing":
                final = value / "stage.sh"
                final.write_bytes(b"original-foreign-final")
                final.chmod(0o600)
                foreign = os.open(final, os.O_RDONLY | os.O_NOFOLLOW)
                os.lseek(foreign, 3, os.SEEK_SET)
                facts["foreign_original"] = (os.fstat(foreign).st_dev, os.fstat(foreign).st_ino)
            return paramiko.SFTP_OK
        def open(self, path, flags, attr):
            value = self.checked(path)
            test.assertIn(value.name, {"stage.sh.part", "stage.sh"})
            if value.name == "stage.sh.part":
                test.assertEqual(os.O_RDWR | os.O_CREAT | os.O_EXCL, flags)
                test.assertEqual(0o600, attr.st_mode)
            else:
                test.assertEqual(os.O_RDONLY, flags)
            return FileHandle(os.open(value, flags | os.O_NOFOLLOW, 0o600), value)
        def rename(self, old, new):
            source, destination = self.checked(old), self.checked(new)
            test.assertEqual("stage.sh.part", source.name)
            test.assertEqual("stage.sh", destination.name)
            operations.append("rename")
            try:
                os.link(source, destination, follow_symlinks=False)
                os.unlink(source)
                return paramiko.SFTP_OK
            except OSError as error:
                return paramiko.SFTPServer.convert_errno(error.errno)

    class ObservedTransport(paramiko.Transport):
        def _send_message(self, message):
            raw = message.asbytes()
            result = super()._send_message(message)
            if raw[:1] == bytes([0x63]) and len(raw) == 5:
                acks.setdefault(int.from_bytes(raw[1:], "big"), threading.Event()).set()
            return result
    class Peer(paramiko.ServerInterface):
        def get_allowed_auths(self, username):
            return "publickey"
        def check_auth_publickey(self, username, key):
            capture()
            attempts.append((username, key.get_name(), key.asbytes()))
            return (paramiko.AUTH_SUCCESSFUL if username == "admin" and key == management_key
                    else paramiko.AUTH_FAILED)
        def check_channel_request(self, kind, channel_id):
            return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        def check_channel_exec_request(self, channel, raw):
            capture()
            text = raw.decode("ascii")
            if text not in IDENTITY and text != HOME_PROBE:
                return False
            commands.append(text)
            server_channels.append(channel)
            requests.put((channel, text))
            return True
        def check_channel_subsystem_request(self, channel, name):
            capture()
            if name != "sftp":
                return False
            server_channels.append(channel)
            return super().check_channel_subsystem_request(channel, name)

    class ObservedSftpServer(paramiko.SFTPServer):
        def _process(self, command, request, message):
            self.observed_command = command
            return super()._process(command, request, message)
        def _send_status(self, request, code, *args, **kwargs):
            result = super()._send_status(request, code, *args, **kwargs)
            if self.observed_command == 4:
                facts.setdefault("actual_original_close_status_sends", []).append(
                    {"request": request, "code": code})
            return result

    server = ObservedTransport(right)
    server.add_server_key(host_key)
    server.set_subsystem_handler("sftp", ObservedSftpServer, Backend)
    interface = Peer()
    ready = threading.Event()
    dispatcher = None
    try:
        server.start_server(event=ready, server=interface)
        def dispatch():
            try:
                while not stop.is_set():
                    try:
                        channel, command = requests.get(timeout=.1)
                    except queue.Empty:
                        continue
                    if not acks.setdefault(channel.remote_chanid, threading.Event()).wait(2):
                        raise AssertionError("actual channel-success ACK absent")
                    if command == HOME_PROBE:
                        raw = str(home).encode() + b"\0" + str(os.getuid()).encode() + b"\0"
                    elif command == IDENTITY[0]:
                        raw = b"EXAMPLE-UFM01\n"
                    elif command == IDENTITY[1]:
                        raw = b'[{"ifname":"eno8303","address":"02:00:00:00:00:21"}]'
                    else:
                        raw = b'[{"ifname":"eno8303","addr_info":[{"family":"inet","local":"192.0.2.21"}]}]'
                    channel.sendall(raw)
                    channel.send_exit_status(0)
                    channel.shutdown_write()
                    channel.close()
            except BaseException as error:
                errors.append(type(error).__name__)
        dispatcher = threading.Thread(target=dispatch, name="f01-sftp-identity-peer", daemon=False)
        dispatcher.start()
        def connector(address, remaining):
            test.assertEqual("192.0.2.21", address)
            test.assertGreater(remaining, 0)
            test.assertLessEqual(remaining, 10)
            return left
        with mock.patch.object(threading.Thread, "start", new=observe_original_start):
            yield connector, commands, operations, facts
    finally:
        capture()
        facts["production_before_fixture_cleanup"] = {
            "client_count": len(clients), "clients_alive": [client.is_alive() for client in clients],
            "clients_active": [client.is_active() for client in clients],
            "left_closed": left.fileno() == -1, "workers_alive": [worker.is_alive() for worker in workers],
            "channels_closed": [channel.closed for channel in channels],
            "private_key_cleared": [getattr(client.auth_handler, "private_key", None) is None for client in clients],
            "server_original_handles_closed": [handle.closed_original for handle in handles]}
        stop.set()
        for channel in server_channels:
            channel.close()
        for client in clients:
            client.close()
        server.close()
        left.close(); right.close()
        for client in clients:
            client.join(2)
        server.join(2)
        if dispatcher is not None:
            dispatcher.join(2)
        for subsystem in subsystems:
            subsystem.join(2)
        if foreign is not None:
            value = os.fstat(foreign)
            test.assertEqual(facts["foreign_original"], (value.st_dev, value.st_ino))
            test.assertEqual(3, os.lseek(foreign, 0, os.SEEK_CUR))
            test.assertEqual(b"original-foreign-final", os.pread(foreign, 65536, 0))
            os.close(foreign)
        # Any backend assistance must remain after production observations.
        for handle in handles:
            if not handle.closed_original:
                handle.close()
        attempts.clear()
        facts.update(socket_closed=[left.fileno() == -1, right.fileno() == -1],
            server_alive=server.is_alive(), dispatcher_alive=dispatcher.is_alive(),
            client_alive_after_fixture=[client.is_alive() for client in clients],
            fixture_errors=errors, secrets_cleared=not attempts,
            original_thread_start_restored=threading.Thread.start is original_thread_start,
            subsystem_count=len(subsystems), subsystems_alive=[thread.is_alive() for thread in subsystems])

class F01DeploymentStagingSftpEncryptedWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server_key = paramiko.ECDSAKey.generate(bits=256)
        cls.management_key = paramiko.ECDSAKey.generate(bits=256)
        cls.laptop_key = paramiko.ECDSAKey.generate(bits=256)

    def test_actual_original_source_signed_sftp_normal_existing_and_interrupted_local_staging(self):
        self.assertEqual(HOME_PROBE, shlex.join(api._HOME_UID_ARGV))
        for scenario in ("normal", "existing", "interrupted"):
            with self.subTest(scenario=scenario), site_fixture.actual_site() as (http, project, logs), \
                    mock.patch.object(builder, "HTTP_ROOT", http), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve() / "admin-home"
                home.mkdir(mode=0o700)
                for name, key in (("mgmt-server.pub", self.management_key), ("laptop.pub", self.laptop_key)):
                    (project / name).write_text(key.get_name() + " " + key.get_base64() + " project\n")
                text = io.StringIO(); self.management_key.write_private_key(text)
                private = logs.parent / "management-private"
                private.write_text(text.getvalue()); private.chmod(0o600)
                approved = ("192.0.2.21 " + self.server_key.get_name() + " " + self.server_key.get_base64() + "\n").encode()
                pin = hashlib.sha256(approved).hexdigest()
                known = logs.parent / "known_hosts"
                known.write_bytes(approved); known.chmod(0o600)
                generated = builder.generate_stage_script(address="192.0.2.21", private_logs_root=logs)
                original = generated.script_path.read_bytes()
                manifest = generated.manifest_path.read_bytes()
                with local_sftp_peer(self, self.server_key, self.management_key, home, scenario) as (connector, commands, operations, facts), \
                        mock.patch.object(auth, "_direct_ipv4_connected_stream", new=connector):
                    kwargs = dict(script_path=generated.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=10)
                    if scenario == "normal":
                        result = api.stage_readonly_project_script(**kwargs)
                        self.assertEqual("STAGED_NOT_EXECUTED", result.state)
                        self.assertFalse(result.execution_permitted)
                        self.assertFalse(result.completion)
                        self.assertTrue(result.protocol_close_confirmed)
                        final = Path(result.remote_path)
                        self.assertEqual(original, final.read_bytes())
                        self.assertEqual(0o600, stat.S_IMODE(final.stat().st_mode))
                        self.assertEqual(0o700, stat.S_IMODE(final.parent.stat().st_mode))
                        self.assertFalse((final.parent / "stage.sh.part").exists())
                        self.assertEqual(["mkdir", "write", "rename"], operations)
                        self.assertEqual(IDENTITY + [HOME_PROBE] + IDENTITY, commands)
                    else:
                        with self.assertRaises(api.StagingSftpHold) as raised:
                            api.stage_readonly_project_script(**kwargs)
                        cause = raised.exception
                        while not hasattr(cause, "remote_residue") and cause.__cause__ is not None:
                            cause = cause.__cause__
                        self.assertFalse(cause.remote_cleanup_confirmed)
                        directory = Path(cause.remote_residue)
                        self.assertEqual(IDENTITY + [HOME_PROBE], commands)
                        self.assertNotIn("rename", operations)
                        if scenario == "existing":
                            self.assertEqual(b"original-foreign-final", (directory / "stage.sh").read_bytes())
                            self.assertEqual(original, (directory / "stage.sh.part").read_bytes())
                        else:
                            self.assertFalse((directory / "stage.sh").exists())
                            self.assertEqual(original[:3], (directory / "stage.sh.part").read_bytes())
                    self.assertEqual({}, owner._ISSUED_STAGES)
                    self.assertEqual({}, owner._ISSUED_NATIVE_OWNERS)
                production = facts["production_before_fixture_cleanup"]
                self.assertEqual(1, production["client_count"])
                self.assertEqual([False], production["clients_alive"])
                self.assertEqual([False], production["clients_active"])
                self.assertTrue(production["left_closed"])
                self.assertTrue(production["workers_alive"])
                self.assertFalse(any(production["workers_alive"]))
                self.assertTrue(all(production["channels_closed"]))
                self.assertEqual([True], production["private_key_cleared"])
                self.assertTrue(all(production["server_original_handles_closed"]))
                self.assertEqual([True, True], facts["socket_closed"])
                self.assertFalse(facts["server_alive"])
                self.assertFalse(facts["dispatcher_alive"])
                self.assertFalse(any(facts["client_alive_after_fixture"]))
                self.assertEqual([], facts["fixture_errors"])
                self.assertTrue(facts["secrets_cleared"])
                self.assertTrue(facts["original_thread_start_restored"])
                self.assertEqual(1, facts["subsystem_count"])
                self.assertEqual([False], facts["subsystems_alive"])
                close_sends = facts["actual_original_close_status_sends"]
                self.assertEqual(2 if scenario == "normal" else 1, len(close_sends))
                self.assertEqual([0] * len(close_sends), [item["code"] for item in close_sends])
                self.assertEqual(len(close_sends), len({item["request"] for item in close_sends}))
                self.assertEqual(original, generated.script_path.read_bytes())
                self.assertEqual(manifest, generated.manifest_path.read_bytes())
