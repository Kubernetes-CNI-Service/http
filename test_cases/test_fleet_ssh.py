"""Fleet jobs (IB upgrade v2): SSH sessions (review 15.1, 15.13, 15.14).

An in-process paramiko server on a socketpair stands in for a switch (no listening
port, no real device). Host keys are pinned from known_hosts including hashed entries,
the key is tried first and the password only after an explicit rejection, commands are
bounded from the moment they are sent and secrets never show in a repr.
"""
import base64
import hashlib
import hmac
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_ssh as ssh  # noqa: E402

ADDRESS = "192.0.2.30"
PASSWORD = "secret-value"


def sdk():
    return ssh._sdk()


class FakeSwitch:
    """Answers exec requests: `echo-stdin`, `fail`, `hang`, anything else echoes the command."""

    def __init__(self, *, accept_key=True):
        paramiko = sdk()
        self.host_key = paramiko.ECDSAKey.generate()
        self.client_key = paramiko.ECDSAKey.generate()
        self.accept_key = accept_key
        self.threads = []

    def known_hosts(self, *, hashed=False, key=None):
        key = key or self.host_key
        host = ADDRESS
        if hashed:
            salt = os.urandom(20)
            digest = hmac.new(salt, ADDRESS.encode(), hashlib.sha1).digest()
            host = "|1|" + base64.b64encode(salt).decode() + "|" + base64.b64encode(digest).decode()
        return f"{host} {key.get_name()} {key.get_base64()}\n".encode()

    def socket(self, _address, _timeout):
        client, server = socket.socketpair()
        thread = threading.Thread(target=self._serve, args=(server,), daemon=True)
        thread.start()
        self.threads.append(thread)
        return client

    def _serve(self, sock):
        paramiko = sdk()
        switch = self

        class Interface(paramiko.ServerInterface):
            def __init__(self):
                self.commands = {}

            def get_allowed_auths(self, username):
                return "publickey,password"

            def check_auth_publickey(self, username, key):
                if switch.accept_key and username == "admin" and key.asbytes() == switch.client_key.asbytes():
                    return paramiko.AUTH_SUCCESSFUL
                return paramiko.AUTH_FAILED

            def check_auth_password(self, username, password):
                return paramiko.AUTH_SUCCESSFUL if (username, password) == ("admin", PASSWORD) else paramiko.AUTH_FAILED

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

            def check_channel_exec_request(self, channel, command):
                self.commands[channel.get_id()] = command.decode()
                return True

        transport = paramiko.Transport(sock)
        transport.add_server_key(self.host_key)
        interface = Interface()
        try:
            transport.start_server(server=interface)
        except Exception:
            return
        while transport.is_active():
            channel = transport.accept(timeout=1)
            if channel is None:
                continue
            for _ in range(100):
                if channel.get_id() in interface.commands:
                    break
                time.sleep(0.01)
            threading.Thread(target=self._exec, args=(channel, interface.commands.get(channel.get_id(), "")),
                             daemon=True).start()

    def _exec(self, channel, command):
        try:
            if command == "echo-stdin":
                data = b""
                while True:
                    chunk = channel.recv(65536)
                    if not chunk:
                        break
                    data += chunk
                channel.sendall(data)
                status = 0
            elif command == "fail":
                channel.sendall_stderr(b"broken\n")
                status = 3
            elif command == "hang":
                time.sleep(5)
                status = 0
            else:
                channel.sendall(command.encode() + b"\n")
                status = 0
            channel.send_exit_status(status)
            channel.shutdown_write()
        finally:
            time.sleep(0.05)
            channel.close()


class SshTest(unittest.TestCase):
    def setUp(self):
        self.switch = FakeSwitch()
        self.creds = ssh.Credentials("admin", self.switch.client_key,
                                     ssh.fingerprint(self.switch.client_key.asbytes()), PASSWORD)
        self.pins = ssh.HostPins(self.switch.known_hosts())

    def connect(self, **kwargs):
        return ssh.connect(ADDRESS, kwargs.pop("pins", self.pins), kwargs.pop("creds", self.creds),
                           sock_factory=self.switch.socket, **kwargs)

    def test_key_login_runs_commands_with_exit_status_and_stdin(self):
        with self.connect() as session:
            self.assertEqual(session.authentication, "key")
            result = session.run("hostname")
            self.assertEqual((result.rc, result.stdout, result.complete, result.ok), (0, b"hostname\n", True, True))
            failed = session.run("fail")
            self.assertEqual((failed.rc, failed.stderr, failed.ok), (3, b"broken\n", False))
            script = b"{\nprintf 'x'\n}\n" * 1000
            self.assertEqual(session.run("echo-stdin", stdin=script).stdout, script)

    def test_password_is_used_only_after_the_key_is_rejected(self):
        self.switch.accept_key = False
        session, rejected = ssh.connect_any(ADDRESS, self.pins, self.creds, sock_factory=self.switch.socket)
        with session:
            self.assertEqual((session.authentication, rejected), ("password", True))
        wrong = ssh.Credentials("admin", self.switch.client_key, None, "not-the-password")
        with self.assertRaises(ssh.SshError) as caught:
            ssh.connect_any(ADDRESS, self.pins, wrong, sock_factory=self.switch.socket)
        self.assertEqual(caught.exception.code, "PASSWORD_REJECTED",
                         "the fallback password was refused (field 2026-10-24: its own code)")
        self.assertNotIn("not-the-password", str(caught.exception))
        key_only = ssh.Credentials("admin", self.switch.client_key, None, None)
        with self.assertRaises(ssh.SshError) as caught:
            ssh.connect_any(ADDRESS, self.pins, key_only, sock_factory=self.switch.socket)
        self.assertEqual(caught.exception.code, "AUTH_REJECTED", "a rejected key keeps AUTH_REJECTED")

    def test_a_refused_password_is_password_rejected_and_never_reboot_like(self):
        """Field 2026-10-24: a mistyped password must be told apart from a rejected key, and must not be
        retried like a rebooting switch."""
        typo = ssh.Credentials("admin", self.switch.client_key, None, PASSWORD + "x")
        with self.assertRaises(ssh.SshError) as caught:
            self.connect(creds=typo, method="password")
        self.assertEqual(caught.exception.code, "PASSWORD_REJECTED")
        self.assertFalse(caught.exception.reboot_like)
        self.assertNotIn(PASSWORD, str(caught.exception))
        self.assertIn("PASSWORD_REJECTED", ssh.SshError.CODES)
        with self.connect(method="password") as session:
            self.assertEqual(session.authentication, "password")
        self.switch.accept_key = False
        with self.assertRaises(ssh.SshError) as caught:
            self.connect(method="key")
        self.assertEqual(caught.exception.code, "AUTH_REJECTED", "the key path keeps its code")

    def test_host_keys_are_pinned_never_trusted_on_first_use(self):
        other = sdk().ECDSAKey.generate()
        with self.assertRaises(ssh.SshError) as caught:
            self.connect(pins=ssh.HostPins(self.switch.known_hosts(key=other)))
        self.assertEqual(caught.exception.code, "HOST_KEY_MISMATCH")
        with self.assertRaises(ssh.SshError) as caught:
            self.connect(pins=ssh.HostPins(b"198.51.100.9 " + self.switch.known_hosts().split(b" ", 1)[1]))
        self.assertEqual(caught.exception.code, "HOST_KEY_UNKNOWN")
        hashed = ssh.HostPins(self.switch.known_hosts(hashed=True))
        with self.connect(pins=hashed) as session:
            self.assertEqual(session.run("x").rc, 0)
        self.assertEqual(hashed.known_hosts_text(ADDRESS),
                         f"{ADDRESS} {self.switch.host_key.get_name()} {self.switch.host_key.get_base64()}\n",
                         "a hashed entry is handed to a receiver switch as a literal-address line")
        revoked = ssh.HostPins(b"@revoked " + self.switch.known_hosts())
        with self.assertRaises(ssh.SshError) as caught:
            revoked.keys(ADDRESS)
        self.assertEqual(caught.exception.code, "HOST_KEY_MISMATCH")

    def test_a_hanging_command_times_out_from_when_it_was_sent(self):
        with self.connect() as session:
            started = time.monotonic()
            with self.assertRaises(ssh.SshError) as caught:
                session.run("hang", timeout=0.5)
            self.assertEqual(caught.exception.code, "COMMAND_TIMEOUT")
            self.assertLess(time.monotonic() - started, 3.0)

    def test_runtime_pins_and_host_matching_equal_ib_v1(self):
        import ibsw_upgrade_driver
        import ibsw_upgrade_observer
        self.assertEqual(ssh.SSH_RUNTIME_PINS, ibsw_upgrade_observer.SSH_RUNTIME_PINS)
        hashed = self.switch.known_hosts(hashed=True).split(b" ")[0]
        for field, endpoints in ((hashed, {ADDRESS}), (hashed, {"198.51.100.1"}), (ADDRESS.encode(), {ADDRESS}),
                                 (b"198.51.100.1,192.0.2.30", {ADDRESS}), (b"[192.0.2.30]:22", {"[192.0.2.30]:22"})):
            self.assertEqual(ssh.endpoint_matches(field, endpoints),
                             ibsw_upgrade_driver._known_host_endpoint_matches(field, endpoints))

    def test_secrets_never_show_in_a_repr(self):
        self.assertNotIn(PASSWORD, repr(self.creds))
        self.assertNotIn("PRIVATE", repr(self.creds))

    def test_private_key_must_match_the_public_key_and_be_private(self):
        with tempfile.TemporaryDirectory() as tmp:
            private, public = Path(tmp) / "id_ecdsa", Path(tmp) / "id_ecdsa.pub"
            self.switch.client_key.write_private_key_file(str(private))
            private.chmod(0o600)
            public.write_text(f"{self.switch.client_key.get_name()} {self.switch.client_key.get_base64()} fixture\n")
            key, expected = ssh.load_private_key(private, public)
            self.assertEqual(expected, ssh.fingerprint(self.switch.client_key.asbytes()))
            other = sdk().ECDSAKey.generate()
            public.write_text(f"{other.get_name()} {other.get_base64()} fixture\n")
            with self.assertRaises(ssh.SshError):
                ssh.load_private_key(private, public)
            private.chmod(0o644)
            with self.assertRaises(ssh.SshError):
                ssh.load_private_key(private, public)


if __name__ == "__main__":
    unittest.main()
