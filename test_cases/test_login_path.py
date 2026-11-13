"""WP3 parser and WP4 local editor/refresh contracts, r508 K7 and items 1-8.

Only public synthetic keys and known_hosts are used in owned HOME/TMPDIR.
Real local ssh-keygen is bounded to those files; no SSH, device or KAT is used.
"""
from __future__ import annotations

import importlib.util
import ast
from dataclasses import replace
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest
from unittest import mock


FINGERPRINT = "SHA256:" + "A" * 43
KNOWN_HOSTS = "/home/cumulus/.ssh/known_hosts"


def warning(address="192.0.2.10", *, path=KNOWN_HOSTS, fingerprint=FINGERPRINT):
    return ("WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!\r\n"
            "The fingerprint for the ED25519 key sent by the remote host is\r\n"
            + fingerprint + ".\r\n"
            "Offending ECDSA key in " + path + ":7\r\n"
            "Offending RSA key in " + path + ":9\r\n"
            "  remove with:\r\n  ssh-keygen -f \"" + path + "\" -R \"" + address + "\"\r\n"
            "Host key for " + address + " has changed and you have requested strict checking.\r\n"
            "Host key verification failed.\r\n")


def parser_module(test):
    # A missing planned interface is an explicit assertion RED, not import ERROR.
    test.assertIsNotNone(importlib.util.find_spec("tools.login_path"),
                         "r504 WP-3 requires the single real tools.login_path parser")
    from tools import login_path
    return login_path


class LoginPathHostKeyTests(unittest.TestCase):
    def test_parse_openssh_warning_with_crlf_and_multiple_offending_lines(self):
        # r504 :717-719: preserve original address and every Offending line.
        api = parser_module(self)
        result = api.parse_host_key_change(warning(), location="jump", jump="EXAMPLE-JUMP01")
        self.assertIs(type(result), api.HostKeyChange)
        self.assertEqual(("192.0.2.10", "ED25519", FINGERPRINT, KNOWN_HOSTS,
                          (7, 9), "jump", "EXAMPLE-JUMP01"),
                         (result.address, result.key_type, result.new_fingerprint,
                          result.known_hosts_path, result.lines, result.location, result.jump))
        self.assertEqual({"address", "key_type", "new_fingerprint", "known_hosts_path",
                          "lines", "location", "jump"}, set(vars(result)))

    def test_unparseable_warning_returns_none(self):
        # r504 :718: missing required fingerprint/Offending/address cannot trigger handling.
        api = parser_module(self)
        raw = warning()
        variants = (raw.replace(FINGERPRINT, "no-fingerprint"),
                    "\n".join(line for line in raw.splitlines() if "Offending" not in line),
                    "\n".join(line for line in raw.splitlines()
                              if "ssh-keygen" not in line and "Host key for" not in line))
        for text in variants:
            with self.subTest(missing=text != raw):
                self.assertIsNone(api.parse_host_key_change(text, location="jump", jump="EXAMPLE-JUMP01"))

    def test_address_validation_and_local_context(self):
        # r504 K7/WP-4 item3: IPv4 or scoped link-local, never names/shell fragments.
        api = parser_module(self)
        for address in ("192.0.2.10", "fe80::10%vlan1000"):
            with self.subTest(address=address):
                result = api.parse_host_key_change(warning(address), location="local")
                self.assertIsNotNone(result)
                self.assertEqual(address, result.address)
                self.assertEqual("local", result.location)
                self.assertIsNone(result.jump)
        for address in ("example-ib01", "192.0.2.10;true", "fe80::10", "2001:db8::10%eth0"):
            with self.subTest(address=address):
                self.assertIsNone(api.parse_host_key_change(warning(address), location="local"))

    def test_host_key_for_line_can_supply_the_original_address(self):
        api = parser_module(self)
        text = "\n".join(line for line in warning().splitlines() if "ssh-keygen" not in line)
        result = api.parse_host_key_change(text, location="local")
        self.assertIsNotNone(result)
        self.assertEqual("192.0.2.10", result.address)


class LocalHostKeyRefreshTests(unittest.TestCase):
    """r508 WP4 720-733: real synthetic files; independent ordered assertions."""

    @classmethod
    def setUpClass(cls):
        cls.keys_root = tempfile.TemporaryDirectory(prefix="wp4-public-keys-")
        cls.addClassCleanup(cls.keys_root.cleanup)
        environment = mock.patch.dict(os.environ, {"HOME": cls.keys_root.name, "TMPDIR": cls.keys_root.name})
        environment.start()
        cls.addClassCleanup(environment.stop)
        cls.keys = {}
        for name, kind in (("old", "ed25519"), ("new", "ed25519"), ("rsa", "rsa")):
            path = Path(cls.keys_root.name) / name
            command = ["ssh-keygen", "-q", "-t", kind, "-N", "", "-f", str(path)]
            if kind == "rsa":
                command += ["-b", "2048"]
            subprocess.run(command, check=True, capture_output=True, timeout=20)
            public = path.with_suffix(".pub").read_text().split()
            fingerprint = subprocess.run(["ssh-keygen", "-l", "-f", str(path.with_suffix(".pub"))],
                                         check=True, capture_output=True, text=True, timeout=10).stdout.split()[1]
            cls.keys[name] = (" ".join(public[:2]), fingerprint)

    @classmethod
    def tearDownClass(cls):
        cls.keys_root.cleanup()

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="wp4-editor-")
        self.addCleanup(self.folder.cleanup)
        self.home = Path(self.folder.name).resolve()
        environment = mock.patch.dict(os.environ, {"HOME": str(self.home), "TMPDIR": str(self.home)})
        environment.start()
        self.addCleanup(environment.stop)
        (self.home / ".ssh").mkdir(mode=0o700)
        self.path = self.home / ".ssh" / "known_hosts"
        self.before = ("192.0.2.11 " + self.keys["old"][0] + "\n"
                       "192.0.2.10 " + self.keys["old"][0] + "\n"
                       "192.0.2.10 " + self.keys["rsa"][0] + "\n"
                       "192.0.2.12 " + self.keys["old"][0] + "\n")
        self.path.write_text(self.before)
        self.path.chmod(0o640)
        self.api = parser_module(self)

    def editor(self):
        self.assertTrue(hasattr(self.api, "LocalKnownHostsEditor"), "r508 WP4 local editor required")
        return self.api.LocalKnownHostsEditor(self.path, home=self.home)

    def change(self, **kwargs):
        return replace(self.api.HostKeyChange("192.0.2.10", "ED25519", self.keys["new"][1],
                                             str(self.path), (2,), "local", None), **kwargs)

    def refresh(self, editor=None, *, reader=None, retry=None, forced=False, change=None):
        self.assertTrue(hasattr(self.api, "refresh_target_host_key"), "r508 WP4 ordered refresh required")
        return self.api.refresh_target_host_key(
            change or self.change(), editor or self.editor(),
            read_device_fingerprint=reader, retry=retry or self.accept_new, operator_forced=forced)

    def accept_new(self):
        with self.path.open("a") as output:
            output.write("192.0.2.10 " + self.keys["new"][0] + "\n")

    def test_local_editor_removes_only_target_lines(self):
        # r508 :721-723, D34-O3(a): every target key type, no other content change.
        editor = self.editor()
        self.assertEqual([(2, "ED25519", self.keys["old"][1]), (3, "RSA", self.keys["rsa"][1])],
                         editor.fingerprints("192.0.2.10"))
        before = self.path.stat()
        receipt = editor.remove("192.0.2.10")
        after = self.path.stat()
        self.assertEqual("".join(self.before.splitlines(True)[index] for index in (0, 3)), self.path.read_text())
        self.assertEqual([], editor.fingerprints("192.0.2.10"))
        self.assertEqual(self.before, self.path.with_name("known_hosts.old").read_text())
        self.assertEqual(((2, 3), True, before.st_ino, after.st_ino,
                          stat.S_IMODE(before.st_mode), stat.S_IMODE(after.st_mode)),
                         (receipt.lines, receipt.old_file, receipt.inode_before, receipt.inode_after,
                          receipt.mode_before, receipt.mode_after))

    def test_hashed_lookup_and_remove_match_the_same_target(self):
        editor = self.editor()
        subprocess.run(["ssh-keygen", "-H", "-f", str(self.path)], check=True,
                       capture_output=True, timeout=10)
        before = self.path.read_bytes().splitlines(True)
        self.assertEqual([2, 3], [row[0] for row in editor.fingerprints("192.0.2.10")])
        editor.remove("192.0.2.10")
        self.assertEqual(before[0] + before[3], self.path.read_bytes())

    def test_keygen_process_inherits_only_owned_home(self):
        # r508 :766: HOME is an actual subprocess environment boundary, not just -f.
        editor = self.editor()
        real_run = self.api.subprocess.run
        seen = []
        def observe(argv, **kwargs):
            environment = kwargs.get("env", os.environ)
            seen.append(environment.get("HOME"))
            self.assertEqual(str(self.home), environment.get("HOME"))
            return real_run(argv, **kwargs)
        with mock.patch.object(self.api.subprocess, "run", side_effect=observe):
            editor.fingerprints("192.0.2.10")
        self.assertEqual([str(self.home)], seen)

    def test_local_editor_refuses_other_files_and_links(self):
        self.editor()
        other = self.home / "other"
        other.write_text("PUBLIC non-host file")
        for path in (other, Path("/etc/ssh/ssh_known_hosts")):
            with self.subTest(path=str(path)), self.assertRaises(ValueError):
                self.api.LocalKnownHostsEditor(path, home=self.home)
        self.path.unlink()
        self.path.symlink_to(other)
        with self.assertRaises(ValueError):
            self.api.LocalKnownHostsEditor(self.path, home=self.home)
        self.assertEqual("PUBLIC non-host file", other.read_text())

    def test_editor_address_validation_precedes_subprocess(self):
        editor = self.editor()
        with mock.patch.object(self.api.subprocess, "run", side_effect=AssertionError("invalid address executed")):
            for address in ("name.example.test", "192.0.2.10;true", "192.0.2.10 x", "fe80::1"):
                with self.subTest(address=address), self.assertRaises(ValueError):
                    editor.remove(address)
        self.assertEqual(self.before, self.path.read_text())

    def test_verified_change_deletes_retries_and_records(self):
        calls = []
        def reader(kind):
            calls.append(("verify", kind))
            self.assertEqual(self.before, self.path.read_text())
            return self.keys["new"][1]
        def retry():
            calls.append(("retry",))
            self.assertNotIn("192.0.2.10", self.path.read_text())
            self.accept_new()
        record = self.refresh(reader=reader, retry=retry)
        self.assertEqual([("verify", "ED25519"), ("retry",)], calls)
        self.assertEqual(("local", None, str(self.path), (2, 3), "192.0.2.10", "ED25519",
                          (self.keys["old"][1], self.keys["rsa"][1]), self.keys["new"][1],
                          "verified", "refreshed"),
                         (record.location, record.jump, record.known_hosts_path, record.lines,
                          record.address, record.key_type, record.old_fingerprints,
                          record.new_fingerprint, record.verification, record.result))
        self.assertIs(type(record.removal), self.api.RemovalReceipt)
        self.assertNotIn("@@@@", repr(record))

    def test_mismatch_or_unreadable_refuses_without_deleting(self):
        for reader in (None, lambda _: None, lambda _: self.keys["old"][1], lambda _: "A" * 43):
            with self.subTest(reader=reader):
                with self.assertRaisesRegex(ValueError, "refresh-host-key|fingerprint"):
                    self.refresh(reader=reader)
                self.assertEqual(self.before, self.path.read_text())
                self.assertFalse(self.path.with_name("known_hosts.old").exists())

    def test_offending_lines_must_be_subset_of_lookup(self):
        with self.assertRaisesRegex(ValueError, "Offending|offending"):
            self.refresh(reader=lambda _: self.keys["new"][1], change=self.change(lines=(2, 99)))
        self.assertEqual(self.before, self.path.read_text())
        self.refresh(reader=lambda _: self.keys["new"][1])  # (2,) is a proper subset of (2,3).

    def test_delete_is_followed_by_empty_lookup_before_retry(self):
        editor = self.editor()
        retry = mock.Mock()
        with mock.patch.object(editor, "remove", return_value=None):
            with self.assertRaisesRegex(ValueError, "removed|remain"):
                self.refresh(editor, reader=lambda _: self.keys["new"][1], retry=retry)
        retry.assert_not_called()

    def test_operator_forced_skips_verification_only(self):
        reader = mock.Mock(side_effect=AssertionError("forced must not read device"))
        record = self.refresh(reader=reader, forced=True)
        self.assertEqual("operator-forced-unverified", record.verification)
        reader.assert_not_called()

    def test_forced_still_requires_offending_subset(self):
        with self.assertRaises(ValueError):
            self.refresh(forced=True, change=self.change(lines=(99,)))
        self.assertEqual(self.before, self.path.read_text())

    def test_post_retry_fingerprint_mismatch_fails(self):
        def wrong_retry():
            with self.path.open("a") as output:
                output.write("192.0.2.10 " + self.keys["old"][0] + "\n")
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.refresh(reader=lambda _: self.keys["new"][1], retry=wrong_retry)

    def test_forced_still_checks_post_retry_fingerprint(self):
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            self.refresh(forced=True, retry=lambda: None)

    def test_failed_write_leaves_file_unchanged(self):
        editor = self.editor()
        real_run = self.api.subprocess.run
        def fail_remove(argv, **kwargs):
            if "-R" in argv:
                return subprocess.CompletedProcess(argv, 1, "", "PUBLIC lookup failure")
            return real_run(argv, **kwargs)
        with mock.patch.object(self.api.subprocess, "run", side_effect=fail_remove):
            with self.assertRaisesRegex(ValueError, "remove|failed"):
                editor.remove("192.0.2.10")
        self.assertEqual(self.before, self.path.read_text())

    def test_record_never_carries_raw_banner(self):
        with self.assertRaises(ValueError) as caught:
            self.refresh(reader=lambda _: "@@@@ PUBLIC warning")
        self.assertNotIn("@@@@", str(caught.exception))

    def test_refresh_has_one_exact_ordered_transaction(self):
        self.assertTrue(hasattr(self.api, "refresh_target_host_key"))
        events = []
        receipt = self.api.RemovalReceipt((2, 3), True, 1, 2, 0o640, 0o600)
        previous = [(2, "ED25519", self.keys["old"][1]), (3, "RSA", self.keys["rsa"][1])]
        editor = mock.Mock()
        editor.fingerprints.side_effect = lambda address: events.append("lookup") or [previous, [], [(2, "ED25519", self.keys["new"][1])]][events.count("lookup") - 1]
        editor.remove.side_effect = lambda address: events.append("remove") or receipt
        self.refresh(editor, reader=lambda _: events.append("verify") or self.keys["new"][1],
                     retry=lambda: events.append("retry"))
        self.assertEqual(["verify", "lookup", "remove", "lookup", "retry", "lookup"], events)

    def test_unreadable_device_fingerprint_is_fixed_refusal(self):
        def unreadable(_kind):
            raise OSError("@@@@ PUBLIC remote output must not escape")
        with self.assertRaises(ValueError) as caught:
            self.refresh(reader=unreadable)
        self.assertIn("refresh-host-key", str(caught.exception))
        self.assertNotIn("@@@@", str(caught.exception))
        self.assertEqual(self.before, self.path.read_text())

    def test_callback_control_and_interrupts_preserve_identity(self):
        for error in (RuntimeError("PUBLIC control stop"), KeyboardInterrupt(), SystemExit(9)):
            with self.subTest(kind=type(error).__name__):
                def stopped(_kind):
                    raise error
                with self.assertRaises(type(error)) as caught:
                    self.refresh(reader=stopped)
                self.assertIs(error, caught.exception)
                self.assertEqual(self.before, self.path.read_text())

    def test_module_imports_and_subprocess_are_closed(self):
        self.editor()
        tree = ast.parse(Path(self.api.__file__).read_text())
        calls = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
                if node.func.value.id == "subprocess":
                    owners = [owner.name for owner in ast.walk(tree)
                              if isinstance(owner, ast.FunctionDef) and node in ast.walk(owner)]
                    calls.append((node.func.attr, owners))
        self.assertEqual([("run", ["fingerprints"]), ("run", ["remove"])], calls)
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        allowed = {"__future__", "dataclasses", "ipaddress", "pathlib", "re", "shlex", "stat", "subprocess", "typing",
                   "tools.device_identity", "tools.hostname_ranges"}
        sources = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertTrue(set(imports + sources).issubset(allowed))
        self.assertFalse({"hashlib", "base64", "argparse"} & set(imports))
        self.assertNotIn('"ssh"', Path(self.api.__file__).read_text())


    def test_optional_write_permission_runs_after_verification_and_before_remove(self):
        # WP5 caller owns first-change authority; the library receives no credentials.
        events = []
        def permit():
            events.append("permit")
            self.assertEqual(self.before, self.path.read_text())
        self.api.refresh_target_host_key(self.change(), self.editor(),
            read_device_fingerprint=lambda _: events.append("verify") or self.keys["new"][1],
            retry=lambda: events.append("retry") or self.accept_new(), operator_forced=False,
            before_remove=permit)
        self.assertEqual(["verify", "permit", "retry"], events)

    def test_permission_is_not_requested_for_unverified_or_stale_change(self):
        for change, reader in ((self.change(), lambda _: None),
                               (self.change(lines=(99,)), lambda _: self.keys["new"][1])):
            permit = mock.Mock(side_effect=AssertionError("invalid change requested write permission"))
            with self.assertRaises(ValueError):
                self.api.refresh_target_host_key(change, self.editor(),
                    read_device_fingerprint=reader, retry=self.accept_new, operator_forced=False,
                    before_remove=permit)
            permit.assert_not_called()
            self.assertEqual(self.before, self.path.read_text())

    def test_write_permission_control_identity_is_not_swallowed(self):
        error = KeyboardInterrupt()
        def stop():
            raise error
        with self.assertRaises(KeyboardInterrupt) as caught:
            self.api.refresh_target_host_key(self.change(), self.editor(),
                read_device_fingerprint=lambda _: self.keys["new"][1], retry=self.accept_new,
                operator_forced=False, before_remove=stop)
        self.assertIs(error, caught.exception)
        self.assertEqual(self.before, self.path.read_text())


if __name__ == "__main__":
    unittest.main()
