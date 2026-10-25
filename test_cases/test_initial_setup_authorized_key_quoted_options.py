#!/usr/bin/env python3
"""PUBLIC generated-shell regression; no real HOME/SSH/network is used.
O-only prospective managed test text; not executed during authoring.
"""
from __future__ import annotations
import base64
import hashlib
import os
from pathlib import Path
import shlex
import stat
import struct
import subprocess
import tempfile
import unittest
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("initial_quoted_option_regression",
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

def public_key(number):
    algorithm = b"ssh-ed25519"
    blob = struct.pack(">I", len(algorithm)) + algorithm + struct.pack(">I", 32) + bytes([number]) * 32
    return ("ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " PUBLIC-key-" + str(number),
            "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode("ascii"))

def held_auth(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode):
            raise AssertionError("PUBLIC auth fixture must be REG")
        chunks = []
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            chunks.append(chunk)
        raw = b"".join(chunks)
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        nine = tuple(getattr(first, name) for name in fields)
        if nine != tuple(getattr(os.fstat(fd), name) for name in fields):
            raise AssertionError("PUBLIC fixture changed while held")
        if nine != tuple(getattr(path.lstat(), name) for name in fields):
            raise AssertionError("PUBLIC auth fixture name changed")
        return nine, raw
    finally:
        os.close(fd)

class QuotedAuthorizedKeysGeneratedShellTests(unittest.TestCase):
    def _install(self, home, request):
        line, fingerprint = public_key(request)
        argv = APP.key_install_command([{
            "name": "PUBLIC-request.pub", "line": line, "fingerprint": fingerprint,
        }])
        self.assertEqual(["sh", "-c"], argv[:2])
        self.assertEqual("--", argv[3])
        self.assertEqual(5, len(argv))
        # Only fixture-home bindings change. The actual canonical generated
        # shell and its real awk/base64/staging/replace are not mocked.
        script = argv[2].replace('"${HOME:-}"', shlex.quote(str(home))).replace(
            '"$HOME"', shlex.quote(str(home))).replace(
            '"$HOME/.ssh"', shlex.quote(str(home / ".ssh")))
        self.assertNotIn("$HOME", script)
        return subprocess.run(
            [argv[0], "-c", script, *argv[3:]],
            cwd=home, env={"HOME": str(home), "PATH": os.defpath, "LC_ALL": "C", "LANG": "C"},
            capture_output=True, text=True, timeout=5, check=False,
        )

    def _fixture(self, folder, old):
        home = Path(folder)
        ssh = home / ".ssh"
        ssh.mkdir(mode=0o700)
        auth = ssh / "authorized_keys"
        auth.write_bytes(old)
        auth.chmod(0o600)
        canary = ssh / "PUBLIC.canary"
        canary.write_bytes(b"PUBLIC unrelated sibling stays unchanged\n")
        canary.chmod(0o600)
        return home, ssh, auth, canary

    def test_quoted_fake_algorithm_cannot_drop_two_distinct_existing_keys(self):
        first, _ = public_key(1)
        second, _ = public_key(2)
        requested, _ = public_key(3)
        option = 'command="echo ssh-ed25519 FAKE",no-agent-forwarding '
        old_first, old_second = option + first, option + second
        old = ("# PUBLIC owner comment\n" + old_first + "\n" + old_second + "\n").encode("ascii")
        expected = old + (requested + "\n").encode("ascii")
        with tempfile.TemporaryDirectory() as folder:
            home, ssh, auth, canary = self._fixture(folder, old)
            canary_before = held_auth(canary)
            result = self._install(home, 3)
            auth_after = held_auth(auth)
            canary_after = held_auth(canary)
            names_after = sorted(path.name for path in ssh.iterdir())
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertEqual(expected, auth_after[1])
            self.assertEqual(1, auth_after[1].splitlines().count(old_first.encode("ascii")))
            self.assertEqual(1, auth_after[1].splitlines().count(old_second.encode("ascii")))
            self.assertEqual(1, auth_after[1].splitlines().count(requested.encode("ascii")))
            self.assertEqual(canary_before, canary_after)
            self.assertEqual(["PUBLIC.canary", "authorized_keys"], names_after)
            # Repeated install must neither strip restrictions nor grow an
            # unrestricted duplicate or replace already-correct authorization.
            again = self._install(home, 3)
            repeated = held_auth(auth)
            self.assertEqual(0, again.returncode, again.stderr)
            self.assertEqual(auth_after[0][:2], repeated[0][:2])
            self.assertEqual(auth_after[1], repeated[1])
            self.assertEqual(0o600, stat.S_IMODE(repeated[0][2]))
            self.assertEqual(canary_before, held_auth(canary))

    def test_unknown_quote_or_escape_syntax_holds_before_authorization_replace(self):
        first, _ = public_key(1)
        malformed = (
            'command="PUBLIC unclosed ssh-ed25519 FAKE ' + first + "\n",
            'command="PUBLIC dangling escape' + "\\" + "\n",
        )
        for raw in malformed:
            with self.subTest(grammar=raw), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, raw.encode("ascii"))
                auth_before = held_auth(auth)
                canary_before = held_auth(canary)
                result = self._install(home, 3)
                auth_after = held_auth(auth)
                canary_after = held_auth(canary)
                names_after = sorted(path.name for path in ssh.iterdir())
                self.assertNotEqual(0, result.returncode)
                self.assertEqual(auth_before, auth_after)
                self.assertEqual(canary_before, canary_after)
                self.assertEqual(["PUBLIC.canary", "authorized_keys"], names_after)
                self.assertNotIn("IBSW_PUBLIC_KEYS_UPDATED", result.stdout)
                self.assertNotIn("IBSW_PUBLIC_KEYS_UNCHANGED", result.stdout)


    def _accepted(self, result, auth_before, auth, canary_before, canary, ssh,
                  expected, *, same_inode):
        auth_after, canary_after = held_auth(auth), held_auth(canary)
        members = sorted(path.name for path in ssh.iterdir())
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual(expected, auth_after[1])
        self.assertEqual(0o600, stat.S_IMODE(auth_after[0][2]))
        self.assertEqual(canary_before, canary_after)
        self.assertEqual(["PUBLIC.canary", "authorized_keys"], members)
        if same_inode:
            self.assertEqual(auth_before[0][:2], auth_after[0][:2])
        return auth_after

    def _rejected(self, result, auth_before, auth, canary_before, canary, ssh):
        auth_after, canary_after = held_auth(auth), held_auth(canary)
        members = sorted(path.name for path in ssh.iterdir())
        self.assertNotEqual(0, result.returncode)
        self.assertEqual(auth_before, auth_after)
        self.assertEqual(canary_before, canary_after)
        self.assertEqual(["PUBLIC.canary", "authorized_keys"], members)
        self.assertNotIn("IBSW_PUBLIC_KEYS_UPDATED", result.stdout)
        self.assertNotIn("IBSW_PUBLIC_KEYS_UNCHANGED", result.stdout)

    def test_existing_same_identity_restrictions_and_exact_duplicates_are_not_deduplicated(self):
        first, _ = public_key(1)
        third, _ = public_key(3)
        restricted_a = "restrict " + first
        restricted_b = 'command="echo PUBLIC two",no-agent-forwarding ' + first
        old = ("# PUBLIC retain order\n" + restricted_a + "\n" + restricted_b
               + "\n" + restricted_a + "\n").encode("ascii")
        for request, expected, same_inode in (
            (1, old, True),
            (3, old + (third + "\n").encode("ascii"), False),
        ):
            with self.subTest(request=request), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, old)
                before, canary_before = held_auth(auth), held_auth(canary)
                result = self._install(home, request)
                after = self._accepted(
                    result, before, auth, canary_before, canary, ssh,
                    expected, same_inode=same_inode)
                self.assertEqual(2, after[1].splitlines().count(restricted_a.encode("ascii")))
                self.assertEqual(1, after[1].splitlines().count(restricted_b.encode("ascii")))
                self.assertEqual(0, after[1].splitlines().count(first.encode("ascii")))

    def test_empty_and_unterminated_old_file_have_independent_record_boundaries(self):
        first, _ = public_key(1)
        third, _ = public_key(3)
        cases = (
            ("empty-old", b"", 3, (third + "\n").encode("ascii"), False),
            ("append-after-noLF", first.encode("ascii"), 3,
             (first + "\n" + third + "\n").encode("ascii"), False),
            ("already-present-noLF", first.encode("ascii"), 1,
             first.encode("ascii"), True),
        )
        for label, old, request, expected, same_inode in cases:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, old)
                before, canary_before = held_auth(auth), held_auth(canary)
                result = self._install(home, request)
                self._accepted(result, before, auth, canary_before, canary, ssh,
                               expected, same_inode=same_inode)

    def test_only_approved_quoted_escape_and_option_spellings_are_admitted(self):
        first, _ = public_key(1)
        # Every escape below is fixture data, never shell-evaluated.
        good = ('command="echo \\"PUBLIC quoted\\" ssh-ed25519 FAKE",no-pty '
                + first + "\n").encode("ascii")
        cases = (
            ("escaped-doublequote", good, True),
            ("unknown-escape", ('command="echo \\q" ' + first + "\n").encode("ascii"), False),
            ("outside-quote-escape", ("no-pty\\ " + first + "\n").encode("ascii"), False),
            ("backslash-backslash", ('command="echo \\\\" ' + first + "\n").encode("ascii"), False),
            ("unknown-option", ("PUBLIC-unknown-option " + first + "\n").encode("ascii"), False),
            ("unquoted-value", ("command=PUBLIC " + first + "\n").encode("ascii"), False),
        )
        for label, old, accepted in cases:
            with self.subTest(grammar=label), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, old)
                before, canary_before = held_auth(auth), held_auth(canary)
                result = self._install(home, 1)
                if accepted:
                    self._accepted(result, before, auth, canary_before, canary, ssh,
                                   old, same_inode=True)
                else:
                    self._rejected(result, before, auth, canary_before, canary, ssh)

    def test_canonical_base64_and_ambiguous_legacy_identity_are_distinguished(self):
        # PUBLIC RSA wire structure only; no private key/crypto authentication.
        # 278 bytes ends with 55 01 hex, independently fixing the literal VQE=
        # suffix. VQF= differs only in unused pad bits but decodes to same bytes.
        def field(raw):
            return struct.pack(">I", len(raw)) + raw
        blob = (field(b"ssh-rsa") + field(b"\x01\x00\x01")
                + field(b"\x7f" + b"\x55" * 254 + b"\x01"))
        canonical = base64.b64encode(blob).decode("ascii")
        self.assertEqual(278, len(blob))
        self.assertTrue(canonical.endswith("VQE="))
        ambiguous = canonical[:-2] + "F="
        self.assertEqual(
            base64.b64decode(canonical, validate=True),
            base64.b64decode(ambiguous, validate=True),
        )
        third, _ = public_key(3)
        cases = (
            ("canonical", canonical, True),
            ("nonzero-padbits", ambiguous, False),
            ("missing-padding", canonical[:-1], False),
            ("excess-padding", canonical + "=", False),
            ("interior-padding", canonical[:10] + "=" + canonical[11:], False),
            ("unknown-alphabet", canonical[:10] + "?" + canonical[11:], False),
        )
        for label, encoded, accepted in cases:
            old = ("ssh-rsa " + encoded + " PUBLIC-old-wire\n").encode("ascii")
            with self.subTest(base64=label), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, old)
                before, canary_before = held_auth(auth), held_auth(canary)
                result = self._install(home, 3)
                if accepted:
                    self._accepted(
                        result, before, auth, canary_before, canary, ssh,
                        old + (third + "\n").encode("ascii"), same_inode=False)
                else:
                    self._rejected(result, before, auth, canary_before, canary, ssh)

    def test_crlf_old_bytes_survive_but_nonterminal_carriage_return_holds(self):
        first, _ = public_key(1)
        second, _ = public_key(2)
        third, _ = public_key(3)
        old = ("# PUBLIC Windows owner comment\r\nrestrict " + first
               + "\r\n" + second + "\r\n").encode("ascii")
        cases = (
            ("existing-CRLF", old, 1, old, True, True),
            ("append-after-CRLF", old, 3, old + (third + "\n").encode("ascii"), False, True),
            ("interior-CR", ("restrict\r " + first + "\n").encode("ascii"),
             3, None, False, False),
        )
        for label, raw, request, expected, same_inode, accepted in cases:
            with self.subTest(records=label), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, raw)
                before, canary_before = held_auth(auth), held_auth(canary)
                result = self._install(home, request)
                if accepted:
                    self._accepted(result, before, auth, canary_before, canary, ssh,
                                   expected, same_inode=same_inode)
                else:
                    self._rejected(result, before, auth, canary_before, canary, ssh)

    def test_required_tr_utility_missing_holds_without_install_or_authorization_change(self):
        import shutil
        from unittest import mock
        first, _ = public_key(1)
        third, _ = public_key(3)
        old = (first + "\n").encode("ascii")
        real_run = subprocess.run
        # Same closed native utility set; only tr presence differs. The positive
        # exercises the real generated program too, preventing a broken PATH
        # from laundering any arbitrary child failure into the negative oracle.
        utilities = ("mkdir", "chmod", "mktemp", "cat", "base64",
                     "awk", "cmp", "mv", "rm", "tail", "tr")
        for tr_available in (True, False):
            with self.subTest(tr_available=tr_available), tempfile.TemporaryDirectory() as folder:
                home, ssh, auth, canary = self._fixture(folder, old)
                tools = home / "PUBLIC-utility-bin"
                tools.mkdir(mode=0o700)
                for name in utilities:
                    path = shutil.which(name, path=os.defpath)
                    if not path:
                        raise RuntimeError("FIXTURE_HOLD: real standard utility missing")
                    target = Path(path).resolve(strict=True)
                    metadata = target.stat()
                    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & 0o022:
                        raise RuntimeError("FIXTURE_HOLD: real standard utility not qualified")
                    if name != "tr" or tr_available:
                        (tools / name).symlink_to(target)
                forbidden = home / "PUBLIC-forbidden-tool-attempts"
                for command in ("apt", "apt-get", "dpkg", "sudo", "pip", "pip3",
                                "ssh", "sshpass", "curl", "wget"):
                    trap = tools / command
                    trap.write_text(
                        "#!/bin/sh\nprintf '%s\\n' " + shlex.quote(command)
                        + " >> " + shlex.quote(str(forbidden)) + "\nexit 97\n",
                        encoding="ascii",
                    )
                    trap.chmod(0o700)
                before, canary_before = held_auth(auth), held_auth(canary)
                calls = []

                def own_utility_environment(argv, **kwargs):
                    if (not isinstance(argv, list) or argv[:2] != ["sh", "-c"]
                            or len(argv) != 5 or argv[3] != "--"):
                        raise RuntimeError("FIXTURE_HOLD: unexpected local program")
                    call = ["/bin/sh", *argv[1:]]
                    actual = dict(kwargs)
                    actual["env"] = dict(kwargs["env"], PATH=str(tools))
                    calls.append((call, actual["env"]["PATH"]))
                    return real_run(call, **actual)

                with mock.patch.object(subprocess, "run", side_effect=own_utility_environment):
                    result = self._install(home, 3)
                self.assertEqual(1, len(calls))
                self.assertEqual(str(tools), calls[0][1])
                self.assertEqual(tr_available, (tools / "tr").exists())
                self.assertFalse(forbidden.exists())
                if tr_available:
                    self._accepted(
                        result, before, auth, canary_before, canary, ssh,
                        old + (third + "\n").encode("ascii"), same_inode=False)
                else:
                    self._rejected(result, before, auth, canary_before, canary, ssh)

if __name__ == "__main__":
    unittest.main()
