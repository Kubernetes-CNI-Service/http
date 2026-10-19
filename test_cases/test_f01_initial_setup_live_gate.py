"""CLI recognition/consent controls; no SDK import or live connection."""
import contextlib
import hashlib
import io
import json
from pathlib import Path
import sys
import unittest
from unittest import mock
from test_cases.test_f01_initial_setup_entry import site

def invoke(argv):
    from tools import ufm_initial_setup as entry
    with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
        try:
            code = entry.main(argv)
        except SystemExit:
            return None
    return code, json.loads(out.getvalue())

class UfmInitialSetupLiveGateDirectTests(unittest.TestCase):
    def test_authenticate_is_a_real_command_but_requires_consent_before_prompt_or_sdk(self):
        before = {name: sys.modules.get(name) for name in
                  ("paramiko", "tools.ufm_bootstrap_auth_adapter")}
        with site() as (_http, project, _logs), mock.patch(
                "getpass.getpass", side_effect=AssertionError("must not prompt")):
            result = invoke(["authenticate", "--project", str(project),
                             "--address", "192.0.2.21"])
            self.assertIsNotNone(result, "AUTHENTICATE_LIVE_GATE_ENTRY_MISSING")
            code, data = result
            self.assertEqual((2, "HOLD", False), (code, data["state"], data["completion"]))
        self.assertEqual(before, {name: sys.modules.get(name) for name in before})

    def test_establish_keys_missing_consent_and_wrong_pin_never_prompt_or_import_sdk(self):
        before = {name: sys.modules.get(name) for name in
                  ("paramiko", "tools.ufm_bootstrap_auth_adapter")}
        with site() as (_http, project, logs), mock.patch(
                "getpass.getpass", side_effect=AssertionError("must not prompt")):
            known = logs.parent / "known_hosts"
            known.write_bytes(b"INDEPENDENT_PIN_GATE_FIXTURE_NOT_HOST_AUTHORITY\n")
            known.chmod(0o600)
            digest = hashlib.sha256(known.read_bytes()).hexdigest()
            base = ["establish-keys", "--project", str(project), "--address", "192.0.2.21",
                    "--private-logs-root", str(logs)]
            variants = [
                [],
                ["--allow-device-access"],
                ["--allow-device-access", "--known-hosts", str(known),
                 "--known-hosts-sha256", digest],
                ["--allow-device-access", "--allow-key-change", "--known-hosts", str(known),
                 "--known-hosts-sha256", "0" * 64],
            ]
            for flags in variants:
                with self.subTest(flags=tuple(flags)):
                    result = invoke(base + flags)
                    self.assertIsNotNone(result, "KEY_BACKUP_LIVE_GATE_ENTRY_MISSING")
                    code, data = result
                    self.assertEqual((2, "HOLD", False),
                                     (code, data["state"], data["completion"]))
            self.assertEqual([], list(logs.iterdir()))
        self.assertEqual(before, {name: sys.modules.get(name) for name in before})
