"""Tests-first canonical key receipt consumption at the existing stage API.

Only the installer SessionResult boundary is modeled. The real key command
builder and stage consumer execute; no SSH, shell or crypto backend is invoked
by this direct module. PUBLIC wire keys contain no private material.
"""
from __future__ import annotations

import base64
from contextlib import redirect_stdout
import hashlib
import io
from pathlib import Path
import struct
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script(
    "initial_key_receipt_consumer_direct",
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
)


def public_key(seed: int) -> str:
    algorithm = b"ssh-ed25519"
    wire = (struct.pack(">I", len(algorithm)) + algorithm
            + struct.pack(">I", 32) + bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(wire).decode("ascii") + " PUBLIC-N2"


def public_fingerprint(line: str) -> str:
    wire = base64.b64decode(line.split()[1], validate=True)
    digest = base64.b64encode(hashlib.sha256(wire).digest()).rstrip(b"=")
    return "SHA256:" + digest.decode("ascii")


class InitialKeyReceiptConsumerTests(unittest.TestCase):
    def fixture(self):
        ib = APP.Device("PUBLIC-IB01", "ib", "203.0.113.2",
                        "203.0.113.2/24", "203.0.113.1", "", "", "")
        jump = APP.Device("PUBLIC-JUMP01", "eth_jump", "192.0.2.10",
                          "192.0.2.10", "", "", "", "")
        target = APP.Target(ib, jump, "swp7", "eth0")
        neighbor = APP.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
        line = public_key(27)
        keys = [{"name": "mgmt-server.pub", "line": line,
                 "fingerprint": public_fingerprint(line)}]
        return target, neighbor, keys

    def invoke(self, output, status):
        target, neighbor, keys = self.fixture()
        dispatches = []
        adapter_errors = []
        original_builder = APP.key_install_command

        def installer(*args, **kwargs):
            try:
                self.assertIs(args[0], target)
                self.assertIs(args[1], neighbor)
                self.assertEqual(args[2], "PUBLIC-OOB-USER")
                self.assertEqual(args[4], "admin")
                self.assertEqual(args[6], 2)
                self.assertEqual(kwargs, {"local": False})
                self.assertEqual(args[7][:2], ["sh", "-c"])
                self.assertEqual(len(args[7]), 5)
                self.assertEqual(args[7][3], "--")
                self.assertEqual(
                    base64.b64decode(args[7][4], validate=True).decode("ascii"),
                    keys[0]["line"] + "\n",
                )
            except BaseException as error:
                adapter_errors.append(type(error).__name__)
                raise
            dispatches.append(True)
            return APP.SessionResult(output, status)

        caught = None
        result = None
        printed = io.StringIO()
        with tempfile.TemporaryDirectory(prefix="initial-key-receipt-direct-") as folder:
            private = Path(folder) / "id_ed25519"
            private.write_text("PUBLIC-NOT-A-REAL-PRIVATE-KEY\n", encoding="ascii")
            with mock.patch.object(APP, "key_install_command", wraps=original_builder) as builder, \
                 mock.patch.object(APP, "run_on_ib", side_effect=installer), \
                 mock.patch.object(APP, "verify_management_key_possession") as possession, \
                 mock.patch.object(APP.getpass, "getpass",
                                   side_effect=AssertionError("unexpected prompt")), \
                 redirect_stdout(printed):
                try:
                    result = APP.run_key_stage(
                        target, neighbor, "PUBLIC-OOB-USER", "PUBLIC-OOB-PASSWORD",
                        "admin", 2, keys, local=False, apply=True, authorized=True,
                        management_private_key=private,
                    )
                except BaseException as error:
                    caught = error
            builder.assert_called_once_with(keys)
            self.assertEqual(adapter_errors, [])
            self.assertEqual(dispatches, [True])
            if caught is None:
                self.assertEqual(result, True)
            return caught, possession.call_count, printed.getvalue()

    def test_only_two_canonical_status_zero_receipts_enable_possession(self):
        for receipt in ("IBSW_PUBLIC_KEYS_UPDATED\n", "IBSW_PUBLIC_KEYS_UNCHANGED\n"):
            with self.subTest(receipt=receipt):
                caught, possession_count, printed = self.invoke(receipt, 0)
                self.assertIsNone(caught)
                self.assertEqual(possession_count, 1)
                self.assertIn("已验证", printed)

    def test_malformed_receipts_refuse_before_possession_or_success_logging(self):
        malformed = (
            "",
            "UPDATED\n",
            "UNCHANGED\n",
            "IBSW_PUBLIC_KEYS_UPDATED_EXTRA\n",
            "banner IBSW_PUBLIC_KEYS_UPDATED\n",
            "IBSW_PUBLIC_KEYS_UPDATED\nIBSW_PUBLIC_KEYS_UPDATED\n",
            "IBSW_PUBLIC_KEYS_UNCHANGED\nIBSW_PUBLIC_KEYS_UPDATED\n",
            "IBSW_PUBLIC_KEYS_UPDATED\nPUBLIC-EXTRA\n",
            "\nIBSW_PUBLIC_KEYS_UPDATED\n",
            "IBSW_PUBLIC_KEYS_UPDATED\n\n",
        )
        for receipt in malformed:
            with self.subTest(receipt=receipt):
                caught, possession_count, printed = self.invoke(receipt, 0)
                self.assertIsInstance(caught, APP.SetupError)
                self.assertEqual(possession_count, 0)
                self.assertNotIn("已验证", printed)
                self.assertNotIn("已写入，未验证", printed)
                self.assertNotIn("Public keys SUCCESS", printed)

    def test_nonzero_installer_status_cannot_be_promoted_by_canonical_receipt(self):
        for status in (1, 255, -15):
            with self.subTest(status=status):
                caught, possession_count, printed = self.invoke(
                    "IBSW_PUBLIC_KEYS_UPDATED\n", status)
                self.assertIsInstance(caught, APP.SetupError)
                self.assertEqual(possession_count, 0)
                self.assertNotIn("已验证", printed)
                self.assertNotIn("已写入，未验证", printed)
                self.assertNotIn("Public keys SUCCESS", printed)

    def test_equal_values_with_nonexact_status_or_output_types_are_refused(self):
        class PublicIntZero(int):
            pass

        class PublicCanonicalString(str):
            pass

        # These values compare equal to the valid receipt/status, but the
        # independent contract requires exact built-in int and str types.
        cases = (
            ("boolean-status", "IBSW_PUBLIC_KEYS_UPDATED\n", False),
            ("int-subclass-status", "IBSW_PUBLIC_KEYS_UPDATED\n", PublicIntZero(0)),
            ("str-subclass-output", PublicCanonicalString("IBSW_PUBLIC_KEYS_UPDATED\n"), 0),
        )
        for label, receipt, status in cases:
            with self.subTest(case=label):
                caught, possession_count, printed = self.invoke(receipt, status)
                self.assertIsInstance(caught, APP.SetupError)
                self.assertEqual(possession_count, 0)
                self.assertNotIn("已验证", printed)
                self.assertNotIn("已写入，未验证", printed)
                self.assertNotIn("Public keys SUCCESS", printed)


if __name__ == "__main__":
    unittest.main()
