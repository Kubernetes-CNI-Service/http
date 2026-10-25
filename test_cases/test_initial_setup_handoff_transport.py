#!/usr/bin/env python3
"""Initial-setup handoff transport packet: PUBLIC fixtures, no device/network or hash KAT.
Normal managed-test placement only; this O prospective text is not executed here.
"""
from __future__ import annotations
from test_cases.private_public_fixture_input import require_fixture_value as _private_fixture_value
from pathlib import Path
import shlex
import sys
import unittest
from unittest.mock import patch
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_handoff_transport_packet1", SCRIPT)
PASSWORD = _private_fixture_value("handoff_transport_password")
CONFIG = "nv set system hostname nvos\n"

def target():
    ib = app.Device("ew-leaf001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


class ResponderTests(unittest.TestCase):
    def responder(self, allow=False):
        return app.NestedResponder("OobOnly123!", "admin", allow,
                                   ib_new_password=PASSWORD)
    def test_outer_and_inner_passwords_are_distinct(self):
        responder = self.responder()
        output = "cumulus@198.51.100.10's password:"
        self.assertEqual(responder(output), "OobOnly123!")
        output += "\nadmin@fe80::10's password:"
        self.assertEqual(responder(output), "admin")
        output += "\nPermission denied, please try again.\nadmin@fe80::10's password:"
        self.assertIsNone(responder(output))  # no guessing the OOB password
    def test_readonly_expiry_notice_blocks_before_new_password(self):
        responder = self.responder()
        self.assertEqual(responder("You are required to change your password immediately."), "\x03")
        self.assertTrue(responder.password_change_blocked)
        self.assertFalse(responder.password_change_attempted)
    def test_current_new_and_retype(self):
        responder = self.responder(allow=True)
        output = "Current password:"
        self.assertEqual(responder(output), "admin")
        output += "\nNew password:"
        self.assertEqual(responder(output), PASSWORD)
        output += "\nRetype new password:"
        self.assertEqual(responder(output), PASSWORD)
        self.assertTrue(responder.password_change_attempted)
    def test_missing_independent_new_password_fails(self):
        responder = app.NestedResponder("OobOnly123!", "admin", True)
        with self.assertRaises(app.SetupError):
            responder("New password:")
    def test_ipv4_verification_uses_ib_password(self):
        responder = app.NestedResponder("OobOnly123!", PASSWORD, False,
                                        ib_destination="admin@192.0.2.10")
        self.assertEqual(responder("admin@192.0.2.10's password:"), PASSWORD)


class TransportTests(unittest.TestCase):
    def test_nested_session_requests_ib_tty_and_framing(self):
        argv = app.nested_ssh_command(target(), app.Neighbor("fe80::10","vlan1000",
                 target().ib.eth0_mac,"oob"), "cumulus", "admin", 5,
                 ["nv","config","show","-o","commands"], marker="test_nonce")
        remote = argv[-1]
        self.assertIn("-tt", remote)
        self.assertIn("__HTTP_IB_BEGIN_test_nonce__", remote)
        self.assertIn("__HTTP_IB_END_test_nonce__", remote)
        self.assertIn("/usr/sbin", remote)
    def test_missing_frame_not_unconfigured(self):
        neighbor = app.Neighbor("fe80::10","vlan1000",target().ib.eth0_mac,"oob")
        with patch.object(app, "interactive_run", return_value=app.SessionResult("",0)):
            with self.assertRaises(app.SetupError):
                app.run_on_ib(target(),neighbor,"cumulus","OobOnly123!","admin","admin",
                              5,["nv","config","show","-o","commands"])
    def test_unframed_expired_notice_is_not_empty_config(self):
        neighbor = app.Neighbor("fe80::10","vlan1000",target().ib.eth0_mac,"oob")
        result = app.SessionResult("WARNING: Your password has expired.",0)
        with patch.object(app, "interactive_run", return_value=result):
            actual = app.run_on_ib(target(),neighbor,"cumulus","OobOnly123!","admin","admin",
                                   5,["nv","config","show","-o","commands"])
        self.assertTrue(actual.password_change_required)
    def test_empty_and_banner_state_rejected(self):
        for output in ("", "NVOS switch\nWARNING: Your password has expired.\n", "Error: permission denied"):
            with self.assertRaises(app.SetupError):
                app.parse_nvue_state(output)
    def test_frame_status_and_nonce(self):
        self.assertEqual(app.extract_command_output("__HTTP_IB_BEGIN_nonce__\n"+CONFIG+
                    "__HTTP_IB_END_nonce__=0\n","nonce"), CONFIG)
        for body in ("", "__HTTP_IB_BEGIN_other__\n"+CONFIG+"__HTTP_IB_END_other__=0\n",
                     "__HTTP_IB_BEGIN_nonce__\nerror\n__HTTP_IB_END_nonce__=1\n"):
            with self.assertRaises(app.SetupError):
                app.extract_command_output(body,"nonce")
    def test_real_pty_readonly_cancels_forced_change(self):
        program = ("import sys,time; print('You are required to change your password immediately.',"
                   "flush=True); time.sleep(3)")
        result = app.interactive_run([sys.executable,"-u","-c",program],
                    app.NestedResponder("OobOnly123!","admin",False),5)
        self.assertTrue(result.password_change_required)
        self.assertFalse(result.password_changed)
    def test_readonly_expiry_terminates_without_writing_to_closing_pty(self):
        program = ("import time; print('You are required to change your password immediately.',"
                   "flush=True); time.sleep(3)")
        with patch.object(app.os, "write", side_effect=OSError(5, "PTY already closed")) as write:
            result = app.interactive_run([sys.executable, "-u", "-c", program],
                         app.NestedResponder("OobOnly123!", "admin", False), 5)
        write.assert_not_called()
        self.assertTrue(result.password_change_required)
        self.assertFalse(result.password_changed)
        self.assertNotEqual(result.exit_code, 0)
    def test_real_pty_completed_password_change(self):
        program = ("import sys; "
                   "print('New password:',flush=True); a=input(); "
                   "print('Retype new password:',flush=True); b=input(); "
                   "print('passwd: "
                   "password updated successfully' if a==b else 'failed',flush=True)")
        result = app.interactive_run([sys.executable,"-u","-c",program],
                    app.NestedResponder("OobOnly123!","admin",True,ib_new_password=PASSWORD),5)
        self.assertTrue(result.password_changed)
        self.assertNotIn(PASSWORD,result.output)



class CurrentFormalTransportCompatibilityTests(unittest.TestCase):
    def test_remote_fixed_path_wrapper_is_one_quoted_exec_boundary(self):
        actual = app.outer_ssh_command(target().ethernet, "PUBLIC-user",
                                      ["nv", "config", "show"], 5)
        self.assertEqual("ssh", actual[0])
        self.assertEqual("PUBLIC-user@198.51.100.10", actual[-2])
        self.assertEqual(
            "sh -c 'export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec nv config show'",
            actual[-1],
        )
        self.assertIn("ControlMaster=no", actual)
        self.assertIn("ControlPath=none", actual)

    def test_remote_exec_keeps_literal_argument_tokens_not_shell_syntax(self):
        command = ["printf", "%s", "PUBLIC value with spaces", "$PUBLIC;still-one-token"]
        actual = app.outer_ssh_command(target().ethernet, "PUBLIC-user", command, 5)
        wrapper = shlex.split(actual[-1])
        self.assertEqual(["sh", "-c"], wrapper[:2])
        self.assertEqual(
            "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec printf %s 'PUBLIC value with spaces' '$PUBLIC;still-one-token'",
            wrapper[2],
        )
        self.assertEqual(command, ["printf", "%s", "PUBLIC value with spaces", "$PUBLIC;still-one-token"])

    def test_missing_remote_endpoint_is_rejected_but_local_stays_typed(self):
        device = app.Device("PUBLIC-JUMP01", "eth_jump", "", "", "", "", "", "")
        with self.assertRaisesRegex(app.SetupError, "login address is required"):
            app.outer_ssh_command(device, "PUBLIC-user", ["hostname"], 5)
        command = ["hostname"]
        self.assertEqual(command, app.outer_ssh_command(device, "PUBLIC-user",
                                                        command, 5, local=True))
        self.assertNotEqual(["sh", "-c"], app.outer_ssh_command(device, "PUBLIC-user",
                                                               command, 5, local=True)[:2])

    def test_ethernet_apply_with_or_without_yes_is_still_rejected_pre_dispatch(self):
        with patch.object(app, "interactive_run") as dispatch:
            for command in (["nv", "config", "apply"],
                            ["nv", "config", "apply", "-y"]):
                with self.subTest(command=command), self.assertRaises(app.SetupError):
                    app.run_on_ethernet(target().ethernet, "PUBLIC-user",
                                        "PUBLIC-ONLY-NOT-A-CREDENTIAL", command, 5)
        dispatch.assert_not_called()

    def test_only_empty_nonzero_ifquery_one_is_default_vrf_absence(self):
        device = target().ethernet
        with patch.object(app, "interactive_run", return_value=app.SessionResult("", 1)):
            self.assertEqual("", app.run_on_ethernet(device, "PUBLIC-user",
                             "PUBLIC-ONLY-NOT-A-CREDENTIAL", ["ifquery", "swp1"], 5))
        for command, output, status in (
            (["ifquery", "swp1"], "Permission denied", 1),
            (["ifquery", "swp1"], "", 2),
            (["hostname"], "", 1),
            (["hostname"], "PUBLIC-JUMP01", 1),
        ):
            with self.subTest(command=command, output=output, status=status):
                with patch.object(app, "interactive_run",
                                  return_value=app.SessionResult(output, status)):
                    with self.assertRaises(app.SetupError):
                        app.run_on_ethernet(device, "PUBLIC-user",
                                           "PUBLIC-ONLY-NOT-A-CREDENTIAL", command, 5)

    def test_oob_authentication_prompt_is_not_hostname_command_payload(self):
        raw = "PUBLIC-user@198.51.100.10's password:\nPUBLIC-JUMP01\n"
        with patch.object(app, "interactive_run", return_value=app.SessionResult(raw, 0)):
            self.assertEqual("PUBLIC-JUMP01\n", app.run_on_ethernet(
                target().ethernet, "PUBLIC-user", "PUBLIC-ONLY-NOT-A-CREDENTIAL",
                ["hostname"], 5))



class CommandFrameBoundaryTests(unittest.TestCase):
    def test_repeated_begin_or_end_is_not_a_single_verified_frame(self):
        for body in (
            "__HTTP_IB_BEGIN_nonce__\n__HTTP_IB_BEGIN_nonce__\nPUBLIC payload\n__HTTP_IB_END_nonce__=0\n",
            "__HTTP_IB_BEGIN_nonce__\nPUBLIC payload\n__HTTP_IB_END_nonce__=0\n__HTTP_IB_END_nonce__=0\n",
        ):
            with self.subTest(body=body), self.assertRaises(app.SetupError):
                app.extract_command_output(body, "nonce")

    def test_end_before_begin_is_rejected(self):
        with self.assertRaises(app.SetupError):
            app.extract_command_output(
                "__HTTP_IB_END_nonce__=0\nPUBLIC banner\n__HTTP_IB_BEGIN_nonce__\n",
                "nonce",
            )

    def test_frame_status_must_equal_independently_expected_status(self):
        failed = "__HTTP_IB_BEGIN_nonce__\nPUBLIC pending diff\n__HTTP_IB_END_nonce__=1\n"
        self.assertEqual("PUBLIC pending diff\n",
                         app.extract_command_output(failed, "nonce", expected_exit_code=1))
        with self.assertRaises(app.SetupError):
            app.extract_command_output(failed, "nonce", expected_exit_code=0)
        with self.assertRaises(app.SetupError):
            app.extract_command_output(
                "__HTTP_IB_BEGIN_nonce__\nPUBLIC successful body\n__HTTP_IB_END_nonce__=0\n",
                "nonce", expected_exit_code=1,
            )

    def test_only_framed_payload_survives_before_and_after_banners(self):
        body = (
            "PUBLIC login banner\n"
            "__HTTP_IB_BEGIN_nonce__\n"
            "nv set system hostname PUBLIC-IB01\n"
            "__HTTP_IB_END_nonce__=0\n"
            "PUBLIC trailing session banner\n"
        )
        actual = app.extract_command_output(body, "nonce")
        self.assertEqual("nv set system hostname PUBLIC-IB01\n", actual)
        self.assertNotIn("PUBLIC login banner", actual)
        self.assertNotIn("PUBLIC trailing session banner", actual)

if __name__ == "__main__":
    unittest.main()
