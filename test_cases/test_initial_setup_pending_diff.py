"""Pending-diff status/frame/ownership literals through real run_on_ib gates.

Only nonce and final interactive transport are explicit PUBLIC models.
No external fixture/KAT is imported; PASSWORD is a disposable PUBLIC token.
The current old diff allowlist can fail before this boundary: report that
admission failure/NOTREACHED, never count masked negative pending cases PASS.
"""
from test_cases.private_public_fixture_input import require_fixture_value as _private_fixture_value
import unittest
from pathlib import Path
from unittest.mock import patch
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
app = load_script("initial_pending_diff_literals", ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")
PASSWORD = _private_fixture_value("pending_diff_password")


def target():
    ib = app.Device("ew-leaf001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


class PendingConfigurationRecoveryTests(unittest.TestCase):
    pending = ("nv set interface eth0 ipv4 address 192.0.2.10/24\n"
               "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
               "nv set interface eth0-1 type eth\n"
               "nv set system hostname ew-leaf001\n")

    def run_command(self, body, transport_status=1, frame_status=1, command=None):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        marker = "ab" * 16
        output = ("__HTTP_IB_BEGIN_" + marker + "__\n" + body +
                  "__HTTP_IB_END_" + marker + "__=" + str(frame_status) + "\n")
        outcome = None
        observed_error = None
        with patch.object(app.os, "urandom", return_value=bytes.fromhex(marker)), \
             patch.object(app, "interactive_run", return_value=app.SessionResult(output, transport_status)) as transport:
            try:
                outcome = app.run_on_ib(t, n, "cumulus", "OobOnly123!", "admin", PASSWORD, 5,
                                        command or ["nv", "config", "diff", "-o", "commands"])
            except app.SetupError as exc:
                observed_error = exc
        # This assertion is outside the production call/error handling. A
        # pre-dispatch argv refusal cannot masquerade as a pending-body reject.
        self.assertEqual(1, transport.call_count, "PUBLIC pending query did not reach transport")
        if observed_error is not None:
            raise observed_error
        return outcome

    def test_matching_previous_pending_diff_status_one_is_accepted(self):
        result = self.run_command(self.pending)
        self.assertEqual(result.output, self.pending)
        self.assertEqual(result.exit_code, 1)  # preserve the observed command status

    def test_conflicting_ip_or_hostname_is_not_committed(self):
        for body in (self.pending.replace("192.0.2.10/24", "192.0.2.99/24"),
                     self.pending.replace("ew-leaf001", "different-switch")):
            with self.subTest(body=body):
                with self.assertRaises(app.SetupError):
                    self.run_command(body)

    def test_empty_diff_status_one_does_not_prove_success(self):
        with self.assertRaises(app.SetupError):
            self.run_command("")

    def test_diff_diagnostics_or_unrelated_changes_are_not_accepted(self):
        for body in ("Error: NVUE service unavailable\n", self.pending + "Error: partial output\n",
                     self.pending + "nv set system dns server 203.0.113.99\n",
                     "nv unset interface eth0\n"):
            with self.subTest(body=body):
                with self.assertRaises(app.SetupError):
                    self.run_command(body)

    def test_status_exception_does_not_extend_to_other_commands(self):
        from contextlib import ExitStack
        import shlex
        import sys
        from types import SimpleNamespace
        from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT

        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        oob, stamp = "PUBLIC-OOB-example", "20261117-040000"
        apply = ["nv", "config", "apply", "-y"]
        backup = ["sh", "-c", EXPECTED_BACKUP_SCRIPT, "--", stamp]
        apply_marker, backup_marker = "ab" * 16, "cd" * 16
        receipt = {"path": f"/home/PUBLIC/current_{stamp}.yaml", "bytes": 137}
        dispatched = []

        def transport(argv, _responder, _timeout):
            outer = shlex.split(argv[-1])
            self.assertTrue(len(outer) == 3 and outer[:2] == ["sh", "-c"])
            nested = shlex.split(outer[2].split("; exec ", 1)[1])
            self.assertEqual("admin@fe80::10", nested[-2])
            frame = shlex.split(nested[-1])
            self.assertTrue(len(frame) == 3 and frame[:2] == ["sh", "-c"])
            if not dispatched:
                name, command, marker, status = "backup", backup, backup_marker, 0
                self.assertEqual("RUNNING", state.backup_state)
                self.assertEqual(1, coordinator.metrics.get("config_backup_attempts"))
                self.assertIsNone(coordinator.metrics.get("nvue_write_commands"))
                body = f"path={receipt['path']}\nbytes={receipt['bytes']}\n"
            else:
                self.assertEqual(["backup"], dispatched, "no repeated backup or apply")
                name, command, marker, status = "apply", apply, apply_marker, 1
                self.assertEqual("VERIFIED", state.backup_state)
                self.assertEqual(receipt, state.backup_receipt)
                self.assertEqual(1, coordinator.metrics.get("nvue_write_commands"))
                body = self.pending
            prefix = 'printf "\\n__HTTP_IB_BEGIN_' + marker + '__\\n"; '
            suffix = ('; task_rc=$?; printf "\\n__HTTP_IB_END_' + marker
                      + '__=%s\\n" "$task_rc"; exit "$task_rc"')
            self.assertTrue(frame[2].startswith(prefix) and frame[2].endswith(suffix)
                            and shlex.split(frame[2][len(prefix):-len(suffix)]) == command,
                            "only the exact modeled backup/apply vector may be dispatched")
            dispatched.append(name)
            return app.SessionResult(
                f"__HTTP_IB_BEGIN_{marker}__\n{body}__HTTP_IB_END_{marker}__={status}\n", status)

        with ExitStack() as context:
            context.enter_context(patch.dict(sys.modules))
            for name in list(sys.modules):
                if name == "tools" or name.startswith("tools."):
                    del sys.modules[name]
            context.enter_context(patch.object(sys, "path", [str(ROOT), *sys.path]))
            context.enter_context(patch.object(app, "_TOOLS_ROOT", None))
            identity = app._check_ib_identity(
                t, "2: eth0: <UP> mtu 1500 state UP\n"
                   "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n",
                "", via_ipv4=False)
            self.assertIs(True, identity["ok"])
            task = app.PreparedIBTask(t, n, oob, False)
            state = app._IBConfigWriteState(task, "admin", "cumulus", stamp, True,
                endpoint=n, current_password=PASSWORD, identity_verified=identity["ok"])
            self.assertEqual("NEW", state.backup_state)
            coordinator = app.RuntimeCoordinator(SimpleNamespace(apply=True, yes=True), None, PASSWORD,
                                                 [task], app.RuntimeInputAuthority([]))
            coordinator.current_target = t
            context.enter_context(patch.object(app, "_TASK_IB_CONFIG", state))
            context.enter_context(patch.object(app, "_ACTIVE_COORDINATOR", coordinator))
            context.enter_context(patch.object(app, "_JUMP_SESSIONS", None))
            # The setter carrier is constructed first, but the backup is dispatched first.
            context.enter_context(patch.object(app.os, "urandom", side_effect=[
                bytes.fromhex(apply_marker), bytes.fromhex(backup_marker)]))
            interactive = context.enter_context(patch.object(app, "interactive_run", side_effect=transport))
            with self.assertRaises(app.SetupError) as rejected:
                app.run_on_ib(t, n, "cumulus", oob, "admin", PASSWORD, 5, apply)
            self.assertTrue(str(rejected.exception).startswith(
                "nested SSH to ew-leaf001 via oob-leaf001 failed, exit=1:"),
                "apply status one must reach and fail at the ordinary transport boundary")
            self.assertEqual(2, interactive.call_count)
        self.assertEqual(["backup", "apply"], dispatched)
        with self.assertRaises(app.SetupError):
            self.run_command(self.pending, transport_status=2, frame_status=2)

    def test_transport_and_frame_status_must_agree(self):
        with self.assertRaises(app.SetupError):
            self.run_command(self.pending, transport_status=1, frame_status=0)

    def test_missing_frame_is_not_a_usable_pending_diff(self):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        with patch.object(app, "interactive_run", return_value=app.SessionResult(self.pending, 1)) as transport:
            with self.assertRaises(app.SetupError):
                app.run_on_ib(t, n, "cumulus", "OobOnly123!", "admin", PASSWORD, 5,
                              ["nv", "config", "diff", "-o", "commands"])
        self.assertEqual(1, transport.call_count, "PUBLIC missing-frame query did not reach transport")

    def test_handoff_initial_and_reserved_pending_literals_are_owned(self):
        positives = (
            "nv set system config auto-save state enabled\n",
            "nv set system ztp config-save enabled\n",
            "nv set interface eth0 link state up\n",
            "nv set interface eth1 link state up\n",
            "nv set interface eth0-1 link state up\n",
            "nv set interface eth0 type eth\n",
            "nv set interface eth1 type eth\n",
            "nv set interface eth0-1 type eth\n",
            "nv set interface eth0 ipv4 gateway 192.0.2.1\n",
            "nv set interface eth0 ipv4 address 192.0.2.10/24\n",
            "nv set system hostname ew-leaf001\n",
        )
        for body in positives:
            with self.subTest(body=body):
                result = self.run_command(body)
                self.assertEqual(body, result.output)
                self.assertEqual(1, result.exit_code)
                self.assertIs(int, type(result.exit_code))

        gateway_bodies = (
            "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n",
            "nv set interface eth1 ipv4 gateway 192.0.2.1\n",
        )
        original_owned = app._validate_owned_pending
        for body in gateway_bodies:
            with self.subTest(kind="single-unrequested-gateway", body=body):
                with patch.object(app, "_validate_owned_pending", wraps=original_owned) as ownership:
                    with self.assertRaises(app.SetupError):
                        self.run_command(body)
                self.assertEqual(1, ownership.call_count, "single refusal must reach the real owned-pending guard")
                self.assertEqual(body, ownership.call_args.args[1])
        single = target()
        ib = app.Device("ew-leaf001", "ib", "192.0.2.10", "192.0.2.10/24",
                        "192.0.2.1", "02:00:00:00:00:10", "192.0.2.11/24", "192.0.2.1")
        dual_same = app.Target(ib, single.ethernet, "swp1", "eth0")
        with patch(__name__ + ".target", return_value=dual_same):
            for body in gateway_bodies:
                with self.subTest(kind="dual-same-owned-gateway", body=body):
                    with patch.object(app, "_validate_owned_pending", wraps=original_owned) as ownership:
                        result = self.run_command(body)
                    self.assertEqual(1, ownership.call_count, "dual positive must reach the real owned-pending guard")
                    self.assertIs(ib, ownership.call_args.args[0])
                    self.assertEqual(body, ownership.call_args.args[1])
                    self.assertEqual(body, result.output)
                    self.assertEqual(1, result.exit_code)
                    self.assertIs(int, type(result.exit_code))

    def test_handoff_pending_is_bound_to_both_csv_addresses_and_gateways(self):
        # Only the PUBLIC fixture constructor changes. Production Target/Device,
        # typed/role/frame/status/pending gates remain actual and unpatched.
        ib = app.Device("ew-leaf001", "ib", "192.0.2.10", "192.0.2.10/24",
                        "192.0.2.1", "02:00:00:00:00:10",
                        "203.0.113.10/24", "203.0.113.1")
        eth = app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", "")
        dual = app.Target(ib, eth, "swp1", "eth0")
        positives = (
            "nv set interface eth0 ipv4 address 192.0.2.10/24\n",
            "nv set interface eth1 ipv4 address 203.0.113.10/24\n",
            "nv set interface eth0 ipv4 gateway 192.0.2.1\n",
            "nv set interface eth1 ipv4 gateway 203.0.113.1\n",
            "nv set system hostname ew-leaf001\n",
        )
        negatives = (
            "nv set interface eth0 ipv4 address 192.0.2.99/24\n",
            "nv set interface eth1 ipv4 address 203.0.113.99/24\n",
            "nv set interface eth0 ipv4 address 203.0.113.10/24\n",
            "nv set interface eth1 ipv4 address 192.0.2.10/24\n",
            "nv set system hostname another-leaf\n",
            "nv set interface eth0 ipv4 gateway 192.0.2.254\n",
            "nv set interface eth1 ipv4 gateway 203.0.113.254\n",
            "nv set interface eth0 ipv4 gateway 203.0.113.1\n",
            "nv set interface eth1 ipv4 gateway 192.0.2.1\n",
            "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n",
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n",
            "nv set system config auto-save state disabled\n",
            "nv set system ztp config-save disabled\n",
            "nv set interface eth0 link state down\n",
            "nv set interface eth1 type ib\n",
            "nv set interface swp1 type eth\n",
        )
        with patch(__name__ + ".target", return_value=dual):
            for body in positives:
                with self.subTest(kind="owned", body=body):
                    result = self.run_command(body)
                    self.assertEqual(body, result.output)
                    self.assertEqual(1, result.exit_code)
                    self.assertIs(int, type(result.exit_code))
            for body in negatives:
                with self.subTest(kind="foreign", body=body):
                    with self.assertRaises(app.SetupError):
                        self.run_command(body)

    def test_status_zero_pending_requires_owned_body_and_matching_frame(self):
        empty = self.run_command("", transport_status=0, frame_status=0)
        self.assertEqual("", empty.output)
        self.assertEqual(0, empty.exit_code)
        self.assertIs(int, type(empty.exit_code))
        owned = self.run_command(self.pending, transport_status=0, frame_status=0)
        self.assertEqual(self.pending, owned.output)
        self.assertEqual(0, owned.exit_code)
        for body in (
            "Error: NVUE service unavailable\n",
            self.pending + "Error: partial output\n",
            self.pending + "nv set system dns server 203.0.113.99\n",
            "nv unset interface eth0\n",
        ):
            with self.subTest(body=body):
                with self.assertRaises(app.SetupError):
                    self.run_command(body, transport_status=0, frame_status=0)
        with self.assertRaises(app.SetupError):
            self.run_command(self.pending, transport_status=0, frame_status=1)

    def test_readonly_diff_cannot_opt_into_password_change_before_dispatch(self):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        observed_error = None
        with patch.object(app.os, "urandom", return_value=b"\xab" * 16) as nonce, \
             patch.object(app, "interactive_run", return_value=app.SessionResult("", 0)) as transport:
            try:
                app.run_on_ib(t, n, "cumulus", "OobOnly123!", "admin", PASSWORD, 5,
                              ["nv", "config", "diff", "-o", "commands"],
                              allow_password_change=True,
                              ib_new_password="PUBLIC-new-password-not-a-credential")
            except app.SetupError as exc:
                observed_error = exc
        nonce.assert_not_called()
        transport.assert_not_called()
        self.assertTrue(isinstance(observed_error, app.SetupError),
                        "readonly diff must reject password-change permission before dispatch")

    def test_readonly_diff_rejects_password_facts_notices_and_responder_block(self):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        marker = "ab" * 16
        notice = "passwd: all authentication tokens updated successfully\n"
        expired = "Your password has expired.\n"
        # These are independent supplied transport facts, not native PAM proof.
        cases = (
            ("changed_notice_without_frame", None, {"password_changed": True}, notice, False),
            ("changed_notice_owned_frame", self.pending, {"password_changed": True}, notice, False),
            ("changed_notice_foreign_frame", "nv set system hostname foreign-leaf\n",
             {"password_changed": True}, notice, False),
            ("changed_flag_only", self.pending, {"password_changed": True}, "", False),
            ("required_flag_only", self.pending, {"password_change_required": True}, "", False),
            ("attempted_flag_only", self.pending, {"password_change_attempted": True}, "", False),
            ("authentication_rejected_flag", self.pending,
             {"ib_authentication_rejected": True}, "", False),
            ("updated_notice_only", self.pending, {}, notice, False),
            ("expiry_notice_only", self.pending, {}, expired, False),
            ("actual_readonly_responder_block", self.pending, {}, "", True),
        )
        for status in (0, 1):
            for label, body, flags, prefix, observe_block in cases:
                with self.subTest(status=status, case=label):
                    output = prefix
                    if body is not None:
                        output += ("__HTTP_IB_BEGIN_" + marker + "__\n" + body +
                                   "__HTTP_IB_END_" + marker + "__=" + str(status) + "\n")
                    supplied = app.SessionResult(output, status, **flags)
                    replies = []
                    delivered = []
                    def transport_boundary(_command, responder, _timeout):
                        if observe_block:
                            replies.append(responder("New password: "))
                        delivered.append(supplied)
                        return supplied
                    observed_error = None
                    with patch.object(app.os, "urandom", return_value=bytes.fromhex(marker)), \
                         patch.object(app, "interactive_run", side_effect=transport_boundary) as transport:
                        try:
                            app.run_on_ib(t, n, "cumulus", "OobOnly123!", "admin", PASSWORD, 5,
                                          ["nv", "config", "diff", "-o", "commands"])
                        except app.SetupError as exc:
                            observed_error = exc
                    self.assertEqual(1, transport.call_count,
                                     "PAM-fact check was not reached: readonly diff admission failed first")
                    self.assertTrue(len(delivered) == 1 and delivered[0] is supplied,
                                    "the actual transport callback must return the supplied frame/body facts")
                    self.assertEqual(["\x03"] if observe_block else [], replies,
                                     "only the actual readonly responder may supply the block witness")
                    self.assertTrue(isinstance(observed_error, app.SetupError),
                                    "PAM/authentication evidence cannot establish a successful readonly diff")
                    self.assertRegex(str(observed_error), "read-only pending diff",
                                         "post-result readonly-PAM fence, not earlier generic rejection")

    def test_non_diff_password_change_result_keeps_its_existing_separate_contract(self):
        t = target()
        n = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
        notice = "passwd: all authentication tokens updated successfully\n"
        for status in (0, 1):
            with self.subTest(status=status):
                supplied = app.SessionResult(notice, status, password_changed=True)
                with patch.object(app.os, "urandom", return_value=b"\xab" * 16), \
                     patch.object(app, "interactive_run", return_value=supplied) as transport:
                    actual = app.run_on_ib(
                        t, n, "cumulus", "OobOnly123!", "admin", PASSWORD, 5,
                        ["nv", "config", "show", "-o", "commands"],
                        allow_password_change=True,
                        ib_new_password="PUBLIC-new-password-not-a-credential",
                    )
                self.assertEqual(1, transport.call_count)
                self.assertIs(supplied, actual)
                self.assertEqual(status, actual.exit_code)
                self.assertTrue(actual.password_changed)
                self.assertEqual(notice, actual.output)

    def test_readonly_diff_accepts_owned_hostname_keywords_not_pam_notifications(self):
        positives = (
            ("password-updated-success",
             "nv set system hostname password-updated-success\n"),
            ("password-changed-success",
             "+ nv set system hostname 'password-changed-success'\n"),
        )
        for hostname, body in positives:
            ib = app.Device(hostname, "ib", "192.0.2.10", "192.0.2.10/24",
                            "192.0.2.1", "02:00:00:00:00:10", "", "")
            eth = app.Device("oob-leaf001", "eth_jump", "198.51.100.10", "", "", "", "", "")
            supplied_target = app.Target(ib, eth, "swp1", "eth0")
            for status in (0, 1):
                with self.subTest(hostname=hostname, status=status):
                    original_extract = app.extract_command_output
                    with patch(__name__ + ".target", return_value=supplied_target), \
                         patch.object(app, "extract_command_output", wraps=original_extract) as extractor:
                        actual = self.run_command(body, transport_status=status, frame_status=status)
                    self.assertEqual(1, extractor.call_count,
                                     "owned-frame qualification must be reached for the legitimate setter")
                    self.assertEqual(body, actual.output)
                    self.assertEqual(status, actual.exit_code)
                    self.assertIs(int, type(actual.exit_code))





if __name__ == "__main__":
    unittest.main()
