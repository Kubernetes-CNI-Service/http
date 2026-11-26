"""Pending-diff status/frame/ownership literals through real run_on_ib gates.

Only nonce and final interactive transport are explicit PUBLIC models.
No external fixture/KAT is imported; PASSWORD is a disposable PUBLIC token.
The current old diff allowlist can fail before this boundary: report that
admission failure/NOTREACHED, never count masked negative pending cases PASS.
"""
from test_cases.private_public_fixture_input import require_fixture_value as _private_fixture_value
import inspect
import re
import shlex
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


# ---------------------------------------------------------------------------------------------
# U3 / R-025 (v3.1.6 D1c).  Expectations come only from the owner's 2026-11-14 ruling
# 「T15按你说的改，记录成U3放3.1.6」 on the issue file's 11.4/11.5 (U3 new contract) and from the
# v3.1.6 guide 8.10 steps 1-6 (guide :2133-2140, tag guide-v3.1.6-approved-r838):
#   - owned set = this device's Initial/Network setters plus every DNS/NTP/timezone value of
#     this run's services profile, token by token; no profile = no services rows (step 1);
#   - a write stage reads the diff where T15 did; any unknown line refuses with zero detach and
#     a reason naming the unknown line count and the manual-check hint (steps 3, 5);
#   - all owned: logged and recorded, then the stage's own consent, the write backup, a real
#     write permit, `nv config detach`, an empty re-read, then the original stage (step 3);
#   - backup failure, non-zero detach, a non-empty or failed re-read fail the device with no
#     later write; the detach counts as an NVUE write attempt (step 4);
#   - check-only reads once where --apply would write and reports, never detaches (step 5);
#   - the record carries pending_detached [{"stage", "lines"}] (step 6, a suggested shape).
# Only the remote NVOS device and the consent terminal are PUBLIC models below.
U3_PROFILE = {"dns": ["203.0.113.53"], "ntp": ["ntp.example.test"], "timezone": "Etc/UTC"}
U3_DIFF = ("nv", "config", "diff", "-o", "commands")
U3_DETACH = ("nv", "config", "detach")
U3_INITIAL = ["nv set system config auto-save state enabled",
              "nv set system ztp config-save enabled"]
U3_NETWORK = ["nv set interface eth0 ipv4 address 192.0.2.10/24",
              "nv set interface eth0 ipv4 gateway 192.0.2.1",
              "nv set interface eth0-1 link state up",
              "nv set interface eth0-1 type eth",
              "nv set system hostname ew-leaf001"]
U3_SERVICES = ["nv set system dns server 203.0.113.53",
               "nv set system ntp server ntp.example.test",
               "nv set system date-time timezone Etc/UTC"]
# Guide 8.10 step 3 (:2135) and issue 11.4 item 5: the refusal hint, verbatim.
U3_HINT = "用 `nv config diff -o commands` 核对，确认后在设备上手工 detach 或 apply，再重跑"
U3_FRAME = re.compile(
    r'^printf "\\n__HTTP_IB_BEGIN_([0-9a-f]{32})__\\n"; (.*); '
    r'task_rc=\$\?; printf "\\n__HTTP_IB_END_([0-9a-f]{32})__=%s\\n" '
    r'"\$task_rc"; exit "\$task_rc"$', re.S)
U3_SAFE = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; exec "


class _U3Device:
    """A PUBLIC NVOS model: applied rows, one pending list and the fixed replies only."""

    def __init__(self, test, applied, pending=(), *, diff_status=1, faults=()):
        self.test = test
        self.applied = list(applied)
        self.pending = [tuple(shlex.split(line)) for line in pending]
        self.diff_status = diff_status
        self.faults = set(faults)
        self.events = []
        self.diff_reads = 0
        self.on_first_diff = None

    def frame(self, argv):
        # Decode the shell quoting as data and never execute it; one complete frame only.
        found = []

        def visit(text, depth):
            if depth > 6:
                return
            match = U3_FRAME.fullmatch(text)
            if match:
                self.test.assertEqual(match[1], match[3])
                found.append((match[1], tuple(shlex.split(match[2]))))
                return
            if text.startswith(U3_SAFE):
                text = text[len(U3_SAFE):]
            try:
                words = shlex.split(text)
            except ValueError:
                return
            for word in words:
                if word != text and "__HTTP_IB_BEGIN_" in word:
                    visit(word, depth + 1)
        for value in argv:
            visit(value, 0)
        self.test.assertEqual(1, len(found), "one complete PUBLIC command frame is required")
        return found[0]

    def reply(self, command):
        from test_cases.test_initial_setup_identity_and_backup import EXPECTED_BACKUP_SCRIPT
        self.events.append(command)
        if command == ("nv", "config", "show", "-o", "commands"):
            return "".join(row + "\n" for row in self.applied), 0
        if command == ("ip", "addr", "show", "eth0"):
            return ("2: eth0: <UP> mtu 1500 state UP\n"
                    "    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
                    "    inet 192.0.2.10/24 scope global eth0\n"), 0
        if command == ("ip", "route"):
            return "default via 192.0.2.1 dev eth0\n", 0
        if command == ("nv", "show", "system", "ztp"):
            return "service disabled\nstate disabled\n", 0
        if command == ("hostname",):
            # U4 (v3.1.6 D1d): a healthy device's Linux name is its applied NVUE hostname.
            names = [row.split()[-1] for row in self.applied if row.startswith("nv set system hostname ")]
            return (names[-1] if names else "nvos") + "\n", 0
        if command == U3_DIFF:
            self.diff_reads += 1
            if self.diff_reads == 1 and self.on_first_diff is not None:
                self.on_first_diff()
            if self.diff_reads > 1 and "readback-unreadable" in self.faults:
                return "Error: NVUE service unavailable\n", 2
            body = "".join(shlex.join(row) + "\n" for row in self.pending)
            return body, (self.diff_status if self.pending else 0)
        if (len(command) == 5 and command[:2] == ("sh", "-c") and command[2] == EXPECTED_BACKUP_SCRIPT
                and command[3] == "--"):
            if "backup-failed" in self.faults:
                return "IB configuration backup failed\n", 1
            return f"path=/home/PUBLIC/current_{command[4]}.yaml\nbytes=137\n", 0
        if (len(command) == 5 and command[:2] == ("sh", "-c") and command[3] == "--"
                and command[4] == "20261125-090000"):
            # The direct IPv4 Network write's deferred apply/save launcher (D4): an apply here.
            self.events.append(("deferred-apply",))
            self.commit()
            return "", 0
        if command == U3_DETACH:
            if "detach-nonzero" in self.faults:
                return "Error: PUBLIC detach refused\n", 1
            if "readback-not-empty" not in self.faults:
                self.pending.clear()
            return "", 0
        if command[:2] == ("nv", "set"):
            self.pending.append(command)
            return "", 0
        if command == ("nv", "config", "apply", "-y"):
            self.commit()
            return "", 0
        if command == ("nv", "config", "save"):
            return "", 0
        raise AssertionError("PUBLIC U3 model refused an unlisted command: " + repr(command))

    def commit(self):
        for row in self.pending:
            line = shlex.join(row)
            if row[:5] not in (("nv", "set", "system", "dns", "server"),
                               ("nv", "set", "system", "ntp", "server")):
                self.applied = [old for old in self.applied
                                if tuple(shlex.split(old))[:-1] != row[:-1]]
            if line not in self.applied:
                self.applied.append(line)
        self.pending.clear()

    def transport(self, argv, _responder, _timeout):
        marker, command = self.frame(argv)
        body, status = self.reply(command)
        return app.SessionResult(
            f"__HTTP_IB_BEGIN_{marker}__\n{body}__HTTP_IB_END_{marker}__={status}\n", status)


class OwnedPendingDetachTests(unittest.TestCase):
    """U3 (R-025): owned pending is recorded, detached after consent/backup/permit, then redone."""

    def u3_flow(self, device, *, route="jump", apply=True, services=U3_PROFILE, yes=True,
                consent=True, authority_file=None):
        from contextlib import ExitStack
        import sys
        from types import SimpleNamespace
        logged = []
        with ExitStack() as context:
            context.enter_context(patch.dict(sys.modules))
            for name in list(sys.modules):
                if name == "tools" or name.startswith("tools."):
                    del sys.modules[name]
            context.enter_context(patch.object(sys, "path", [str(ROOT), *sys.path]))
            context.enter_context(patch.object(app, "_TOOLS_ROOT", None))
            ib = target().ib
            if route == "jump":
                t = target()
                point = app.Neighbor("fe80::10", "vlan1000", ib.eth0_mac, "oob")
                outer = "PUBLIC-Outer-Only"
            else:
                path = app._import_tools("tools.login_path").Route(
                    ib.hostname, "direct", "PUBLIC", None, None, None)
                t = app.Target(ib, None, "", "eth0", route=path)
                point = app.DirectEndpoint("192.0.2.10")
                outer = ""
            task = app.PreparedIBTask(t, point, outer, False)
            args = SimpleNamespace(eth_user="cumulus", ib_user="admin", connect_timeout=5,
                                   apply=apply, yes=yes, force=False, run_stamp="20261125-090000",
                                   execution_mode="ethernet" if route == "jump" else "management",
                                   _on_management_server=route != "jump")
            authority = app.RuntimeInputAuthority([] if authority_file is None else [authority_file])
            coordinator = app.RuntimeCoordinator(args, None, "PUBLIC-Factory-U3", [task], authority)
            coordinator.current_target = t
            real_permit = app.obtain_write_permit

            def permit(category="nvue"):
                device.events.append(("permit", category))
                return real_permit(category)

            def ask(_target, _reason, **_options):
                device.events.append(("consent", consent))
                return consent

            def inspected(device_target, endpoint, *_args, **options):
                self.assertIs(t, device_target)
                self.assertIs(point, endpoint)
                result = app.SessionResult("".join(row + "\n" for row in device.applied), 0)
                if route != "jump":
                    result._direct_endpoint = point
                return result, PASSWORD, options["authorized"]

            def direct_ready(_target, _user, _credential, _timeout, **options):
                options["details"].update(identity={"ok": True, "via_ipv4": True}, endpoint=point)
                return "".join(row + "\n" for row in device.applied)

            for name, value in (("_TASK_IB_CONFIG", None), ("_ACTIVE_COORDINATOR", coordinator),
                                ("_WORKER_CONNECTION", None), ("_WORKER_STOP", None),
                                ("_TASK_DEADLINE", None), ("_TASK_LOG_BUFFER", None),
                                ("_JUMP_SESSIONS", None)):
                context.enter_context(patch.object(app, name, value))
            context.enter_context(patch.object(app, "interactive_run", side_effect=device.transport))
            context.enter_context(patch.object(app, "obtain_write_permit", side_effect=permit))
            context.enter_context(patch.object(app, "_ask_first_device_change", side_effect=ask))
            context.enter_context(patch.object(app, "inspect_ib_device", side_effect=inspected))
            context.enter_context(patch.object(app, "verify_ipv4_login",
                side_effect=lambda *_a, **_k: "".join(row + "\n" for row in device.applied)))
            context.enter_context(patch.object(app, "_wait_direct_ipv4_readback", side_effect=direct_ready))
            context.enter_context(patch.object(app, "run_key_stage",
                                               side_effect=lambda *_a, **k: k["authorized"]))
            context.enter_context(patch.object(app, "run_management_direct_checks", return_value=[]))
            context.enter_context(patch.object(app, "refresh_ib_host_key",
                side_effect=AssertionError("PUBLIC U3 model has no host-key change")))
            context.enter_context(patch.object(app, "log", side_effect=lambda text="", *_a, **_k:
                                               logged.append(str(text))))
            result = app.execute_ib_task(task, args, None, "PUBLIC-Factory-U3", services, [], None)
        return result, coordinator, "\n".join(logged)

    @staticmethod
    def nvue_events(device):
        return [event for event in device.events if event == ("deferred-apply",) or event[0] == "nv"
                and (event[:2] == ("nv", "set") or event[:3] in (
                    ("nv", "config", "apply"), ("nv", "config", "save"), ("nv", "config", "detach")))]

    def scene(self, stage):
        """(applied rows, the one owned pending row) for the first write stage `stage`."""
        if stage == "initial":
            return U3_NETWORK + U3_SERVICES, U3_INITIAL[0]
        if stage == "day0":
            return ["nv set system hostname nvos", *U3_INITIAL, *U3_SERVICES], U3_NETWORK[-1]
        return U3_INITIAL + U3_NETWORK, U3_SERVICES[0]

    def test_profile_rows_are_owned_only_by_exact_tokens_of_this_run_profile(self):
        # Guide 8.10 step 1: a keyword-only profile, default None, positional (device, output) kept.
        parameters = inspect.signature(app._validate_owned_pending).parameters
        self.assertEqual(["device", "output"], [name for name, item in parameters.items()
                                                if item.kind is item.POSITIONAL_OR_KEYWORD])
        self.assertIn("services", parameters)
        self.assertIs(inspect.Parameter.KEYWORD_ONLY, parameters["services"].kind)
        self.assertIsNone(parameters["services"].default)
        device = target().ib
        profile = {"dns": ["203.0.113.53", "198.51.100.53"], "ntp": ["ntp.example.test", "203.0.113.123"],
                   "timezone": "Etc/UTC"}
        # Every profile value counts, not only the missing ones (step 1; issue 11.4 item 1).
        owned = "".join(f"nv set system dns server {value}\n" for value in profile["dns"])
        owned += "".join(f"nv set system ntp server {value}\n" for value in profile["ntp"])
        owned += "nv set system date-time timezone Etc/UTC\n"
        self.assertEqual(5, app._validate_owned_pending(device, owned, services=profile))
        self.assertEqual(7, app._validate_owned_pending(
            device, owned + U3_INITIAL[0] + "\n" + U3_NETWORK[-1] + "\n", services=profile))
        for body in ("nv set system dns server 203.0.113.53\n", "nv set system date-time timezone Etc/UTC\n"):
            with self.subTest(case="no-profile", body=body):
                with self.assertRaises(app.SetupError):
                    app._validate_owned_pending(device, body)
                with self.assertRaises(app.SetupError):
                    app._validate_owned_pending(device, body, services=None)
        for label, body in (
                ("dns-outside-profile", "nv set system dns server 203.0.113.99\n"),
                ("dns-substring", "nv set system dns server 203.0.113.530\n"),
                ("ntp-extra-attribute", "nv set system ntp server ntp.example.test iburst on\n"),
                ("ntp-state-attribute", "nv set system ntp server ntp.example.test state enabled\n"),
                ("unset", "nv unset system dns server 203.0.113.53\n"),
                ("timezone-other", "nv set system date-time timezone Asia/Taipei\n"),
                ("dns-as-ntp", "nv set system ntp server 203.0.113.53\n"),
                ("illegal-quote", "nv set system dns server '203.0.113.53\n")):
            with self.subTest(case=label):
                with self.assertRaises(app.SetupError) as refused:
                    app._validate_owned_pending(device, owned + body, services=profile)
                # Step 3/5: the reason names how many lines are unknown and how to proceed.
                self.assertIn("有 1 行不认识的待提交", str(refused.exception))
                self.assertIn(U3_HINT, str(refused.exception))
        with self.assertRaises(app.SetupError) as refused:
            app._validate_owned_pending(device, "nv set system dns server 203.0.113.99\n"
                                                "nv set system hostname another-leaf\n" + owned,
                                        services=profile)
        self.assertIn("有 2 行不认识的待提交", str(refused.exception))

    def test_owned_profile_rows_pass_rc0_and_rc1_on_jump_and_direct_transport(self):
        # Step 1: all four classifier call points (jump and direct, rc 0 and rc 1) see the profile.
        for function in (app.run_on_ib, app._run_on_ib_direct):
            parameters = inspect.signature(function).parameters
            self.assertIn("_pending_services", parameters, function.__name__)
            self.assertIs(inspect.Parameter.KEYWORD_ONLY, parameters["_pending_services"].kind)
            self.assertIsNone(parameters["_pending_services"].default)
        from contextlib import ExitStack
        import sys
        body = "nv set system dns server 203.0.113.53\n"
        marker = "ab" * 16
        for route in ("jump", "direct"):
            for status in (0, 1):
                for services in (U3_PROFILE, None):
                    with self.subTest(route=route, status=status, profile=services is not None), \
                            ExitStack() as context:
                        context.enter_context(patch.dict(sys.modules))
                        for name in list(sys.modules):
                            if name == "tools" or name.startswith("tools."):
                                del sys.modules[name]
                        context.enter_context(patch.object(sys, "path", [str(ROOT), *sys.path]))
                        context.enter_context(patch.object(app, "_TOOLS_ROOT", None))
                        if route == "jump":
                            t = target()
                            point = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
                            outer_user, outer = "cumulus", "OobOnly123!"
                        else:
                            ib = target().ib
                            t = app.Target(ib, None, "", "eth0", route=app._import_tools("tools.login_path").Route(
                                ib.hostname, "direct", "PUBLIC", None, None, None))
                            point = app.DirectEndpoint("192.0.2.10")
                            outer_user, outer = "", ""
                        output = (f"__HTTP_IB_BEGIN_{marker}__\n{body}__HTTP_IB_END_{marker}__={status}\n")
                        context.enter_context(patch.object(app.os, "urandom", return_value=bytes.fromhex(marker)))
                        transport = context.enter_context(patch.object(
                            app, "interactive_run", return_value=app.SessionResult(output, status)))
                        error = result = None
                        try:
                            result = app.run_on_ib(t, point, outer_user, outer, "admin", PASSWORD, 5,
                                                   list(U3_DIFF), _pending_services=services)
                        except app.SetupError as exc:
                            error = exc
                        self.assertEqual(1, transport.call_count, "the diff must reach the transport")
                        if services is None:
                            self.assertIsInstance(error, app.SetupError)
                        else:
                            self.assertIsNone(error, error)
                            self.assertEqual((body, status), (result.output, result.exit_code))

    def test_owned_pending_detach_requires_consent_and_empty_readback(self):
        for route in ("jump", "direct"):
            for stage in ("initial", "day0", "services"):
                for status in (0, 1):
                    applied, line = self.scene(stage)
                    device = _U3Device(self, applied, [line], diff_status=status)
                    with self.subTest(route=route, stage=stage, status=status):
                        result, coordinator, logged = self.u3_flow(device, route=route)
                        self.assertNotIn("failed_stage", result, result.get("reason"))
                        events = device.events
                        diffs = [index for index, event in enumerate(events) if event == U3_DIFF]
                        detach = events.index(U3_DETACH) if U3_DETACH in events else None
                        self.assertIsNotNone(detach, "the owned pending is detached")
                        self.assertEqual(1, events.count(U3_DETACH))
                        backup = next(index for index, event in enumerate(events)
                                      if event[:2] == ("sh", "-c"))
                        setters = [index for index, event in enumerate(events)
                                   if event[:2] == ("nv", "set")]
                        # Read where T15 read -> backup -> real NVUE permit -> detach -> empty re-read
                        # -> the stage's own setters (step 3).
                        self.assertTrue(diffs[0] < backup < detach < diffs[1] < setters[0], events)
                        self.assertEqual(("permit", "nvue"), events[detach - 1])
                        self.assertEqual(diffs[1], detach + 1, "the re-read follows the detach directly")
                        first_apply = next(index for index, event in enumerate(events)
                                           if event in (("nv", "config", "apply", "-y"), ("deferred-apply",)))
                        self.assertLess(detach, first_apply, "the old pending is never committed")
                        self.assertEqual([], device.pending)
                        self.assertIn(line, device.applied)
                        # Step 4: the detach is an NVUE write attempt on the original counter.
                        self.assertEqual(len(self.nvue_events(device)),
                                         coordinator.metrics.get("nvue_write_commands"))
                        self.assertTrue(coordinator.writes_attempted)
                        # Steps 3 and 6: the original line and its stage go to the log and the record.
                        self.assertEqual([{"stage": stage, "lines": [line], "detached": True}],
                                         result.get("pending_detached"))
                        self.assertIn(line, logged)

    def test_unrecognized_or_mixed_pending_is_refused_with_zero_detach(self):
        applied = U3_NETWORK + U3_SERVICES  # Initial is the first write stage.
        for route in ("jump", "direct"):
            for label, pending, services, unknown in (
                    ("outside-profile", ["nv set system dns server 198.51.100.99"], U3_PROFILE, 1),
                    ("mixed-owned-and-foreign", [U3_INITIAL[0], "nv set system hostname another-leaf"],
                     U3_PROFILE, 1),
                    ("no-profile-services-row", ["nv set system dns server 203.0.113.53"], None, 1),
                    ("unset", ["nv unset system dns server 203.0.113.53"], U3_PROFILE, 1),
                    ("two-foreign", ["nv set system dns server 198.51.100.99",
                                     "nv set interface swp1 type eth"], U3_PROFILE, 2)):
                device = _U3Device(self, applied, pending)
                with self.subTest(route=route, case=label):
                    result, coordinator, _ = self.u3_flow(device, route=route, services=services)
                    self.assertEqual("FAILED", result["outcome"])
                    self.assertIn(f"有 {unknown} 行不认识的待提交", result["reason"])
                    self.assertIn(U3_HINT, result["reason"])
                    self.assertEqual(1, device.events.count(U3_DIFF))
                    self.assertNotIn(U3_DETACH, device.events)
                    self.assertFalse(any(event[:2] == ("sh", "-c") or event[0] == "permit"
                                         for event in device.events), device.events)
                    self.assertEqual([], self.nvue_events(device))
                    self.assertEqual([tuple(shlex.split(row)) for row in pending], device.pending)
                    self.assertFalse(coordinator.writes_attempted)
                    self.assertEqual([], result.get("pending_detached"))

    def test_owned_pending_detach_failures_stop_the_device_without_stage_writes(self):
        import tempfile
        applied, line = self.scene("services")
        for route in ("jump", "direct"):
            for fault in ("backup-failed", "detach-nonzero", "readback-not-empty", "readback-unreadable",
                          "batch-stopped", "input-changed", "deadline"):
                device = _U3Device(self, applied, [line], faults=(fault,))
                with self.subTest(route=route, fault=fault), tempfile.TemporaryDirectory() as folder:
                    pinned = Path(folder) / "01-global.yaml"
                    pinned.write_text("PUBLIC U3 pinned input\n", encoding="ascii")

                    def disturb():
                        if fault == "batch-stopped":
                            app._ACTIVE_COORDINATOR.stopped = True
                            app._ACTIVE_COORDINATOR.fatal = "PUBLIC operator stop"
                        elif fault == "input-changed":
                            pinned.write_text("PUBLIC U3 changed input\n", encoding="ascii")
                        elif fault == "deadline":
                            app._TASK_DEADLINE = -1.0
                    device.on_first_diff = disturb
                    result, coordinator, _ = self.u3_flow(device, route=route, authority_file=pinned)
                    self.assertEqual("services", result.get("failed_stage"), result.get("reason"))
                    events = device.events
                    self.assertFalse(any(event[:2] == ("nv", "set") for event in events), events)
                    self.assertNotIn(("nv", "config", "apply", "-y"), events)
                    self.assertNotIn(("nv", "config", "save"), events)
                    # Recorded before consent/detach (step 3), whatever the detach outcome.
                    self.assertEqual([{"stage": "services", "lines": [line],
                                       "detached": False}], result.get("pending_detached"))
                    if fault in ("batch-stopped", "input-changed", "deadline"):
                        self.assertNotIn(U3_DETACH, events)
                        self.assertFalse(any(event[:2] == ("sh", "-c") for event in events))
                        self.assertEqual(0, coordinator.metrics.get("nvue_write_commands", 0))
                    elif fault == "backup-failed":
                        self.assertNotIn(U3_DETACH, events)
                        self.assertEqual("FAILED_CONFIG_BACKUP", result.get("category"))
                        self.assertEqual(0, coordinator.metrics.get("nvue_write_commands", 0))
                    else:
                        self.assertEqual(1, events.count(U3_DETACH))
                        self.assertEqual(1, coordinator.metrics.get("nvue_write_commands"))
                        self.assertEqual("FAILED", result["outcome"])
                        self.assertEqual(1 if fault == "detach-nonzero" else 2, events.count(U3_DIFF))

    def test_services_detach_waits_for_its_own_consent(self):
        applied, line = self.scene("services")
        for consent in (True, False):
            device = _U3Device(self, applied, [line])
            with self.subTest(consent=consent):
                result, coordinator, _ = self.u3_flow(device, yes=False, consent=consent)
                events = device.events
                self.assertIn(("consent", consent), events, result.get("reason"))
                asked = events.index(("consent", consent))
                # Step 3: the Services pending is read at its original place, before the consent,
                # and nothing is cleared before the consent.
                self.assertLess(events.index(U3_DIFF), asked)
                self.assertFalse(any(event == U3_DETACH or event[:2] == ("sh", "-c")
                                     for event in events[:asked]), events)
                if consent:
                    self.assertLess(asked, events.index(U3_DETACH))
                    self.assertNotIn("failed_stage", result, result.get("reason"))
                else:
                    self.assertNotIn(U3_DETACH, events)
                    self.assertEqual([tuple(shlex.split(line))], device.pending)
                    self.assertFalse(coordinator.writes_attempted)

    def test_check_only_reads_once_and_reports_without_detach(self):
        for route in ("jump", "direct"):
            # Initial and Services both still need writes: one read-only diff at the first of them.
            device = _U3Device(self, U3_NETWORK, ["nv set system dns server 203.0.113.53", U3_INITIAL[1]])
            with self.subTest(route=route, case="owned"):
                result, coordinator, logged = self.u3_flow(device, route=route, apply=False)
                self.assertEqual(1, device.events.count(U3_DIFF))
                self.assertNotIn(U3_DETACH, device.events)
                self.assertFalse(any(event[0] == "permit" for event in device.events))
                self.assertEqual(2, len(device.pending))
                self.assertIn({"item": "pending", "value": "2 owned lines"}, result["planned_changes"])
                self.assertIs(True, result["needs_change"])
                self.assertEqual("CHECK_ONLY", result["outcome"])
                self.assertIn("有 2 行自有待提交，--apply 时会 detach 后重做", logged)
                self.assertFalse(coordinator.writes_attempted)
            device = _U3Device(self, U3_NETWORK + U3_SERVICES, ["nv set system dns server 198.51.100.99"])
            with self.subTest(route=route, case="foreign"):
                result, coordinator, _ = self.u3_flow(device, route=route, apply=False)
                self.assertEqual(1, device.events.count(U3_DIFF))
                self.assertNotIn(U3_DETACH, device.events)
                self.assertIn("有 1 行不认识的待提交，--apply 会拒绝", result["reason"])
            # Keys-only / nothing to write: no new pending query at all (step 5).
            for apply in (False, True):
                device = _U3Device(self, U3_INITIAL + U3_NETWORK + U3_SERVICES,
                                   ["nv set system dns server 198.51.100.99"])
                with self.subTest(route=route, case="nothing-to-write", apply=apply):
                    result, _, _ = self.u3_flow(device, route=route, apply=apply)
                    self.assertNotIn(U3_DIFF, device.events)
                    self.assertNotIn("failed_stage", result, result.get("reason"))

    def test_detach_follows_the_stage_route_on_all_four_ib_paths(self):
        # Step 4: ordinary and strict/helper, jump and direct route the detach like any stage write;
        # the pending reads stay on run_on_ib (`_require_empty_pending`'s original reader).
        enabled = "".join(row + "\n" for row in U3_INITIAL)
        for strict in (False, True):
            for direct in (False, True):
                t = target()
                point = app.Neighbor("fe80::10", "vlan1000", t.ib.eth0_mac, "oob")
                if direct:
                    t = app.Target(t.ib, None, "", "eth0")
                    point = app.DirectEndpoint("192.0.2.10")
                timeline = []
                pending = [U3_INITIAL[0]]

                def reply(label, command):
                    command = tuple(command)
                    timeline.append((label, command))
                    if command == U3_DIFF:
                        return app.SessionResult("".join(row + "\n" for row in pending), 1 if pending else 0)
                    if command == U3_DETACH:
                        pending.clear()
                    if command == ("nv", "config", "show", "-o", "commands"):
                        return app.SessionResult(enabled, 0)
                    if command == ("nv", "show", "system", "ztp"):
                        return app.SessionResult("service disabled\nstate disabled\n", 0)
                    return app.SessionResult("", 0)

                class Guard:
                    @staticmethod
                    def assert_unchanged():
                        timeline.append(("guard", ()))

                ordinary = lambda *a, **_k: reply("run_on_ib", a[7])
                jump_helper = lambda *a, **_k: reply("jump-helper", a[7])
                direct_helper = lambda *a, **_k: reply("direct-helper", a[7])
                context = ({"_ib_current_password": PASSWORD, "_password_policy": Guard()} if strict
                           else {"ib_password": PASSWORD})
                with self.subTest(strict=strict, direct=direct), \
                        patch.object(app, "run_on_ib", side_effect=ordinary), \
                        patch.object(app, "_run_authorized_ib_command", side_effect=jump_helper), \
                        patch.object(app, "_run_authorized_ib_direct_command", side_effect=direct_helper), \
                        patch.object(app, "log"):
                    error = None
                    try:
                        app.run_initial_stage(t, point, "" if direct else "cumulus", "" if direct else "OOB",
                                              "admin", 5, "nv set system hostname nvos\n", local=False,
                                              apply=True, authorized=True,
                                              initial_ztp_output="service enabled\nstate enabled\n", **context)
                    except app.SetupError as exc:
                        error = exc
                    self.assertIsNone(error, error)
                    route = ("direct-helper" if direct else "jump-helper") if strict else "run_on_ib"
                    detach = timeline.index((route, U3_DETACH))
                    diffs = [index for index, (label, command) in enumerate(timeline) if command == U3_DIFF]
                    self.assertEqual(["run_on_ib", "run_on_ib"], [timeline[index][0] for index in diffs])
                    self.assertTrue(diffs[0] < detach < diffs[1], timeline)
                    first_setter = next(index for index, (_, command) in enumerate(timeline)
                                        if command[:2] == ("nv", "set"))
                    self.assertLess(diffs[1], first_setter)
                    self.assertEqual(route, timeline[first_setter][0])


if __name__ == "__main__":
    unittest.main()
