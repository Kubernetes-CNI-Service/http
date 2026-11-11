"""Direct: initial-setup's Initial/Network stages accept a configuration that contains the
expected values, keep extra configuration, and inspect/rotate the IB password in v15 order.

Expectation source: v15 CURRENT-CONTRACT.md:54 ("期望配置被包含即可通过，额外配置保留；真冲突或不明
pending 不盲目覆盖") and :49-:50 (credential order), taken from the v15 delivered tests
initial-setup-test-cases/test_desktop_initial_setup.py::DesiredConfigurationSubsetTests (:447),
::InspectFlowTests (:190), ::InitialAndBaseConfigurationTests (:1004) and
test_initial_setup_log_review.py::ServiceStageWorkflowTests (:148), whose bytes are bound by
HANDOFF-SHA256SUMS:27 and :29 (v3.1.3 guide WP-7, table 7-1 :821; ServiceStage is the one
log-review gap no DEV test pins, guide :818 "缺的补").  Expectations are not derived from the
merged implementation.

Decided changes against the v15 assertions (each also cited at the test):
- T15 (guide :2301): a write stage starts only on an empty pending diff (DEV), so v15's
  validate_owned_pending test is rewritten against the merged refusal, which refuses every
  non-empty pending diff (owned or unrelated) before any write.

Fixture rewrites (public audit, guide :835): synthetic host names, documentation addresses,
02:00:00 MACs, credentials assembled at run time, a synthetic SHA-512-shaped project hash whose
verification is replaced by an exact comparison with the run-time target value (no hash literal
may be public).  Nothing here reaches main(), HOME or the network; time.sleep is replaced where
the IPv4 readiness probe could be reached.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import shlex
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
app = load_script("initial_setup_v15_base_and_subset", INITIAL)


def secret(label: str) -> str:
    return "-".join(("PUBLIC", "wp7", label, "Zq7"))


PASSWORD = secret("target")
OOB_PASSWORD = secret("oob")
# Synthetic SHA-512-crypt shape; assembled so no reusable hash literal appears in the source.
PROJECT_HASH = "$" + "6$PUBLICsalt$" + "A" * 86
CONFIG = "nv set system hostname nvos\n"


def target():
    ib = app.Device("example-ib001", "ib", "192.0.2.10", "192.0.2.10/24",
                    "192.0.2.1", "02:00:00:00:00:10", "", "")
    eth = app.Device("example-oob-leaf01", "eth_jump", "198.51.100.10", "", "", "", "", "")
    return app.Target(ib, eth, "swp1", "eth0")


def neighbor():
    return app.Neighbor("fe80::10", "vlan1000", target().ib.eth0_mac, "oob")


def global_text(hash_value=PROJECT_HASH):
    return ('schema_version: 2\ncommon:\n  switch:\n    system:\n'
            '      config:\n        auto-save:\n          state: enabled\n'
            'switches:\n- ib:\n    system:\n      aaa:\n        user:\n'
            '          admin:\n            password: "' + hash_value + '"\n')


def verify_hash(value, digest):
    """Exact stand-in for the native hash check: only the run-time target matches."""
    return digest == PROJECT_HASH and value == PASSWORD


class BaseAndSubsetTests(unittest.TestCase):
    # -- v15 DesiredConfigurationSubsetTests fixture ------------------------------------------
    def current(self):
        return app.parse_nvue_state(
            "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
            "nv set interface eth0 ipv4 address 198.51.100.10/24\n"
            "nv set interface eth1 ipv4 address 203.0.113.10/24\n"
            "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
            "nv set interface eth0 ipv4 gateway 192.0.2.1\n"
            "nv set interface eth0-1 link state up\n"
            "nv set interface eth0-1 type eth\n"
            "nv set system hostname example-ib001\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set interface lo description existing-config\n")

    # v15 DesiredConfigurationSubsetTests.test_expected_configuration_with_extra_addresses_is_complete (test_desktop_initial_setup.py:461)
    def test_expected_configuration_with_extra_addresses_is_complete(self):
        self.assertEqual(app.classify_auto_day0(target().ib, self.current()), "complete")
        app.verify_state(target().ib, self.current())

    # v15 DesiredConfigurationSubsetTests.test_extra_applied_configuration_does_not_require_force_or_base_reapply (test_desktop_initial_setup.py:465)
    def test_extra_applied_configuration_does_not_require_force_or_base_reapply(self):
        self.assertFalse(app.base_stage_needed(target().ib, self.current(), False))
        self.assertFalse(app.base_stage_needed(target().ib, self.current(), True))

    # v15 DesiredConfigurationSubsetTests.test_extra_and_duplicate_gateway_values_do_not_require_exact_tuple_equality (test_desktop_initial_setup.py:469)
    def test_extra_and_duplicate_gateway_values_do_not_require_exact_tuple_equality(self):
        state = app.parse_nvue_state(self.current().raw_commands +
                                     "\nnv set interface eth0 ipv4 gateway 198.51.100.1\n")
        self.assertEqual(app.classify_auto_day0(target().ib, state), "complete")
        self.assertFalse(app.force_day0_needed(target().ib, state))

    # v15 DesiredConfigurationSubsetTests.test_unrequested_eth1_configuration_is_not_a_conflict (test_desktop_initial_setup.py:475)
    def test_unrequested_eth1_configuration_is_not_a_conflict(self):
        state = app.parse_nvue_state(self.current().raw_commands +
                                     "\nnv set interface eth1 ipv4 gateway 203.0.113.1\n")
        self.assertFalse(app.base_stage_needed(target().ib, state, False))
        self.assertFalse(app.force_day0_needed(target().ib, state))

    # v15 DesiredConfigurationSubsetTests.test_missing_expected_address_is_not_hidden_by_an_extra_address (test_desktop_initial_setup.py:481)
    def test_missing_expected_address_is_not_hidden_by_an_extra_address(self):
        state = app.parse_nvue_state(self.current().raw_commands.replace(
            "nv set interface eth0 ipv4 address 192.0.2.10/24\n", ""))
        self.assertEqual(app.classify_auto_day0(target().ib, state), "terminal")
        with self.assertRaises(app.SetupError):
            app.verify_state(target().ib, state)
        self.assertTrue(app.force_day0_needed(target().ib, state))

    # v15 DesiredConfigurationSubsetTests.test_wrong_singleton_hostname_or_missing_gateway_is_not_success (test_desktop_initial_setup.py:489)
    def test_wrong_singleton_hostname_or_missing_gateway_is_not_success(self):
        for current in (
                self.current().raw_commands.replace("hostname example-ib001", "hostname another-switch"),
                self.current().raw_commands.replace("gateway 192.0.2.1", "gateway 192.0.2.254")):
            with self.subTest(current=current):
                state = app.parse_nvue_state(current)
                with self.assertRaises(app.SetupError):
                    app.force_day0_needed(target().ib, state)

    # v15 DesiredConfigurationSubsetTests.test_services_only_require_requested_members_not_equal_server_lists (test_desktop_initial_setup.py:498)
    def test_services_only_require_requested_members_not_equal_server_lists(self):
        services = {"dns": ["192.0.2.53"], "ntp": ["ntp.example.com"], "timezone": "Etc/UTC"}
        current = ("nv set system dns server 192.0.2.53\n"
                   "nv set system dns server 198.51.100.53\n"
                   "nv set system ntp server ntp.example.com state enabled\n"
                   "nv set system ntp server other.example.com state enabled\n"
                   "nv set system date-time timezone Etc/UTC\n")
        self.assertEqual(app.desired_service_commands(services, current), [])

    # v15 DesiredConfigurationSubsetTests.test_unrelated_unapplied_pending_is_not_implicitly_authorized (test_desktop_initial_setup.py:507)
    def test_unrelated_unapplied_pending_is_not_implicitly_authorized(self):
        # T15 (guide :2301, "采用 DEV：Initial（未就绪时）、Network、Services 三个写阶段前要求
        # nv config diff 为空，不去掉这道安全检查"): v15's validate_owned_pending is gone; the
        # merged gate refuses every non-empty pending diff, so the unrelated pending of the v15
        # case is still refused and so is a pending that only holds this device's own Network
        # setters (never adopted or committed).  An empty diff passes.  Only T15's behaviour is
        # asserted: the diff is read, a non-empty one is refused, an empty one passes, no write
        # follows a refusal.  How often or in which argument position the gate calls run_on_ib,
        # its password-change flag and the order of the Initial reads are implementation shape
        # that no expectation source states (WP-7b, review A wa7-2; guide :877).  The diff
        # command form is the one DEV's own tests pin (test_initial_setup_pending_diff,
        # test_initial_setup_nvos_argv; principle 8).
        t, n = target(), neighbor()
        # The v15 assertion itself, on DEV's renamed qualifier of a pending-diff readback.
        with self.assertRaises(app.SetupError):
            app._validate_owned_pending(t.ib, "nv set system dns server 203.0.113.99\n")
        owned = "\n".join(shlex.join(command) for command in app.desired_commands(t.ib)
                          if command[:2] == ["nv", "set"]) + "\n"
        for body, status in (("nv set system dns server 203.0.113.99\n", 0),
                             ("nv set system dns server 203.0.113.99\n", 1),
                             (owned, 0), (owned, 1)):
            with self.subTest(body=body, status=status), \
                    patch.object(app, "run_on_ib", return_value=app.SessionResult(body, status)) as run:
                with self.assertRaisesRegex(app.SetupError, "pending"):
                    app._require_empty_pending(t, n, "cumulus", OOB_PASSWORD, "admin", PASSWORD, 5,
                                               local=False)
                self.assertIn(["nv", "config", "diff", "-o", "commands"],
                              [argument for call in run.call_args_list
                               for argument in (*call.args, *call.kwargs.values())])
        with patch.object(app, "run_on_ib", return_value=app.SessionResult("", 0)):
            app._require_empty_pending(t, n, "cumulus", OOB_PASSWORD, "admin", PASSWORD, 5, local=False)
        # The refusal comes before the first write of a write stage (Initial, not yet ready).
        sent = []

        def device(*args, **kwargs):
            sent.append(args[7])
            if args[7] == ["nv", "show", "system", "ztp"]:
                return app.SessionResult("service disabled\n", 0)
            if args[7] == ["nv", "config", "diff", "-o", "commands"]:
                return app.SessionResult("nv set system dns server 203.0.113.99\n", 0)
            raise AssertionError("no write may follow a non-empty pending diff: " + repr(args[7]))
        with patch.object(app, "run_on_ib", side_effect=device), patch.object(app, "log"):
            with self.assertRaisesRegex(app.SetupError, "pending"):
                app.run_initial_stage(t, n, "cumulus", OOB_PASSWORD, "admin", 5, CONFIG,
                                      local=False, apply=True, authorized=True, ib_password=PASSWORD)
        self.assertIn(["nv", "config", "diff", "-o", "commands"], sent)

    # -- v15 InspectFlowTests ------------------------------------------------------------------
    def inspect(self, policy, apply=True, authorized=False):
        return app.inspect_ib_device(target(), neighbor(), "cumulus", OOB_PASSWORD,
                                     "admin", "admin", 5, policy, apply=apply,
                                     authorized=authorized, local=False)

    @contextlib.contextmanager
    def policy(self):
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(app, "verify_password_hash", side_effect=verify_hash):
            path = Path(directory) / "01-global.yaml"
            path.write_text(global_text())
            yield app.ProjectPasswordPolicy(path, "admin")

    # v15 InspectFlowTests.test_factory_change_then_password_only_fresh_login (test_desktop_initial_setup.py:202)
    def test_factory_change_then_password_only_fresh_login(self):
        required = app.SessionResult("", 0, password_change_required=True)
        changed = app.SessionResult("", 0, password_changed=True)
        with self.policy() as policy, \
             patch.object(app, "run_on_ib", side_effect=[required, changed, app.SessionResult(CONFIG, 0)]) as run, \
             patch.object(app.getpass, "getpass", side_effect=[PASSWORD, PASSWORD]), \
             patch.object(app, "confirm_first_device_change", return_value=True), \
             patch.object(app, "log"):
            result, credential, authorized = self.inspect(policy)
        self.assertEqual(result.output, CONFIG)
        self.assertEqual(credential, PASSWORD)
        self.assertTrue(authorized)
        self.assertFalse(run.call_args_list[0].kwargs["allow_password_change"])
        self.assertEqual(run.call_args_list[1].kwargs["ib_new_password"], PASSWORD)
        self.assertTrue(run.call_args_list[2].kwargs["password_only"])
        self.assertEqual(run.call_args_list[2].args[5], PASSWORD)

    # v15 InspectFlowTests.test_already_changed_target_password_no_rotation (test_desktop_initial_setup.py:215)
    def test_already_changed_target_password_no_rotation(self):
        with self.policy() as policy, \
             patch.object(app, "run_on_ib", side_effect=[
                 app.IBAuthenticationError("authentication rejected"), app.SessionResult(CONFIG, 0)]) as run, \
             patch.object(app.getpass, "getpass", side_effect=[PASSWORD, PASSWORD]), \
             patch.object(app, "confirm_first_device_change") as confirm, \
             patch.object(app, "log"):
            result, credential, authorized = self.inspect(policy)
        self.assertEqual(credential, PASSWORD)
        self.assertEqual(result.output, CONFIG)
        confirm.assert_not_called()
        self.assertTrue(all(not call.kwargs.get("allow_password_change", False)
                            for call in run.call_args_list))

    # v15 InspectFlowTests.test_actual_current_password_different_from_global_blocks_apply (test_desktop_initial_setup.py:225)
    def test_actual_current_password_different_from_global_blocks_apply(self):
        with self.policy() as policy, \
             patch.object(app, "run_on_ib", side_effect=[
                 app.IBAuthenticationError("rejected"), app.IBAuthenticationError("rejected"),
                 app.SessionResult(CONFIG, 0)]), \
             patch.object(app.getpass, "getpass", side_effect=[PASSWORD, PASSWORD, secret("historical")]), \
             patch.object(app, "confirm_first_device_change") as confirm, \
             patch.object(app, "log"):
            with self.assertRaisesRegex(app.SetupError, "does not match"):
                self.inspect(policy)
        confirm.assert_not_called()

    # v15 InspectFlowTests.test_readonly_expiry_no_new_password_no_confirmation (test_desktop_initial_setup.py:234)
    def test_readonly_expiry_no_new_password_no_confirmation(self):
        with self.policy() as policy, \
             patch.object(app, "run_on_ib", return_value=app.SessionResult("", 0, password_change_required=True)), \
             patch.object(app.getpass, "getpass") as prompt, \
             patch.object(app, "confirm_first_device_change") as confirm, \
             patch.object(app, "log"):
            result, _, _ = self.inspect(policy, apply=False)
        self.assertTrue(result.password_change_required)
        prompt.assert_not_called()
        confirm.assert_not_called()

    # v15 InspectFlowTests.test_failed_fresh_login_no_day0_commands (test_desktop_initial_setup.py:241)
    def test_failed_fresh_login_no_day0_commands(self):
        with self.policy() as policy, \
             patch.object(app, "run_on_ib", side_effect=[
                 app.SessionResult("", 0, password_change_required=True),
                 app.SessionResult("", 0, password_changed=True),
                 app.IBAuthenticationError("fresh login failed")]) as run, \
             patch.object(app.getpass, "getpass", side_effect=[PASSWORD, PASSWORD]), \
             patch.object(app, "confirm_first_device_change", return_value=True), \
             patch.object(app, "log"):
            with self.assertRaises(app.SetupError):
                self.inspect(policy)
        self.assertTrue(all(call.args[7] == ["nv", "config", "show", "-o", "commands"]
                            for call in run.call_args_list))

    # -- v15 InitialAndBaseConfigurationTests ---------------------------------------------------
    # v15 InitialAndBaseConfigurationTests.test_initial_stage_is_saved_before_base_configuration (test_desktop_initial_setup.py:1005)
    def test_initial_stage_is_saved_before_base_configuration(self):
        self.assertEqual(app.initial_configuration_commands(), [
            ["nv", "set", "system", "config", "auto-save", "state", "enabled"],
            ["nv", "set", "system", "ztp", "config-save", "enabled"],
            ["nv", "config", "apply", "-y"],
            ["nv", "config", "save"],
        ])

    # v15 InitialAndBaseConfigurationTests.test_base_commands_include_link_type_and_noninteractive_apply (test_desktop_initial_setup.py:1013)
    def test_base_commands_include_link_type_and_noninteractive_apply(self):
        # The full desired Network command list (plan/generator view).  The run's write set is
        # only the missing setters (T16, guide :2302), pinned by the DEV tests.
        device = app.Device("example-ib002", "ib", "192.0.2.12", "192.0.2.12/24",
                            "192.0.2.1", "02:00:00:00:00:12", "192.0.2.13/24", "192.0.2.1")
        self.assertEqual(app.desired_commands(device), [
            ["nv", "set", "interface", "eth0", "ipv4", "address", "192.0.2.12/24"],
            ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "192.0.2.1"],
            ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
            ["nv", "set", "interface", "eth0-1", "type", "eth"],
            ["nv", "set", "interface", "eth1", "ipv4", "address", "192.0.2.13/24"],
            ["nv", "set", "system", "hostname", "example-ib002"],
            ["nv", "config", "apply", "-y"],
            ["nv", "config", "save"],
        ])

    # v15 InitialAndBaseConfigurationTests.test_allowlist_requires_noninteractive_apply (test_desktop_initial_setup.py:1027)
    def test_allowlist_requires_noninteractive_apply(self):
        self.assertEqual(app.ib_command_argv(["nv", "config", "apply", "-y"]),
                         ["nv", "config", "apply", "-y"])
        with self.assertRaises(app.SetupError):
            app.ib_command_argv(["nv", "config", "apply"])

    # v15 InitialAndBaseConfigurationTests.test_ztp_operational_disabled_is_not_confused_with_config_save (test_desktop_initial_setup.py:1033)
    def test_ztp_operational_disabled_is_not_confused_with_config_save(self):
        output = ("             operational  applied\n"
                  "-----------  -----------  -------\n"
                  "service      disabled\nstatus       aborted\n"
                  "config-save  enabled      enabled\n\nZTP stages\nNo Data\n")
        self.assertTrue(app._ztp_disabled(output))
        self.assertFalse(app._ztp_disabled(output.replace("service      disabled", "service      enabled")))
        self.assertTrue(app._ztp_disabled("state disabled\n"))
        with self.assertRaises(app.SetupError):
            app._ztp_disabled("config-save enabled\n")

    # v15 InitialAndBaseConfigurationTests.test_matching_address_does_not_hide_conflicting_hostname (test_desktop_initial_setup.py:1044)
    def test_matching_address_does_not_hide_conflicting_hostname(self):
        state = app.parse_nvue_state(
            "nv set interface eth0 ipv4 address 192.0.2.10/24\n"
            "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
            "nv set system hostname another-switch\n")
        with self.assertRaises(app.SetupError):
            app.base_stage_needed(target().ib, state, False)

    # v15 InitialAndBaseConfigurationTests.test_services_apply_is_noninteractive_and_readback_is_idempotent (test_desktop_initial_setup.py:1052)
    def test_services_apply_is_noninteractive_and_readback_is_idempotent(self):
        t, n = target(), neighbor()
        services = {"dns": ["192.0.2.53"], "ntp": ["192.0.2.123"], "timezone": "Etc/UTC"}
        current = ("nv set system dns server 192.0.2.53\n"
                   "nv set system date-time timezone Etc/UTC\n")
        readback = current + "nv set system ntp server 192.0.2.123 state enabled\n"
        calls = []

        def fake_run(*args, **kwargs):
            calls.append(args[7])
            return app.SessionResult(readback, 0)
        with patch.object(app, "run_on_ib", side_effect=fake_run), patch.object(app, "log"):
            authorized, skipped = app.run_service_stage(
                t, n, "cumulus", OOB_PASSWORD, "admin", 5, services, current,
                local=False, apply=True, authorized=True, ib_password=PASSWORD)
        self.assertTrue(authorized)
        self.assertFalse(skipped)
        self.assertEqual(calls, [
            ["nv", "set", "system", "ntp", "server", "192.0.2.123"],
            ["nv", "config", "apply", "-y"],
            ["nv", "config", "save"],
            ["nv", "config", "show", "-o", "commands"],
        ])

    # -- log-review gap (table 7-1 :818) ------------------------------------------------------
    # v15 ServiceStageWorkflowTests.test_preexisting_infra_is_already_present_not_an_unchecked_skip (test_initial_setup_log_review.py:149)
    def test_preexisting_infra_is_already_present_not_an_unchecked_skip(self):
        t = target()
        task = app.PreparedIBTask(t, neighbor(), "", False)
        current = "\n".join(shlex.join(c) for c in app.desired_commands(t.ib) if c[:2] == ["nv", "set"]) + "\n"
        current += "\n".join(shlex.join(c) for c in app.initial_configuration_commands()[:2]) + "\n"
        current += ("nv set system dns server 192.0.2.53\nnv set system ntp server 192.0.2.123 state enabled\n"
                    "nv set system date-time timezone Etc/UTC\n")
        args = SimpleNamespace(apply=True, force=False, eth_user="cumulus", ib_user="admin",
                               connect_timeout=5, execution_mode="management")
        commands = []

        def query(*values, **kwargs):
            command = values[7]
            commands.append(command)
            return app.SessionResult("service disabled\n" if command == ["nv", "show", "system", "ztp"] else "", 0)
        with patch.object(app, "inspect_ib_device",
                          return_value=(app.SessionResult(current, 0), secret("ib"), True)), \
             patch.object(app, "run_on_ib", query), patch.object(app, "verify_ipv4_login"), \
             patch.object(app.time, "sleep"), \
             patch.object(app, "run_management_direct_checks", return_value=[dict(
                 hostname=t.ib.hostname, interface="eth0", ip=t.ib.login_ip, status="PASS")]), \
             contextlib.redirect_stdout(io.StringIO()):
            row = app.execute_ib_task(task, args, None, "admin",
                                      dict(dns=["192.0.2.53"], ntp=["192.0.2.123"], timezone="Etc/UTC"),
                                      [], None, True)
        self.assertEqual(row["outcome"], "ALREADY_CONFIGURED", row)
        self.assertEqual(row["stage_status"]["services"], "ALREADY_PRESENT")
        self.assertFalse(any(c[:2] == ["nv", "set"] for c in commands))


if __name__ == "__main__":
    unittest.main()
