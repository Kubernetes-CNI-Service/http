"""Pure management Network construction/readback contracts, tests first.

Only supplied PUBLIC Device/NVUE data is used. Missing proposed APIs is a
prerequisite HOLD, never a behavioral RED. No transport, project permission,
MAIN stage, device write or native Linux/AIR result is modeled as complete.
"""
from __future__ import annotations

import builtins
import contextlib
from pathlib import Path
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("management_network_pure_contract",
                  ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

FRESH = "nv set system hostname nvos\nnv set service lldp state enabled\n"
HOST = "nv set system hostname EXAMPLE-IB01\n"
ADDRESS0 = "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
ADDRESS1_SAME = "nv set interface eth1 ipv4 address 203.0.113.3/24\n"
ADDRESS1_DIFF = "nv set interface eth1 ipv4 address 198.51.100.2/24\n"
GATEWAY0 = "nv set interface eth0 ipv4 gateway 203.0.113.1\n"
GATEWAY1_SAME = "nv set interface eth1 ipv4 gateway 203.0.113.1\n"
GATEWAY1_DIFF = "nv set interface eth1 ipv4 gateway 198.51.100.1\n"
GATEWAY_RANGE = "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
LINK_RANGE = "nv set interface eth0-1 link state up\n"
TYPE_RANGE = "nv set interface eth0-1 type eth\n"
LINK0 = "nv set interface eth0 link state up\n"
LINK1 = "nv set interface eth1 link state up\n"
TYPE0 = "nv set interface eth0 type eth\n"
TYPE1 = "nv set interface eth1 type eth\n"
SINGLE_COMPLETE = ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE_RANGE + HOST
DUAL_DIFF_COMPLETE = (ADDRESS0 + ADDRESS1_DIFF + GATEWAY0 + GATEWAY1_DIFF +
                      LINK_RANGE + TYPE_RANGE + HOST)

# Quoting changes representation, never actual NVUE token authority.
QUOTED_SINGLE = (
    'nv set interface "eth0" ipv4 address "203.0.113.2/24"\n'
    'nv set interface "eth0" ipv4 gateway "203.0.113.1"\n'
    'nv set interface "eth0-1" link state "up"\n'
    'nv set interface "eth0-1" type "eth"\n'
    'nv set system hostname "EXAMPLE-IB01"\n'
)
# Independent literal actual-command expectations, not SUT canonical output.
SINGLE_NVSET_TOKENS = [
    ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
    ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
    ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
    ["nv", "set", "interface", "eth0-1", "type", "eth"],
    ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
]
EXTRA_SINGLE_NVSET_TOKENS = [
    ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
    ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.99/24"],
    ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.77/24"],
    ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
    ["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"],
    ["nv", "set", "interface", "eth0", "link", "state", "up"],
    ["nv", "set", "interface", "eth1", "link", "state", "up"],
    ["nv", "set", "interface", "eth0", "type", "eth"],
    ["nv", "set", "interface", "eth1", "type", "eth"],
    ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
]
DUAL_DIFF_NVSET_TOKENS = [
    ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
    ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.2/24"],
    ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
    ["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"],
    ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
    ["nv", "set", "interface", "eth0-1", "type", "eth"],
    ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
]


class ManagementNetworkPureContractDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not all(callable(getattr(APP, name, None)) for name in
                   ("_management_network_commands", "_verify_management_network_state")):
            raise RuntimeError("FIXTURE HOLD: proposed pure management Network APIs are not implemented")

    def device(self, kind="single"):
        eth1, gateway1 = ("", "")
        if kind == "dual-different":
            eth1, gateway1 = "198.51.100.2/24", "198.51.100.1"
        elif kind == "dual-same":
            eth1, gateway1 = "203.0.113.3/24", "203.0.113.1"
        elif kind != "single":
            raise AssertionError("PUBLIC unknown Network fixture kind")
        return APP.Device("EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
                          "203.0.113.1", "02:00:00:00:00:17", eth1, gateway1)

    def call_pure(self, api, device, current):
        # Transparent business-parser delegates. These are reach/identity
        # witnesses, never a generator of the independent expected vectors.
        parse_real = APP.parse_nvue_state
        verify_real = APP.verify_state
        parsed = []
        parse_inputs = []
        verified = []
        io_attempts = []
        def parse(value):
            result = parse_real(value)
            parse_inputs.append(value == current)
            parsed.append(result)
            return result
        def verify(actual_device, state):
            result = verify_real(actual_device, state)
            verified.append(actual_device is device and
                            any(state is item for item in parsed))
            return result
        def forbidden(*args, **kwargs):
            # Do not echo arbitrary arguments, even for an unexpected caller.
            io_attempts.append("PUBLIC forbidden IO/native/prompt")
            raise AssertionError("PUBLIC pure Network helper attempted IO/native/prompt")
        result = None
        caught = None
        with contextlib.ExitStack() as stack:
            for owner, name in (
                (APP, "interactive_run"), (APP, "verify_password_hash"),
                (APP.subprocess, "run"), (APP.subprocess, "Popen"),
                (APP.os, "open"), (APP.os, "system"),
                (APP.Path, "open"), (builtins, "open"),
                (APP.getpass, "getpass"),
            ):
                stack.enter_context(mock.patch.object(owner, name, side_effect=forbidden))
            stack.enter_context(mock.patch.object(APP, "parse_nvue_state", side_effect=parse))
            stack.enter_context(mock.patch.object(APP, "verify_state", side_effect=verify))
            try:
                result = getattr(APP, api)(device, current)
            except BaseException as error:
                caught = error
        self.assertEqual([], io_attempts, "pure helper crossed a forbidden external boundary")
        return result, caught, parse_inputs, verified

    def _expect_commands(self, kind, current, expected):
        device = self.device(kind)
        result, caught, parsed, verified = self.call_pure(
            "_management_network_commands", device, current)
        self.assertTrue(caught is None, "pure constructor failed on a qualified PUBLIC state")
        self.assertEqual(expected, result)
        self.assertTrue(type(result) is list and all(
            type(command) is list and all(type(token) is str for token in command)
            for command in result), "constructor must return closed typed argv vectors")
        self.assertTrue(all(command[:2] == ["nv", "set"] for command in result),
                        "pure constructor must never commit, save, unset or delete")
        self.assertTrue(bool(parsed) and any(parsed), "actual current parser must be reached")
        return result

    def test_fresh_single_and_dual_have_exact_independent_setter_order(self):
        cases = (
            ("single", [
                ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
                ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"],
                ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
                ["nv", "set", "interface", "eth0-1", "type", "eth"],
                ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
            ]),
            ("dual-different", [
                ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
                ["nv", "set", "interface", "eth1", "ipv4", "address", "198.51.100.2/24"],
                ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
                ["nv", "set", "interface", "eth1", "ipv4", "gateway", "198.51.100.1"],
                ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
                ["nv", "set", "interface", "eth0-1", "type", "eth"],
                ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
            ]),
            ("dual-same", [
                ["nv", "set", "interface", "eth0", "ipv4", "address", "203.0.113.2/24"],
                ["nv", "set", "interface", "eth1", "ipv4", "address", "203.0.113.3/24"],
                ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"],
                ["nv", "set", "interface", "eth0-1", "link", "state", "up"],
                ["nv", "set", "interface", "eth0-1", "type", "eth"],
                ["nv", "set", "system", "hostname", "EXAMPLE-IB01"],
            ]),
        )
        for kind, expected in cases:
            with self.subTest(kind=kind):
                self._expect_commands(kind, FRESH, expected)

    def test_satisfied_range_and_single_aliases_preserve_extra_addresses_and_unrequired_eth1(self):
        cases = (
            ("single-all-quoted-fields", "single", QUOTED_SINGLE),
            ("single-range-extra", "single",
             ADDRESS0 + "nv set interface eth0 ipv4 address 203.0.113.99/24\n" +
             "nv set interface eth1 ipv4 address 198.51.100.77/24\n" +
             GATEWAY_RANGE + LINK_RANGE + TYPE_RANGE + HOST),
            ("single-port-aliases", "single",
             ADDRESS0 + GATEWAY0 + GATEWAY1_DIFF + LINK0 + LINK1 + TYPE0 + TYPE1 + HOST),
            ("dual-mixed-aliases", "dual-different",
             ADDRESS0 + ADDRESS1_DIFF + GATEWAY0 + GATEWAY1_DIFF +
             LINK0 + LINK1 + TYPE_RANGE + HOST),
        )
        for label, kind, current in cases:
            with self.subTest(case=label):
                self._expect_commands(kind, current, [])

    def test_partial_network_only_adds_the_missing_port_fact_without_rebinding_other_port(self):
        ready = LINK_RANGE + TYPE_RANGE + HOST
        cases = (
            ("single-fresh-gateways", "single", ADDRESS0 + ready, [
                ["nv", "set", "interface", "eth0-1", "ipv4", "gateway", "203.0.113.1"],
            ]),
            ("single-preserve-unrequired-eth1-gateway", "single",
             ADDRESS0 + GATEWAY1_DIFF + ready, [
                ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ]),
            ("single-no-independent-eth1-gateway", "single",
             ADDRESS0 + GATEWAY0 + ready, []),
            ("dual-only-eth1-gateway-missing", "dual-same",
             ADDRESS0 + ADDRESS1_SAME + GATEWAY0 + ready, [
                ["nv", "set", "interface", "eth1", "ipv4", "gateway", "203.0.113.1"],
            ]),
            ("dual-only-eth0-gateway-missing", "dual-same",
             ADDRESS0 + ADDRESS1_SAME + GATEWAY1_SAME + ready, [
                ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.1"],
            ]),
            ("only-eth1-link-missing", "single",
             ADDRESS0 + GATEWAY0 + LINK0 + TYPE_RANGE + HOST, [
                ["nv", "set", "interface", "eth1", "link", "state", "up"],
            ]),
            ("only-eth0-type-missing", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE1 + HOST, [
                ["nv", "set", "interface", "eth0", "type", "eth"],
            ]),
        )
        for label, kind, current, expected in cases:
            with self.subTest(case=label):
                self._expect_commands(kind, current, expected)

    def test_existing_gateway_and_hostname_conflicts_or_contradictions_are_not_repair_permission(self):
        cases = (
            ("foreign-required-eth0-gateway", "single",
             ADDRESS0 + "nv set interface eth0 ipv4 gateway 203.0.113.254\n" +
             LINK_RANGE + TYPE_RANGE + HOST),
            ("foreign-required-eth1-gateway", "dual-different",
             ADDRESS0 + ADDRESS1_DIFF + GATEWAY0 +
             "nv set interface eth1 ipv4 gateway 198.51.100.254\n" +
             LINK_RANGE + TYPE_RANGE + HOST),
            ("nondefault-hostname-conflict", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE_RANGE +
             "nv set system hostname EXAMPLE-OTHER\n"),
            ("contradictory-reserved-type", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE +
             "nv set interface eth0 type bridge\n" + TYPE0 + TYPE1 + HOST),
            ("contradictory-hostname", "single",
             "nv set system hostname EXAMPLE-OTHER\n" + SINGLE_COMPLETE),
        )
        for label, kind, current in cases:
            with self.subTest(case=label):
                result, caught, parsed, verified = self.call_pure(
                    "_management_network_commands", self.device(kind), current)
                self.assertTrue(isinstance(caught, APP.SetupError),
                                "conflicting actual state must HOLD, not authorize an overwrite")
                self.assertTrue(result is None, "conflict returned setters")

    def test_actual_readback_requires_all_csv_members_and_both_reserved_ports(self):
        import shlex
        positives = (
            ("single-all-quoted-fields", "single", QUOTED_SINGLE,
             ("203.0.113.2/24",), (), ("203.0.113.1",), (), SINGLE_NVSET_TOKENS),
            ("single-range", "single", SINGLE_COMPLETE,
             ("203.0.113.2/24",), (), ("203.0.113.1",), (), SINGLE_NVSET_TOKENS),
            ("single-alias-extra", "single",
             ADDRESS0 + "nv set interface eth0 ipv4 address 203.0.113.99/24\n" +
             "nv set interface eth1 ipv4 address 198.51.100.77/24\n" +
             GATEWAY0 + GATEWAY1_DIFF + LINK0 + LINK1 + TYPE0 + TYPE1 + HOST,
             ("203.0.113.2/24", "203.0.113.99/24"), ("198.51.100.77/24",),
             ("203.0.113.1",), ("198.51.100.1",), EXTRA_SINGLE_NVSET_TOKENS),
            ("dual-different", "dual-different", DUAL_DIFF_COMPLETE,
             ("203.0.113.2/24",), ("198.51.100.2/24",),
             ("203.0.113.1",), ("198.51.100.1",), DUAL_DIFF_NVSET_TOKENS),
        )
        for label, kind, current, ips0, ips1, gateways0, gateways1, expected_tokens in positives:
            with self.subTest(case=label):
                result, caught, parsed, verified = self.call_pure(
                    "_verify_management_network_state", self.device(kind), current)
                self.assertTrue(caught is None, "qualified actual readback was refused")
                self.assertTrue(type(result) is APP.DeviceState)
                self.assertEqual(ips0, result.eth0_addresses)
                self.assertEqual(ips1, result.eth1_addresses)
                self.assertEqual(gateways0, result.eth0_gateways)
                self.assertEqual(gateways1, result.eth1_gateways)
                self.assertEqual("EXAMPLE-IB01", result.hostname)
                actual_tokens = [tokens for tokens in map(shlex.split, result.raw_commands.splitlines())
                                 if tokens[:2] == ["nv", "set"]]
                supplied_tokens = [tokens for tokens in map(shlex.split, current.splitlines())
                                   if tokens[:2] == ["nv", "set"]]
                self.assertEqual((expected_tokens, supplied_tokens),
                                 (actual_tokens, actual_tokens),
                                 "actual nv set tokens must preserve all supplied rows in order, including extras")
                self.assertTrue(bool(parsed) and any(parsed), "actual current parse was not reached")
                self.assertTrue(bool(verified) and all(verified),
                                "real verify_state must consume the actual parser-returned state")
        negatives = (
            ("missing-csv-eth0-address", "single",
             GATEWAY0 + LINK_RANGE + TYPE_RANGE + HOST),
            ("missing-csv-eth0-gateway", "single",
             ADDRESS0 + LINK_RANGE + TYPE_RANGE + HOST),
            ("wrong-required-hostname", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE_RANGE +
             "nv set system hostname EXAMPLE-OTHER\n"),
            ("wrong-reserved-eth0-link", "single",
             ADDRESS0 + GATEWAY0 + "nv set interface eth0 link state down\n" +
             LINK1 + TYPE_RANGE + HOST),
            ("missing-reserved-eth1-link", "single",
             ADDRESS0 + GATEWAY0 + LINK0 + TYPE_RANGE + HOST),
            ("missing-reserved-eth0-type", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE1 + HOST),
            ("wrong-reserved-eth1-type", "single",
             ADDRESS0 + GATEWAY0 + LINK_RANGE + TYPE0 +
             "nv set interface eth1 type bridge\n" + HOST),
            ("missing-csv-eth1-address", "dual-different",
             ADDRESS0 + GATEWAY0 + GATEWAY1_DIFF + LINK_RANGE + TYPE_RANGE + HOST),
            ("wrong-csv-eth1-gateway", "dual-different",
             ADDRESS0 + ADDRESS1_DIFF + GATEWAY0 +
             "nv set interface eth1 ipv4 gateway 198.51.100.254\n" +
             LINK_RANGE + TYPE_RANGE + HOST),
        )
        for label, kind, current in negatives:
            with self.subTest(case=label):
                result, caught, parsed, verified = self.call_pure(
                    "_verify_management_network_state", self.device(kind), current)
                self.assertTrue(isinstance(caught, APP.SetupError),
                                "actual readback did not prove the required CSV/reserved fact")
                self.assertTrue(result is None, "incomplete actual readback returned a state")

    def test_unknown_empty_and_relevant_malformed_state_never_become_fresh_configuration(self):
        cases = (
            ("empty", ""),
            ("unknown", "PUBLIC configuration unavailable\n"),
            ("malformed-reserved-quote",
             SINGLE_COMPLETE + 'nv set interface eth0 link state "up\n'),
        )
        for label, current in cases:
            for api in ("_management_network_commands", "_verify_management_network_state"):
                with self.subTest(case=label, api=api):
                    result, caught, parsed, verified = self.call_pure(
                        api, self.device(), current)
                    self.assertTrue(isinstance(caught, APP.SetupError),
                                    "unknown/malformed supplied state must fail closed")
                    self.assertTrue(result is None, "unknown/malformed state produced a result")


    def test_closed_reserved_projection_and_gateway_membership_keep_independent_boundaries(self):
        bad_bodies = (
            ("truncated-reserved-link-family",
             SINGLE_COMPLETE + "nv set interface eth0 link\n"),
            ("truncated-reserved-ipv4-family",
             SINGLE_COMPLETE + "nv set interface eth0 ipv4\n"),
            ("truncated-reserved-interface",
             SINGLE_COMPLETE + "nv set interface eth0\n"),
            ("unsupported-reserved-range",
             SINGLE_COMPLETE + "nv set interface eth0-2 link state up\n"),
            ("relevant-extra-token",
             SINGLE_COMPLETE + "nv set interface eth0 ipv4 address 203.0.113.2/24 EXTRA\n"),
            ("range-and-single-link-contradiction",
             SINGLE_COMPLETE + "nv set interface eth0 link state down\n"),
        )
        for label, current in bad_bodies:
            for api in ("_management_network_commands", "_verify_management_network_state"):
                with self.subTest(case=label, api=api):
                    result, caught, parsed, verified = self.call_pure(api, self.device(), current)
                    self.assertTrue(isinstance(caught, APP.SetupError),
                                    "unqualified reserved facts must HOLD, never become missing setters")
                    self.assertTrue(result is None, "unqualified facts returned a business result")
        # Gateway is a membership collection, unlike single-value link/type.
        # The expected gateway is already present; the extra one alone does
        # not authorize rewriting either port or rejecting the old contract.
        current = SINGLE_COMPLETE + "nv set interface eth0 ipv4 gateway 203.0.113.254\n"
        self._expect_commands("single", current, [])
        result, caught, parsed, verified = self.call_pure(
            "_verify_management_network_state", self.device(), current)
        self.assertTrue(caught is None, "expected gateway membership with an extra was refused")
        self.assertTrue(type(result) is APP.DeviceState)
        self.assertEqual(("203.0.113.1", "203.0.113.254"), result.eth0_gateways)
        self.assertTrue(bool(parsed) and any(parsed), "actual supplied current was not parsed")
        self.assertTrue(bool(verified) and all(verified), "actual parser state did not reach real verification")
        import shlex
        actual_tokens = [tokens for tokens in map(shlex.split, result.raw_commands.splitlines())
                         if tokens[:2] == ["nv", "set"]]
        supplied_tokens = [tokens for tokens in map(shlex.split, current.splitlines())
                           if tokens[:2] == ["nv", "set"]]
        expected_tokens = SINGLE_NVSET_TOKENS + [
            ["nv", "set", "interface", "eth0", "ipv4", "gateway", "203.0.113.254"],
        ]
        self.assertEqual((expected_tokens, supplied_tokens), (actual_tokens, actual_tokens),
                         "extra actual gateway must not be dropped or synthesized")



if __name__ == "__main__":
    unittest.main()
