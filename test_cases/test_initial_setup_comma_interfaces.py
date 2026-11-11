"""Direct: NVUE comma-merged interface lines and fnm interfaces at the initial-setup readback entry.

What (v3.1.3 WP-12, I-005): the readback entry ``_split_comma_interface_lines`` splits every
``nv set interface <A,B,...> <rest>`` line into one line per member and keeps every other line
byte for byte; the existing management Network readback then judges each member (``fnm<N>`` is
unrelated, O16), and ``_management_selector_location`` names the line, member and setting of an
unqualified member without any value (O15).  Every case enters through the readback entry (or a
transport function that is one) and only then reaches the production consumers parse_nvue_state,
_management_network_commands, _verify_management_network_state, _management_ports_ready,
base_stage_needed and _validate_owned_pending; no raw comma line is fed to a consumer directly.

Expectation sources (not derived from the implementation):
- 问题文档 I-005 (:158-216 at doc tag guide-v3.1.3-approved-r328): field samples :163-196,
  期望 1-4 :204-207, 验收 :211-215.
- v3.1.3 guide (tag guide-v3.1.3-approved-r328) WP-12 :1157-1192; O15 :268; O16 :269.
- The existing management Network contract the guide keeps (:1151-1154): the fixed literals
  "management Network setter plan is not qualified" and "management Network post-configuration
  verification failed; device state is UNKNOWN" (test_initial_setup_network_diagnostics.py
  GENERIC and READBACK), and safe errors without chains or extra attributes.

Fixtures follow the problem-document sample structure with an anonymized host name and
documentation addresses (192.0.2.0/24, 198.51.100.0/24).  No device I/O: where a transport
function is the entry, interactive_run is replaced and the frame nonce is fixed.
"""
from __future__ import annotations

from pathlib import Path
import unittest
from unittest import mock

from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("initial_setup_comma_interfaces_direct",
                  ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")

GENERIC = "management Network setter plan is not qualified"
READBACK = "management Network post-configuration verification failed; device state is UNKNOWN"
MARKER = "cd" * 16
DIFF = ["nv", "config", "diff", "-o", "commands"]

# 问题文档 :182-193 (the device with fnm1), anonymized; :194 the device without fnm1 has
# `nv set interface eth0-1 link state up` at the same position and no fnm1 lines.
COMMA_LINK = "nv set interface eth0-1,fnm1 link state up\n"
PLAIN_LINK = "nv set interface eth0-1 link state up\n"
FNM_TYPE = "nv set interface fnm1 type fnm\n"
SAMPLE_A = (
    "nv set interface eth0 ipv4 address 192.0.2.11/24\n"
    "nv set interface eth0-1 ipv4 gateway 192.0.2.1\n"
    "nv set interface eth0-1 type eth\n"
    + COMMA_LINK +
    "nv set interface eth1 ipv4 address 192.0.2.12/24\n"
    + FNM_TYPE +
    "nv set interface lo acl acl-default-loopback inbound control-plane\n"
    "nv set interface lo acl acl-default-loopback-ipv6 inbound control-plane\n"
    "nv set interface lo type loopback\n"
    "nv set system hostname EXAMPLE-IB01\n"
)
SAMPLE_B = SAMPLE_A.replace(COMMA_LINK, PLAIN_LINK).replace(FNM_TYPE, "")
# 期望 1 (:204) names the gateway among the fields recorded from a comma line.
GATEWAY_SAMPLE = (
    "nv set interface eth0 ipv4 address 198.51.100.11/24\n"
    "nv set interface eth0-1,fnm1 ipv4 gateway 198.51.100.1\n"
    "nv set interface eth0-1 type eth\n"
    + COMMA_LINK +
    "nv set interface eth1 ipv4 address 198.51.100.12/24\n"
    + FNM_TYPE +
    "nv set system hostname EXAMPLE-IB02\n"
)


def secret(label: str) -> str:
    # Assembled at run time so no credential literal appears in the source (public audit).
    return "-".join(("PUBLIC", "wp12", label, "Qx4"))


class CommaInterfaceSelectorTests(unittest.TestCase):
    def device(self):
        return APP.Device("EXAMPLE-IB01", "ib", "192.0.2.11", "192.0.2.11/24", "192.0.2.1",
                          "02:00:00:00:00:11", "192.0.2.12/24", "192.0.2.1")

    def gateway_device(self):
        return APP.Device("EXAMPLE-IB02", "ib", "198.51.100.11", "198.51.100.11/24",
                          "198.51.100.1", "02:00:00:00:00:12", "198.51.100.12/24", "198.51.100.1")

    def target(self, device):
        jump = APP.Device("example-oob-leaf01", "eth_jump", "203.0.113.10", "", "", "", "", "")
        return APP.Target(device, jump, "swp1", "eth0")

    def assert_fixed(self, error, message):
        # Guide :1152 (network_diagnostics safe_error): exact literal, no chains, no attributes.
        self.assertTrue(type(error) is APP.SetupError, "a fixed SetupError is required")
        self.assertEqual((message,), error.args)
        self.assertTrue(error.__cause__ is None and error.__context__ is None
                        and error.__dict__ == {}, "the fixed error kept chains or attributes")

    def refused(self, function, *args):
        error = None
        try:
            function(*args)
        except APP.SetupError as caught:
            error = caught
        self.assertIsNotNone(error, "an unqualified comma readback was accepted")
        return error

    def test_fnm_comma_sample_equals_plain_sample(self):
        # 问题文档 :211 (验收): with `eth0-1,fnm1 link state up` and `fnm1 type fnm` the check
        # passes, nothing is missing, and the result equals the device without fnm1; guide :1176.
        device = self.device()
        parsed = {}
        for label, sample in (("A-with-fnm1", SAMPLE_A), ("B-without-fnm1", SAMPLE_B)):
            with self.subTest(sample=label):
                lines = APP._split_comma_interface_lines(sample)
                state = APP.parse_nvue_state(lines)
                parsed[label] = (state.eth0_addresses, state.eth1_addresses, state.eth0_gateways,
                                 state.eth1_gateways, state.hostname)
                self.assertEqual([], APP._management_network_commands(device, lines),
                                 "the Network stage fill must be empty")
                self.assertTrue(type(APP._verify_management_network_state(device, lines))
                                is APP.DeviceState, "the Network readback verification must pass")
                self.assertTrue(APP._management_ports_ready(lines),
                                "both reserved ports are link-up and typed eth")
                # Guide :1149 and :1371: the device is no longer judged to need base configuration.
                self.assertFalse(APP.base_stage_needed(device, state, False))
        self.assertEqual((("192.0.2.11/24",), ("192.0.2.12/24",), ("192.0.2.1",), ("192.0.2.1",),
                          "EXAMPLE-IB01"), parsed["B-without-fnm1"])
        self.assertEqual(parsed["B-without-fnm1"], parsed["A-with-fnm1"])

    def test_unknown_comma_member_refused_and_located(self):
        # 问题文档 :212 (验收) and :206 (期望 3): an unknown member is still refused and the report
        # names that line and that interface; O15 :268 / guide :1166, :1177: the error keeps its
        # fixed literal and the location (line, member, setting) carries no value.
        sample = SAMPLE_A.replace(COMMA_LINK, "nv set interface eth0-1,xyz1 link state up\n")
        lines = APP._split_comma_interface_lines(sample)
        error = self.refused(APP._management_network_commands, self.device(), lines)
        self.assert_fixed(error, GENERIC)
        self.assertNotIn("xyz1", str(error))
        self.assert_fixed(self.refused(APP._verify_management_network_state, self.device(), lines),
                          READBACK)
        self.assertEqual((4, "xyz1", "link state"), APP._management_selector_location(sample))
        with self.subTest(case="address-line-without-value"):
            addressed = SAMPLE_A.replace(
                "nv set interface eth1 ipv4 address 192.0.2.12/24\n",
                "nv set interface eth1,xyz2 ipv4 address 192.0.2.12/24\n")
            location = APP._management_selector_location(addressed)
            self.assertEqual((5, "xyz2", "ipv4 address"), location)
            self.assertFalse(any("192.0.2." in str(part) for part in location))
        with self.subTest(case="qualified-samples-have-no-location"):
            self.assertIsNone(APP._management_selector_location(SAMPLE_A))
            self.assertIsNone(APP._management_selector_location(SAMPLE_B))

    def test_management_member_down_or_wrong_type_not_bypassed(self):
        # 问题文档 :213 (验收): eth0/eth1 in a comma list set link down or a non-eth type are handled
        # by the existing rules, never bypassed; guide :1165, :1178.
        cases = (
            ("eth0-1,fnm1-link-down", SAMPLE_A.replace(
                COMMA_LINK, "nv set interface eth0-1,fnm1 link state down\n")),
            ("eth0,fnm1-type-bridge", SAMPLE_A.replace(
                "nv set interface eth0-1 type eth\n",
                "nv set interface eth0,fnm1 type bridge\nnv set interface eth1 type eth\n")),
        )
        for label, sample in cases:
            with self.subTest(case=label):
                lines = APP._split_comma_interface_lines(sample)
                self.assert_fixed(self.refused(APP._management_network_commands,
                                               self.device(), lines), GENERIC)
                self.assert_fixed(self.refused(APP._verify_management_network_state,
                                               self.device(), lines), READBACK)
                self.refused(APP._management_ports_ready, lines)

    def test_comma_range_beyond_reserved_ports_refused(self):
        # 问题文档 :204, :206 (期望 1, 3) and guide :1161, :1179: `ethA-B` reaching past eth1
        # (eth0-2) is refused as before, also inside a comma list.
        sample = SAMPLE_A.replace(COMMA_LINK, "nv set interface eth0-2,fnm1 link state up\n")
        lines = APP._split_comma_interface_lines(sample)
        self.assert_fixed(self.refused(APP._management_network_commands, self.device(), lines),
                          GENERIC)
        self.assert_fixed(self.refused(APP._verify_management_network_state, self.device(), lines),
                          READBACK)
        self.assertEqual((4, "eth0-2", "link state"), APP._management_selector_location(sample))

    def test_gateway_in_comma_line_is_not_lost(self):
        # 问题文档 :204 (期望 1) "eth0、eth1、eth0-1 照常记录 link、type、地址、网关"; guide :1180.
        lines = APP._split_comma_interface_lines(GATEWAY_SAMPLE)
        state = APP.parse_nvue_state(lines)
        self.assertEqual(("198.51.100.1",), state.eth0_gateways)
        self.assertEqual(("198.51.100.1",), state.eth1_gateways)
        self.assertEqual([], APP._management_network_commands(self.gateway_device(), lines))
        self.assertTrue(type(APP._verify_management_network_state(self.gateway_device(), lines))
                        is APP.DeviceState)

    def test_lines_without_comma_pass_through_unchanged(self):
        # Guide :1158 ("只拆带逗号的行"; a split line is `nv set interface <A,B,…> <其余>`), :1160
        # (member eth0-1 becomes one `eth0-1 …` line), :1181 and 问题文档 :214 (existing
        # interface-list tests keep their assertions because the lines they see do not change).
        unchanged = (
            SAMPLE_B,
            SAMPLE_B.rstrip("\n"),
            SAMPLE_B.replace("\n", "\r\n"),
            'nv set interface "eth0" ipv4 address "192.0.2.11/24"\n'
            'nv set interface "eth0-1" link state "up"\n',
            "# comment, with a comma\n"
            "nv set interface swp1 description uplink,spare\n"
            "nv set system message pre-login PUBLIC,banner\n"
            "  nv set interface eth0-1 type eth  \n",
            "",
        )
        for index, text in enumerate(unchanged):
            with self.subTest(case=index):
                self.assertEqual(text, APP._split_comma_interface_lines(text))
        split = APP._split_comma_interface_lines(SAMPLE_A)
        self.assertEqual(SAMPLE_A.replace(COMMA_LINK, PLAIN_LINK + "nv set interface fnm1 link state up\n"),
                         split)

    def test_pending_diff_comma_line_passes_the_entry_before_ownership(self):
        # Guide :1168: the pending diff also passes the readback entry before the owned-setter
        # check; an unrelated member stays refused (期望 3 :206, security unchanged).
        target = self.target(self.device())
        neighbor = APP.Neighbor("fe80::11", "vlan1000", target.ib.eth0_mac, "oob")
        owned = "nv set interface eth0 link state up\nnv set interface eth1 link state up\n"
        cases = (
            ("owned-reserved-members-status-1", "nv set interface eth0,eth1 link state up\n", owned, 1),
            ("owned-reserved-members-status-0", "nv set interface eth0,eth1 link state up\n", owned, 0),
            ("unrelated-member-status-1", COMMA_LINK, None, 1),
            ("unrelated-member-status-0", COMMA_LINK, None, 0),
        )
        for label, pending, expected, status in cases:
            with self.subTest(case=label):
                framed = ("__HTTP_IB_BEGIN_" + MARKER + "__\n" + pending
                          + "__HTTP_IB_END_" + MARKER + "__=" + str(status) + "\n")
                result, error = None, None
                with mock.patch.object(APP.os, "urandom", return_value=bytes.fromhex(MARKER)), \
                        mock.patch.object(APP, "interactive_run",
                                          return_value=APP.SessionResult(framed, status)):
                    try:
                        result = APP.run_on_ib(target, neighbor, "cumulus", secret("oob"), "admin",
                                               secret("ib"), 5, DIFF)
                    except APP.SetupError as caught:
                        error = caught
                if expected is None:
                    self.assertIsNotNone(error, "an unrelated pending member was accepted")
                else:
                    self.assertIsNone(error, "owned pending setters in a comma line were refused")
                    self.assertEqual((expected, status), (result.output, result.exit_code))

    def test_final_direct_readback_keeps_comma_gateway(self):
        # Guide :1158 ("再交给所有下游（`parse_nvue_state`…）") with 期望 1 :204: the final direct
        # SSH readback of the same device also records the gateway written in a comma line.
        device = self.gateway_device()
        framed = ("__HTTP_IB_BEGIN_" + MARKER + "__\n" + GATEWAY_SAMPLE
                  + "__HTTP_IB_END_" + MARKER + "__=0\n")
        error = None
        with mock.patch.object(APP.os, "urandom", return_value=bytes.fromhex(MARKER)), \
                mock.patch.object(APP, "interactive_run", return_value=APP.SessionResult(framed, 0)), \
                mock.patch.object(APP.time, "sleep"):
            try:
                APP.verify_management_direct_ssh(device, "eth0", "admin", secret("ib"), 10)
            except APP.SetupError as caught:
                error = caught
        self.assertIsNone(error, "the final direct readback lost the comma-line gateway")


if __name__ == "__main__":
    unittest.main()
