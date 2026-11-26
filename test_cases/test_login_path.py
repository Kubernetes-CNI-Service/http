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


class LoginPathRouteTests(unittest.TestCase):
    """v315 r617 WP1 pure facts; literal expectations from guide 4.1/WP1.

    No old editor test setup is inherited. New calls must be pure; in particular
    missing planned interfaces give assertion RED, never import/API ERROR.
    """

    def setUp(self):
        self.api = parser_module(self)
        from contextlib import ExitStack
        self.effects = ExitStack()
        self.addCleanup(self.effects.close)
        for owner, name in ((subprocess, "Popen"), (os, "system"), (os, "execve")):
            self.effects.enter_context(mock.patch.object(
                owner, name, side_effect=AssertionError("pure route called external effect")))
        self.effects.enter_context(mock.patch("socket.socket", side_effect=AssertionError(
            "pure route called network")))

    def need(self, *names):
        for name in names:
            self.assertTrue(callable(getattr(self.api, name, None)),
                            "r617 4.1 requires pure interface " + name)
        return self.api

    def eth0(self, **changes):
        self.need("check_eth0_inputs")
        values = dict(mac="02:00:00:00:00:10", address="192.0.2.10",
                      netmask="255.255.255.0", gateway="192.0.2.1")
        values.update(changes)
        return self.api.check_eth0_inputs("example-ib01", **values)

    def test_jump_type_is_suffix_jump_only(self):
        api = self.need("is_jump_type")
        for value in ("eth_jump", " IB_JUMP ", "customjump"):
            with self.subTest(value=value):
                self.assertIs(True, api.is_jump_type(value))
        for value in ("eth", "eth_spx", "spx", "ethernet", "jump_extra", ""):
            with self.subTest(value=value):
                self.assertIs(False, api.is_jump_type(value))

    def test_eth0_inputs_each_missing_or_wrong_field_blocks(self):
        api = self.need("check_eth0_inputs")
        import ipaddress
        plan, issues = self.eth0(mac="0200.0000.0010")
        self.assertEqual((), issues)
        self.assertEqual("02:00:00:00:00:10", plan.mac)
        self.assertEqual(ipaddress.IPv4Interface("192.0.2.10/24"), plan.address)
        self.assertEqual("192.0.2.1", plan.gateway)
        for changes, field in (({"mac": ""}, "eth0_mac"), ({"mac": "bad"}, "eth0_mac"),
                               ({"address": ""}, "eth0_ip"), ({"address": "no-ip"}, "eth0_ip"),
                               ({"netmask": ""}, "netmask"), ({"netmask": "x"}, "netmask"),
                               ({"gateway": ""}, "eth0_gw"),
                               ({"gateway": "198.51.100.1"}, "eth0_gw"),
                               ({"gateway": "192.0.2.0"}, "eth0_gw"),
                               ({"gateway": "192.0.2.255"}, "eth0_gw"),
                               ({"address": "192.0.2.0"}, "eth0_ip")):
            with self.subTest(changes=changes):
                result, found = self.eth0(**changes)
                self.assertIsNone(result)
                self.assertTrue(any(i.field == field and i.blocking for i in found))
                self.assertTrue(all(i.hostname == "example-ib01" for i in found))

    def test_eth1_inputs_only_hint_and_configure_valid_items(self):
        api = self.need("check_eth1_inputs")
        def check(**kw):
            values = dict(eth0_mac="02:00:00:00:00:10", mac="02:00:00:00:00:11",
                          address="198.51.100.10", netmask="24", gateway="198.51.100.1")
            values.update(kw)
            return api.check_eth1_inputs("example-ib01", **values)
        good, hints = check()
        self.assertEqual("198.51.100.10/24", str(good.address))
        self.assertEqual("198.51.100.1", good.gateway)
        self.assertEqual((), hints)
        partial, hints = check(gateway="")
        self.assertEqual("198.51.100.10/24", str(partial.address))
        self.assertEqual("", partial.gateway)
        self.assertTrue(hints)
        for kw in ({"address": ""}, {"gateway": "192.0.2.1"}, {"mac": "02:00:00:00:00:19"},
                   {"mac": ""}, {"eth0_mac": ""}, {"mac": "wrong"}):
            with self.subTest(changes=kw):
                plan, hints = check(**kw)
                self.assertTrue(hints)
                self.assertTrue(all(not i.blocking for i in hints))
                if "gateway" in kw:
                    self.assertEqual("", plan.gateway)
        empty, hints = check(mac="", address="", gateway="")
        self.assertIsNone(empty.address)
        self.assertEqual("", empty.gateway)
        spelled, hints = check(mac="0200-0000.0011")
        self.assertEqual((), hints)

    def test_jump_login_candidates_order_and_dedup(self):
        api = self.need("jump_login_candidates")
        result, issues = api.jump_login_candidates("example-jump01", eth0_ip="192.0.2.1",
            vlan_groups=(("20", "198.51.100.2", "24"),
                         ("30", "203.0.113.3", "255.255.255.0"),
                         ("40", "192.0.2.1", ""), ("4095", "203.0.113.4", "24"),
                         ("50", "not-an-ip", "24")))
        self.assertEqual((("192.0.2.1", "JUMP_ETH0"), ("198.51.100.2", "JUMP_VLAN20"),
                          ("203.0.113.3", "JUMP_VLAN30")),
                         tuple((v.address, v.entry) for v in result))
        self.assertEqual(2, len(issues))
        self.assertTrue(all(not i.blocking for i in issues))
        for invalid in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255"):
            with self.subTest(invalid=invalid):
                result, issues = api.jump_login_candidates("example-jump01", eth0_ip=invalid,
                                                          vlan_groups=())
                self.assertEqual((), result)
                self.assertTrue(issues)

    def test_direct_access_selector_forms(self):
        api = self.need("select_direct_access")
        from tools.hostname_ranges import SelectorError
        hosts = ("example-ib01.example.test", "example-ib02", "example-ib03", "example-ib09")
        for text, expected in (("example-ib01", {hosts[0]}), ("example-ib0*", set(hosts)),
                               ("example-ib[01-03]", set(hosts[:3])),
                               ("example-ib02,example-ib09", {hosts[1], hosts[3]}),
                               ("all", set(hosts))):
            with self.subTest(text=text):
                self.assertEqual(frozenset(expected), api.select_direct_access(text, hosts))
        for text in ("missing", "all,example-ib02", "example-ib[1-09]"):
            with self.subTest(text=text):
                with self.assertRaises(SelectorError) as error:
                    api.select_direct_access(text, hosts)
                self.assertIn("--direct-access", str(error.exception))
                self.assertIn(text.split(",")[0], str(error.exception))

    def test_classify_routes(self):
        api = self.need("classify", "Attachment")
        from types import SimpleNamespace
        devices = [SimpleNamespace(hostname=n) for n in ("ib-a", "ib-b", "ib-c", "ib-d")]
        attachments = {"ib-a": api.Attachment("jump-a", "eth_jump", "swp1"),
                       "ib-b": api.Attachment("leaf-b", "eth", "swp2"),
                       "ib-c": None, "ib-d": api.Attachment("jump-d", "ib_jump", "swp4")}
        rows = api.classify(devices, attachments, direct=frozenset({"ib-d"}),
                            same_subnet={"ib-b": "en7"})
        self.assertEqual([("ib-a", "jump", "JUMP_LINK", "jump-a", "swp1", None),
                          ("ib-b", "direct", "PEER_NOT_JUMP", None, None, "en7"),
                          ("ib-c", "direct", "NO_MGMT_LINK", None, None, None),
                          ("ib-d", "direct", "DIRECT_ACCESS", None, None, None)],
                         [(r.hostname, r.path, r.reason, r.jump, r.port, r.same_subnet) for r in rows])
        self.assertEqual("jump-a", attachments["ib-a"].peer)

    def test_same_subnet_needs_ipv4_in_plan_and_ipv6(self):
        api = self.need("parse_local_interfaces", "same_subnet_interface")
        import ipaddress
        text = '[{"ifname":"en7","addr_info":[{"family":"inet","local":"192.0.2.99","prefixlen":24},{"family":"inet6","local":"fe80::1","prefixlen":64}]},{"ifname":"en8","addr_info":[{"family":"inet","local":"198.51.100.99","prefixlen":24}]}]'
        local = api.parse_local_interfaces(text)
        self.assertEqual("en7", api.same_subnet_interface(ipaddress.IPv4Interface("192.0.2.10/24"), local))
        self.assertIsNone(api.same_subnet_interface(ipaddress.IPv4Interface("198.51.100.10/24"), local))
        self.assertIsNone(api.same_subnet_interface(ipaddress.IPv4Interface("203.0.113.10/24"), local))
        self.assertEqual((), api.parse_local_interfaces("[]"))

    def test_link_local_eui64_vectors(self):
        api = self.need("link_local_from_mac")
        self.assertEqual("fe80::ff:fe00:10", api.link_local_from_mac("02:00:00:00:00:10"))
        self.assertEqual("fe80::ff:fe00:1", api.link_local_from_mac("0200.0000.0001"))
        for value in ("00:00:00:00:00:00", "01:00:00:00:00:01", "ff:ff:ff:ff:ff:ff", "bad"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                api.link_local_from_mac(value)

    def test_credential_order(self):
        api = self.need("credential_order")
        self.assertEqual(("key", "project", "initial", "ask"),
                         api.credential_order("direct", key_available=True))
        self.assertEqual(("project", "initial", "ask"),
                         api.credential_order("direct", key_available=False))
        self.assertEqual(("project", "initial", "ask"),
                         api.credential_order("jump", key_available=True))

    def test_login_interface_from_port_vlan(self):
        api = self.need("login_interface")
        links = ("2: bridge: <BROADCAST,UP> mtu 1500\n"
                 "3: swp7: <BROADCAST,UP> mtu 1500 master bridge\n"
                 "4: vlan20@bridge: <BROADCAST,UP> mtu 1500\n"
                 "    vlan protocol 802.1Q id 20 <REORDER_HDR>\n"
                 "5: vlan20-v0@vlan20: <BROADCAST,UP> mtu 1500\n"
                 "    macvlan mode private\n"
                 "6: swp8: <BROADCAST,UP> mtu 1500\n")
        vlans = "port              vlan-id\nswp7              20 PVID Egress Untagged\n"
        self.assertEqual("vlan20", api.login_interface(links, vlans, "swp7"))
        self.assertEqual("swp8", api.login_interface(links, vlans, "swp8"))
        for bad_links, bad_vlans in ((links.replace("id 20", "id 21"), vlans),
                                     (links, vlans + "                  30\n"),
                                     (links + "7: another@bridge: <UP> mtu 1500\n    vlan id 20\n", vlans)):
            with self.subTest(links=bad_links, vlans=bad_vlans), self.assertRaises(ValueError):
                api.login_interface(bad_links, bad_vlans, "swp7")

    def test_cable_check_two_results_and_not_learned(self):
        api = self.need("check_cable", "JumpTables")
        mac = "02:00:00:00:00:10"
        links = ("2: bridge: <UP> mtu 1500\n3: swp7: <UP> mtu 1500 master bridge\n"
                 "4: vlan20@bridge: <UP> mtu 1500\n    vlan protocol 802.1Q id 20\n"
                 "5: swp8: <UP> mtu 1500 master bridge\n")
        vlans = "port vlan-id\nswp7 20 PVID Egress Untagged\nswp8 20 PVID Egress Untagged\n"
        def table(host, fdb, linktext=links):
            return api.JumpTables(host, linktext, fdb, vlans)
        cases = (([table("jump-a", mac + " dev swp7 vlan 20 master bridge\n"
                         "02:00:00:00:00:19 dev swp7 vlan 20 master bridge\n")],
                  "MATCH", (("jump-a", "swp7"),), ("02:00:00:00:00:19",)),
                 ([table("jump-a", mac + " dev swp8 vlan 20 master bridge\n")],
                  "ELSEWHERE", (("jump-a", "swp8"),), ()),
                 ([table("jump-a", ""), table("jump-b", mac + " dev swp8 vlan 20 master bridge\n")],
                  "ELSEWHERE", (("jump-b", "swp8"),), ()),
                 ([table("jump-a", "")], "NOT_LEARNED", (), ()))
        for tables, verdict, actual, extra in cases:
            with self.subTest(verdict=verdict, actual=actual):
                check = api.check_cable("example-ib01", mac, ("jump-a", "swp7"), tables,
                                        cascade_ports=frozenset())
                self.assertEqual((verdict, actual, extra, "fe80::ff:fe00:10", "vlan20"),
                    (check.verdict, check.actual, check.extra_macs, check.link_local, check.login_interface))
                self.assertIs(False, check.after_ping)
                self.assertIsNone(check.ping_ok)
        cascaded = [table("jump-a", mac + " dev swp8 vlan 20 master bridge\n"),
                    table("jump-b", mac + " dev swp7 vlan 20 master bridge\n")]
        check = api.check_cable("example-ib01", mac, ("jump-a", "swp7"), cascaded,
                                cascade_ports=frozenset({("jump-a", "swp8")}))
        self.assertEqual((("jump-b", "swp7"),), check.actual)
        bonded_links = links.replace("swp7: <UP> mtu 1500 master bridge",
                                      "swp7: <UP> mtu 1500 master bond1") + "6: bond1: <UP> mtu 1500 master bridge\n"
        check = api.check_cable("example-ib01", mac, ("jump-a", "swp7"),
            [table("jump-a", mac + " dev bond1 vlan 20 master bridge\n", bonded_links)],
            cascade_ports=frozenset(), after_ping=True, ping_ok=False)
        self.assertEqual("MATCH", check.verdict)
        self.assertEqual((("jump-a", "bond1"),), check.actual)
        self.assertIs(True, check.after_ping)
        self.assertIs(False, check.ping_ok)

    def test_ping_argv_and_plan(self):
        api = self.need("ping_argv", "ping_plan", "CableCheck")
        self.assertEqual(["ip", "vrf", "exec", "default", "ping", "-6", "-c", "2", "-W", "1",
                          "fe80::ff:fe00:10%vlan20"],
                         api.ping_argv("default", "fe80::ff:fe00:10", "vlan20"))
        def check(host, jump, verdict):
            return api.CableCheck(host, "02:00:00:00:00:10", "fe80::ff:fe00:10",
                (jump, "swp7"), verdict, (), (), "vlan20", False, None)
        checks = [check("ib-a", "jump-a", "NOT_LEARNED"), check("ib-b", "jump-b", "NOT_LEARNED"),
                  check("ib-c", "jump-a", "MATCH"), check("ib-d", "jump-a", "ELSEWHERE")]
        grouped = api.ping_plan(checks)
        self.assertEqual({"jump-a", "jump-b"}, set(grouped))
        self.assertEqual(["ib-a"], [item.hostname for item in grouped["jump-a"]])
        self.assertEqual(["ib-b"], [item.hostname for item in grouped["jump-b"]])

    def test_identity_checks_by_path(self):
        api = self.need("IdentityFacts", "check_identity")
        import ipaddress
        def observed(mac="02:00:00:00:00:10", addresses=("192.0.2.10/24",), gateways=("192.0.2.1",)):
            return api.IdentityFacts(mac, tuple(ipaddress.IPv4Interface(v) for v in addresses), gateways)
        def check(facts, via_ipv4=True):
            return api.check_identity("02:00:00:00:00:10", facts, via_ipv4=via_ipv4,
                                      expected_ipv4="192.0.2.10/24", expected_gateway="192.0.2.1")
        for facts in (observed(), observed(gateways=())):
            self.assertIs(True, check(facts).ok)
        for facts, field in ((observed(mac="02:00:00:00:00:11"), "mac"),
                             (observed(addresses=("192.0.2.10/25",)), "ipv4"),
                             (observed(addresses=("192.0.2.11/24",)), "ipv4"),
                             (observed(gateways=("192.0.2.2",)), "gateway")):
            with self.subTest(field=field):
                result = check(facts)
                self.assertIs(False, result.ok)
                self.assertIn(field, {row[0] for row in result.mismatches})
        self.assertIs(True, check(observed(addresses=(), gateways=("198.51.100.1",)), False).ok)
        self.assertIs(False, check(observed(mac="", addresses=(), gateways=()), False).ok)

    def test_identity_readback_parsers(self):
        api = self.need("parse_ip_addr", "parse_default_routes", "neighbor_mac")
        addr = ("2: eth0: <BROADCAST,UP> mtu 1500\n    link/ether 02:00:00:00:00:10 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 192.0.2.10/24 brd 192.0.2.255 scope global eth0\n"
                "3: eth1: <UP> mtu 1500\n    link/ether 02:00:00:00:00:11 brd ff:ff:ff:ff:ff:ff\n"
                "    inet 198.51.100.10/24 scope global eth1\n")
        facts = api.parse_ip_addr(addr)
        self.assertEqual("02:00:00:00:00:10", facts.mac)
        self.assertEqual(("192.0.2.10/24",), tuple(map(str, facts.ipv4)))
        self.assertEqual(("192.0.2.1",), api.parse_default_routes(
            "default via 192.0.2.1 dev eth0\n192.0.2.0/24 dev eth0 scope link\n"))
        self.assertEqual((), api.parse_default_routes("192.0.2.0/24 dev eth0 scope link\n"))
        self.assertEqual("02:00:00:00:00:10", api.neighbor_mac(
            "192.0.2.10 dev en7 lladdr 02:00:00:00:00:10 REACHABLE\n", "192.0.2.10"))
        self.assertIsNone(api.neighbor_mac("192.0.2.10 dev en7 FAILED\n", "192.0.2.10"))


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

    # ------------------------------------------------------------ v3.1.6 U7 (问题文件 §36.3; 指导 8.25.6 改法 4)
    def pin(self, address="192.0.2.13", *, before_write=None):
        self.assertTrue(hasattr(self.api, "pin_unknown_host_key"), "v3.1.6 U7 first registration required")
        kind, blob = self.keys["new"][0].split()
        return self.api.pin_unknown_host_key(address, kind, blob, self.keys["new"][1], self.editor(),
                                             before_write=before_write or (lambda: None), hostname="sw13",
                                             run_id="r1")

    def test_pin_appends_one_literal_line_and_keeps_every_original_byte(self):
        record = self.pin()
        text = self.path.read_text()
        self.assertTrue(text.startswith(self.before), "the original bytes are unchanged")
        self.assertEqual(text[len(self.before):], "192.0.2.13 " + self.keys["new"][0] + "\n", "one line more")
        self.assertEqual([row[2] for row in self.editor().fingerprints("192.0.2.13")], [self.keys["new"][1]])
        backup = self.home / ".ssh" / "known_hosts.pin-r1"
        self.assertEqual(backup.read_text(), self.before)
        self.assertEqual(stat.S_IMODE(backup.stat().st_mode) & 0o077, 0, "the backup is private")
        self.assertEqual((record.address, record.hostname, record.key_type, record.fingerprint, record.basis,
                          record.backup),
                         ("192.0.2.13", "sw13", self.keys["new"][0].split()[0], self.keys["new"][1], "hostname+MAC",
                          str(backup)))

    def test_pin_refuses_an_address_that_already_has_an_entry(self):
        permit = mock.Mock()
        with self.assertRaises(ValueError):
            self.pin("192.0.2.10", before_write=permit)
        permit.assert_not_called()
        self.assertEqual(self.before, self.path.read_text())
        self.assertFalse((self.home / ".ssh" / "known_hosts.pin-r1").exists())

    def test_pin_into_a_hashed_file_is_read_by_fleet_ssh_and_ssh_keygen(self):
        import sys
        subprocess.run(["ssh-keygen", "-H", "-f", str(self.path)], check=True, capture_output=True, timeout=10)
        hashed = self.path.read_bytes()
        self.pin()
        self.assertTrue(self.path.read_bytes().startswith(hashed), "hashed lines stay; a literal line is added")
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))
        import fleet_ssh
        self.assertEqual(fleet_ssh.HostPins.load(self.path).fingerprints("192.0.2.13"), {self.keys["new"][1]})
        found = subprocess.run(["ssh-keygen", "-F", "192.0.2.13", "-f", str(self.path)], capture_output=True,
                               text=True, timeout=10)
        self.assertEqual(found.returncode, 0, found.stdout)

    def test_a_refused_write_permission_writes_nothing(self):
        error = PermissionError("operator declined")

        def refuse():
            raise error
        with self.assertRaises(PermissionError) as caught:
            self.pin(before_write=refuse)
        self.assertIs(caught.exception, error)
        self.assertEqual(self.before, self.path.read_text())
        self.assertFalse((self.home / ".ssh" / "known_hosts.pin-r1").exists())

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
        allowed = {"__future__", "dataclasses", "ipaddress", "json", "pathlib", "re", "shlex", "stat", "subprocess", "typing",
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
