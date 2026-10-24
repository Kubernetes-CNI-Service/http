"""Fleet jobs (IB upgrade v2): ztp-server egress speed decides the OS distribution mode (owner 2026-10-23).

Below 10G the switches relay the image per OOB leaf; 10G-<100G pull directly with
window 60*ceil(N/16) and at most Gbps*0.8 concurrent downloads; 100G and above use
60*ceil(N/32) and no cap. Physical, bond and bridge egress interfaces must all resolve
to the real port; anything unresolved counts as 1G (relay).

Several HTTP addresses (owner 2026-10-24): common.mgmt.http.address may list one address
per ztp-server network, and those networks are normally not routed to each other. Each
switch uses the configured address on the interface of `ip route get <switch>`: the
route's src when it is configured, else the only configured address on that interface;
several without the src is ambiguous, none means no HTTP listener there, and no route is
no route. Those switches fail closed; nothing falls back to another network's address.
[LINK] lists every egress with its speed and switch count; the mode follows the slowest.
"""
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_link as link  # noqa: E402

SERVER = "192.0.2.10"


class FakeHost:
    """A /sys/class/net tree plus canned `ip`/`bridge` output."""

    def __init__(self, root: Path):
        self.root = root
        self.net = root / "class" / "net"
        self.net.mkdir(parents=True)
        self.routes = {}                  # switch -> (device, next hop[, src])
        self.addresses = [SERVER]         # on every interface unless device_addresses names it
        self.device_addresses = {}        # interface -> [address, ...] (primary first)
        self.neighbours = {}
        self.fdb = {}

    def iface(self, name, *, speed=None, physical=False, devtype=None, operstate="up", lower=None):
        path = self.net / name
        path.mkdir()
        if physical:
            (path / "device").mkdir()
        if speed is not None:
            (path / "speed").write_text(f"{speed}\n")
        (path / "operstate").write_text(operstate + "\n")
        (path / "uevent").write_text(f"INTERFACE={name}\n" + (f"DEVTYPE={devtype}\n" if devtype else ""))
        if lower:
            (path / ("lower_" + lower)).mkdir()
        return path

    def bond(self, name, mode, slaves, active=None):
        path = self.iface(name, devtype="bond", speed=999999)
        (path / "bonding").mkdir()
        (path / "bonding" / "mode").write_text(mode + "\n")
        (path / "bonding" / "slaves").write_text(" ".join(slaves) + "\n")
        (path / "bonding" / "active_slave").write_text((active or "") + "\n")

    def bridge(self, name, members, *, own_speed=None):
        path = self.iface(name, devtype="bridge", speed=own_speed)
        (path / "bridge").mkdir()
        (path / "brif").mkdir()
        for member in members:
            (path / "brif" / member).mkdir()

    def run(self, argv):
        if argv[:6] == ["ip", "-o", "addr", "show", "dev", argv[5] if len(argv) > 5 else None]:
            on = self.device_addresses.get(argv[5], self.addresses)
            return "".join(f"2: {argv[5]}    inet {address}/24 scope global {'secondary ' if index else ''}{argv[5]}\n"
                           for index, address in enumerate(on))
        if argv == ["ip", "-o", "addr", "show"]:
            everything = list(self.addresses) + [a for on in self.device_addresses.values() for a in on]
            return "".join(f"2: x    inet {address}/24 scope global x\n" for address in everything)
        if argv[:3] == ["ip", "route", "get"]:
            if argv[3] not in self.routes:
                raise OSError("ip route get exited 2")             # RTNETLINK answers: Network is unreachable
            device, via, *src = self.routes[argv[3]]
            return (f"{argv[3]} " + (f"via {via} " if via else "")
                    + f"dev {device} src {src[0] if src else SERVER} uid 0\n    cache\n")
        if argv[:3] == ["ip", "neigh", "show"]:
            mac = self.neighbours.get(argv[3])
            return f"{argv[3]} lladdr {mac} REACHABLE\n" if mac else ""
        if argv[:3] == ["bridge", "fdb", "show"]:
            return "".join(f"{mac} dev {port} master {argv[4]}\n" for mac, port in self.fdb.items())
        raise OSError("unexpected command " + " ".join(argv))

    def detect(self, switches, **kwargs):
        return link.detect(switches, SERVER, run=self.run, sysfs_root=self.root, **kwargs)


class LinkDecisionTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.host = FakeHost(Path(self.tmp.name))

    def test_tiers_follow_the_owner_formula(self):
        ten = link.decide(10000, source="detected")
        self.assertEqual((ten.mode, ten.divisor, ten.cap), ("direct", 16, 8))
        self.assertEqual(ten.window_seconds(40), 180)            # 60 * ceil(40/16)
        self.assertEqual(link.decide(20000, source="detected").cap, 16)
        hundred = link.decide(100000, source="detected")
        self.assertEqual((hundred.mode, hundred.divisor, hundred.cap), ("direct", 32, None))
        self.assertEqual(hundred.window_seconds(40), 120)        # 60 * ceil(40/32)
        for speed in (1000, 2000, None):
            decision = link.decide(speed, source="detected")
            self.assertEqual((decision.mode, decision.window_seconds(40)), ("relay", 0))
        self.assertEqual(link.decide(25000, source="detected").mode, "direct")
        self.assertEqual(link.decide(400000, source="detected").divisor, 32)

    def test_physical_port(self):
        self.host.iface("eno1", speed=10000, physical=True)
        self.host.routes["198.51.100.1"] = ("eno1", None)
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.speed_mbps, decision.mode, decision.source), (10000, "direct", "detected"))
        self.assertIn("[LINK] egress=eno1 speed=10G source=detected → direct window=60*ceil(N/16) cap=8", decision.line())

    def test_bond_sums_active_members_and_active_backup_counts_one(self):
        for name in ("eno1", "eno2"):
            self.host.iface(name, speed=1000, physical=True)
        self.host.bond("bond0", "802.3ad 4", ["eno1", "eno2"])
        self.host.routes["198.51.100.1"] = ("bond0", None)
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.speed_mbps, decision.mode), (2000, "relay"))
        self.assertIn("802.3ad: eno1 1G + eno2 1G", decision.line())
        (self.host.net / "eno2" / "operstate").write_text("down\n")
        self.assertEqual(self.host.detect(["198.51.100.1"]).speed_mbps, 1000)

        for name in ("ens1", "ens2"):
            self.host.iface(name, speed=10000, physical=True)
        self.host.bond("bond1", "active-backup 1", ["ens1", "ens2"], active="ens2")
        self.host.routes["198.51.100.2"] = ("bond1", None)
        decision = self.host.detect(["198.51.100.2"])
        self.assertEqual((decision.speed_mbps, decision.mode, decision.cap), (10000, "direct", 8))

    def test_bridge_ignores_its_own_speed_and_virtual_members(self):
        self.host.iface("eno1", speed=1000, physical=True)
        self.host.iface("veth0a1b2c", speed=10000)              # veth reports a fake 10G
        self.host.bridge("br0", ["eno1", "veth0a1b2c"], own_speed=10000)
        self.host.routes["198.51.100.1"] = ("br0", None)
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.speed_mbps, decision.mode), (1000, "relay"))
        self.assertIn("member eno1", decision.line())

    def test_bridge_with_two_ports_uses_the_fdb_or_the_slowest(self):
        self.host.iface("eno1", speed=1000, physical=True)
        self.host.iface("ens1", speed=100000, physical=True)
        self.host.bridge("br0", ["eno1", "ens1"])
        self.host.routes["203.0.113.5"] = ("br0", "192.0.2.1")
        self.host.neighbours["192.0.2.1"] = "02:00:00:00:00:01"
        self.host.fdb["02:00:00:00:00:01"] = "ens1"
        decision = self.host.detect(["203.0.113.5"])
        self.assertEqual((decision.speed_mbps, decision.mode, decision.divisor), (100000, "direct", 32))
        self.assertIn("member ens1 (FDB)", decision.line())
        self.host.fdb.clear()
        decision = self.host.detect(["203.0.113.5"])
        self.assertEqual(decision.speed_mbps, 1000)
        self.assertTrue(any("slowest" in warning for warning in decision.warnings), decision.warnings)

    def test_bridge_over_vlan_over_bond(self):
        for name in ("eno1", "eno2"):
            self.host.iface(name, speed=10000, physical=True)
        self.host.bond("bond0", "balance-xor 2", ["eno1", "eno2"])
        self.host.iface("bond0.100", devtype="vlan", lower="bond0")
        self.host.bridge("br100", ["bond0.100", "tap0"])
        self.host.iface("tap0", speed=10)
        self.host.routes["198.51.100.1"] = ("br100", None)
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.speed_mbps, decision.cap), (20000, 16))

    def test_unresolved_links_count_as_1g_relay(self):
        self.host.iface("eth0", speed=10000)                    # container side of a veth pair
        self.host.routes["198.51.100.1"] = ("eth0", None)
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.speed_mbps, decision.source, decision.mode), (None, "unknown", "relay"))
        self.assertTrue(any("virtual interface" in warning for warning in decision.warnings))

        self.host.iface("eno9", speed=-1, physical=True)        # link down
        self.host.routes["198.51.100.2"] = ("eno9", None)
        self.assertEqual(self.host.detect(["198.51.100.2"]).mode, "relay")

        self.host.addresses = ["192.0.2.99"]                    # package server is another host
        decision = self.host.detect(["198.51.100.1"])
        self.assertEqual((decision.source, decision.mode), ("unknown", "relay"))
        self.assertIn("not on this host", decision.warnings[0])

    def test_several_egress_interfaces_use_the_slowest(self):
        self.host.iface("eno1", speed=100000, physical=True)
        self.host.iface("eno2", speed=10000, physical=True)
        self.host.routes.update({"198.51.100.1": ("eno1", None), "198.51.100.2": ("eno2", None)})
        decision = self.host.detect(["198.51.100.1", "198.51.100.2"])
        self.assertEqual((decision.speed_mbps, decision.divisor), (10000, 16))
        self.assertEqual(decision.egress, ("eno1", "eno2"))

    # ------------------------------------------------------------ several HTTP addresses (owner 2026-10-24)
    def two_networks(self):
        """eno1 192.0.2.0/24 (HTTP 192.0.2.10, 100G) and eno2 198.51.100.0/24 (HTTP 198.51.100.10, 10G)."""
        self.host.iface("eno1", speed=100000, physical=True)
        self.host.iface("eno2", speed=10000, physical=True)
        self.host.device_addresses.update({"eno1": ["192.0.2.10"], "eno2": ["198.51.100.10"]})
        self.host.routes.update({"192.0.2.41": ("eno1", None, "192.0.2.10"),
                                 "192.0.2.42": ("eno1", None, "192.0.2.10"),
                                 "198.51.100.41": ("eno2", None, "198.51.100.10")})
        return ["192.0.2.41", "192.0.2.42", "198.51.100.41"], ["192.0.2.10", "198.51.100.10"]

    def test_each_switch_uses_the_http_address_on_its_own_network(self):
        switches, configured = self.two_networks()
        services = link.resolve_services(switches, configured, run=self.host.run)
        self.assertEqual({switch: (item.address, item.device, item.reason) for switch, item in services.items()},
                         {"192.0.2.41": ("192.0.2.10", "eno1", None), "192.0.2.42": ("192.0.2.10", "eno1", None),
                          "198.51.100.41": ("198.51.100.10", "eno2", None)})
        decision = link.detect(switches, configured, run=self.host.run, sysfs_root=self.host.root)
        self.assertEqual((decision.speed_mbps, decision.mode, decision.source), (10000, "direct", "detected"),
                         "the slowest egress decides")
        self.assertEqual(decision.egress, ("eno1", "eno2"))
        line = decision.line()
        self.assertIn("eno1 100G 2 switch(es) http 192.0.2.10", line)
        self.assertIn("eno2 10G 1 switch(es) http 198.51.100.10", line)
        self.assertFalse([argv for argv in self.calls() if argv[:3] == ["ip", "route", "get"] and "from" in argv],
                         "the route to a switch is looked up without a source address")

    def calls(self):
        seen, original = [], self.host.run

        def record(argv):
            seen.append(list(argv))
            return original(argv)
        switches, configured = list(self.host.routes), ["192.0.2.10", "198.51.100.10"]
        link.resolve_services(switches, configured, run=record)
        link.detect(switches, configured, run=record, sysfs_root=self.host.root)
        return seen

    def test_a_single_scalar_address_still_works(self):
        self.host.iface("eno1", speed=10000, physical=True)
        self.host.routes["198.51.100.1"] = ("eno1", None)
        services = link.resolve_services(["198.51.100.1"], [SERVER], run=self.host.run)
        self.assertEqual((services["198.51.100.1"].address, services["198.51.100.1"].reason), (SERVER, None))
        decision = link.detect(["198.51.100.1"], SERVER, run=self.host.run, sysfs_root=self.host.root)
        self.assertEqual((decision.speed_mbps, decision.mode), (10000, "direct"))

    def test_a_network_without_a_configured_address_fails_closed(self):
        switches, configured = self.two_networks()
        self.host.iface("eno3", speed=10000, physical=True)
        self.host.device_addresses["eno3"] = ["203.0.113.10"]           # this host is there, Apache is not
        self.host.routes["203.0.113.41"] = ("eno3", None, "203.0.113.10")
        services = link.resolve_services(switches + ["203.0.113.41"], configured, run=self.host.run)
        lost = services["203.0.113.41"]
        self.assertEqual((lost.address, lost.device, lost.reason), (None, "eno3", "HTTP_SERVICE_ADDRESS_NONE"))
        decision = link.detect(switches + ["203.0.113.41"], configured, run=self.host.run, sysfs_root=self.host.root)
        self.assertTrue(any("eno3" in warning and "no configured HTTP address" in warning
                            for warning in decision.warnings), decision.warnings)

    def test_a_configured_secondary_address_is_used_when_the_route_source_is_not_configured(self):
        switches, configured = self.two_networks()
        self.host.device_addresses["eno2"] = ["198.51.100.10", "198.51.100.20"]   # primary, secondary
        services = link.resolve_services(switches, ["192.0.2.10", "198.51.100.20"], run=self.host.run)
        self.assertEqual((services["198.51.100.41"].address, services["198.51.100.41"].reason), ("198.51.100.20", None))

    def test_several_configured_addresses_on_one_interface(self):
        switches, configured = self.two_networks()
        self.host.device_addresses["eno2"] = ["198.51.100.10", "198.51.100.20", "198.51.100.30"]
        both = ["192.0.2.10", "198.51.100.20", "198.51.100.30"]
        ambiguous = link.resolve_services(switches, both, run=self.host.run)["198.51.100.41"]
        self.assertEqual((ambiguous.address, ambiguous.reason), (None, "HTTP_SERVICE_ADDRESS_AMBIGUOUS"))
        self.host.routes["198.51.100.41"] = ("eno2", None, "198.51.100.30")       # the route's src is one of them
        chosen = link.resolve_services(switches, both, run=self.host.run)["198.51.100.41"]
        self.assertEqual((chosen.address, chosen.reason), ("198.51.100.30", None))

    def test_no_route_fails_closed(self):
        switches, configured = self.two_networks()
        services = link.resolve_services(switches + ["203.0.113.99"], configured, run=self.host.run)
        self.assertEqual((services["203.0.113.99"].address, services["203.0.113.99"].reason),
                         (None, "HTTP_SERVICE_ADDRESS_NO_ROUTE"))
        decision = link.detect(switches + ["203.0.113.99"], configured, run=self.host.run, sysfs_root=self.host.root)
        self.assertEqual(decision.speed_mbps, 10000, "the routed switches still decide the mode")

    def test_override_wins_and_is_validated(self):
        decision = self.host.detect(["198.51.100.1"], override="100G")
        self.assertEqual((decision.source, decision.mode, decision.divisor), ("override", "direct", 32))
        with self.assertRaises(ValueError):
            link.from_override("3G")


if __name__ == "__main__":
    unittest.main()
