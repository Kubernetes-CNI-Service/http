"""IB upgrade v2 entry (upgrade2.py; owner 2026-10-23).

--help needs no guard or inputs; --upgrade needs --yes; the link line and the OOB groups
are printed before any password is asked; --plan prechecks simulated switches without
writing them; --upgrade -y upgrades them through the same entry; invalid inventory rows
are reported as SKIPPED; the run's evidence goes to xdr-upgrade-v2-logs and never holds
the password.

Mistyped password (field 2026-10-24, v1 parity): when a password is asked, one read-only
password-only login on the first selected switch that answers TCP/22 checks it before the
engine fans out; a refusal asks again, up to three attempts, and the third refusal exits
with "nothing was changed". Switches that do not answer are skipped for this check; when
none answers the run continues and the precheck reports them.

Several HTTP addresses (owner 2026-10-24): common.mgmt.http.address may be one address or a
list; each switch downloads from the configured address on the ztp-server interface that
`ip route get <switch>` leaves by, and a switch whose network has none fails closed in
precheck without any write. The `ip` commands run against a fake routing table.
"""
import importlib.util
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py"
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))

import fleet_probe as probe  # noqa: E402
import fleet_ssh as ssh  # noqa: E402
import ibsw_v2_device as ib  # noqa: E402
from ibsw_v2_switch_sim import LocalSwitch, SimFleet  # noqa: E402
from test_ibsw_v2_device import SENTINEL, TYPO  # noqa: E402

FAST = probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05, ssh_check=0.3,
                     dwell=8.0, ladder_budget=4.0, deadline=15.0)
class FakeIp:
    """This host's `ip` for the entry: a route per switch (device, src) and the addresses on each device."""

    def __init__(self):
        self.routes, self.on, self.calls = {}, {}, []

    def run(self, argv):
        self.calls.append(list(argv))
        if argv[:3] == ["ip", "route", "get"]:
            if argv[3] not in self.routes:
                raise OSError("ip route get exited 2")
            device, src = self.routes[argv[3]]
            return f"{argv[3]} dev {device} src {src} uid 0\n    cache\n"
        if argv[:4] == ["ip", "-o", "addr", "show"]:
            devices = [argv[5]] if argv[4:5] == ["dev"] else list(self.on)
            return "".join(f"2: {device}    inet {address}/24 scope global {device}\n"
                           for device in devices for address in self.on.get(device, ()))
        raise OSError("unexpected command " + " ".join(argv))


HEADER = ("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,bgp_asn,"
          "bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl")


def load_entry():
    spec = importlib.util.spec_from_file_location("ibsw_upgrade2_entry_under_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EntryTest(unittest.TestCase):
    def test_help_and_argument_checks(self):
        done = subprocess.run([sys.executable, "-B", str(ENTRY), "--help"], capture_output=True, text=True, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        for option in ("--plan", "--upgrade", "--server-link", "--method", "--p2p", "--in-flight", "--relay-fanout"):
            self.assertIn(option, done.stdout)
        entry = load_entry()
        out = io.StringIO()
        self.assertEqual(entry.run(["--upgrade"], out=out), 2)
        self.assertIn("--upgrade needs --yes", out.getvalue())
        out = io.StringIO()
        self.assertEqual(entry.run(["--method", "scp"], out=out), 2)
        self.assertIn("--method scp needs", out.getvalue())

    def test_check_workers_default_to_sixteen_and_upgrade_limits_stay(self):
        """O2 2026-10-24: 16 parallel prechecks/verifications (read-only SSH); upgrade workers 8, in-flight 32."""
        entry = load_entry()
        args = entry.parser().parse_args([])
        self.assertEqual((args.check_workers, args.upgrade_workers, args.in_flight), (16, 8, 32))
        self.assertRegex(" ".join(entry.parser().format_help().split()),
                         r"--check-workers CHECK_WORKERS parallel prechecks and post-upgrade verifications "
                         r"\(default: 16\)")
        out = io.StringIO()
        self.assertEqual(entry.run(["--check-workers", "33"], out=out), 2)
        self.assertIn("--check-workers must be 1..32", out.getvalue())

    def test_the_same_runtime_guard_as_upgrade_py_and_initial_setup(self):
        entry = load_entry()
        import ib_bringup_runtime_guard as guard
        calls = []

        class Busy:
            def __enter__(self):
                calls.append("enter")
                raise guard._InstanceGuardError("ALREADY_RUNNING", "another upgrade is running")

            def __exit__(self, *_exc):
                return False
        original, argv = guard._runtime_instance_guard, sys.argv
        guard._runtime_instance_guard, sys.argv = Busy, ["upgrade2.py", "--project", "/nonexistent"]
        try:
            self.assertEqual(entry.main(), 75, "busy guard: nothing starts")
        finally:
            guard._runtime_instance_guard, sys.argv = original, argv
        self.assertEqual(calls, ["enter"])
        self.assertEqual(Path(guard.__file__).resolve(), ROOT / "tools/ib_bringup_runtime_guard.py")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        self.project = base / "project"
        self.project.mkdir()
        http = base / "http"
        (http / "image").mkdir(parents=True)
        for version in ("25.02.6077", "25.02.7002", "25.02.8008"):
            (http / "image" / f"nvos-amd64-{version}.bin").write_bytes(f"image {version}\n".encode() * 64)
        (self.project / "01-global.yaml").write_text(f"""schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.10
      port: 8088
      http_root: {http}
switches:
- ib:
    version: '25.02.8008'
    upgrade:
      package_dir: {http}
      packages:
        os:
          sub_dir: image
          files:
          - file: nvos-amd64-25.02.6077.bin
          - file: nvos-amd64-25.02.7002.bin
          - file: nvos-amd64-25.02.8008.bin
""")
        self.key = ssh._sdk().ECDSAKey.generate()
        keydir = base / "keys"
        keydir.mkdir(mode=0o700)
        self.private, self.public = keydir / "id_mgmt", keydir / "id_mgmt.pub"
        self.key.write_private_key_file(str(self.private))
        self.private.chmod(0o600)
        self.public.write_text(f"{self.key.get_name()} {self.key.get_base64()} mgmt\n")
        rows, self.switches, pins = [HEADER], [], ""
        for index, (name, version) in enumerate((("sw01", "25.02.7002"), ("sw02", "25.02.7002"),
                                                 ("sw03", "25.02.8008")), 1):
            address, mac = f"192.0.2.{40 + index}", f"02:00:00:00:00:{40 + index:02x}"
            rows.append(",".join([name, "ib", "nvos", address, "24", "192.0.2.1", mac] + ["na"] * 12))
            switch = LocalSwitch(base / "switches", name, address, mac, version, password=SENTINEL)
            self.switches.append(switch)
            host_key = ssh._sdk().ECDSAKey.generate()
            pins += f"{address} {host_key.get_name()} {host_key.get_base64()}\n"
        rows.append(",".join(["sw09", "ib", "nvos", "192.0.2.49", "24", "192.0.2.1", "na"] + ["na"] * 12))
        (self.project / "02-devices_config.csv").write_text("\n".join(rows) + "\n")
        (base / "p2p.csv").write_text("a-node,a-port,z-node,z-port\nsw01,eth0,oob-leaf01,swp1\n"
                                      "sw02,eth0,oob-leaf01,swp2\nsw03,eth0,oob-leaf02,swp1\n")
        self.known_hosts = base / "known_hosts"
        self.known_hosts.write_text(pins)
        self.fleet = SimFleet(self.switches, http, self.key.get_base64())
        self.ip = FakeIp()                                       # one network: eth0 carries the HTTP address
        self.ip.on["eth0"] = ["192.0.2.10"]
        for switch in self.switches:
            self.ip.routes[switch.address] = ("eth0", "192.0.2.10")
        self.common = ["--project", str(self.project), "--p2p", str(base / "p2p.csv"), "--os",
                       "--identity", str(self.private), "--management-public-key", str(self.public),
                       "--known-hosts", str(self.known_hosts), "--server-link", "1G", "--progress-seconds", "1"]

    def entry(self, argv, **kwargs):
        return load_entry().run(argv, link_run=self.ip.run, **kwargs)

    def ops_factory(self, **kwargs):
        return ib.LiveOps(**kwargs, connector=self.fleet.connector_for(kwargs["credentials"]),
                          ping_run=self.fleet.ping_run, tcp_probe=self.fleet.tcp, dir_for=self.fleet.dir_for)

    @staticmethod
    def reader(*answers):
        """password_reader typing `answers` in turn (the last one repeats); records every prompt."""
        asked = []

        def read(prompt):
            asked.append(prompt)
            return answers[min(len(asked), len(answers)) - 1]
        return read, asked

    def untouched(self, before):
        for switch in self.switches:
            self.assertEqual((switch.home / ".ssh/authorized_keys").read_bytes(), before[switch.hostname])
            self.assertEqual([path.name for path in switch.home.iterdir() if path.name.startswith(".ibsw-")], [])
            self.assertIn((switch.state / "version").read_text(), ("25.02.7002", "25.02.8008"))

    def run_dir(self):
        [run] = list((self.project / "99-output-ib_nvl/bringup/xdr-upgrade-v2-logs").iterdir())
        return run

    def test_plan_reads_only_and_reports_every_switch(self):
        for switch in self.switches:
            keys = switch.home / ".ssh/authorized_keys"
            keys.write_text(keys.read_text() + f"{self.key.get_name()} {self.key.get_base64()} mgmt\n")
        before = {switch.hostname: (switch.home / ".ssh/authorized_keys").read_bytes() for switch in self.switches}
        out = io.StringIO()
        asked = []
        code = self.entry(self.common, out=out, password_reader=lambda prompt: asked.append(prompt) or SENTINEL,
                                ops_factory=self.ops_factory)
        text = out.getvalue()
        self.assertEqual(code, 3, text)
        self.assertEqual(asked, [], "--plan asks no password unless --password")
        self.assertIn("[LINK] egress=- speed=1G source=override → relay", text)
        self.assertIn("[GROUPS] oob-leaf01 2 · oob-leaf02 1", text)
        self.assertIn("[PREFLIGHT PROGRESS]", text)
        self.assertRegex(text, r"NOT_EXECUTED \(2\)[^\n]*\n  sw01  PLAN_ONLY\n  sw02  PLAN_ONLY")
        self.assertRegex(text, r"AT_TARGET \(1\)[^\n]*\n  sw03")
        self.assertRegex(text, r"SKIPPED \(1\)[^\n]*\n  sw09  ETH0_MAC_MISSING")
        for switch in self.switches:
            self.assertEqual((switch.home / ".ssh/authorized_keys").read_bytes(), before[switch.hostname])
            self.assertEqual([path.name for path in switch.home.iterdir() if path.name.startswith(".ibsw-")], [])
        self.assertTrue((self.run_dir() / "plan.json").is_file())

    def test_upgrade_through_the_entry(self):
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=lambda prompt: SENTINEL,
                                ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertRegex(text, r"UPGRADED \(2\)[^\n]*\n  sw01\n  sw02", text)
        self.assertEqual(code, 3, "sw09's inventory row is invalid, so the run is incomplete")
        for switch in self.switches:
            self.assertEqual((switch.state / "version").read_text(), "25.02.8008")
        for path in self.run_dir().rglob("*"):
            if path.is_file():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)

    def test_the_summary_lists_an_at_target_switch_whose_key_was_rejected(self):
        """O3 2026-10-24: sw03 needs nothing, so no access bootstrap adds the key; the summary says so and how."""
        sw03_keys = (self.switches[2].home / ".ssh/authorized_keys").read_bytes()
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=lambda prompt: SENTINEL,
                                ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertEqual(code, 3, text)
        section = text.split("MANAGEMENT KEY REJECTED", 1)[1]
        self.assertIn("key was not changed", section)
        self.assertIn(f"sw03  ssh-copy-id -i {self.public} admin@192.0.2.43", section)
        self.assertEqual((self.switches[2].home / ".ssh/authorized_keys").read_bytes(), sw03_keys, "report only")
        self.assertFalse(self.switches[2].key_allowed(self.key.get_base64()))

    def test_plan_without_a_password_says_the_password_was_not_tried(self):
        out = io.StringIO()
        code = self.entry(self.common, out=out, password_reader=lambda prompt: SENTINEL,
                                ops_factory=self.ops_factory)
        text = out.getvalue()
        self.assertEqual(code, 3, text)
        section = text.split("MANAGEMENT KEY REJECTED", 1)[1]
        self.assertIn("password was not tried", section)
        for name in ("sw01", "sw02", "sw03"):
            self.assertIn(f"  {name}", section)

    # ------------------------------------------------------------ mistyped password (field 2026-10-24)
    def test_a_refused_password_is_asked_again_before_the_fan_out(self):
        read, asked = self.reader(TYPO, SENTINEL)
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=read,
                                ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertEqual(asked, ["Switch password: "] * 2, text)
        self.assertIn("Attempt 2/3", text)
        self.assertEqual(self.fleet.password_logins[0], ("sw01", False), "checked on the first selected switch")
        self.assertEqual([login for login in self.fleet.password_logins if not login[1]], [("sw01", False)],
                         "the mistyped password was tried once, on one switch")
        self.assertRegex(text, r"UPGRADED \(2\)[^\n]*\n  sw01\n  sw02", text)
        self.assertEqual(code, 3, "sw09's inventory row is invalid, so the run is incomplete")
        for path in self.run_dir().rglob("*"):
            if path.is_file():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)
                self.assertNotIn(TYPO.encode(), path.read_bytes(), path)

    def test_the_third_refusal_exits_without_touching_a_switch(self):
        before = {switch.hostname: (switch.home / ".ssh/authorized_keys").read_bytes() for switch in self.switches}
        read, asked = self.reader(TYPO)
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=read,
                                ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertEqual(asked, ["Switch password: "] * 3, text)
        self.assertEqual(self.fleet.password_logins, [("sw01", False)] * 3, "three attempts, one switch, nothing else")
        self.assertEqual(self.fleet.commands, [], "no command ran on any switch")
        self.assertIn("nothing was changed", text)
        self.assertNotEqual(code, 0)
        self.assertEqual(code, 2)
        self.untouched(before)

    def test_switches_not_answering_are_skipped_for_the_password_check(self):
        first = self.switches[0].address
        read, asked = self.reader(TYPO, SENTINEL)
        out = io.StringIO()

        def factory(**kwargs):
            ops = self.ops_factory(**kwargs)
            ops.tcp_probe = lambda address: address != first and self.fleet.tcp(address)
            return ops
        code = self.entry(self.common + ["--plan", "--password"], out=out, password_reader=read,
                                ops_factory=factory)
        text = out.getvalue()
        self.assertEqual(asked, ["Switch password: "] * 2, text)
        self.assertEqual(self.fleet.password_logins[:2], [("sw02", False), ("sw02", True)],
                         "sw01 does not answer TCP/22, so sw02 is the first one checked")
        self.assertTrue(all(accepted for _host, accepted in self.fleet.password_logins[2:]))
        self.assertEqual(code, 3, text)

    def test_when_no_switch_answers_the_run_continues_and_reports_them(self):
        before = {switch.hostname: (switch.home / ".ssh/authorized_keys").read_bytes() for switch in self.switches}
        read, asked = self.reader(TYPO)
        out = io.StringIO()

        def factory(**kwargs):
            ops = self.ops_factory(**kwargs)
            ops.tcp_probe = lambda address: False

            def unreachable(device, method):
                raise ssh.SshError("CONNECT_FAILED")
            ops.connector = unreachable
            return ops
        code = self.entry(self.common + ["--plan", "--password"], out=out, password_reader=read,
                                ops_factory=factory)
        text = out.getvalue()
        self.assertEqual(asked, ["Switch password: "], "nothing answered, so nothing refused the password")
        self.assertEqual(self.fleet.password_logins, [])
        for name in ("sw01", "sw02", "sw03"):
            self.assertRegex(text, rf"SKIPPED \(4\)[^\n]*\n(?:  [^\n]*\n)*  {name}  UNREACHABLE_CONNECT_FAILED")
        self.assertEqual(code, 3, text)
        self.untouched(before)


    # ------------------------------------------------------------ several HTTP addresses (owner 2026-10-24)
    def second_network(self, address, *, device, server_address, configured):
        """sw04 at `address`, reached through `device` whose address is `server_address`; the project lists
        `configured` as common.mgmt.http.address."""
        base = Path(self.tmp.name)
        sw04 = LocalSwitch(base / "switches", "sw04", address, "02:00:00:00:00:44", "25.02.7002", password=SENTINEL)
        self.switches.append(sw04)
        self.fleet = SimFleet(self.switches, base / "http", self.key.get_base64())
        csv = self.project / "02-devices_config.csv"
        csv.write_text(csv.read_text() + ",".join(["sw04", "ib", "nvos", address, "24", "198.51.100.1",
                                                   "02:00:00:00:00:44"] + ["na"] * 12) + "\n")
        host_key = ssh._sdk().ECDSAKey.generate()
        self.known_hosts.write_text(self.known_hosts.read_text() + f"{address} {host_key.get_name()} {host_key.get_base64()}\n")
        p2p = base / "p2p.csv"
        p2p.write_text(p2p.read_text() + "sw04,eth0,oob-leaf03,swp1\n")
        globals_file = self.project / "01-global.yaml"
        text = globals_file.read_text()
        self.assertEqual(text.count("address: 192.0.2.10"), 1)
        globals_file.write_text(text.replace("address: 192.0.2.10", "address: " + configured))
        self.ip.on[device] = [server_address]
        self.ip.routes[address] = (device, server_address)
        return sw04

    def downloads(self):
        """{hostname: [url, ...]} of the HTTP pulls the switches made."""
        found = {}
        for context in self.fleet.contexts:
            if context.get("method") == "http":
                found.setdefault(Path(context["dest_dir"]).parents[1].name, []).append(context["url"])
        return found

    def test_each_switch_downloads_from_the_http_address_on_its_own_network(self):
        self.second_network("198.51.100.44", device="eth1", server_address="198.51.100.10",
                            configured="[192.0.2.10, 198.51.100.10]")
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=lambda prompt: SENTINEL,
                          ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertRegex(text, r"UPGRADED \(3\)[^\n]*\n  sw01\n  sw02\n  sw04", text)
        self.assertEqual(code, 3, text)
        downloads = self.downloads()
        self.assertTrue(downloads.get("sw04"), downloads)
        self.assertTrue(all(url.startswith("http://198.51.100.10:8088/") for url in downloads["sw04"]), downloads)
        for name, urls in downloads.items():
            if name != "sw04":
                self.assertTrue(all(url.startswith("http://192.0.2.10:8088/") for url in urls), downloads)
        self.assertIn(["ip", "route", "get", "198.51.100.44"], self.ip.calls, "its own route, no source address")
        self.assertFalse([argv for argv in self.ip.calls if "from" in argv])

    def test_a_switch_on_a_network_without_an_http_address_fails_closed(self):
        sw04 = self.second_network("203.0.113.44", device="eth2", server_address="203.0.113.10",
                                   configured="[192.0.2.10, 198.51.100.10]")
        keys = (sw04.home / ".ssh/authorized_keys").read_bytes()
        out = io.StringIO()
        code = self.entry(self.common + ["--upgrade", "-y"], out=out, password_reader=lambda prompt: SENTINEL,
                          ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertRegex(text, r"FAILED \(1\)[^\n]*\n  sw04  HTTP_SERVICE_ADDRESS_NONE[^\n]*eth2", text)
        self.assertRegex(text, r"UPGRADED \(2\)[^\n]*\n  sw01\n  sw02", text)
        self.assertEqual(code, 3, text)
        self.assertNotIn("sw04", self.downloads(), "never pointed at another network's address")
        self.assertEqual((sw04.home / ".ssh/authorized_keys").read_bytes(), keys, "nothing written")
        self.assertEqual([path.name for path in sw04.home.iterdir() if path.name.startswith(".ibsw-")], [])
        self.assertEqual((sw04.state / "version").read_text(), "25.02.7002")


if __name__ == "__main__":
    unittest.main()
