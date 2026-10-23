"""IB upgrade v2 entry (upgrade2.py; owner 2026-10-23).

--help needs no guard or inputs; --upgrade needs --yes; the link line and the OOB groups
are printed before any password is asked; --plan prechecks simulated switches without
writing them; --upgrade -y upgrades them through the same entry; invalid inventory rows
are reported as SKIPPED; the run's evidence goes to xdr-upgrade-v2-logs and never holds
the password.
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
from test_ibsw_v2_device import SENTINEL  # noqa: E402

FAST = probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05, ssh_check=0.3,
                     dwell=8.0, ladder_budget=4.0, deadline=15.0)
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
        self.common = ["--project", str(self.project), "--p2p", str(base / "p2p.csv"), "--os",
                       "--identity", str(self.private), "--management-public-key", str(self.public),
                       "--known-hosts", str(self.known_hosts), "--server-link", "1G", "--progress-seconds", "1"]

    def ops_factory(self, **kwargs):
        return ib.LiveOps(**kwargs, connector=self.fleet.connector, ping_run=self.fleet.ping_run,
                          tcp_probe=self.fleet.tcp, dir_for=self.fleet.dir_for)

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
        code = load_entry().run(self.common, out=out, password_reader=lambda prompt: asked.append(prompt) or SENTINEL,
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
        code = load_entry().run(self.common + ["--upgrade", "-y"], out=out, password_reader=lambda prompt: SENTINEL,
                                ops_factory=self.ops_factory, timings=FAST)
        text = out.getvalue()
        self.assertRegex(text, r"UPGRADED \(2\)[^\n]*\n  sw01\n  sw02", text)
        self.assertEqual(code, 3, "sw09's inventory row is invalid, so the run is incomplete")
        for switch in self.switches:
            self.assertEqual((switch.state / "version").read_text(), "25.02.8008")
        for path in self.run_dir().rglob("*"):
            if path.is_file():
                self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)


if __name__ == "__main__":
    unittest.main()
