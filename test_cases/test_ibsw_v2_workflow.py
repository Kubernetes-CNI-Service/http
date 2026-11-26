"""IB upgrade v2 end to end: fleet engine + IB adapter + switch scripts on simulated switches.

Owner 2026-10-23: 1G ztp-server link, so OS images relay per OOB leaf (from P2P); the
canary (v1 route cover: the longest route) pulls directly and upgrades first through
both hops; every other switch gets each hop's image from the server once per leaf and
otherwise by scp from a holder with the switch password; nobody reboots while serving;
a switch already at target and an unreachable one are reported, not touched; the run's
evidence never contains the password.
"""
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "test_cases"))

import fleet_distribution as dist  # noqa: E402
import fleet_engine  # noqa: E402
import fleet_link  # noqa: E402
import fleet_probe as probe  # noqa: E402
import fleet_ssh as ssh  # noqa: E402
import ibsw_v2_device as ib  # noqa: E402
from ibsw_upgrade_contract import InventoryDevice  # noqa: E402
from ibsw_v2_switch_sim import LocalSwitch, SimFleet  # noqa: E402
from test_ibsw_v2_device import SENTINEL, global_yaml, policy_for  # noqa: E402

FAST = probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05, ssh_check=0.3,
                     dwell=8.0, ladder_budget=4.0, deadline=15.0, post_ready_settle=0.05)
ENTRY = ROOT / "infiniband/bringup/xdr-upgrade/upgrade2.py"
HEADER = ("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,bgp_asn,"
          "bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl")


def load_entry():
    import importlib.util
    spec = importlib.util.spec_from_file_location("ibsw_upgrade2_workflow_under_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class EntryWorld:
    """v3.1.6 A4c workflows: the real upgrade2.py entry -> fleet_engine -> ibsw_v2_device -> simulated switches.

    `switches` is [(hostname, OS version)]; each gets an inventory row, a pinned host key (unless listed in
    `unpinned`), an OOB leaf from `leaves` (default one leaf) and the switch password. The project declares
    os -> bios -> cpld packages (global_yaml) and optionally packages.ssd.version."""

    def __init__(self, test, switches, *, ssd_version=None, unpinned=(), leaves=None, home=None):
        tmp = tempfile.TemporaryDirectory()
        test.addCleanup(tmp.cleanup)
        self.base = base = Path(tmp.name).resolve()
        self.http = base / "http"
        self.project = base / "project"
        self.project.mkdir()
        (self.project / "01-global.yaml").write_text(global_yaml(self.http, ssd_version=ssd_version))
        self.key = ssh._sdk().ECDSAKey.generate()
        keydir = base / "keys"
        keydir.mkdir(mode=0o700)
        self.private, self.public = keydir / "id_mgmt", keydir / "id_mgmt.pub"
        self.key.write_private_key_file(str(self.private))
        self.private.chmod(0o600)
        self.public.write_text(f"{self.key.get_name()} {self.key.get_base64()} mgmt\n")
        rows, self.switches, pins, p2p = [HEADER], {}, "", "a-node,a-port,z-node,z-port\n"
        for index, (name, version) in enumerate(switches, 1):
            address, mac = f"192.0.2.{60 + index}", f"02:00:00:00:00:{60 + index:02x}"
            rows.append(",".join([name, "ib", "nvos", address, "24", "192.0.2.1", mac] + ["na"] * 12))
            self.switches[name] = LocalSwitch(base / "switches", name, address, mac, version, password=SENTINEL)
            p2p += f"{name},eth0,{(leaves or {}).get(name, 'oob-leaf01')},swp{index}\n"
        self.fleet = SimFleet(list(self.switches.values()), self.http, self.key.get_base64())
        for name, switch in self.switches.items():
            if name not in unpinned:
                host_key = self.fleet.host_key(name)
                pins += f"{switch.address} {host_key.get_name()} {host_key.get_base64()}\n"
        (self.project / "02-devices_config.csv").write_text("\n".join(rows) + "\n")
        (base / "p2p.csv").write_text(p2p)
        self.home = home or base / "home"
        (self.home / ".ssh").mkdir(parents=True, exist_ok=True)
        self.known_hosts = self.home / ".ssh" / "known_hosts"
        self.known_hosts.write_text(pins)
        self.routes = {switch.address: ("eth0", "192.0.2.10") for switch in self.switches.values()}

    def ip(self, argv):
        if argv[:3] == ["ip", "route", "get"]:
            device, src = self.routes[argv[3]]
            return f"{argv[3]} dev {device} src {src} uid 0\n    cache\n"
        if argv[:4] == ["ip", "-o", "addr", "show"]:
            return "2: eth0    inet 192.0.2.10/24 scope global eth0\n"
        raise OSError("unexpected command " + " ".join(argv))

    def ops_factory(self, **kwargs):
        return ib.LiveOps(**kwargs, connector=self.fleet.pinned_connector(kwargs["credentials"], kwargs["pins"]),
                          ping_run=self.fleet.ping_run, tcp_probe=self.fleet.tcp, dir_for=self.fleet.dir_for)

    def argv(self, *extra):
        return ["--project", str(self.project), "--p2p", str(self.base / "p2p.csv"),
                "--identity", str(self.private), "--management-public-key", str(self.public),
                "--known-hosts", str(self.known_hosts), "--server-link", "1G", "--progress-seconds", "1", *extra]

    def run(self, *extra, ops_factory=None, **kwargs):
        out = io.StringIO()
        code = load_entry().run(self.argv(*extra), out=out, password_reader=lambda prompt: SENTINEL,
                                ops_factory=ops_factory or self.ops_factory, link_run=self.ip, timings=FAST,
                                **kwargs)
        return code, out.getvalue()

    def run_dirs(self):
        logs = self.project / "99-output-ib_nvl/bringup/xdr-upgrade-v2-logs"
        return sorted(path for path in logs.iterdir() if path.is_dir())

    @staticmethod
    def section(text, category):
        """{hostname: reason} listed under one summary category."""
        lines, found, inside = text.splitlines(), {}, False
        for line in lines:
            if line.startswith(category + " ("):
                inside = True
                continue
            if inside and line.startswith("  ") and not line.startswith("   "):
                name, _sep, rest = line.strip().partition("  ")
                found[name] = rest
            elif inside:
                break
        return found


class WorkflowTest(unittest.TestCase):
    def test_relay_fleet_upgrade_through_two_hops(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        policy = policy_for(base / "http")
        key = ssh._sdk().ECDSAKey.generate()
        versions = {"sw01": "25.02.7002", "sw02": "25.02.6077", "sw03": "25.02.7002", "sw04": "25.02.7002",
                    "sw05": "25.02.8008", "sw06": "25.02.7002"}
        switches, devices, pins = [], [], b""
        for index, (name, version) in enumerate(versions.items(), 1):
            address, mac = f"192.0.2.{20 + index}", f"02:00:00:00:00:{20 + index:02x}"
            switches.append(LocalSwitch(base / "switches", name, address, mac, version, password=SENTINEL))
            devices.append(InventoryDevice(name, address, mac))
            host_key = ssh._sdk().ECDSAKey.generate()
            pins += f"{address} {host_key.get_name()} {host_key.get_base64()}\n".encode()
        fleet = SimFleet(switches, base / "http", key.get_base64())
        original_connector = fleet.connector

        def connector(device, method):
            if device.hostname == "sw06":
                raise ssh.SshError("CONNECT_FAILED")
            return original_connector(device, method)
        fleet.connector = connector
        p2p = base / "p2p.csv"
        p2p.write_text("a-node,a-port,z-node,z-port\n" + "".join(
            f"{name},eth0,oob-leaf0{1 if index <= 3 else 2},swp{index}\n" for index, name in enumerate(versions, 1)))
        groups, warnings = dist.oob_groups(p2p, list(versions))
        self.assertEqual(warnings, [])
        creds = ssh.Credentials("admin", key, ssh.fingerprint(key.asbytes()), SENTINEL)
        ops = ib.LiveOps(pins=ssh.HostPins(pins), credentials=creds, policy=policy, selected=("os",), run_id="r1",
                         management_line=f"{key.get_name()} {key.get_base64()} mgmt\n".encode(),
                         connector=fleet.connector, ping_run=fleet.ping_run, tcp_probe=fleet.tcp,
                         dir_for=fleet.dir_for)
        options = fleet_engine.Options(run_id="r1", selected=("os",), upgrade=True,
                                       link=fleet_link.decide(1000, source="override"), groups=groups,
                                       timings=FAST, progress_seconds=0.5, later_hop_batch_seconds=0.05)
        out = io.StringIO()
        engine = fleet_engine.Engine(devices, ib.IbFamily(policy), ops, options,
                                     fleet_engine.Evidence(base / "run"), out=out)
        report = engine.run()
        results = {row["hostname"]: (row["category"], row["reason"]) for row in report["devices"]}
        self.assertEqual(results, {"sw01": ("UPGRADED", None), "sw02": ("UPGRADED", None), "sw03": ("UPGRADED", None),
                                   "sw04": ("UPGRADED", None), "sw05": ("AT_TARGET", None),
                                   "sw06": ("SKIPPED", "UNREACHABLE_CONNECT_FAILED")}, out.getvalue())
        for switch in switches[:4]:
            self.assertEqual((switch.state / "version").read_text(), "25.02.8008")
        self.assertIn("[PHASE OS] 4 switch(es); canaries: sw02", out.getvalue(),
                      "v1 route cover: sw02 has the longest route (6077 -> 7002 -> 8008)")
        scp = [(context["host"], Path(context["path"]).name) for context in fleet.contexts if context["method"] == "scp"]
        http = [Path(context["url"]).name for context in fleet.contexts if context["method"] == "http"]
        self.assertIn("nvos-amd64-25.02.8008.bin", http, "a queue's first copy comes from the ztp-server")
        self.assertTrue(scp, "other switches relay from a holder")
        self.assertTrue(all(context["password"] == SENTINEL and context["host_keys"].strip()
                            for context in fleet.contexts if context["method"] == "scp"))
        for name in versions:
            for path in (base / "run").rglob("*"):
                if path.is_file():
                    self.assertNotIn(SENTINEL.encode(), path.read_bytes(), path)
        report_file = json.loads((base / "run" / "run-report.json").read_text())
        self.assertEqual(report_file["counts"], {"UPGRADED": 4, "AT_TARGET": 1, "SKIPPED": 1})
        self.assertEqual(fleet_engine.exit_code(report), 3)


    def test_real_ladder_ready_waits_before_the_real_verification(self):
        """R-024 / U2 (需求 R-024; 指导 8.12): the real probe ladder hands back READY, the engine waits the
        post-ready settle as a main-loop timer, and only then calls the real LiveOps.verify; shortened real
        time like every FAST timing (the 30 s production default is the engine direct test's subject)."""
        settle = 0.6
        timings = probe.Timings(**dict(FAST.__dict__, post_ready_settle=settle))
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        base = Path(tmp.name)
        policy = policy_for(base / "http")
        key = ssh._sdk().ECDSAKey.generate()
        switch = LocalSwitch(base / "switches", "sw01", "192.0.2.21", "02:00:00:00:00:21", "25.02.7002",
                             password=SENTINEL)
        device = InventoryDevice("sw01", "192.0.2.21", "02:00:00:00:00:21")
        host_key = ssh._sdk().ECDSAKey.generate()
        pins = f"192.0.2.21 {host_key.get_name()} {host_key.get_base64()}\n".encode()
        fleet = SimFleet([switch], base / "http", key.get_base64())
        p2p = base / "p2p.csv"
        p2p.write_text("a-node,a-port,z-node,z-port\nsw01,eth0,oob-leaf01,swp1\n")
        groups, _warnings = dist.oob_groups(p2p, ["sw01"])
        creds = ssh.Credentials("admin", key, ssh.fingerprint(key.asbytes()), SENTINEL)
        ops = ib.LiveOps(pins=ssh.HostPins(pins), credentials=creds, policy=policy, selected=("os",), run_id="r1",
                         management_line=f"{key.get_name()} {key.get_base64()} mgmt\n".encode(),
                         connector=fleet.connector, ping_run=fleet.ping_run, tcp_probe=fleet.tcp,
                         dir_for=fleet.dir_for)
        options = fleet_engine.Options(run_id="r1", selected=("os",), upgrade=True,
                                       link=fleet_link.decide(1000, source="override"), groups=groups,
                                       timings=timings, progress_seconds=0.5, later_hop_batch_seconds=0.05)
        out = io.StringIO()
        engine = fleet_engine.Engine([device], ib.IbFamily(policy), ops, options,
                                     fleet_engine.Evidence(base / "run"), out=out)
        verify_calls, original_verify = [], ops.verify

        def verify(*args, **kwargs):
            verify_calls.append(round(engine.clock() - engine.started, 3))
            return original_verify(*args, **kwargs)
        ops.verify = verify
        report = engine.run()
        results = {row["hostname"]: (row["category"], row["reason"]) for row in report["devices"]}
        self.assertEqual(results, {"sw01": ("UPGRADED", None)}, out.getvalue())
        timeline = [json.loads(line) for line in
                    (engine.evidence.directory("sw01") / "timeline.jsonl").read_text().splitlines()]
        ready = [record["t"] for record in timeline if record.get("state") == "VERIFYING" and record.get("boot_id")]
        self.assertEqual(len(ready), len(verify_calls), (timeline, verify_calls))
        self.assertTrue(verify_calls)
        for ready_at, verified_at in zip(ready, verify_calls):
            self.assertGreaterEqual(verified_at - ready_at, settle - 0.01,
                                    "the real verification started before the post-ready wait ended")
        self.assertEqual((switch.state / "version").read_text(), "25.02.8008")


class A4cWorkflowTest(unittest.TestCase):
    """v3.1.6 A4c (指导 8.25) through the real upgrade2.py entry, the engine, the IB adapter and simulated
    switches."""

    def test_a_bios_judgement_error_holds_only_that_switchs_bios(self):
        """G1 (R-043; 指导 8.25.1): two switches need OS and BIOS; one BIOS version cannot be read. Both OS
        reach the target; that switch ends REVIEW_REQUIRED (partly upgraded: os), the other UPGRADED; exit 3."""
        world = EntryWorld(self, [("sw01", "25.02.7002"), ("sw02", "25.02.7002")])
        for switch in world.switches.values():
            (switch.state / "bios_offer").write_text("0ACQF_06.01.008")
        (world.switches["sw02"].state / "bios").write_text("UNKNOWN-BIOS")
        code, text = world.run("--os", "--bios", "--upgrade", "-y")
        self.assertEqual(world.section(text, "UPGRADED"), {"sw01": ""}, text)
        self.assertEqual(world.section(text, "REVIEW_REQUIRED"),
                         {"sw02": "BIOS_VERSION_CHECK_FAILED (partly upgraded: os)"}, text)
        self.assertEqual(code, 3, text)
        for switch in world.switches.values():
            self.assertEqual((switch.state / "version").read_text(), "25.02.8008")
        self.assertEqual((world.switches["sw01"].state / "bios").read_text(), "0ACQF_06.01.008")
        self.assertEqual((world.switches["sw02"].state / "bios").read_text(), "UNKNOWN-BIOS")
        self.assertNotIn("0ACQF.cab", (world.switches["sw02"].state / "cpld-installs").read_text()
                         if (world.switches["sw02"].state / "cpld-installs").exists() else "")

    def test_a_password_changed_after_precheck_fails_only_that_switch_before_any_write(self):
        """G6 (R-044; 指导 8.25.2): three switches; one switch's password changes after its precheck. It ends
        FAILED PASSWORD_PREWRITE_REJECTED with nothing written; the other two are upgraded."""
        world = EntryWorld(self, [("sw01", "25.02.7002"), ("sw02", "25.02.7002"), ("sw03", "25.02.7002")])
        sw02 = world.switches["sw02"]

        def factory(**kwargs):
            ops = world.ops_factory(**kwargs)
            original = ops.dispatch

            def dispatch(device, step, **rest):
                if device.hostname == "sw02":
                    sw02.login_password = "changed-after-precheck"
                return original(device, step, **rest)
            ops.dispatch = dispatch
            return ops
        code, text = world.run("--os", "--upgrade", "-y", ops_factory=factory)
        self.assertEqual(world.section(text, "FAILED"), {"sw02": "PASSWORD_PREWRITE_REJECTED"}, text)
        self.assertEqual(set(world.section(text, "UPGRADED")), {"sw01", "sw03"}, text)
        self.assertEqual(code, 3, text)
        self.assertEqual((sw02.state / "version").read_text(), "25.02.7002")
        self.assertEqual([path.name for path in sw02.home.iterdir() if path.name.startswith(".ibsw-")], [])
        [run] = world.run_dirs()
        self.assertFalse((run / "devices/sw02/dispatch.json").exists(), "no write-ahead record")
        self.assertIn(("sw02", False), world.fleet.password_logins)


    def test_ssd_rows_for_switches_at_target_and_after_an_upgrade_like_v1(self):
        """U8 + G5 (问题文件 §38 :2406-2431; 指导 8.25.3-8.25.4): two switches already at target (one SSD differs)
        get their row in precheck, the switch upgraded gets a POST_UPGRADE row; the summary lists each switch
        once. v1 parity: the same firmware text through v1's start-of-run comparison (ssd_check_from_firmware
        with basis PREFLIGHT_OS_AT_TARGET over v1's raw record) gives the same MISMATCH hosts."""
        from ibsw_upgrade_contract import ssd_check_from_firmware
        from ibsw_upgrade_executor import _raw_record
        world = EntryWorld(self, [("sw01", "25.02.8008"), ("sw02", "25.02.8008"), ("sw03", "25.02.7002")],
                           ssd_version="SSD-1.2")
        for name, ssd in (("sw01", "SSD-1.2"), ("sw02", "SSD-0.9"), ("sw03", "SSD-0.9")):
            (world.switches[name].state / "ssd").write_text(ssd)
        code, text = world.run("--os", "--upgrade", "-y")
        self.assertEqual(code, 0, text)
        self.assertEqual(set(world.section(text, "AT_TARGET")), {"sw01", "sw02"}, text)
        self.assertEqual(set(world.section(text, "UPGRADED")), {"sw03"}, text)
        self.assertIn("SSD (informational): passed=1 warnings=2", text)
        [run] = world.run_dirs()
        report = json.loads((run / "run-report.json").read_text())
        rows = {row["hostname"]: (row["status"], row["verification_basis"]) for row in report["ssd"]}
        self.assertEqual(rows, {"sw01": ("MATCH", "PREFLIGHT_OS_AT_TARGET"),
                                "sw02": ("MISMATCH", "PREFLIGHT_OS_AT_TARGET"),
                                "sw03": ("MISMATCH", "POST_UPGRADE")})
        self.assertEqual(len(report["ssd"]), 3, "one row per switch")
        for name, basis in (("sw02", "PREFLIGHT_OS_AT_TARGET"), ("sw03", "POST_UPGRADE")):
            self.assertEqual(text.count(f"  {name}  MISMATCH observed=SSD-0.9 target=SSD-1.2 basis={basis}"), 1)
        v1 = set()
        for name in ("sw01", "sw02"):                        # v1 compares only switches already at target
            switch = world.switches[name]
            done = subprocess.run([str(switch.bin / "nv"), "show", "platform", "firmware"], capture_output=True,
                                  env={"FAKE_STATE": str(switch.state), "PATH": "/usr/bin:/bin"}, timeout=30)
            check = ssd_check_from_firmware("SSD-1.2", _raw_record("nv show platform firmware", (
                done.stdout, done.stderr, done.returncode, True)), verification_basis="PREFLIGHT_OS_AT_TARGET")
            if check["status"] == "MISMATCH":
                v1.add(name)
        self.assertEqual(v1, {name for name, (status, basis) in rows.items()
                              if status == "MISMATCH" and basis == "PREFLIGHT_OS_AT_TARGET"})

    def test_push_relays_between_switches_and_never_lets_a_switch_reach_the_server(self):
        """U10 (owner 11-20 第7条; 问题文件 §41; 指导 8.25.5): two OOB leaf queues, five switches with a canary,
        --push: the server pushes each queue's first copy, switches forward the rest with scp between
        themselves, no switch pulls from the server; a sixth switch without room fails before any transfer
        with NO_SPACE need=<bytes> free=<bytes> and does not affect the others."""
        names = [f"sw0{index}" for index in range(1, 7)]
        world = EntryWorld(self, [(name, "25.02.7002") for name in names],
                           leaves={name: "oob-leaf01" if name in ("sw01", "sw02", "sw03") else "oob-leaf02"
                                   for name in names})
        (world.switches["sw06"].state / "free_kib").write_text("1")
        code, text = world.run("--os", "--push", "--upgrade", "-y")
        self.assertEqual(set(world.section(text, "UPGRADED")), set(names[:5]), text)
        failed = world.section(text, "FAILED")
        self.assertEqual(list(failed), ["sw06"], text)
        image = (world.http / "image/nvos-amd64-25.02.8008.bin").stat().st_size
        self.assertEqual(failed["sw06"], f"NO_SPACE need={2 * image} free=1024", text)
        self.assertEqual(code, 3, text)
        addresses = {switch.address for switch in world.switches.values()}
        self.assertTrue(world.fleet.contexts, "switches forwarded between themselves")
        self.assertEqual([context for context in world.fleet.contexts
                          if context["method"] != "scp" or context["host"] not in addresses], [],
                         "no switch connected back to the server")
        self.assertIn("[PUSH] the server pushed to", text)
        for name in names[:5]:
            self.assertEqual((world.switches[name].state / "version").read_text(), "25.02.8008")
        self.assertEqual((world.switches["sw06"].state / "version").read_text(), "25.02.7002")
        self.assertEqual([path.name for path in world.switches["sw06"].home.iterdir()
                          if path.name.endswith(".bin") or ".push-" in path.name], [], "nothing sent to sw06")
        [run] = world.run_dirs()
        self.assertEqual(json.loads((run / "plan.json").read_text())["method"], "push")
        records = [json.loads(path.read_text()) for path in (run / "devices").glob("*/distribution-os-*.json")]
        pushed = [result for record in records for result in record["results"] if result.get("pushed")]
        self.assertTrue(pushed and all(result["sha256"] for result in pushed), records)

    def test_unknown_host_keys_are_pinned_only_after_the_hostname_and_mac_check(self):
        """U7 (问题文件 §36.3; 指导 8.25.6; owner 11-20 P-06 (a)): four pinned switches and two never pinned,
        one of which reports another eth0 MAC than the inventory. With --pin-unknown-host-keys one run pins
        the matching one (read back by known_hosts) and checks its version to AT_TARGET; the other is
        REVIEW_REQUIRED DEVICE_IDENTITY_MISMATCH and is not in known_hosts. Without the option both are
        REVIEW_REQUIRED HOST_KEY_UNKNOWN and known_hosts keeps its bytes."""
        names = [f"sw0{index}" for index in range(1, 7)]
        for option in (False, True):
            with self.subTest(option=option):
                world = EntryWorld(self, [(name, "25.02.8008") for name in names], unpinned=("sw05", "sw06"))
                (world.switches["sw06"].sysroot / "sys/class/net/eth0/address").write_text("02:00:00:00:00:99\n")
                before = world.known_hosts.read_bytes()
                extra = ("--pin-unknown-host-keys",) if option else ()
                try:
                    code, text = world.run("--os", "--upgrade", "-y", *extra, home=world.home,
                                           presented_connector=world.fleet.presented)
                except (SystemExit, TypeError) as error:
                    self.fail(f"upgrade2.py has no --pin-unknown-host-keys entry seam: {error!r}")
                review = world.section(text, "REVIEW_REQUIRED")
                pins = ssh.HostPins.load(world.known_hosts)
                if not option:
                    self.assertEqual(review, {"sw05": "HOST_KEY_UNKNOWN", "sw06": "HOST_KEY_UNKNOWN"}, text)
                    self.assertEqual(world.known_hosts.read_bytes(), before)
                    self.assertEqual(world.fleet.presented_to, [])
                    continue
                self.assertEqual(review, {"sw06": "DEVICE_IDENTITY_MISMATCH"}, text)
                self.assertEqual(set(world.section(text, "AT_TARGET")), set(names[:5]), text)
                self.assertEqual(world.fleet.presented_to, ["sw05", "sw06"], "only the never-pinned switches")
                key = world.fleet.host_key("sw05")
                self.assertEqual(pins.fingerprints(world.switches["sw05"].address), {ssh.fingerprint(key.asbytes())})
                self.assertEqual(pins.keys(world.switches["sw06"].address), [])
                self.assertTrue(world.known_hosts.read_bytes().startswith(before))
                self.assertIn(f"[HOSTKEY] pinned sw05 {world.switches['sw05'].address} {ssh.fingerprint(key.asbytes())}"
                              " basis=hostname+MAC", text)
                self.assertNotIn("[KNOWN_HOSTS]", text, "the run uses the registered entry, no modified warning")
                [run] = world.run_dirs()
                records = {row["hostname"]: row for row in json.loads((run / "host-key-pins.json").read_text())}
                self.assertEqual((records["sw05"]["state"], records["sw06"]["state"], records["sw06"]["reason"]),
                                 ("PINNED", "NOT_PINNED", "DEVICE_IDENTITY_MISMATCH"))
                self.assertEqual(records["sw06"]["fingerprint"],
                                 ssh.fingerprint(world.fleet.host_key("sw06").asbytes()), "listed for review")

    def test_a_rerun_verifies_a_switch_the_interrupted_run_left_unknown(self):
        """G9 (R-049; 指导 8.25.9): the first run installs the OS on sw01 but its verification ends UNKNOWN
        (the result was lost); the next --upgrade run finds sw01 at target, sees the earlier run had no final
        result and runs the post-upgrade verification from that run's evidence: UPGRADED, source run named."""
        world = EntryWorld(self, [("sw01", "25.02.7002"), ("sw02", "25.02.8008")])

        def losing(**kwargs):
            ops = world.ops_factory(**kwargs)
            ops.verify = lambda *args, **rest: dict(state="UNKNOWN", reason="COMPONENT_VERSION_NOT_VERIFIED")
            return ops
        code, text = world.run("--os", "--upgrade", "-y", ops_factory=losing)
        self.assertEqual(world.section(text, "UNKNOWN"), {"sw01": "COMPONENT_VERSION_NOT_VERIFIED"}, text)
        self.assertEqual((world.switches["sw01"].state / "version").read_text(), "25.02.8008")
        [first] = world.run_dirs()
        earlier = {path: path.read_bytes() for path in first.rglob("*") if path.is_file()}
        code, text = world.run("--os", "--plan")
        self.assertEqual(world.section(text, "NOT_EXECUTED"),
                         {"sw01": f"RECHECK_NEEDED: last run {first.name} has no final result"}, text)
        code, text = world.run("--os", "--upgrade", "-y")
        self.assertEqual(world.section(text, "UPGRADED"), {"sw01": f"RECHECKED_AFTER_INTERRUPTION run={first.name}"},
                         text)
        self.assertEqual(world.section(text, "AT_TARGET"), {"sw02": ""}, text)
        self.assertEqual(code, 0, text)
        self.assertEqual({path: path.read_bytes() for path in first.rglob("*") if path.is_file()}, earlier,
                         "the earlier run's evidence is read only")
        self.assertEqual(len(world.run_dirs()), 3)

if __name__ == "__main__":
    unittest.main()
