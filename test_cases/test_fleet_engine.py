"""Fleet engine (IB upgrade v2; reusable for nvl-sw): the main loop with a simulated fleet.

A family-neutral fake family (components "os" and "fw") and simulated switches that
install, go down, come back with a new boot and get nvued ready on real (shortened)
time. Checks the owner's flow (2026-10-23) and review 15.x: canaries first; relay inside
each OOB leaf with one server pull per queue and no holder rebooting while it serves;
small packages pulled directly; in-flight cap; precheck classification; plan-only does
not touch switches; stop, write-ahead failure, a job without reboot, multi-hop; the
progress block showing every queue; and the single verification retry after a timed-out
query (owner 2026-10-23); a switch refusing the password holds the prechecks (field 2026-10-24).
"""
import hashlib
import io
import json
import sys
import tempfile
import threading
import time
import unittest
import uuid
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import fleet_engine as engine  # noqa: E402
import fleet_link as link  # noqa: E402
import fleet_probe as probe  # noqa: E402
from fleet_ssh import SshError  # noqa: E402

FAST = probe.Timings(upgrading_ping=0.05, reboot_wait=0.1, ladder_ping=0.05, ladder_retry=0.05, ssh_check=0.3,
                     dwell=5.0, ladder_budget=3.0, deadline=10.0, config_check=0.05,
                     post_ready_settle=0.05)


@dataclass(frozen=True)
class Device:
    hostname: str
    address: str
    mac: str = "02:00:00:00:00:01"


@dataclass(frozen=True)
class Package:
    file: str
    path: str
    url: str
    version: str


@dataclass
class Plan:
    needed_steps: dict
    issues: tuple = ()
    rows: tuple = ()
    start_versions: dict = field(default_factory=lambda: {'os': '1.0', 'fw': 'fw1'})

    @property
    def needed(self):
        return tuple(component for component, steps in self.needed_steps.items() if steps)


@dataclass
class Facts:
    os_version: str
    boot_id: str
    staged: dict = field(default_factory=dict)
    free_bytes: int = 10 ** 12
    capability_missing: tuple = ()


@dataclass(frozen=True)
class Step:
    component: str
    stage: str
    target_version: str
    effect: str = "REBOOT_EXPECTED"
    remote_dir: str = ""


class FakeFamily(engine.Family):
    name = "test-sw"
    components = ("os", "fw")
    required_programs = ("/usr/bin/python3",)

    def __init__(self, packages, components=None, held_alone=()):
        self.by_name = packages
        if components is not None:
            self.components = components
        self.held_alone = held_alone

    def packages(self, selected):
        return [package for package in self.by_name.values()]

    def steps(self, plan, component, infos):
        return [engine.StepPlan(component, index, tuple(infos[self.by_name[name].path] for name in names),
                                self.by_name[names[0]].version)
                for index, names in enumerate(plan.needed_steps.get(component, ()))]

    def canaries(self, component, members):
        return [members[0][0]]

    def segments(self, plan, component, infos):
        start, result = plan.start_versions.get(component, '1.0'), []
        for step in self.steps(plan, component, infos):
            result.append((component, start, step.target_version, tuple(p.file for p in step.packages),
                           tuple(p.sha256 for p in step.packages)))
            start = step.target_version
        return result

    def render(self, device, step_plan, *, run_id, switch_dir):
        effect = "NONE" if step_plan.component == "fw" and step_plan.target_version == "cfg" else "REBOOT_EXPECTED"
        return Step(step_plan.component, f"{step_plan.component}-{step_plan.package_index}", step_plan.target_version,
                    effect)

    def relay(self, component):
        return component == "os"

    space = 0                                          # U10: bytes the switch needs (default: nothing)

    def space_needed(self, plan, infos):
        return self.space


class Sim:
    def __init__(self, version):
        self.boot, self.version, self.state = str(uuid.uuid4()), version, "up"
        self.files, self.until, self.next_boot, self.target = {}, {}, None, None


class FakeOps:
    switch_dir = "/home/admin"

    def dir_for(self, device):
        return self.switch_dir

    def __init__(self, devices, *, versions=None, install=0.05, down=0.15, nvue=0.05):
        self.sims = {device.hostname: Sim((versions or {}).get(device.hostname, "1.0")) for device in devices}
        self.lock = threading.Lock()
        self.install, self.down, self.nvue = install, down, nvue
        self.log = []                         # (time, kind, host, detail)
        self.precheck_behaviour, self.verify_behaviour, self.fetch_fail = {}, {}, set()
        self.free = {}                         # U10: host -> free bytes reported by the precheck
        self.health_pending = {}               # G7: host -> how many verifications answer HEALTH_PENDING
        self.verify_version = {}               # Q-113: host -> version_at_target in a non-VERIFIED answer
        self.verify_errors = {}               # host -> [exception], one raised per verify call
        self.dispatch_journal_error = set()
        self.plans = {}
        self.ssd_rows, self.verify_ssd = {}, {}     # U8/G5: host -> SSD row from precheck / verification

    def note(self, kind, host, detail=None):
        with self.lock:
            self.log.append((time.monotonic(), kind, host, detail))

    def _refresh(self, sim):
        now = time.monotonic()
        if sim.state == "installing" and now >= sim.until["install"]:
            sim.state = "down" if sim.next_boot else "up"
            if not sim.next_boot:
                sim.version = sim.target                       # a job without reboot takes effect at once
        if sim.state == "down" and now >= sim.until["down"]:
            sim.state, sim.boot, sim.version, sim.next_boot = "up", sim.next_boot, sim.target, None
        return sim

    def ping(self, device):
        sim = self._refresh(self.sims[device.hostname])
        if self.precheck_behaviour.get(device.hostname) == "no-ping":
            return "no_reply"
        return "no_reply" if sim.state == "down" else "reply"

    def tcp(self, device):
        return self._refresh(self.sims[device.hostname]).state != "down"

    def precheck(self, device, *, upgrade, staged_names, journal):
        self.note("precheck", device.hostname, upgrade)
        behaviour = self.precheck_behaviour.get(device.hostname)
        if behaviour == "unreachable":
            raise SshError("CONNECT_FAILED")
        if behaviour == "password-rejected":
            raise SshError("PASSWORD_REJECTED")
        if behaviour == "key-refused":                       # key rejected and no password to fall back to
            raise SshError("AUTH_REJECTED")
        sim = self.sims[device.hostname]
        plan = self.plans[device.hostname]
        guard = ("PREVIOUS_INSTALL_PENDING", ".ibsw-x") if behaviour == "pending" else (None, None)
        return dict(facts=Facts(sim.version, sim.boot, dict(sim.files), self.free.get(device.hostname, 10 ** 12)),
                    plan=plan,
                    health=dict(observed="PASS", reason=None, admitted=behaviour != "unhealthy"),
                    guard=guard, backup=object() if upgrade else None, key_rejected=behaviour == "key-rejected",
                    **({"ssd": self.ssd_rows[device.hostname]} if device.hostname in self.ssd_rows else {}))

    def fetch(self, device, info, *, size, sha256, holder=None, url=None):
        source = holder.hostname if holder else "@server"
        self.note("fetch-start", device.hostname, (info.file, source))
        if holder is not None:
            holder_sim = self.sims[holder.hostname]
            assert holder_sim.files.get(info.file) == (size, sha256), "a holder serves only a verified copy"
            assert holder_sim.state == "up", "a holder never serves while upgrading"
        time.sleep(0.02)
        if device.hostname in self.fetch_fail:
            self.note("fetch-end", device.hostname, (info.file, source, False))
            return {"ok": False, "class": "receiver", "code": "NO_SPACE"}
        self.sims[device.hostname].files[info.file] = (size, sha256)
        self.note("fetch-end", device.hostname, (info.file, source, True))
        return {"ok": True, "class": "none", "code": "OK"}

    def dispatch(self, device, step, *, backup, staged, journal):
        sim = self._refresh(self.sims[device.hostname])
        for name, expected in staged.items():
            if sim.files.get(name) != expected:
                return dict(state="FAILED", reason="STAGED_PACKAGE_CHANGED")
        if device.hostname in self.dispatch_journal_error:
            raise engine.EvidenceError("disk full")
        journal("dispatch.json", dict(state="REQUESTED", stage=step.stage))
        self.note("dispatch", device.hostname, step.stage)
        boot_before = sim.boot
        now = time.monotonic()
        with self.lock:
            sim.state, sim.target = "installing", step.target_version
            sim.next_boot = str(uuid.uuid4()) if step.effect != "NONE" else None
            sim.until = {"install": now + self.install, "down": now + self.install + self.down,
                         "nvue": now + self.install + self.down + self.nvue}
            if step.component == "os":
                sim.files.pop(next(iter(staged)), None)            # an OS install can erase /home/admin
        return dict(state="DISPATCHED", remote_dir="/home/admin/.ibsw-x", boot_before=boot_before, confirmed=True,
                    before_commands=b"nv set system hostname x\n", health_record=None, facts=None)

    def previous_backup(self, directory):
        """G9: the access backup an earlier run saved for this switch (opaque here), None when missing."""
        return object() if (directory / "access-backup.json").is_file() else None

    def status(self, device, step, boot_before):
        sim = self._refresh(self.sims[device.hostname])
        if sim.state == "down":
            return {"kind": "connect_fail"}
        outcome = "running" if sim.state == "installing" else "exit_zero"
        return {"kind": "ok", "boot_id": sim.boot, "outcome": outcome}

    def ladder(self, device, boot_before, *, backup, journal):
        sim = self._refresh(self.sims[device.hostname])
        if sim.state == "down":
            return {"kind": "connect_fail"}
        if sim.boot == boot_before:
            return {"kind": "boot_same", "boot_id": sim.boot}
        if time.monotonic() < sim.until["nvue"]:
            return {"kind": "nvued_down", "boot_id": sim.boot}
        return {"kind": "ready", "boot_id": sim.boot, "version": sim.version}

    def verify(self, device, step, *, boot_after, before, baseline_health, backup, journal):
        self.note("verify", device.hostname, step.stage)
        errors = self.verify_errors.get(device.hostname)
        if errors:
            error = errors.pop(0)
            self.note("verify-error", device.hostname, error.code)
            raise error
        version = ({"version_at_target": self.verify_version[device.hostname]}    # Q-113: the read-back verdict
                   if device.hostname in self.verify_version else {})
        if self.verify_behaviour.get(device.hostname) == "unknown":
            return dict(state="UNKNOWN", reason="COMPONENT_VERSION_NOT_VERIFIED", **version)
        if self.verify_behaviour.get(device.hostname) == "degraded":
            return dict(state="UNKNOWN", reason="HEALTH_DEGRADED", **version)
        if self.health_pending.get(device.hostname, 0) > 0:      # G7: the health record read status N/A
            self.health_pending[device.hostname] -= 1
            return dict(state="HEALTH_PENDING", reason="HEALTH_STATUS_UNAVAILABLE",
                        health=dict(command="health", stdout_base64="c3RhdHVzIE4vQQo="), **version)
        sim = self._refresh(self.sims[device.hostname])
        if sim.version != step.target_version:
            return dict(state="UNKNOWN", reason="COMPONENT_VERSION_NOT_VERIFIED")
        return dict(state="VERIFIED", os_version=sim.version, repaired=False,
                    **({"ssd": self.verify_ssd[device.hostname]} if device.hostname in self.verify_ssd else {}))


class QuickLink(link.LinkDecision):
    """The owner's window formula, in seconds divided by 60 so a test waits one second, not one minute."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        object.__setattr__(self, "counts", [])

    def window_seconds(self, count):
        self.counts.append(count)
        return super().window_seconds(count) // 60


class World:
    def __init__(self, test, hosts, *, speed=1000, groups=None, needs=None, in_flight=32, versions=None,
                 upgrade=True, selected=("os", "fw"), verify_retry_seconds=None, check_workers=None,
                 service_issues=None, components=None, held_alone=(), issues=None, method="http",
                 health_recheck_seconds=None, health_wait_seconds=None, **ops):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        packages = {}
        names = (("os-2.bin", "2.0"), ("os-3.bin", "3.0"), ("fw.bin", "fw2"), ("cfg.txt", "cfg"))
        if components is not None:                      # G1: a three-component family (os -> bios -> cpld)
            names += (("bios.bin", "b2"), ("cpld.bin", "c2"))
        for name, version in names:
            path = base / name
            path.write_bytes(name.encode() * 100)
            packages[name] = Package(name, str(path), "http://192.0.2.10/" + name, version)
        self.family = FakeFamily(packages, components, held_alone)
        self.devices = [Device(host, f"198.51.100.{index + 1}") for index, host in enumerate(hosts)]
        self.ops = FakeOps(self.devices, versions=versions, **ops)
        for device in self.devices:
            self.ops.plans[device.hostname] = Plan(dict((needs or {}).get(device.hostname,
                                                                          {"os": [["os-2.bin"]], "fw": [["fw.bin"]]})),
                                                   issues=tuple((issues or {}).get(device.hostname, ())))
        base_decision = link.decide(speed, source="override")
        decision = QuickLink(**{name: getattr(base_decision, name) for name in base_decision.__dataclass_fields__})
        self.out = io.StringIO()
        self.options = engine.Options(run_id="r1", selected=selected, upgrade=upgrade, link=decision,
                                      groups=groups or {}, in_flight=in_flight, timings=FAST,
                                      progress_seconds=0.2, later_hop_batch_seconds=0.05, method=method,
                                      **({} if verify_retry_seconds is None
                                         else {"verify_retry_seconds": verify_retry_seconds}),
                                      **({} if check_workers is None else {"check_workers": check_workers}),
                                      **({} if health_recheck_seconds is None else
                                         {"health_recheck_seconds": health_recheck_seconds,
                                          "health_wait_seconds": health_wait_seconds}))
        self.engine = engine.Engine(self.devices, self.family, self.ops, self.options,
                                    engine.Evidence(base / "run"), out=self.out,
                                    **({} if service_issues is None else {"service_issues": service_issues}))

    def run(self, **kwargs):
        report = self.engine.run(**kwargs)
        self.report = report
        return {row["hostname"]: (row["category"], row["reason"]) for row in report["devices"]}

    def events(self, kind):
        return [(t, host, detail) for t, k, host, detail in self.ops.log if k == kind]


class EngineTest(unittest.TestCase):
    def test_canary_first_relay_inside_each_leaf_and_direct_small_packages(self):
        hosts = [f"a{i}" for i in range(5)] + [f"b{i}" for i in range(5)]
        groups = {host: ("leaf-a" if host.startswith("a") else "leaf-b") for host in hosts}
        world = World(self, hosts, groups=groups)
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)}, results)
        dispatches = world.events("dispatch")
        os_dispatches = [item for item in dispatches if item[2] == "os-0"]
        self.assertEqual(os_dispatches[0][1], "a0", "the canary upgrades first")
        canary_verified = min(t for t, host, stage in world.events("verify") if host == "a0" and stage == "os-0")
        self.assertTrue(all(t > canary_verified for t, host, _s in os_dispatches[1:]),
                        "nobody else upgrades before the canary verified")
        fetches = [(host, detail) for _t, host, detail in world.events("fetch-start")]
        os_sources = {host: source for host, (name, source) in fetches if name == "os-2.bin"}
        self.assertEqual(os_sources["a0"], "@server", "the canary pulls from the server")
        for leaf in ("a", "b"):
            members = [host for host in os_sources if host.startswith(leaf) and host != "a0"]
            server = [host for host in members if os_sources[host] == "@server"]
            self.assertEqual(len(server), 1, f"one server pull per OOB leaf queue: {os_sources}")
            self.assertTrue(all(os_sources[host] == "@server" or os_sources[host].startswith(leaf)
                                for host in members), "relays stay inside the OOB leaf")
        for _t, host, (name, source) in world.events("fetch-start"):
            if name == "fw.bin":
                self.assertEqual(source, "@server", "small packages are pulled directly")
        serving_end = {}
        for t, _host, detail in world.events("fetch-end"):
            if detail[1] != "@server":
                serving_end[detail[1]] = max(serving_end.get(detail[1], 0), t)
        for t, host, stage in os_dispatches:
            if host in serving_end:
                self.assertGreater(t, serving_end[host], f"{host} rebooted while serving")
        out = world.out.getvalue()
        for text in ("[PREFLIGHT PROGRESS]", "[PROGRESS OS]", "  main     events-waiting=", "  check    busy",
                     "  upgrade  OS busy", "  probe    upgrading-Q", "rebooting-Q", "  distrib  os-2.bin",
                     "[CANARY OS] all canaries passed", "[DISTRIBUTE] os os-2.bin: 9 switch(es), relay per OOB leaf"):
            self.assertIn(text, out)
        self.assertEqual(engine.exit_code(world.report), 0)

    def test_direct_mode_staggers_and_caps_without_relay(self):
        hosts = [f"s{i}" for i in range(6)]
        world = World(self, hosts, speed=10000)
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)})
        self.assertTrue(all(source == "@server" for _t, _h, (_n, source) in world.events("fetch-start")))
        self.assertIn("direct, window 1 s, cap 8", world.out.getvalue())
        self.assertIn(5, world.options.link.counts, "N = the switches in the round, the canary excluded")

    def test_a_failed_canary_blocks_the_rest(self):
        world = World(self, ["c0", "c1", "c2"])
        world.ops.verify_behaviour["c0"] = "unknown"
        results = world.run()
        self.assertEqual(results["c0"], ("UNKNOWN", "COMPONENT_VERSION_NOT_VERIFIED"))
        self.assertEqual({results["c1"][0], results["c2"][0]}, {"BLOCKED"})
        self.assertEqual([host for _t, host, _s in world.events("dispatch")], ["c0"])
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_the_in_flight_cap_holds(self):
        hosts = [f"s{i}" for i in range(6)]
        world = World(self, hosts, in_flight=2, needs={host: {"os": [["os-2.bin"]]} for host in hosts},
                      selected=("os",))
        active, peak = set(), 0
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)})
        timeline = sorted([(t, "d", host) for t, host, _s in world.events("dispatch")]
                          + [(t, "v", host) for t, host, _s in world.events("verify")])
        for _t, kind, host in timeline:
            active.add(host) if kind == "d" else active.discard(host)
            peak = max(peak, len(active))
        self.assertLessEqual(peak, 2)

    def test_precheck_classification_and_plan_only(self):
        hosts = ["ok", "gone", "pending", "sick", "done", "silent"]
        needs = {host: {"os": [["os-2.bin"]], "fw": []} for host in hosts}
        needs["done"] = {"os": [], "fw": []}
        world = World(self, hosts, needs=needs, upgrade=False)
        for host, behaviour in (("gone", "unreachable"), ("pending", "pending"), ("sick", "unhealthy"),
                                ("silent", "no-ping")):
            world.ops.precheck_behaviour[host] = behaviour
        results = world.run()
        self.assertEqual(results, {"ok": ("NOT_EXECUTED", "PLAN_ONLY"), "gone": ("SKIPPED", "UNREACHABLE_CONNECT_FAILED"),
                                   "pending": ("REVIEW_REQUIRED", "PREVIOUS_INSTALL_PENDING"),
                                   "sick": ("HEALTH_BLOCKED", None), "done": ("AT_TARGET", None),
                                   "silent": ("FAILED", "PING_UNREACHABLE")})
        self.assertEqual(world.events("fetch-start") + world.events("dispatch"), [], "plan only never writes")
        self.assertTrue(all(detail is False for _t, _h, detail in world.events("precheck")))

    def test_a_write_ahead_failure_holds_the_batch(self):
        hosts = [f"s{i}" for i in range(4)]
        world = World(self, hosts, in_flight=1, needs={host: {"os": [["os-2.bin"]]} for host in hosts},
                      selected=("os",))
        world.ops.dispatch_journal_error.add("s1")
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", None))
        self.assertEqual(results["s1"], ("FAILED", "NOT_DISPATCHED_EvidenceError"))
        self.assertEqual(world.report["hold"], "EVIDENCE_WRITE_FAILED")
        self.assertEqual(engine.exit_code(world.report), 2)
        self.assertEqual([host for _t, host, _s in world.events("dispatch")], ["s0"], "no dispatch after the hold")
        self.assertEqual({results["s2"][0], results["s3"][0]}, {"NOT_EXECUTED"})

    def test_stop_lets_in_flight_switches_finish_and_skips_the_rest(self):
        hosts = [f"s{i}" for i in range(4)]
        world = World(self, hosts, in_flight=1, needs={host: {"os": [["os-2.bin"]]} for host in hosts},
                      selected=("os",))
        original = world.ops.dispatch

        def dispatch_then_stop(device, step, **kwargs):
            result = original(device, step, **kwargs)
            if device.hostname == "s1":
                world.engine.request_stop()
            return result
        world.ops.dispatch = dispatch_then_stop
        results = world.run()
        self.assertEqual((results["s0"], results["s1"]), (("UPGRADED", None), ("UPGRADED", None)))
        self.assertEqual({results["s2"][0], results["s3"][0]}, {"NOT_EXECUTED"})
        self.assertIn("[STOP]", world.out.getvalue())

    def test_a_job_without_reboot_and_a_two_hop_route(self):
        needs = {"h0": {"os": [["os-2.bin"], ["os-3.bin"]], "fw": [["cfg.txt"]]},
                 "h1": {"os": [["os-2.bin"], ["os-3.bin"]], "fw": [["cfg.txt"]]}}
        world = World(self, ["h0", "h1"], needs=needs)
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)}, results)
        stages = [(host, stage) for _t, host, stage in world.events("dispatch")]
        self.assertEqual([stage for host, stage in stages if host == "h1"], ["os-0", "os-1", "fw-0"])
        sessions = world.out.getvalue().count("[DISTRIBUTE] os")
        self.assertEqual(sessions, 2, "each hop gets its own distribution round")
        self.assertEqual(world.ops.sims["h1"].version, "cfg")


class PasswordHoldTest(unittest.TestCase):
    """Field 2026-10-24 (v1 CPLD log): every precheck opened a password session, so one mistyped password
    meant a failed password login on each of the ~118 switches that needed an upgrade. Contract: the first
    PASSWORD_REJECTED from a precheck holds the batch; no further precheck starts (one already running
    finishes), the switches not prechecked yet are SKIPPED with PASSWORD_REJECTED_HOLD, nothing is
    transferred or dispatched, and the summary says the password was rejected and nothing was written to
    those switches. The same password is never tried on another switch afterwards."""

    def test_the_first_rejection_stops_the_remaining_prechecks(self):
        hosts = [f"p{i}" for i in range(6)]
        world = World(self, hosts, check_workers=1)
        world.ops.precheck_behaviour["p2"] = "password-rejected"
        results = world.run()
        self.assertEqual(results["p2"], ("FAILED", "PASSWORD_REJECTED"))
        for host in ("p3", "p4", "p5"):
            self.assertEqual(results[host], ("SKIPPED", "PASSWORD_REJECTED_HOLD"), host)
        self.assertEqual({results["p0"][0], results["p1"][0]}, {"NOT_EXECUTED"}, "prechecked, then held")
        self.assertEqual([host for _t, host, _d in world.events("precheck")], ["p0", "p1", "p2"],
                         "no precheck after the rejection")
        self.assertEqual(world.events("fetch-start") + world.events("dispatch"), [])
        self.assertIn("PASSWORD_REJECTED", world.report["hold"])
        self.assertEqual(engine.exit_code(world.report), 2)
        summary = engine.render_summary(world.report)
        self.assertIn("password was rejected", summary)
        self.assertIn("nothing was written", summary)

    def test_a_precheck_already_running_finishes(self):
        hosts = [f"p{i}" for i in range(5)]
        world = World(self, hosts, check_workers=2)
        world.ops.precheck_behaviour["p1"] = "password-rejected"
        original = world.ops.precheck

        def p0_still_running(device, **kwargs):
            if device.hostname == "p0":                      # p0 is in flight when p1's rejection holds the batch
                deadline = time.monotonic() + 5.0
                while not world.engine.hold and time.monotonic() < deadline:
                    time.sleep(0.01)
            return original(device, **kwargs)
        world.ops.precheck = p0_still_running
        results = world.run()
        self.assertEqual(results["p1"], ("FAILED", "PASSWORD_REJECTED"))
        self.assertEqual(results["p0"][0], "NOT_EXECUTED", "its precheck finished; the hold stops the upgrade")
        for host in ("p2", "p3", "p4"):
            self.assertEqual(results[host], ("SKIPPED", "PASSWORD_REJECTED_HOLD"), host)
        self.assertEqual(sorted(host for _t, host, _d in world.events("precheck")), ["p0", "p1"])
        self.assertEqual(world.events("fetch-start") + world.events("dispatch"), [])
        self.assertEqual(engine.exit_code(world.report), 2)

    def test_other_precheck_failures_do_not_hold(self):
        world = World(self, ["q0", "q1", "q2"], needs={host: {"os": [["os-2.bin"]]} for host in ("q0", "q1", "q2")},
                      selected=("os",), check_workers=1)
        world.ops.precheck_behaviour["q0"] = "unreachable"
        results = world.run()
        self.assertEqual(results["q0"], ("SKIPPED", "UNREACHABLE_CONNECT_FAILED"))
        self.assertEqual((results["q1"], results["q2"]), (("UPGRADED", None), ("UPGRADED", None)))
        self.assertIsNone(world.report["hold"])


class ServiceIssueTest(unittest.TestCase):
    """Owner 2026-10-24: a switch whose network has no usable HTTP address fails closed in precheck. It is
    prechecked read-only (no access bootstrap), ends FAILED with the reason when it needs an upgrade, and
    nothing is fetched or dispatched for it; one that needs nothing is still AT_TARGET."""

    def test_a_switch_without_a_service_address_is_failed_before_any_write(self):
        needs = {"s0": {"os": [["os-2.bin"]]}, "s1": {"os": []}, "s2": {"os": [["os-2.bin"]]}}
        reason = "HTTP_SERVICE_ADDRESS_NONE: s0 egress eno3"
        world = World(self, ["s0", "s1", "s2"], needs=needs, selected=("os",),
                      service_issues={"s0": reason, "s1": "HTTP_SERVICE_ADDRESS_NONE: s1 egress eno3"})
        results = world.run()
        self.assertEqual(results, {"s0": ("FAILED", reason), "s1": ("AT_TARGET", None), "s2": ("UPGRADED", None)})
        self.assertEqual({host: upgrade for _t, host, upgrade in world.events("precheck")},
                         {"s0": False, "s1": False, "s2": True}, "read-only precheck: no access bootstrap")
        self.assertEqual([host for _t, host, _d in world.events("fetch-start") + world.events("dispatch")
                          if host == "s0"], [])


class KeyRejectedSummaryTest(unittest.TestCase):
    """O3 2026-10-24 (in the operator's last v1 run 18 switches rejected the management key while needing no
    installation): the summary lists, in its own section, every switch whose management key was rejected in
    precheck. One that needs no installation keeps a rejected key (no access bootstrap runs, so an --upgrade
    run does not fix it): the summary says the key was not changed and how to add it (ssh-copy-id with the
    management public key, or a later access-repair tool). A precheck without a password to fall back to says
    the password was not tried. Report only: nothing is written for this."""

    def section(self, world, **kwargs):
        summary = engine.render_summary(world.report, **kwargs)
        self.assertIn("MANAGEMENT KEY REJECTED", summary)
        return summary.split("MANAGEMENT KEY REJECTED", 1)[1].split("elapsed ", 1)[0]

    def test_a_switch_needing_no_installation_keeps_its_rejected_key_and_the_summary_says_how_to_fix_it(self):
        needs = {"k0": {"os": []}, "k1": {"os": [["os-2.bin"]]}, "k2": {"os": []}}
        world = World(self, ["k0", "k1", "k2"], needs=needs, selected=("os",))
        world.ops.precheck_behaviour.update(k0="key-rejected", k1="key-rejected")
        results = world.run()
        self.assertEqual(results, {"k0": ("AT_TARGET", None), "k1": ("UPGRADED", None), "k2": ("AT_TARGET", None)})
        groups = {row["hostname"]: row["group"] for row in world.report["key_rejected"]}
        self.assertEqual(groups, {"k0": "NO_INSTALLATION", "k1": "OTHER"}, "k2's key worked: not listed")
        section = self.section(world, management_key="/keys/mgmt.pub", user="admin")
        self.assertIn("key was not changed", section)
        self.assertIn("ssh-copy-id -i /keys/mgmt.pub admin@198.51.100.1", section, "k0's address")
        self.assertNotIn("k2", section)
        self.assertEqual([host for _t, host, _d in world.events("dispatch") + world.events("fetch-start")
                          if host == "k0"], [], "report only: nothing is done to k0")
        self.assertEqual(engine.exit_code(world.report), 0, "a listed key does not make the run incomplete")

    def test_without_a_password_the_summary_says_it_was_not_tried(self):
        world = World(self, ["k0", "k1"], upgrade=False)
        world.ops.precheck_behaviour["k0"] = "key-refused"
        results = world.run()
        self.assertEqual(results["k0"], ("FAILED", "AUTH_REJECTED"))
        self.assertEqual([(row["hostname"], row["group"]) for row in world.report["key_rejected"]],
                         [("k0", "PASSWORD_NOT_TRIED")])
        self.assertIn("password was not tried", self.section(world))
        self.assertIsNone(world.report["hold"])


def ssh_error(code, repair_requested=False):
    """An SshError as an ops.verify raises it. `repair_requested` tells whether that attempt already
    wrote repair-requested.json; None models an ops that does not say."""
    error = SshError(code)
    if repair_requested is not None:
        error.repair_requested = repair_requested
    return error


class VerifyRetryTest(unittest.TestCase):
    """Owner 2026-10-23. On the v1 field run five switches were left UNKNOWN by one timed-out query
    during verification and were at target on the next run. Contract: a verification that fails
    with COMMAND_TIMEOUT or CHANNEL_FAILED, and whose attempt has not requested a configuration
    repair, runs once more after a 30-second pause kept by the main loop (no check worker held);
    the switch carries VERIFY_RETRIED and a second failure is UNKNOWN with the usual reason. Every
    other error and a failed judgement keep their behaviour; reboot-like errors still go back to
    the rebooting queue."""

    def world(self, **kwargs):
        return World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",), **kwargs)

    @staticmethod
    def verifies(world):
        return [t for t, host, _stage in world.events("verify") if host == "s0"]

    @staticmethod
    def row(world):
        return next(row for row in world.report["devices"] if row["hostname"] == "s0")

    @staticmethod
    def timeline(world):
        path = world.engine.evidence.directory("s0") / "timeline.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]

    def test_the_pause_is_thirty_seconds_by_default(self):
        options = engine.Options(run_id="r1", selected=("os",), upgrade=True, link=None, groups={})
        self.assertEqual(options.verify_retry_seconds, 30.0)

    def test_sixteen_check_workers_by_default_and_the_upgrade_blast_radius_unchanged(self):
        """O2 2026-10-24: prechecks and verifications are read-only SSH (v1 preflights ran 16 wide on 192
        switches); upgrade workers stay 8 and in-flight stays 32 (many spines rebooting at once is a fabric risk)."""
        options = engine.Options(run_id="r1", selected=("os",), upgrade=True, link=None, groups={})
        self.assertEqual((options.check_workers, options.upgrade_workers, options.in_flight), (16, 8, 32))

    def test_a_timed_out_verification_runs_once_more_after_the_pause_and_passes(self):
        for code in ("COMMAND_TIMEOUT", "CHANNEL_FAILED"):
            with self.subTest(code=code):
                world = self.world(verify_retry_seconds=1.0)
                world.ops.verify_errors["s0"] = [ssh_error(code)]
                samples, stop = [], threading.Event()

                def sample():
                    while not stop.is_set():
                        pool = world.engine.pools.get("check")
                        if pool is not None:
                            now = time.monotonic()
                            samples.append((now,) + tuple(pool.stats(now)[:2]))
                        time.sleep(0.02)
                sampler = threading.Thread(target=sample, daemon=True)
                sampler.start()
                try:
                    results = world.run()
                finally:
                    stop.set()
                    sampler.join()
                self.assertEqual(results["s0"], ("UPGRADED", None), world.out.getvalue())
                self.assertIn("VERIFY_RETRIED", self.row(world)["warnings"])
                verifies = self.verifies(world)
                self.assertEqual(len(verifies), 2, "the whole verification ran exactly once more")
                (failed_at, _host, _code), = world.events("verify-error")
                self.assertGreaterEqual(verifies[1] - failed_at, 1.0, "the retry waits for the pause")
                pause = [(busy, queued) for t, busy, queued in samples if failed_at + 0.2 < t < verifies[1] - 0.2]
                self.assertTrue(pause, "the check pool was sampled during the pause")
                self.assertEqual(set(pause), {(0, 0)}, "no check worker is held or queued during the pause")
                retries = [record for record in self.timeline(world) if "verify_retry" in record]
                self.assertEqual(len(retries), 1, "one timeline record per retry")
                self.assertEqual(retries[0]["verify_retry"]["reason"], code)
                self.assertEqual(engine.exit_code(world.report), 0)

    def test_a_second_failure_is_unknown_with_the_usual_reason_and_the_retry_warning(self):
        for first, second in (("COMMAND_TIMEOUT", "COMMAND_TIMEOUT"), ("COMMAND_TIMEOUT", "CHANNEL_FAILED")):
            with self.subTest(first=first, second=second):
                world = self.world(verify_retry_seconds=0.3)
                world.ops.verify_errors["s0"] = [ssh_error(first), ssh_error(second), ssh_error("COMMAND_TIMEOUT")]
                results = world.run()
                self.assertEqual(results["s0"], ("UNKNOWN", "VERIFY_" + second))
                self.assertIn("VERIFY_RETRIED", self.row(world)["warnings"])
                self.assertEqual(len(self.verifies(world)), 2, "one retry only")
                self.assertEqual(len(world.ops.verify_errors["s0"]), 1, "no third attempt")
                self.assertEqual(engine.exit_code(world.report), 3)

    def test_no_retry_once_the_attempt_requested_a_repair_or_does_not_say(self):
        for marker in (True, None):
            with self.subTest(repair_requested=marker):
                world = self.world()
                world.ops.verify_errors["s0"] = [ssh_error("COMMAND_TIMEOUT", marker)]
                results = world.run()
                self.assertEqual(results["s0"], ("UNKNOWN", "VERIFY_COMMAND_TIMEOUT"))
                self.assertNotIn("VERIFY_RETRIED", self.row(world)["warnings"])
                self.assertEqual(len(self.verifies(world)), 1)
                self.assertEqual([record for record in self.timeline(world) if "verify_retry" in record], [])

    def test_other_errors_and_a_failed_judgement_are_not_retried(self):
        for code in ("AUTH_REJECTED", "HOST_KEY_MISMATCH", "HOST_KEY_UNKNOWN", "OUTPUT_LIMIT"):
            with self.subTest(code=code):
                world = self.world()
                world.ops.verify_errors["s0"] = [ssh_error(code)]
                results = world.run()
                self.assertEqual(results["s0"], ("UNKNOWN", "VERIFY_" + code))
                self.assertNotIn("VERIFY_RETRIED", self.row(world)["warnings"])
                self.assertEqual(len(self.verifies(world)), 1)
        with self.subTest(judgement="UNKNOWN"):
            world = self.world()
            world.ops.verify_behaviour["s0"] = "unknown"
            results = world.run()
            self.assertEqual(results["s0"], ("UNKNOWN", "COMPONENT_VERSION_NOT_VERIFIED"))
            self.assertNotIn("VERIFY_RETRIED", self.row(world)["warnings"])
            self.assertEqual(len(self.verifies(world)), 1)

    def test_a_reboot_like_error_still_goes_back_to_the_rebooting_queue(self):
        for code in ("CONNECT_FAILED", "COMMAND_INCOMPLETE"):
            with self.subTest(code=code):
                world = self.world()
                world.ops.verify_errors["s0"] = [ssh_error(code)]
                results = world.run()
                self.assertEqual(results["s0"], ("UPGRADED", None))
                warnings = self.row(world)["warnings"]
                self.assertIn("VERIFY_CONNECTION_LOST", warnings)
                self.assertNotIn("VERIFY_RETRIED", warnings)
                self.assertEqual(len(self.verifies(world)), 2)
                timeline = self.timeline(world)
                requeued = [index for index, record in enumerate(timeline)
                            if record.get("requeued") == "VERIFY_CONNECTION_LOST"]
                self.assertEqual(len(requeued), 1)
                self.assertEqual(timeline[requeued[0]]["state"], "PROBING")
                self.assertIn("ladder", [record.get("probe") for record in timeline[requeued[0]:]],
                              "the rebooting queue's SSH step ran again before the second verification")
                self.assertEqual([record for record in timeline if "verify_retry" in record], [])


class ComponentIssueHoldTest(unittest.TestCase):
    """G1 (需求 R-043; 指导 8.25.1; owner 11-20 第6条): a judgement error on one firmware component holds
    only that component, like v1 (observer.py: such a component goes to component_issues, not needed, and
    the others go on). The switch keeps going through the other admission checks and upgrades the other
    components it needs, including those after the held one; at the end it is REVIEW_REQUIRED with
    `<first issue code> (partly upgraded: <components done>)`, without the brackets when nothing was done;
    exit code 3. An issue on the OS (route unavailable, final OS not reached) still holds the whole switch
    exactly as before. The family names the components whose own issue holds only themselves."""

    THREE = ("os", "bios", "cpld")

    def world(self, needs, issues, hosts=("s0",)):
        return World(self, list(hosts), components=self.THREE, held_alone=("bios", "cpld"), selected=self.THREE,
                     needs={host: needs for host in hosts}, issues={host: issues for host in hosts})

    @staticmethod
    def stages(world, host="s0"):
        return [stage for _t, name, stage in world.events("dispatch") if name == host]

    @staticmethod
    def fetched(world, host="s0"):
        return [detail[0] for _t, name, detail in world.events("fetch-start") if name == host]

    ALL = {"os": [["os-2.bin"]], "bios": [["bios.bin"]], "cpld": [["cpld.bin"]]}

    def test_a_bios_issue_holds_only_bios(self):
        world = self.world(self.ALL, (("bios", "BIOS_VERSION_CHECK_FAILED"),))
        results = world.run()
        self.assertEqual(results["s0"], ("REVIEW_REQUIRED", "BIOS_VERSION_CHECK_FAILED (partly upgraded: os, cpld)"),
                         world.out.getvalue())
        self.assertEqual(self.stages(world), ["os-0", "cpld-0"], "BIOS: nothing dispatched")
        self.assertNotIn("bios.bin", self.fetched(world), "BIOS: nothing transferred")
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_a_cpld_issue_holds_only_cpld(self):
        world = self.world(self.ALL, (("cpld", "CPLD_VERSION_CHECK_FAILED"),))
        results = world.run()
        self.assertEqual(results["s0"], ("REVIEW_REQUIRED", "CPLD_VERSION_CHECK_FAILED (partly upgraded: os, bios)"))
        self.assertEqual(self.stages(world), ["os-0", "bios-0"])
        self.assertNotIn("cpld.bin", self.fetched(world))
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_an_os_issue_still_holds_the_whole_switch(self):
        world = self.world(self.ALL, (("os", "OS_UPGRADE_PATH_REJECTED"), ("bios", "BIOS_VERSION_CHECK_FAILED")))
        results = world.run()
        self.assertEqual(results["s0"], ("REVIEW_REQUIRED", "OS_UPGRADE_PATH_REJECTED"))
        self.assertEqual(self.stages(world) + self.fetched(world), [], "nothing transferred or dispatched")
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_a_bios_issue_with_os_at_target_still_does_cpld(self):
        needs = {"os": [], "bios": [["bios.bin"]], "cpld": [["cpld.bin"]]}
        world = self.world(needs, (("bios", "BIOS_VERSION_CHECK_FAILED"),))
        results = world.run()
        self.assertEqual(results["s0"], ("REVIEW_REQUIRED", "BIOS_VERSION_CHECK_FAILED (partly upgraded: cpld)"))
        self.assertEqual(self.stages(world), ["cpld-0"])

    def test_a_held_component_with_nothing_else_to_do_has_no_brackets(self):
        needs = {"os": [], "bios": [["bios.bin"]], "cpld": []}
        world = self.world(needs, (("bios", "FIRMWARE_QUERY_FAILED"),))
        results = world.run()
        self.assertEqual(results["s0"], ("REVIEW_REQUIRED", "FIRMWARE_QUERY_FAILED"))
        self.assertEqual(self.stages(world), [])


def ssd_row(state, status, observed, basis, reason=None):
    """An SSD row as ibsw_upgrade_contract.ssd_check_from_firmware returns it (expected SSD-1.2)."""
    return dict(state=state, status=status, expected_version="SSD-1.2", observed_version=observed,
                reason_code=reason, informational_only=True, verification_basis=basis)


class SsdPrecheckTest(unittest.TestCase):
    """U8 (问题文件 §38 :2406-2431; 指导 8.25.3): the precheck SSD row of a switch whose OS is already at
    target is kept in precheck.json (key `ssd`) as an opaque informational row; it never changes admission,
    the AT_TARGET category or the exit code."""

    def test_a_precheck_row_keeps_at_target_and_goes_to_precheck_json(self):
        world = World(self, ["s0", "s1"], needs={"s0": {"os": []}, "s1": {"os": []}}, selected=("os",))
        mismatch = ssd_row("WARNING", "MISMATCH", "SSD-0.9", "PREFLIGHT_OS_AT_TARGET", "SSD_VERSION_MISMATCH")
        world.ops.ssd_rows["s0"] = mismatch
        results = world.run()
        self.assertEqual(results, {"s0": ("AT_TARGET", None), "s1": ("AT_TARGET", None)})
        self.assertEqual(engine.exit_code(world.report), 0, "informational only")
        precheck = json.loads((world.engine.evidence.directory("s0") / "precheck.json").read_text())
        self.assertIn("ssd", precheck, "precheck.json keeps the SSD row")
        self.assertEqual(precheck["ssd"], mismatch)
        other = json.loads((world.engine.evidence.directory("s1") / "precheck.json").read_text())
        self.assertIn("ssd", other)
        self.assertIsNone(other["ssd"], "a family that gives no row has none")


class SsdSummaryTest(unittest.TestCase):
    """G5 (问题文件 §40 G5, :2425; 指导 8.25.4): the summary takes per switch the last post-upgrade SSD row,
    else the U8 precheck row (one row per switch, never listed twice), counts passed/warnings, lists
    MISMATCH/UNAVAILABLE with host, observed, target and basis, and says the next step; with no SSD row at all
    (no packages.ssd.version) there is no SSD section. The exit code never changes."""

    def test_only_a_precheck_row_is_listed(self):
        world = World(self, ["s0", "s1"], needs={"s0": {"os": []}, "s1": {"os": []}}, selected=("os",))
        mismatch = ssd_row("WARNING", "MISMATCH", "SSD-0.9", "PREFLIGHT_OS_AT_TARGET", "SSD_VERSION_MISMATCH")
        world.ops.ssd_rows["s0"] = mismatch
        world.run()
        summary = engine.render_summary(world.report)
        self.assertIn("SSD (informational): passed=0 warnings=1", summary)
        self.assertEqual(world.report.get("ssd"), [dict(mismatch, hostname="s0")])
        self.assertIn("  s0  MISMATCH observed=SSD-0.9 target=SSD-1.2 basis=PREFLIGHT_OS_AT_TARGET", summary)
        self.assertIn("SSD firmware comes with the OS install; a mismatch does not change this run's result",
                      summary)
        self.assertEqual(engine.exit_code(world.report), 0)

    def test_a_post_upgrade_row_replaces_the_precheck_row(self):
        world = World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",))
        world.ops.ssd_rows["s0"] = ssd_row("WARNING", "UNAVAILABLE", None, "PREFLIGHT_OS_AT_TARGET",
                                           "SSD_VERSION_UNAVAILABLE")
        post = ssd_row("PASS", "MATCH", "SSD-1.2", "POST_UPGRADE")
        world.ops.verify_ssd["s0"] = post
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", None))
        summary = engine.render_summary(world.report)
        self.assertIn("SSD (informational): passed=1 warnings=0", summary)
        self.assertEqual(world.report.get("ssd"), [dict(post, hostname="s0")], "one row per switch: the last one")
        self.assertNotIn("UNAVAILABLE", summary)
        self.assertEqual(engine.exit_code(world.report), 0)

    def test_without_any_ssd_row_there_is_no_ssd_section(self):
        world = World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",))
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", None))
        self.assertEqual(world.report.get("ssd"), [], "the report always has the (empty) SSD list")
        self.assertNotIn("SSD", engine.render_summary(world.report))
        self.assertEqual(engine.exit_code(world.report), 0)


class PushTest(unittest.TestCase):
    """U10 (owner 11-20 第7条「1. 先检查空间大小，够放image才推送 2. 使用分布式方式在各个ib-sw之间分发image」;
    问题文件 §41; 指导 8.25.5): with method push the schedule is unchanged (a relay queue's first copy comes
    from the server, the rest from switches; small packages from the server; a verified staged copy is not
    sent again), server transfers are spaced like scp, the space check runs before any transfer with
    `NO_SPACE need=<bytes> free=<bytes>` (only with push; enough space passes, equal passes), and the summary
    counts the server pushes and the switch forwards."""

    def test_push_spaces_server_transfers_like_scp(self):
        self.assertEqual(World(self, ["s0"], method="push").engine.gate.gap, 0.25)
        self.assertEqual(World(self, ["s0"]).engine.gate.gap, 0.0, "http unchanged")

    def test_space_is_checked_before_any_transfer(self):
        hosts = ["s0", "s1", "s2"]
        world = World(self, hosts, method="push", needs={host: {"os": [["os-2.bin"]]} for host in hosts},
                      selected=("os",))
        world.family.space = 1000
        world.ops.free.update(s0=999, s1=1000, s2=4000)
        results = world.run()
        self.assertEqual(results, {"s0": ("FAILED", "NO_SPACE need=1000 free=999"), "s1": ("UPGRADED", None),
                                   "s2": ("UPGRADED", None)})
        self.assertEqual([host for _t, host, _d in world.events("fetch-start") + world.events("dispatch")
                          if host == "s0"], [], "nothing transferred to it")

    def test_without_push_the_space_reason_is_unchanged(self):
        world = World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",))
        world.family.space = 1000
        world.ops.free["s0"] = 999
        self.assertEqual(world.run()["s0"], ("FAILED", "NO_SPACE"))

    def test_a_verified_staged_copy_is_not_pushed_again(self):
        hosts = ["s0", "s1", "s2"]
        world = World(self, hosts, speed=10000, method="push", needs={host: {"os": [["os-2.bin"]]} for host in hosts},
                      selected=("os",))
        info = engine.PackageInfo.read(world.family.by_name["os-2.bin"])
        world.ops.sims["s1"].files["os-2.bin"] = (info.size, info.sha256)
        world.ops.sims["s2"].files["os-2.bin"] = (info.size, "0" * 64)
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)})
        fetched = {host for _t, host, (name, _source) in world.events("fetch-start") if name == "os-2.bin"}
        self.assertNotIn("s1", fetched, "size and sha256 match: PRE_STAGED")
        self.assertIn("s2", fetched, "a wrong sha256 is sent again")

    def test_relay_first_copies_come_from_the_server_and_the_rest_from_switches(self):
        hosts = [f"a{i}" for i in range(3)] + [f"b{i}" for i in range(3)]
        groups = {host: ("leaf-a" if host.startswith("a") else "leaf-b") for host in hosts}
        world = World(self, hosts, groups=groups, method="push")
        results = world.run()
        self.assertEqual(set(results.values()), {("UPGRADED", None)}, results)
        os_sources = {host: source for _t, host, (name, source) in world.events("fetch-start") if name == "os-2.bin"}
        for leaf in ("a", "b"):
            members = [host for host in os_sources if host.startswith(leaf) and host != "a0"]
            self.assertEqual(len([host for host in members if os_sources[host] == "@server"]), 1, os_sources)
        self.assertTrue(all(source == "@server" for _t, _h, (name, source) in world.events("fetch-start")
                            if name == "fw.bin"), "small packages: from the server")
        starts = [(host, source) for _t, host, (_name, source) in world.events("fetch-start")]
        server = len({host for host, source in starts if source == "@server"})
        forwarded = len({host for host, source in starts if source != "@server"})
        self.assertEqual((server, forwarded), (6, 3), starts)
        self.assertEqual(world.report.get("push"), dict(server=server, switches=forwarded))
        self.assertIn("[PUSH] the server pushed to 6 switch(es); switches forwarded to 3 switch(es)",
                      engine.render_summary(world.report))


class HealthRecheckTest(unittest.TestCase):
    """G7 (R-046; OWNER-DECISIONS 第20条; 指导 8.25.8 with review F07/F18): a verification whose health
    record reads `status N/A` comes back as HEALTH_PENDING; the engine re-submits the verification as a
    main-loop timer every 15 s (no worker waits), from the first N/A for at most 2 minutes, writing
    health-wait-<n>.json for each N/A answer; a later answer is judged as usual; still N/A at the end is
    UNKNOWN with the original HEALTH_STATUS_UNAVAILABLE. Other health results are never re-checked."""

    def world(self, **kwargs):
        return World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",), **kwargs)

    @staticmethod
    def verifies(world):
        return [t for t, host, _stage in world.events("verify") if host == "s0"]

    @staticmethod
    def waits(world):
        return sorted(path.name for path in world.engine.evidence.directory("s0").glob("health-wait-*.json"))

    def test_the_defaults_are_fifteen_seconds_and_two_minutes(self):
        options = engine.Options(run_id="r1", selected=("os",), upgrade=True, link=None, groups={})
        self.assertEqual((options.health_recheck_seconds, options.health_wait_seconds), (15.0, 120.0))

    def test_an_na_health_is_checked_again_and_then_judged(self):
        world = self.world(health_recheck_seconds=0.2, health_wait_seconds=2.0)
        world.ops.health_pending["s0"] = 1
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", None), world.out.getvalue())
        verifies = self.verifies(world)
        self.assertEqual(len(verifies), 2)
        self.assertGreaterEqual(verifies[1] - verifies[0], 0.2, "the recheck waits for its interval")
        self.assertEqual(self.waits(world), ["health-wait-1.json"], "one record per N/A answer")
        record = json.loads((world.engine.evidence.directory("s0") / "health-wait-1.json").read_text())
        self.assertEqual(record["reason"], "HEALTH_STATUS_UNAVAILABLE")
        self.assertEqual(record.get("health"), dict(command="health", stdout_base64="c3RhdHVzIE4vQQo="),
                         "R-046: each answer's health output is kept as the family gave it")
        self.assertEqual(record.get("n"), 1)

    def test_a_health_still_na_at_the_end_of_the_window_is_unknown(self):
        world = self.world(health_recheck_seconds=0.1, health_wait_seconds=0.5)
        world.ops.health_pending["s0"] = 1000
        results = world.run()
        self.assertEqual(results["s0"], ("UNKNOWN", "HEALTH_STATUS_UNAVAILABLE"))
        verifies = self.verifies(world)
        self.assertGreaterEqual(verifies[-1] - verifies[0], 0.5, "the window counts from the first N/A")
        self.assertLessEqual(len(verifies), 0.5 / 0.1 + 2, "bounded")
        self.assertEqual(len(self.waits(world)), len(verifies), "one evidence record per recheck answer")
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_other_health_results_are_not_rechecked(self):
        world = self.world(health_recheck_seconds=0.1, health_wait_seconds=1.0)
        world.ops.verify_behaviour["s0"] = "degraded"
        results = world.run()
        self.assertEqual(results["s0"], ("UNKNOWN", "HEALTH_DEGRADED"))
        self.assertEqual(len(self.verifies(world)), 1)
        self.assertEqual(self.waits(world), [])


class InterruptedRunRecheckTest(unittest.TestCase):
    """G9 (R-049; 04 Q-097; OWNER-DECISIONS 第22条; 指导 8.25.9 with review F02/F04/F05/F06): a switch already
    at target whose latest other --upgrade run (the newest run directory in this project's v2 evidence that
    wrote its dispatch.json; plan runs and runs that failed in precheck have none) ended without a final
    result (UNKNOWN, or a dispatch.json without any result) gets the post-upgrade verification in an
    --upgrade run instead of AT_TARGET, from that run's evidence (dispatch.json, before-<stage>.commands,
    access backup), read only; missing evidence is REVIEW_REQUIRED naming it. --plan only lists it. A
    verified switch is UPGRADED with the source run named. Earlier evidence is never written."""

    PREV = "20261101_000000Z_upgrade-v2_prev"

    def world(self, **kwargs):
        return World(self, ["s0"], needs={"s0": {"os": []}}, versions={"s0": "2.0"}, selected=("os",), **kwargs)

    def previous(self, world, name=PREV, *, category="UNKNOWN", dispatch=True, before=True, backup=True,
                 report=False):
        run = world.engine.evidence.root.parent / name
        device = run / "devices" / "s0"
        device.mkdir(parents=True)
        (run / "plan.json").write_text("{}\n")
        if dispatch:
            (device / "dispatch.json").write_text(json.dumps(dict(
                state="REQUESTED", component="os", stage="os-0", target_version="2.0", remote_dir="/home/admin/.ibsw-x",
                boot_before="b0", script_sha256="0" * 64)))
        if before:
            (device / "before-os-0.commands").write_bytes(b"nv set system hostname s0\n")
        if backup:
            (device / "access-backup.json").write_text("{}\n")
        events = [dict(host="s0", state="DISPATCHING", t=1.0)]
        if category:
            events.append(dict(host="s0", state="DONE", category=category, reason="VERIFY_COMMAND_TIMEOUT", t=2.0))
        (run / "events.jsonl").write_text("".join(json.dumps(item) + "\n" for item in events))
        if report:
            (run / "run-report.json").write_text(json.dumps(dict(devices=[dict(hostname="s0", category=report)])))
        return run

    def snapshot(self, run):
        return {path: path.read_bytes() for path in sorted(run.rglob("*")) if path.is_file()}

    def verifies(self, world):
        return [stage for _t, host, stage in world.events("verify") if host == "s0"]

    def test_an_unknown_previous_result_is_verified_again_and_reported_upgraded(self):
        world = self.world()
        run = self.previous(world)
        before = self.snapshot(run)
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", f"RECHECKED_AFTER_INTERRUPTION run={self.PREV}"),
                         world.out.getvalue())
        self.assertEqual(self.verifies(world), ["os-0"])
        self.assertEqual(world.events("dispatch") + world.events("fetch-start"), [], "nothing installed again")
        self.assertEqual(self.snapshot(run), before, "earlier evidence is read only")
        self.assertEqual(engine.exit_code(world.report), 0)

    def test_a_dispatch_without_any_result_is_verified_again(self):
        world = self.world()
        self.previous(world, category=None)
        self.assertEqual(world.run()["s0"][0], "UPGRADED")
        self.assertEqual(self.verifies(world), ["os-0"])

    def test_plan_only_lists_it(self):
        world = self.world(upgrade=False)
        self.previous(world)
        results = world.run()
        self.assertEqual(results["s0"], ("NOT_EXECUTED", f"RECHECK_NEEDED: last run {self.PREV} has no final result"))
        self.assertEqual(self.verifies(world), [])

    def test_a_previous_final_result_or_no_previous_run_keeps_at_target(self):
        for case in ("conclusive", "report", "none"):
            with self.subTest(case=case):
                world = self.world()
                if case == "conclusive":
                    self.previous(world, category="FAILED")
                elif case == "report":
                    self.previous(world, category=None, report="UPGRADED")
                self.assertEqual(world.run()["s0"], ("AT_TARGET", None))
                self.assertEqual(self.verifies(world), [])

    def test_plan_and_precheck_failed_runs_in_between_are_skipped(self):
        world = self.world()
        self.previous(world)
        self.previous(world, "20261102_000000Z_upgrade-v2_plan", category=None, dispatch=False)
        self.previous(world, "20261103_000000Z_upgrade-v2_failed", category="FAILED", dispatch=False)
        self.assertEqual(world.run()["s0"], ("UPGRADED", f"RECHECKED_AFTER_INTERRUPTION run={self.PREV}"))

    def test_missing_earlier_evidence_is_review_required(self):
        for missing, reason in (("before", "RECHECK_EVIDENCE_MISSING: before-os-0.commands"),
                                ("backup", "RECHECK_EVIDENCE_MISSING: access backup")):
            with self.subTest(missing=missing):
                world = self.world()
                self.previous(world, **{missing: False})
                self.assertEqual(world.run()["s0"], ("REVIEW_REQUIRED", reason))
                self.assertEqual(self.verifies(world), [])


class PerformedAtTargetVersionTest(unittest.TestCase):
    """G7 / 04 Q-113 (owner 2026-11-26 12:1x「只要版本确实是目标版本就是已执行，至于健康检查有问题就如实返回即
    可」): a step whose post-upgrade read-back shows exactly its target version is recorded in `performed` with
    its verdict even when the verification ends UNKNOWN (e.g. health still N/A after the 2-minute recheck);
    a version that cannot be read or differs from the target is not. Category, reason and exit code are
    unchanged; a VERIFIED step is recorded exactly as before."""

    def world(self):
        return World(self, ["s0"], needs={"s0": {"os": [["os-2.bin"]]}}, selected=("os",),
                     health_recheck_seconds=0.1, health_wait_seconds=0.3)

    @staticmethod
    def row(world):
        return next(row for row in world.report["devices"] if row["hostname"] == "s0")

    def test_the_target_version_with_a_health_still_na_is_unknown_and_performed(self):
        world = self.world()
        world.ops.health_pending["s0"] = 1000
        world.ops.verify_version["s0"] = True
        results = world.run()
        self.assertEqual(results["s0"], ("UNKNOWN", "HEALTH_STATUS_UNAVAILABLE"), "health is reported as it is")
        performed = self.row(world)["performed"]
        self.assertEqual([(item["component"], item["stage"], item["target"], item.get("verdict"), item.get("reason"))
                          for item in performed],
                         [("os", "os-0", "2.0", "UNKNOWN", "HEALTH_STATUS_UNAVAILABLE")])
        self.assertEqual(engine.exit_code(world.report), 3)

    def test_an_unreadable_or_different_version_is_not_performed(self):
        for value in (None, False):
            with self.subTest(version_at_target=value):
                world = self.world()
                world.ops.verify_behaviour["s0"] = "unknown"
                world.ops.verify_version["s0"] = value
                results = world.run()
                self.assertEqual(results["s0"], ("UNKNOWN", "COMPONENT_VERSION_NOT_VERIFIED"))
                self.assertEqual(self.row(world)["performed"], [])

    def test_a_verified_step_is_recorded_as_before(self):
        world = self.world()
        results = world.run()
        self.assertEqual(results["s0"], ("UPGRADED", None))
        self.assertEqual(self.row(world)["performed"], [dict(component="os", stage="os-0", target="2.0", warnings=[])])


class PostReadySettleTest(unittest.TestCase):
    """R-024 / U2 (owner 2026-11-14, 问题文件 10.1; 需求 R-024; 指导 8.12): after a real reboot's READY
    hand-back the engine waits a fixed 30 s as a main-loop timer and only then submits verification; the
    original device deadline (dispatched_at + Timings.deadline, never reset) is checked before the wait and
    when it ends, with the original DEVICE_DEADLINE_EXCEEDED / UNKNOWN. A job that finished without a reboot
    and the single verification retry on the same boot do not wait. Engine-injected clock with the production
    default timings; nothing sleeps."""

    SETTLE = 30.0      # R-024 「固定等待 30 秒」
    DEADLINE = 3600.0  # original Timings().deadline, unchanged by R-024

    def setUp(self):
        self.now = 1000.0
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        devices = [Device("s0", "198.51.100.1"), Device("s1", "198.51.100.2")]
        options = engine.Options(run_id="r1", selected=("os",), upgrade=True,
                                 link=link.decide(1000, source="override"), groups={}, verify_retry_seconds=5.0)
        self.engine = engine.Engine(devices, FakeFamily({}), FakeOps(devices), options,
                                    engine.Evidence(Path(tmp.name) / "run"), out=io.StringIO(),
                                    clock=lambda: self.now)
        self.submitted = []
        self.engine._submit = lambda pool, dev, kind, function, **info: self.submitted.append((dev.host, kind, self.now))
        for dev in self.engine.devs.values():
            dev.state, dev.step = "PROBING", Step("os", "os-0", "2.0")
            dev.dispatch = dict(dispatched_at=1000.0, before_commands=b"", health_record=None, boot_before="b0")

    def ready(self, host="s0", reason="READY", boot="b1"):
        self.engine._on_handback(self.engine.devs[host],
                                 probe.Handback(host, probe.READY, reason, boot_id=boot, version="2.0"))

    def tick(self, now):
        self.now = now
        self.engine._run_timers(now)

    def verifies(self, host="s0"):
        return [t for name, kind, t in self.submitted if kind == "verify" and name == host]

    def test_ready_waits_thirty_seconds_then_verifies_once(self):
        self.now = 1100.0
        self.ready()
        self.assertEqual(self.verifies(), [], "no verification right at READY")
        self.assertEqual(self.engine.devs["s0"].state, "VERIFYING", "the switch keeps its in-flight slot")
        self.tick(1100.0 + self.SETTLE - 0.001)
        self.assertEqual(self.verifies(), [])
        self.tick(1100.0 + self.SETTLE)
        self.assertEqual(self.verifies(), [1100.0 + self.SETTLE])
        self.tick(1300.0)
        self.assertEqual(self.verifies(), [1100.0 + self.SETTLE], "one verification per READY")
        self.assertEqual(self.engine.devs["s0"].dispatch["dispatched_at"], 1000.0, "dispatch start never reset")

    def test_the_wait_ending_after_the_original_deadline_is_unknown_without_verification(self):
        self.now = 1000.0 + self.DEADLINE - 10.0
        self.ready()
        self.tick(self.now + self.SETTLE)
        dev = self.engine.devs["s0"]
        self.assertEqual((dev.category, dev.reason), ("UNKNOWN", "DEVICE_DEADLINE_EXCEEDED"))
        self.assertEqual(self.verifies(), [])

    def test_ready_after_the_original_deadline_is_unknown_at_once(self):
        self.now = 1000.0 + self.DEADLINE + 1.0
        self.ready()
        dev = self.engine.devs["s0"]
        self.assertEqual((dev.category, dev.reason), ("UNKNOWN", "DEVICE_DEADLINE_EXCEEDED"))
        self.tick(self.now + 2 * self.SETTLE)
        self.assertEqual(self.verifies(), [])

    def test_a_wait_ending_exactly_at_the_deadline_still_verifies(self):
        # The original tracker fails a switch only when now - dispatched_at > deadline.
        self.now = 1000.0 + self.DEADLINE - self.SETTLE
        self.ready()
        self.tick(1000.0 + self.DEADLINE)
        self.assertEqual(self.verifies(), [1000.0 + self.DEADLINE])
        self.assertIsNone(self.engine.devs["s0"].category)

    def test_a_job_that_finished_without_a_reboot_verifies_at_once(self):
        self.now = 1100.0
        self.ready(reason="COMPLETED_WITHOUT_REBOOT", boot="b0")
        self.assertEqual(self.verifies(), [1100.0])

    def test_the_verification_retry_on_the_same_boot_does_not_wait_again(self):
        self.now = 1100.0
        self.ready()
        self.tick(1130.0)
        self.now = 1131.0
        self.engine._retry_verify(self.engine.devs["s0"], "COMMAND_TIMEOUT")
        self.tick(1136.0)
        self.assertEqual(self.verifies(), [1130.0, 1136.0], "the retry uses only its own 5 s pause")

    def test_a_new_boot_after_a_requeue_waits_again(self):
        self.now = 1100.0
        self.ready()
        self.tick(1130.0)
        self.now = 1140.0
        self.engine._requeue(self.engine.devs["s0"], "BOOT_CHANGED_DURING_VERIFY")
        self.engine.tracker.drop("s0")
        self.now = 1150.0
        self.ready(boot="b2")
        self.tick(1179.0)
        self.assertEqual(self.verifies(), [1130.0])
        self.tick(1180.0)
        self.assertEqual(self.verifies(), [1130.0, 1180.0])

    def test_a_switch_already_settled_is_not_verified_when_its_wait_ends(self):
        self.now = 1100.0
        self.ready()
        dev = self.engine.devs["s0"]
        dev.category, dev.reason = "UNKNOWN", "ABORTED_WHILE_UPGRADING"
        self.tick(1130.0)
        self.assertEqual(self.verifies(), [])

    def test_switches_wait_independently(self):
        self.now = 1100.0
        self.ready("s0")
        self.now = 1110.0
        self.ready("s1")
        self.tick(1130.0)
        self.assertEqual((self.verifies("s0"), self.verifies("s1")), ([1130.0], []))
        self.tick(1140.0)
        self.assertEqual(self.verifies("s1"), [1140.0])


if __name__ == "__main__":
    unittest.main()
