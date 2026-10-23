"""Fleet engine (IB upgrade v2; reusable for nvl-sw): the main loop with a simulated fleet.

A family-neutral fake family (components "os" and "fw") and simulated switches that
install, go down, come back with a new boot and get nvued ready on real (shortened)
time. Checks the owner's flow (2026-10-23) and review 15.x: canaries first; relay inside
each OOB leaf with one server pull per queue and no holder rebooting while it serves;
small packages pulled directly; in-flight cap; precheck classification; plan-only does
not touch switches; stop, write-ahead failure, a job without reboot, multi-hop; the
progress block showing every queue; and the single verification retry after a timed-out
query (owner 2026-10-23).
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
                     dwell=5.0, ladder_budget=3.0, deadline=10.0, config_check=0.05)


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

    def __init__(self, packages):
        self.by_name = packages

    def packages(self, selected):
        return [package for package in self.by_name.values()]

    def steps(self, plan, component, infos):
        return [engine.StepPlan(component, index, tuple(infos[self.by_name[name].path] for name in names),
                                self.by_name[names[0]].version)
                for index, names in enumerate(plan.needed_steps.get(component, ()))]

    def canaries(self, component, members):
        return [members[0][0]]

    def render(self, device, step_plan, *, run_id, switch_dir):
        effect = "NONE" if step_plan.component == "fw" and step_plan.target_version == "cfg" else "REBOOT_EXPECTED"
        return Step(step_plan.component, f"{step_plan.component}-{step_plan.package_index}", step_plan.target_version,
                    effect)

    def relay(self, component):
        return component == "os"


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
        self.verify_errors = {}               # host -> [exception], one raised per verify call
        self.dispatch_journal_error = set()
        self.plans = {}

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
        sim = self.sims[device.hostname]
        plan = self.plans[device.hostname]
        guard = ("PREVIOUS_INSTALL_PENDING", ".ibsw-x") if behaviour == "pending" else (None, None)
        return dict(facts=Facts(sim.version, sim.boot, dict(sim.files)), plan=plan,
                    health=dict(observed="PASS", reason=None, admitted=behaviour != "unhealthy"),
                    guard=guard, backup=object() if upgrade else None, key_rejected=False)

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
        if self.verify_behaviour.get(device.hostname) == "unknown":
            return dict(state="UNKNOWN", reason="COMPONENT_VERSION_NOT_VERIFIED")
        sim = self._refresh(self.sims[device.hostname])
        if sim.version != step.target_version:
            return dict(state="UNKNOWN", reason="COMPONENT_VERSION_NOT_VERIFIED")
        return dict(state="VERIFIED", os_version=sim.version, repaired=False)


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
                 upgrade=True, selected=("os", "fw"), verify_retry_seconds=None, **ops):
        self.tmp = tempfile.TemporaryDirectory()
        test.addCleanup(self.tmp.cleanup)
        base = Path(self.tmp.name)
        packages = {}
        for name, version in (("os-2.bin", "2.0"), ("os-3.bin", "3.0"), ("fw.bin", "fw2"), ("cfg.txt", "cfg")):
            path = base / name
            path.write_bytes(name.encode() * 100)
            packages[name] = Package(name, str(path), "http://192.0.2.10/" + name, version)
        self.family = FakeFamily(packages)
        self.devices = [Device(host, f"198.51.100.{index + 1}") for index, host in enumerate(hosts)]
        self.ops = FakeOps(self.devices, versions=versions, **ops)
        for device in self.devices:
            self.ops.plans[device.hostname] = Plan(dict((needs or {}).get(device.hostname,
                                                                          {"os": [["os-2.bin"]], "fw": [["fw.bin"]]})))
        base_decision = link.decide(speed, source="override")
        decision = QuickLink(**{name: getattr(base_decision, name) for name in base_decision.__dataclass_fields__})
        self.out = io.StringIO()
        self.options = engine.Options(run_id="r1", selected=selected, upgrade=upgrade, link=decision,
                                      groups=groups or {}, in_flight=in_flight, timings=FAST,
                                      progress_seconds=0.2, later_hop_batch_seconds=0.05,
                                      **({} if verify_retry_seconds is None
                                         else {"verify_retry_seconds": verify_retry_seconds}))
        self.engine = engine.Engine(self.devices, self.family, self.ops, self.options,
                                    engine.Evidence(base / "run"), out=self.out)

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


if __name__ == "__main__":
    unittest.main()
