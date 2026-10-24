"""Main process for switch fleet jobs (owner 2026-10-23; design: ibsw-upgrade-v2 DESIGN.md).

Family-neutral: a Family adapter supplies the components and their order, the packages,
the steps, canary choice and step rendering, and an ops object acts on one switch (IB
today: ibsw_v2_device.IbFamily / LiveOps; nvl-sw can bring its own adapter).

One event loop owns every decision; worker pools only run I/O on one switch at a time:
check workers (precheck, verification first), one upgrade pool per component, probe
workers (ping/TCP/SSH) and package transfers. A switch belongs to exactly one actor at a
time, so its evidence directory has one writer and no cross-switch lock exists.

Per component in the family's order (IB: os -> bios -> cpld, like v1): canaries first,
one at a time, through every hop; packages are distributed in parallel with the canaries
(relay per OOB leaf below 10G for the components the family relays, otherwise direct
pulls from the ztp-server); a staged switch upgrades
once the canaries passed and an in-flight slot is free; after the upgrade script starts
the probe takes over; READY goes to a check worker for verification. Budgets count switch
time only; time spent queued here is recorded, never charged.

A verification that loses a query to COMMAND_TIMEOUT or CHANNEL_FAILED runs once more per
step after `verify_retry_seconds`, kept as a main-loop timer (no worker waits), but only when
the ops said that attempt had not requested a configuration repair: ops.verify sets
`repair_requested` on the SshError it raises, and an error without it is not retried.

A switch named in `service_issues` (e.g. no HTTP address on its network, owner 2026-10-24)
is prechecked read-only (no access bootstrap) and, when it needs an upgrade, ends FAILED
with that reason before anything is written to it.

A precheck that raises SshError PASSWORD_REJECTED holds the batch (field 2026-10-24): no
precheck starts after it (one already running finishes), the switches not prechecked yet
are SKIPPED with PASSWORD_REJECTED_HOLD and nothing is written to them; the engine never
retries the password, and no switch prechecked after the refusal is offered it.
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
import hashlib
import heapq
import itertools
import json
import os
from pathlib import Path
import queue
import resource
import sys
import threading
import time

import fleet_distribution as dist
import fleet_probe as probe
from fleet_ssh import SshError

CATEGORIES = (
    ("UPGRADED", "Upgraded and verified"),
    ("AT_TARGET", "Already at target / not flashed"),
    ("FAILED", "Failed before anything was installed (safe to rerun)"),
    ("UNKNOWN", "Unknown / manual verification required"),
    ("REVIEW_REQUIRED", "Needs review before any upgrade"),
    ("BLOCKED", "Blocked by a component canary / earlier failure"),
    ("HEALTH_BLOCKED", "Pre-upgrade health check blocked (installer was not dispatched)"),
    ("SKIPPED", "Precheck could not reach or identify the switch"),
    ("NOT_EXECUTED", "Not executed (stopped or planned only)"),
)
IN_FLIGHT_STATES = {"DISPATCHING", "PROBING", "VERIFYING"}
WAITING_STATES = {"READY", "NEED_STAGE", "STAGING", "STAGED", "WAIT_SLOT"}
VERIFY_RETRY_CODES = {"COMMAND_TIMEOUT", "CHANNEL_FAILED"}   # one slow query, not a reboot (owner 2026-10-23)
PASSWORD_HOLD = "PASSWORD_REJECTED_HOLD"                     # not prechecked after a refused password (2026-10-24)
_PRECHECK_HELD = object()                                    # a precheck task that did not start


@dataclass(frozen=True)
class Options:
    run_id: str
    selected: tuple
    upgrade: bool
    link: object                       # fleet_link.LinkDecision
    groups: dict                       # hostname -> OOB leaf
    skip_canary: bool = False
    check_workers: int = 16           # read-only SSH (2026-10-24); upgrade workers and in-flight stay
    upgrade_workers: int = 8
    in_flight: int = 32
    probe_workers: int = 16
    relay_fanout: int = 4
    relay_transfers: int = 32
    method: str = "http"
    timings: probe.Timings = probe.Timings()
    progress_seconds: float = 30.0
    later_hop_batch_seconds: float = 60.0
    stall_fraction: float = 2 / 3
    verify_retry_seconds: float = 30.0
    password_given: bool | None = None   # a switch password was typed; None: assume one exactly when upgrading


@dataclass(frozen=True)
class PackageInfo:
    file: str
    path: str
    url: str | None
    size: int
    sha256: str
    identity: tuple

    @classmethod
    def read(cls, package):
        item = os.stat(package.path)
        digest = hashlib.sha256()
        with open(package.path, "rb") as handle:
            for block in iter(lambda: handle.read(4 * 1024 * 1024), b""):
                digest.update(block)
        return cls(package.file, package.path, package.url, item.st_size, digest.hexdigest(), _identity(item))

    def unchanged(self):
        try:
            return _identity(os.stat(self.path)) == self.identity
        except OSError:
            return False


def _identity(item):
    return (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)


@dataclass
class Event:
    kind: str
    host: str
    result: object = None
    error: BaseException | None = None
    info: dict = field(default_factory=dict)
    waited: float = 0.0
    seconds: float = 0.0


class Pool:
    """Fixed threads over a priority queue; results go to the main event queue."""

    def __init__(self, name, size, events):
        self.name, self.size, self.events = name, size, events
        self.tasks = queue.PriorityQueue()
        self.counter = itertools.count()
        self.lock = threading.Lock()
        self.busy, self.pending = 0, {}
        self.threads = [threading.Thread(target=self._work, name=f"ibsw-v2-{name}-{index}", daemon=True)
                        for index in range(size)]
        for thread in self.threads:
            thread.start()

    def submit(self, host, kind, function, *, priority=1, **info):
        sequence = next(self.counter)
        with self.lock:
            self.pending[sequence] = time.monotonic()
        self.tasks.put((priority, sequence, host, kind, function, info))

    def _work(self):
        while True:
            priority, sequence, host, kind, function, info = self.tasks.get()
            if function is None:
                return
            with self.lock:
                queued = self.pending.pop(sequence, time.monotonic())
                self.busy += 1
            started = time.monotonic()
            result, error = None, None
            try:
                result = function()
            except BaseException as caught:          # reported, never lost
                error = caught
            finally:
                with self.lock:
                    self.busy -= 1
            self.events.put(Event(kind, host, result, error, info, started - queued, time.monotonic() - started))

    def stats(self, now):
        with self.lock:
            waits = list(self.pending.values())
            return self.busy, len(waits), (max(now - value for value in waits) if waits else 0.0)

    def close(self):
        for _ in self.threads:
            self.tasks.put((99, next(self.counter), "", "stop", None, {}))


class Hold(Exception):
    """The whole batch stops before any further transfer or upgrade."""


class Family:
    """What a switch family supplies to the engine (IB: ibsw_v2_device.IbFamily)."""
    name = "switch"
    components = ()                    # in upgrade order
    required_programs = ()             # missing on a switch -> FAILED CAPABILITY_MISSING

    def packages(self, selected):      # objects with .file, .path, .url
        raise NotImplementedError

    def steps(self, plan, component, infos):   # [StepPlan] this switch needs for component
        raise NotImplementedError

    def canaries(self, component, members):    # members: [(hostname, plan)] -> [hostname]
        raise NotImplementedError

    def render(self, device, step_plan, *, run_id, switch_dir):   # -> step with .component .stage .effect
        raise NotImplementedError

    def relay(self, component):        # True: large image, relay below 10G and stagger at 10G+
        return False

    def space_needed(self, plan, infos):
        return 0


class EvidenceError(Exception):
    """A durable evidence write failed; the batch must stop (no write-ahead record, no dispatch)."""


class Evidence:
    """Run directory: run-level files by the main loop, one directory per switch."""

    def __init__(self, root):
        self.root = Path(root)
        self.root.mkdir(mode=0o700, parents=True, exist_ok=False)
        self.locks, self.guard = {}, threading.Lock()

    def _lock(self, host):
        with self.guard:
            return self.locks.setdefault(host, threading.Lock())

    def directory(self, host):
        path = self.root / "devices" / host
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        return path

    @staticmethod
    def _write(path, payload):
        data = payload if isinstance(payload, bytes) else (json.dumps(payload, indent=2, sort_keys=True, default=str)
                                                           + "\n").encode("utf-8")
        temporary = path.with_name("." + path.name + ".tmp")
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, data)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def journal(self, host):
        def write(name, payload):
            try:
                with self._lock(host):
                    self._write(self.directory(host) / name, payload)
            except OSError as error:
                raise EvidenceError(f"{host}/{name}: {error.strerror}") from None
        return write

    def timeline(self, host, record):
        with self._lock(host):
            with open(self.directory(host) / "timeline.jsonl", "a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")

    def write(self, name, payload):
        self._write(self.root / name, payload)

    def event(self, record):
        with open(self.root / "events.jsonl", "a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True, default=str) + "\n")


@dataclass
class StepPlan:
    component: str
    package_index: int
    packages: tuple                    # PackageInfo, in fetch order
    target_version: str

    @property
    def key(self):
        return (self.component,) + tuple(package.path for package in self.packages)


@dataclass
class Dev:
    device: object
    order: int
    state: str = "NEW"
    category: str | None = None
    reason: str | None = None
    warnings: list = field(default_factory=list)
    plan: object = None
    facts: object = None
    backup: object = None
    health: dict | None = None
    canary: bool = False
    steps: list = field(default_factory=list)
    step_index: int = 0
    step: object = None                # ibsw_v2_device.Step being installed
    dispatch: dict | None = None
    boot_after: str | None = None
    performed: list = field(default_factory=list)
    completed: set = field(default_factory=set)
    holds_slot: bool = False
    verify_retried: bool = False       # this step already used its one verification retry
    need_since: float | None = None
    state_since: float = 0.0
    session: object = None
    key_rejected: bool = False         # the management key was rejected in precheck (O3 2026-10-24)
    password_not_tried: bool = False   # ... and no password was there to fall back to

    @property
    def host(self):
        return self.device.hostname

    @property
    def current(self):
        return self.steps[self.step_index] if self.step_index < len(self.steps) else None


class Session:
    """One distribution round for one package set (relay or direct)."""

    def __init__(self, key, members, scheduler, relay):
        self.key, self.members, self.scheduler, self.relay = key, list(members), scheduler, relay


class Engine:
    def __init__(self, devices, family, ops, options, evidence, *, out=sys.stderr, clock=time.monotonic,
                 blocked_inputs=(), service_issues=None):
        self.family, self.ops, self.options, self.evidence = family, ops, options, evidence
        self.out, self.clock = out, clock
        self.devs = {device.hostname: Dev(device, index) for index, device in enumerate(devices)}
        self.blocked_inputs = tuple(blocked_inputs)
        self.service_issues = dict(service_issues or {})    # hostname -> reason: read-only precheck, then FAILED
        self.events = queue.Queue()
        self.tracker = probe.ProbeTracker(options.timings)
        self.packages, self.sessions, self.canary_queue = {}, [], []
        self.phase, self.hold, self.stopping, self.aborted = "precheck", None, False, False
        self.phase_blocked, self.canaries_passed = False, True
        self.password_held = threading.Event()     # set by the check worker that saw PASSWORD_REJECTED
        self.password_rejected_by = []
        self.started = self.clock()
        self.last_progress = self.started
        self.outstanding = 0
        self.timers, self.timer_order = [], itertools.count()   # heap of (due, order, action), main loop only
        mode = options.link.mode
        speed = options.link.speed_mbps
        server_cap = (options.link.cap if mode == "direct" else max(1, (speed or 1000) // 1000))
        self.gate = dist.ServerGate(cap=server_cap, gap=0.25 if options.method == "scp" else 0.0)
        self.pools = {}

    # ------------------------------------------------------------ helpers
    def say(self, text):
        print(text, file=self.out, flush=True)

    def _set(self, dev, state, **extra):
        now = self.clock()
        dev.state, dev.state_since = state, now
        record = dict(t=round(now - self.started, 3), state=state, **extra)
        self.evidence.timeline(dev.host, record)
        self.evidence.event(dict(record, host=dev.host))

    def _final(self, dev, category, reason=None, *, keep_slot=False):
        dev.category, dev.reason = category, reason or dev.reason
        dev.holds_slot = keep_slot
        self._set(dev, "DONE", category=category, reason=reason)

    def _submit(self, pool, dev, kind, function, *, priority=1, **info):
        self.outstanding += 1
        self.pools[pool].submit(dev.host if dev else "", kind, function, priority=priority, **info)

    def _later(self, delay, action):
        """Run action() in the main loop once delay seconds have passed."""
        heapq.heappush(self.timers, (self.clock() + delay, next(self.timer_order), action))

    def _run_timers(self, now):
        while self.timers and self.timers[0][0] <= now:
            _due, _order, action = heapq.heappop(self.timers)
            action()

    def _password_given(self):
        given = self.options.password_given
        return self.options.upgrade if given is None else given

    def _in_flight(self):
        return sum(1 for dev in self.devs.values() if dev.state in IN_FLIGHT_STATES or dev.holds_slot)

    def request_stop(self):
        """First Ctrl-C: no new transfers or dispatches; in-flight switches are still followed."""
        if not self.stopping:
            self.stopping = True
            self.say("[STOP] no new transfers or upgrades; following the switches already upgrading "
                     "(press Ctrl-C again to leave them UNKNOWN and exit)")

    # ------------------------------------------------------------ run
    def run(self, *, plan_only=False):
        self._raise_fd_limit()
        self.pools = {"check": Pool("check", self.options.check_workers, self.events),
                      "probe": Pool("probe", self.options.probe_workers, self.events),
                      "transfer": Pool("transfer", max(self.options.relay_transfers, self.gate.cap or 0, 4), self.events)}
        for component in self.family.components:
            self.pools[component] = Pool(component, self.options.upgrade_workers, self.events)
        try:
            self._load_packages()
            for dev in self.devs.values():
                self._set(dev, "PRECHECKING")
                self._submit("check", dev, "precheck", self._precheck_task(dev), priority=2)
            self._pump(lambda: self.outstanding == 0)
            self._print_progress(force=True)
            if plan_only or not self.options.upgrade:
                for dev in self.devs.values():
                    if dev.category is None:
                        dev.category, dev.reason = "NOT_EXECUTED", "PLAN_ONLY"
                return self._summary()
            for component in self.family.components:
                if component in self.options.selected:
                    self._run_phase(component)
            for dev in self.devs.values():
                if dev.category is None:
                    remaining = [component for component in dev.plan.needed
                                 if component in self.options.selected and component not in dev.completed]
                    if remaining:
                        dev.category = "NOT_EXECUTED"
                        dev.reason = (self.hold or ("STOPPED" if self.stopping else "NOT_REACHED")) + \
                            ": " + ",".join(remaining) + (" (partly upgraded)" if dev.performed else "")
                    else:
                        dev.category = "UPGRADED" if dev.performed else "AT_TARGET"
            return self._summary()
        except KeyboardInterrupt:
            self.aborted = True
            for dev in self.devs.values():
                if dev.category is None:
                    if dev.state in IN_FLIGHT_STATES:
                        dev.category, dev.reason = "UNKNOWN", "ABORTED_WHILE_UPGRADING"
                    else:
                        dev.category, dev.reason = "NOT_EXECUTED", "ABORTED"
            return self._summary()
        finally:
            for pool in self.pools.values():
                pool.close()

    def _raise_fd_limit(self):
        try:
            soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
            wanted = 4096 if hard == resource.RLIM_INFINITY else min(hard, 4096)
            if soft < wanted:
                resource.setrlimit(resource.RLIMIT_NOFILE, (wanted, hard))
        except (ValueError, OSError):
            pass

    def _load_packages(self):
        for package in self.family.packages(self.options.selected):
            try:
                self.packages[package.path] = PackageInfo.read(package)
            except OSError as error:
                raise Hold(f"package unreadable: {package.path} ({error.strerror})") from None
        self.evidence.write("packages.json", {path: dict(file=info.file, size=info.size, sha256=info.sha256)
                                              for path, info in self.packages.items()})

    def _pump(self, done):
        while True:
            self._advance()
            if done():
                return
            now = self.clock()
            wake = [self.last_progress + self.options.progress_seconds]
            tracker_wake = self.tracker.next_wake()
            if tracker_wake is not None:
                wake.append(tracker_wake)
            if self.timers:
                wake.append(self.timers[0][0])
            for session in self.sessions:
                if not session.relay:
                    nxt = session.scheduler.next_wake(now)
                    if nxt is not None:
                        wake.append(nxt)
            timeout = max(0.01, min(1.0, min(wake) - now))
            try:
                event = self.events.get(timeout=timeout)
            except queue.Empty:
                continue
            self._handle(event)
            while True:
                try:
                    self._handle(self.events.get_nowait())
                except queue.Empty:
                    break

    # ------------------------------------------------------------ precheck
    def _staged_names(self):
        return sorted({info.file for info in self.packages.values()})

    def _precheck_task(self, dev):
        names = self._staged_names()
        journal = self.evidence.journal(dev.host)

        def task():
            if self.password_held.is_set():         # a refused password: no further precheck starts
                return _PRECHECK_HELD
            pinged = self.ops.ping(dev.device)
            upgrade = self.options.upgrade and dev.host not in self.service_issues   # no write to such a switch
            try:
                facts = self.ops.precheck(dev.device, upgrade=upgrade, staged_names=names, journal=journal)
            except SshError as error:
                if error.code == "PASSWORD_REJECTED":
                    self.password_held.set()        # here, before the main loop sees it: no task can slip through
                raise
            facts["ping"] = pinged
            return facts
        return task

    def _on_precheck(self, dev, event):
        if event.error is None and event.result is _PRECHECK_HELD:
            return self._final(dev, "SKIPPED", PASSWORD_HOLD)
        if event.error is not None:
            error = event.error
            code = getattr(error, "code", None) or type(error).__name__
            if isinstance(error, SshError) and error.code == "PASSWORD_REJECTED":
                self.password_rejected_by.append(dev.host)
                if not self.hold:
                    self.hold = "PASSWORD_REJECTED"
                    self.say(f"[HOLD] {dev.host} rejected the switch password; no new precheck starts (running "
                             f"ones finish), no transfers or upgrades")
                return self._final(dev, "FAILED", "PASSWORD_REJECTED")
            if isinstance(error, SshError) and error.code in ("CONNECT_FAILED", "CONNECT_TIMEOUT", "HANDSHAKE_FAILED"):
                return self._final(dev, "SKIPPED", "UNREACHABLE_" + error.code)
            if isinstance(error, SshError) and error.code == "AUTH_REJECTED":
                dev.key_rejected, dev.password_not_tried = True, not self._password_given()
            if getattr(error, "code", None):
                category = "REVIEW_REQUIRED" if code in ("HOST_KEY_MISMATCH", "HOST_KEY_UNKNOWN",
                                                         "DEVICE_IDENTITY_MISMATCH") else "FAILED"
                return self._final(dev, category, code)
            if isinstance(error, Hold):
                self.hold = str(error)
            return self._final(dev, "FAILED", "PRECHECK_ERROR_" + type(error).__name__)
        result = event.result
        dev.facts, dev.plan, dev.backup, dev.health = result["facts"], result["plan"], result["backup"], result["health"]
        dev.key_rejected = bool(result["key_rejected"])
        self.evidence.journal(dev.host)("precheck.json", dict(
            os_version=dev.facts.os_version, boot_id=dev.facts.boot_id, ping=result["ping"],
            plan=[dict(row) for row in dev.plan.rows], issues=list(dev.plan.issues), health=dev.health,
            guard=list(result["guard"]), staged={k: list(v) for k, v in dev.facts.staged.items()},
            free_bytes=dev.facts.free_bytes, capability_missing=list(dev.facts.capability_missing),
            key_rejected=result["key_rejected"], queued_seconds=round(event.waited, 3)))
        if result["ping"] != "reply":
            return self._final(dev, "FAILED", "PING_UNREACHABLE")
        if dev.plan.issues:
            return self._final(dev, "REVIEW_REQUIRED", dev.plan.issues[0][1])
        guard, where = result["guard"]
        if guard:
            return self._final(dev, "REVIEW_REQUIRED", guard)
        if not dev.plan.needed:
            return self._final(dev, "AT_TARGET")
        if dev.host in self.service_issues:
            return self._final(dev, "FAILED", self.service_issues[dev.host])
        if not dev.health["admitted"]:
            return self._final(dev, "HEALTH_BLOCKED", dev.health["reason"])
        if set(dev.facts.capability_missing) & set(self.family.required_programs):
            return self._final(dev, "FAILED", "CAPABILITY_MISSING")
        needed = self.family.space_needed(dev.plan, self.packages)
        if dev.facts.free_bytes is not None and dev.facts.free_bytes < needed:
            return self._final(dev, "FAILED", "NO_SPACE")
        if self.options.upgrade and dev.backup is None:
            return self._final(dev, "FAILED", "ACCESS_BACKUP_MISSING")
        self._set(dev, "READY")

    # ------------------------------------------------------------ component phase
    def _steps_for(self, dev, component):
        return list(self.family.steps(dev.plan, component, self.packages))

    def _run_phase(self, component):
        if self.hold or self.stopping:
            return
        self.phase = component
        members = [dev for dev in sorted(self.devs.values(), key=lambda item: item.order)
                   if dev.category is None and dev.state == "READY" and self._steps_for(dev, component)]
        if not members:
            return
        for dev in members:
            dev.steps, dev.step_index, dev.canary = self._steps_for(dev, component), 0, False
        canaries = [] if self.options.skip_canary else list(
            self.family.canaries(component, [(dev.host, dev.plan) for dev in members]))
        for name in canaries:
            self.devs[name].canary = True
        self.canary_queue = list(canaries)
        self.canaries_passed, self.phase_blocked = not canaries, False
        self.say(f"[PHASE {component.upper()}] {len(members)} switch(es); canaries: {', '.join(canaries) or 'none'}")
        for dev in members:
            dev.need_since = self.clock()
            self._set(dev, "NEED_STAGE", component=component, step=dev.current.key[1:], canary=dev.canary)
        def settled(dev):
            return (dev.category is not None or dev.state == "READY"
                    or ((self.stopping or self.hold or self.phase_blocked) and dev.state in WAITING_STATES))
        self._pump(lambda: self.outstanding == 0 and not self.tracker.devices and not self.timers
                   and all(settled(dev) for dev in members))
        for dev in members:
            if dev.category is None and dev.state != "READY":
                reason = "CANARY_FAILED" if self.phase_blocked else self.hold or "STOPPED"
                self._final(dev, "BLOCKED" if self.phase_blocked else "NOT_EXECUTED", reason)
        self.sessions = []

    # ------------------------------------------------------------ advance
    def _advance(self):
        now = self.clock()
        self._run_timers(now)
        if self.phase in self.family.components:
            self._check_packages()
            canary_waiting = self._start_canary_pull(now)
            self._open_sessions(now)
            self._run_sessions(now, starts=not canary_waiting)
            self._dispatch(now)
        actions, handbacks = self.tracker.due(now)
        for handback in handbacks:
            self._on_handback(self.devs[handback.host], handback)
        for host, action, token in actions:
            dev = self.devs[host]
            self._submit("probe", dev, "probe", self._probe_task(dev, action), priority=1, action=action, token=token)
        self._print_progress()

    def _check_packages(self):
        if self.hold:
            return
        for info in self.packages.values():
            if not info.unchanged():
                self.hold = f"PACKAGE_CHANGED: {info.path}"
                self.say(f"[HOLD] {self.hold}; no further transfers or upgrades")
                return

    def _start_canary_pull(self, now):
        """The running canary pulls straight from the ztp-server ahead of everything else.
        Returns True while it waits for the server gate (other server pulls hold back)."""
        if self.stopping or self.hold or self.phase_blocked or not self.canary_queue:
            return False
        dev = self.devs[self.canary_queue[0]]
        if dev.state != "NEED_STAGE" or dev.category is not None:
            return False
        if not self.gate.available(now):
            return True
        self.gate.start(now)
        self._set(dev, "STAGING", source="server", canary=True)
        self._submit("transfer", dev, "fetch", self._fetch_task(dev, None), priority=0, session=None,
                     source=dist.SERVER)
        return False

    def _open_sessions(self, now):
        if self.stopping or self.hold or self.phase_blocked:
            return
        waiting = {}
        for dev in self.devs.values():
            if dev.state == "NEED_STAGE" and dev.category is None and not dev.canary:
                waiting.setdefault(dev.current.key, []).append(dev)
        for key, devs in waiting.items():
            later_hop = any(dev.step_index > 0 for dev in devs)
            if later_hop and now - min(dev.need_since for dev in devs) < self.options.later_hop_batch_seconds:
                continue
            names = [dev.host for dev in sorted(devs, key=lambda item: item.order)]
            groups = dist.ordered_groups(self.options.groups, names)
            staged = [dev.host for dev in devs if all(dev.facts.staged.get(info.file) == (info.size, info.sha256)
                                                       for info in dev.current.packages) and dev.step_index == 0]
            relay = self.family.relay(key[0]) and self.options.link.mode == "relay"
            window = 0
            if relay:
                scheduler = dist.RelayScheduler(groups, self.gate, holders=staged, fanout=self.options.relay_fanout,
                                                max_transfers=self.options.relay_transfers)
            else:
                window = self.options.link.window_seconds(len(names)) if self.family.relay(key[0]) else 0
                scheduler = dist.DirectScheduler({group: [h for h in hosts if h not in staged]
                                                  for group, hosts in groups.items()}, self.gate,
                                                 window=window, now=now)
                for host in staged:
                    self._staged(self.devs[host], "PRE_STAGED")
            session = Session(key, names, scheduler, relay)
            self.sessions.append(session)
            for dev in devs:
                dev.session = session
                if dev.state == "NEED_STAGE":
                    self._set(dev, "STAGING", session=list(key[1:]), relay=relay)
            how = ("relay per OOB leaf" if relay else
                   f"direct, window {min(window, dist.MAX_WINDOW_SECONDS)} s, cap {self.gate.cap or 'none'}")
            self.say(f"[DISTRIBUTE] {key[0]} {', '.join(Path(p).name for p in key[1:])}: {len(names)} switch(es), {how}")

    def _run_sessions(self, now, *, starts=True):
        blocked = self.stopping or self.hold or self.phase_blocked or not starts
        for session in self.sessions:
            scheduler = session.scheduler
            if session.relay:
                if not blocked:
                    for receiver, source in scheduler.assignments(now):
                        dev = self.devs[receiver]
                        holder = None if source == dist.SERVER else self.devs[source].device
                        self._submit("transfer", dev, "fetch", self._fetch_task(dev, holder), priority=1,
                                     session=session, source=source)
                for group in scheduler.releasable():
                    for host in scheduler.release(group):
                        dev = self.devs[host]
                        if dev.state == "STAGING" and dev.session is session:
                            self._staged(dev, "RELAY_RELEASED")
                    for host, reason in list(scheduler.failed.items()):
                        dev = self.devs[host]
                        if dev.category is None and dev.session is session and dev.state == "STAGING":
                            self._final(dev, "FAILED", reason)
            elif not blocked:
                for host in scheduler.starts(now):
                    dev = self.devs[host]
                    self._submit("transfer", dev, "fetch", self._fetch_task(dev, None), priority=1,
                                 session=session, source=dist.SERVER)

    def _staged(self, dev, how):
        dev.session = None
        self._set(dev, "STAGED", how=how)

    def _fetch_task(self, dev, holder):
        step = dev.current

        def task():
            results = []
            for info in step.packages:
                result = self.ops.fetch(dev.device, info, size=info.size, sha256=info.sha256, holder=holder,
                                        url=info.url)
                results.append(result)
                if not result.get("ok"):
                    break
            return results
        return task

    def _on_fetch(self, dev, event):
        session, source = event.info.get("session"), event.info.get("source")
        results = event.result or []
        ok = event.error is None and bool(results) and all(item.get("ok") for item in results)
        failure = None if ok else (results[-1] if results else {"class": "unknown",
                                                                "code": getattr(event.error, "code", "FETCH_ERROR")})
        self.evidence.journal(dev.host)(f"distribution-{dev.current.component}-{dev.step_index}.json", dict(
            source=source, ok=ok, results=results, failure=failure, queued_seconds=round(event.waited, 3),
            seconds=round(event.seconds, 3)))
        if session is None:                              # canary pull
            self.gate.finish()
            if ok:
                self._staged(dev, "CANARY_DIRECT")
            else:
                self._final(dev, "FAILED", "DISTRIBUTION_" + failure.get("code", "FAILED"))
                self._canary_failed(dev)
            return
        scheduler = session.scheduler
        if session.relay:
            scheduler.finished(dev.host, ok, error=failure.get("class") if failure else dist.UNCLEAR,
                               reason="DISTRIBUTION_" + (failure.get("code") if failure else "FAILED"))
            if not ok and dev.host in scheduler.failed:
                self._final(dev, "FAILED", scheduler.failed[dev.host])
        else:
            scheduler.finished(dev.host, ok, reason="DISTRIBUTION_" + (failure.get("code") if failure else "FAILED"))
            if ok:
                self._staged(dev, "DIRECT")
            else:
                self._final(dev, "FAILED", scheduler.failed[dev.host])

    # ------------------------------------------------------------ dispatch
    def _dispatch(self, now):
        if self.stopping or self.hold:
            return
        for dev in sorted(self.devs.values(), key=lambda item: item.order):
            if dev.state != "STAGED" or dev.category is not None:
                continue
            if dev.canary:
                if self.canary_queue and self.canary_queue[0] != dev.host:
                    continue
            elif not self.canaries_passed:
                continue
            if self._in_flight() >= self.options.in_flight:
                return
            plan = dev.current
            step = self.family.render(dev.device, plan, run_id=self.options.run_id,
                                      switch_dir=self.ops.dir_for(dev.device))
            dev.step = step
            staged = {info.file: (info.size, info.sha256) for info in plan.packages}
            journal = self.evidence.journal(dev.host)
            self._set(dev, "DISPATCHING", component=plan.component, stage=step.stage, target=step.target_version)
            self._submit(plan.component, dev, "dispatch",
                         lambda dev=dev, step=step, staged=staged, journal=journal: self.ops.dispatch(
                             dev.device, step, backup=dev.backup, staged=staged, journal=journal), priority=1)

    def _on_dispatch(self, dev, event):
        if event.error is not None:
            error = event.error
            if isinstance(error, EvidenceError):
                self.hold = "EVIDENCE_WRITE_FAILED"           # the write-ahead record could not be saved
                self.say(f"[HOLD] {dev.host}: dispatch record could not be saved; no further upgrades")
            self._final(dev, "FAILED", "NOT_DISPATCHED_" + (getattr(error, "code", None) or type(error).__name__))
            return self._canary_failed(dev)
        result = event.result
        state = result["state"]
        if state == "DISPATCHED":
            dev.dispatch = dict(result, dispatched_at=self.clock())
            dev.step = replace(dev.step, remote_dir=result["remote_dir"])
            self.evidence.journal(dev.host)(f"before-{dev.step.stage}.commands", result["before_commands"])
            if result["confirmed"] is not True:
                dev.warnings.append("LAUNCH_UNCONFIRMED")
            self._set(dev, "PROBING", boot_before=result["boot_before"], confirmed=result["confirmed"],
                      queued_seconds=round(event.waited, 3))
            self.tracker.add(dev.host, now=self.clock(), dispatched_at=dev.dispatch["dispatched_at"],
                             boot_before=result["boot_before"], expect_reboot=dev.step.effect != "NONE")
            return
        if state == "AT_TARGET":
            return self._step_done(dev, performed=False)
        category = {"GUARD": "REVIEW_REQUIRED", "HEALTH_BLOCKED": "HEALTH_BLOCKED", "BLOCKED": "BLOCKED"}.get(state, "FAILED")
        self._final(dev, category, result.get("reason", "DISPATCH_FAILED"))
        self._canary_failed(dev)

    # ------------------------------------------------------------ probing and verification
    def _probe_task(self, dev, action):
        ops, device = self.ops, dev.device
        if action == probe.PING:
            return lambda: ops.ping(device)
        if action == probe.TCP:
            return lambda: ops.tcp(device)
        if action == probe.STATUS:
            return lambda: ops.status(device, dev.step, dev.dispatch["boot_before"])
        journal = self.evidence.journal(dev.host)
        return lambda: ops.ladder(device, dev.dispatch["boot_before"], backup=dev.backup, journal=journal)

    def _on_probe(self, dev, event):
        action, token = event.info["action"], event.info["token"]
        if event.error is not None:
            result = "error" if action == probe.PING else False if action == probe.TCP else {"kind": "connect_fail"}
        else:
            result = event.result
        handback = self.tracker.report(dev.host, token, action, result, self.clock())
        if action in (probe.STATUS, probe.LADDER):
            self.evidence.timeline(dev.host, dict(t=round(self.clock() - self.started, 3), probe=action,
                                                  result={k: v for k, v in result.items() if k != "facts"}))
        if handback is not None:
            self._on_handback(dev, handback)

    def _on_handback(self, dev, handback):
        dev.warnings += [warning for warning in handback.warnings if warning not in dev.warnings]
        if handback.outcome == probe.READY:
            dev.boot_after = handback.boot_id
            self._set(dev, "VERIFYING", boot_id=handback.boot_id, version=handback.version)
            return self._submit_verify(dev)
        if handback.outcome == probe.FAILED:
            self._final(dev, "FAILED", handback.reason)
        elif handback.outcome == probe.REVIEW:
            self._final(dev, "REVIEW_REQUIRED", handback.reason, keep_slot=True)
        else:
            self._final(dev, "UNKNOWN", handback.reason, keep_slot=True)
        self._canary_failed(dev)

    def _submit_verify(self, dev):
        journal = self.evidence.journal(dev.host)
        before = dev.dispatch["before_commands"]
        baseline = dev.dispatch["health_record"]
        self._submit("check", dev, "verify", lambda: self.ops.verify(
            dev.device, dev.step, boot_after=dev.boot_after, before=before, baseline_health=baseline,
            backup=dev.backup, journal=journal), priority=0)

    def _retry_verify(self, dev, code):
        """One more whole verification after a pause, kept as a main-loop timer; the switch keeps its
        in-flight slot (state VERIFYING) and no check worker waits for it."""
        dev.verify_retried = True
        if "VERIFY_RETRIED" not in dev.warnings:
            dev.warnings.append("VERIFY_RETRIED")
        delay = self.options.verify_retry_seconds
        self._set(dev, "VERIFYING", verify_retry=dict(reason=code, delay_seconds=delay))
        step = dev.step

        def again():
            if dev.category is None and dev.state == "VERIFYING" and dev.step is step:
                self._submit_verify(dev)
        self._later(delay, again)

    def _on_verify(self, dev, event):
        if event.error is not None:
            error = event.error
            if isinstance(error, SshError) and error.reboot_like:
                return self._requeue(dev, "VERIFY_CONNECTION_LOST")
            code = getattr(error, "code", None) or type(error).__name__
            if (isinstance(error, SshError) and code in VERIFY_RETRY_CODES and not dev.verify_retried
                    and getattr(error, "repair_requested", True) is False):   # unsaid counts as requested
                return self._retry_verify(dev, code)
            self._final(dev, "UNKNOWN", "VERIFY_" + code)
            return self._canary_failed(dev) if dev.canary else None
        result = event.result
        self.evidence.journal(dev.host)(f"verify-{dev.step.stage}.json", dict(
            state=result["state"], reason=result.get("reason"), os_version=result.get("os_version"),
            repaired=result.get("repaired"), ssd=result.get("ssd"), queued_seconds=round(event.waited, 3)))
        if result["state"] == "REBOOTED":
            return self._requeue(dev, "BOOT_CHANGED_DURING_VERIFY")
        if result["state"] != "VERIFIED":
            self._final(dev, "UNKNOWN", result.get("reason") or "VERIFY_FAILED")
            return self._canary_failed(dev) if dev.canary else None
        dev.performed.append(dict(component=dev.step.component, stage=dev.step.stage,
                                  target=dev.step.target_version, warnings=list(dev.warnings)))
        self._step_done(dev, performed=True)

    def _requeue(self, dev, why):
        dev.warnings.append(why)
        self._set(dev, "PROBING", requeued=why)
        self.tracker.requeue_rebooting(dev.host, now=self.clock(), dispatched_at=dev.dispatch["dispatched_at"],
                                       boot_before=dev.dispatch["boot_before"], warnings=dev.warnings)

    def _step_done(self, dev, *, performed):
        dev.step_index += 1
        dev.dispatch, dev.step, dev.verify_retried = None, None, False
        if dev.current is not None:
            dev.need_since = self.clock()
            self._set(dev, "NEED_STAGE", step=dev.current.key[1:])
            return
        dev.completed.add(self.phase)
        self._set(dev, "READY", component_done=self.phase)
        if dev.canary and self.canary_queue and self.canary_queue[0] == dev.host:
            self.canary_queue.pop(0)
            if not self.canary_queue:
                self.canaries_passed = True
                self.say(f"[CANARY {self.phase.upper()}] all canaries passed; releasing the batch")

    def _canary_failed(self, dev):
        if not dev.canary:
            return
        self.say(f"[CANARY {self.phase.upper()}] {dev.host} did not pass ({dev.reason}); the rest of "
                 f"{self.phase.upper()} is blocked")
        self.canary_queue, self.phase_blocked = [], True
        for session in self.sessions:
            for host in session.members:
                session.scheduler.drop(host, "CANARY_FAILED")

    # ------------------------------------------------------------ events
    def _handle(self, event):
        if event.kind == "stop":
            return
        self.outstanding -= 1
        dev = self.devs.get(event.host)
        if dev is None:
            return
        handler = {"precheck": self._on_precheck, "fetch": self._on_fetch, "dispatch": self._on_dispatch,
                   "probe": self._on_probe, "verify": self._on_verify}[event.kind]
        if dev.category is not None and event.kind != "fetch":
            if event.kind == "probe":
                self.tracker.report(dev.host, event.info["token"], event.info["action"], None, self.clock())
            return
        if event.kind == "fetch" and dev.category is not None:
            session = event.info.get("session")
            if session is None:
                self.gate.finish()
            elif session.relay:
                session.scheduler.finished(dev.host, False, reason="DISTRIBUTION_ABANDONED", abandon=True)
            else:
                session.scheduler.finished(dev.host, False, reason="DISTRIBUTION_ABANDONED")
            return
        handler(dev, event)

    # ------------------------------------------------------------ progress and summary
    def _print_progress(self, force=False):
        now = self.clock()
        if not force and now - self.last_progress < self.options.progress_seconds:
            return
        self.last_progress = now
        elapsed = int(now - self.started)
        clock = f"{elapsed // 3600:02d}:{elapsed % 3600 // 60:02d}:{elapsed % 60:02d}"
        link = self.options.link
        speed = "unknown" if link.speed_mbps is None else f"{link.speed_mbps // 1000}G"
        states, categories = {}, {}
        for dev in self.devs.values():
            if dev.category:
                categories[dev.category] = categories.get(dev.category, 0) + 1
            else:
                states[dev.state] = states.get(dev.state, 0) + 1
        title = "[PREFLIGHT PROGRESS]" if self.phase == "precheck" else f"[PROGRESS {self.phase.upper()}]"
        canary = "" if self.phase == "precheck" else (" canary=PASSED" if getattr(self, "canaries_passed", False)
                                                      else " canary=RUNNING")
        lines = [f"{title} {clock} link={speed} {link.mode}{canary}",
                 "  devices  " + (" · ".join(f"{k.lower()} {v}" for k, v in sorted(categories.items())) or "none final")
                 + f" · active {sum(states.values())}",
                 f"  main     events-waiting={self.events.qsize()}"
                 + (("  states: " + " · ".join(f"{k.lower()} {v}" for k, v in sorted(states.items()))) if states else "")]
        busy, queued, wait = self.pools["check"].stats(now)
        lines.append(f"  check    busy {busy}/{self.pools['check'].size}  queued {queued}  longest-wait {int(wait)}s")
        parts = []
        for component in self.family.components:
            busy, queued, wait = self.pools[component].stats(now)
            parts.append(f"{component.upper()} busy {busy}/{self.pools[component].size} queued {queued}")
        lines.append("  upgrade  " + " · ".join(parts) + f"  in-flight {self._in_flight()}/{self.options.in_flight}")
        counts = self.tracker.snapshot(now)
        busy, _queued, _wait = self.pools["probe"].stats(now)
        lines.append(f"  probe    upgrading-Q {counts['upgrading']} (ssh-check due {counts['ssh_due']}) · "
                     f"reboot-wait {counts['reboot_wait']}")
        lines.append(f"           rebooting-Q {counts['ping'] + counts['tcp'] + counts['ladder']} (ping {counts['ping']} · "
                     f"tcp {counts['tcp']} · ssh {counts['ladder']})  threads busy {busy}/{self.pools['probe'].size}")
        for session in self.sessions:
            snap = (session.scheduler.snapshot() if session.relay else session.scheduler.snapshot(now))
            if session.relay:
                groups = " · ".join(f"{name} {have}/{total}{' ' + tag if tag else ''}"
                                    for name, (have, total, tag) in snap["groups"].items())
                lines.append(f"  distrib  {Path(session.key[1]).name}: transfers {snap['transfers']}/{snap['max_transfers']}"
                             f" · holders {snap['holders']} · waiting {snap['waiting']}"
                             + (" · PEER RELAY DISABLED" if snap["peer_disabled"] else ""))
                lines.append("           " + groups)
            else:
                lines.append(f"  distrib  {Path(session.key[1]).name}: downloads {snap['downloads']}/"
                             f"{snap['cap'] if snap['cap'] else '-'} · staggering {snap['staggering']} · "
                             f"staged {snap['staged']} · failed {snap['failed']}")
        stalled = self._stalled(now)
        if stalled:
            lines.append("  stalled  " + " · ".join(stalled[:10]) + (" ..." if len(stalled) > 10 else ""))
        self.say("\n".join(lines))
        self.evidence.event(dict(t=elapsed, progress=dict(states=states, categories=categories,
                                                          probe=counts, in_flight=self._in_flight())))

    def _stalled(self, now):
        t = self.options.timings
        limits = {"PROBING": t.dwell, "VERIFYING": 600.0, "DISPATCHING": 240.0, "STAGING": 1800.0}
        found = []
        for dev in self.devs.values():
            limit = limits.get(dev.state)
            if dev.category is None and limit and now - dev.state_since > limit * self.options.stall_fraction:
                found.append(f"{dev.host} {dev.state.lower()} {int((now - dev.state_since) // 60)}m")
        return found

    def _summary(self):
        rows, counts = [], {}
        for dev in sorted(self.devs.values(), key=lambda item: item.order):
            counts[dev.category] = counts.get(dev.category, 0) + 1
            rows.append(dict(hostname=dev.host, category=dev.category, reason=dev.reason, warnings=dev.warnings,
                             performed=dev.performed, canary=dev.canary))
        for issue in self.blocked_inputs:
            counts["SKIPPED"] = counts.get("SKIPPED", 0) + 1
            rows.append(dict(hostname=issue.hostname, category="SKIPPED", reason=",".join(issue.reasons),
                             warnings=[], performed=[], canary=False))
        key_rows = [dict(hostname=dev.host, address=dev.device.address, category=dev.category, reason=dev.reason,
                         group="PASSWORD_NOT_TRIED" if dev.password_not_tried else
                         "NO_INSTALLATION" if dev.category == "AT_TARGET" else "OTHER")
                    for dev in sorted(self.devs.values(), key=lambda item: item.order) if dev.key_rejected]
        report = dict(family=self.family.name, run_id=self.options.run_id, hold=self.hold, stopped=self.stopping,
                      aborted=self.aborted, password_rejected_by=list(self.password_rejected_by),
                      key_rejected=key_rows, link=self.options.link.line(), counts=counts, devices=rows,
                      seconds=round(self.clock() - self.started, 1))
        self.evidence.write("run-report.json", report)
        return report


def exit_code(report):
    if report.get("aborted"):
        return 130
    if report.get("hold"):
        return 2
    bad = set(report["counts"]) - {"UPGRADED", "AT_TARGET"}
    return 3 if bad else 0


def render_summary(report, *, management_key=None, user=None):
    lines = ["", f"== {report.get('family', 'switch')} upgrade summary ==", report["link"]]
    for category, label in CATEGORIES:
        names = [row for row in report["devices"] if row["category"] == category]
        if not names:
            continue
        lines.append(f"{category} ({len(names)}): {label}")
        for row in names:
            extra = (f"  {row['reason']}" if row.get("reason") else "") + (
                f"  [{', '.join(row['warnings'])}]" if row.get("warnings") else "")
            lines.append(f"  {row['hostname']}{extra}")
    if report.get("hold"):
        lines.append(f"HOLD: {report['hold']}")
    if report.get("password_rejected_by"):
        held = sum(1 for row in report["devices"] if row["reason"] == PASSWORD_HOLD)
        lines.append(f"The switch password was rejected by {', '.join(report['password_rejected_by'])}; prechecks "
                     f"stopped there and nothing was written to the {held} switch(es) marked {PASSWORD_HOLD}. "
                     "Check the password and run again.")
    lines += _key_rejected_lines(report.get("key_rejected") or [], management_key, user)
    lines.append(f"elapsed {report['seconds']} s")
    return "\n".join(lines)


def _key_rejected_lines(rows, management_key, user):
    """O3 2026-10-24: switches whose management key was rejected in precheck, listed only (nothing is written)."""
    if not rows:
        return []
    lines = [f"MANAGEMENT KEY REJECTED in precheck ({len(rows)}): listed only, this changes nothing"]
    groups = {name: [row for row in rows if row["group"] == name]
              for name in ("NO_INSTALLATION", "PASSWORD_NOT_TRIED", "OTHER")}
    if groups["NO_INSTALLATION"]:
        lines.append("  needs no installation: the key was not changed (no access bootstrap runs, so an --upgrade run "
                     "does not add it); add it with ssh-copy-id and the management public key, or a later "
                     "access-repair tool:")
        for row in groups["NO_INSTALLATION"]:
            lines.append(f"    {row['hostname']}  ssh-copy-id -i {management_key or '<management public key>'} "
                         f"{user or '<user>'}@{row['address']}")
    if groups["PASSWORD_NOT_TRIED"]:
        lines.append("  the password was not tried (no password was asked); run again with --password to precheck "
                     "them with it:")
        lines += [f"    {row['hostname']}" for row in groups["PASSWORD_NOT_TRIED"]]
    if groups["OTHER"]:
        lines.append("  the others: an --upgrade run adds the key in its access bootstrap before installing anything:")
        lines += [f"    {row['hostname']}  {row['category']}" + (f" {row['reason']}" if row.get("reason") else "")
                  for row in groups["OTHER"]]
    return lines
