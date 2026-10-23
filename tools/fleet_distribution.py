"""Package distribution for switch fleet jobs (IB upgrade v2; reusable for nvl-sw; owner 2026-10-23).

Pure scheduling, no I/O except reading the P2P workbook. Every package lands in the
switch's /home/admin and is verified there before the switch may upgrade.

- Relay (ztp-server link below 10G): one queue per OOB leaf. While a queue holds no
  copy and nothing is in flight, one waiting switch pulls from the ztp-server; every
  switch that finishes a verified pull becomes a source at once and serves at most
  `fanout` switches at a time. When a queue has no receiver left its holders stop
  taking new transfers (drain); the queue is released for upgrade once their outbound
  transfers end, because an OS reboot can erase /home/admin.
- Direct (10G and above, and BIOS/CPLD always): every switch pulls from the ztp-server
  after a random delay in [0, window); starts rotate across OOB leaves.

Pulls from the ztp-server share one ServerGate: at most `cap` at once and, for scp,
starts spaced by `gap` seconds so sshd MaxStartups is not hit.
"""
from __future__ import annotations

from collections import deque
import importlib.util
from pathlib import Path
import secrets
import sys

SERVER = "@server"
UNKNOWN_GROUP = "@unknown"
MAX_WINDOW_SECONDS = 3600
SOURCE, RECEIVER, UNCLEAR = "source", "receiver", "unknown"
_INITIAL_SETUP = Path(__file__).resolve().parents[1] / "infiniband/bringup/xdr-initial-setup/initial-setup.py"


def _p2p_module():
    """The P2P reader of the IB initial setup; it reads any device's eth0/mgmt links."""
    name = "fleet_initial_setup_p2p"
    if name in sys.modules:
        return sys.modules[name]
    spec = importlib.util.spec_from_file_location(name, _INITIAL_SETUP)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module                 # dataclasses resolve their module by name
    try:
        spec.loader.exec_module(module)
    except BaseException:
        del sys.modules[name]
        raise
    return module


def oob_groups(p2p_path, hostnames, *, module=None):
    """{hostname: OOB leaf} from the management links in P2P; unmatched hosts get UNKNOWN_GROUP."""
    setup = module or _p2p_module()
    links = setup.parse_p2p(Path(p2p_path))
    wanted = {setup.normalize_name(name): name for name in hostnames}
    found, conflicts, warnings = {}, set(), []
    for link in links:
        for ib_name, ib_port, peer in ((link.left_device, link.left_port, link.right_device),
                                       (link.right_device, link.right_port, link.left_device)):
            if setup.clean(ib_port).casefold() not in setup.IB_PORT_ALIASES:
                continue
            key = setup.normalize_name(ib_name)
            host = wanted.get(key)
            if host is None:
                matches = [name for normalized, name in wanted.items() if setup.names_match(normalized, key)]
                host = matches[0] if len(matches) == 1 else None
            if host is None:
                continue
            leaf = setup.normalize_name(peer)
            if host in found and found[host] != leaf:
                conflicts.add(host)
            found.setdefault(host, leaf)
    for host in sorted(conflicts):
        warnings.append(f"{host}: management port listed on two OOB leaves; relayed from any holder")
    groups = {host: (found[host] if host in found and host not in conflicts else UNKNOWN_GROUP)
              for host in hostnames}
    missing = [host for host in hostnames if host not in found]
    if missing:
        warnings.append(f"{len(missing)} switch(es) have no management link in P2P; relayed from any holder: "
                        + ", ".join(missing[:10]) + (" ..." if len(missing) > 10 else ""))
    return groups, warnings


def ordered_groups(group_of, hostnames):
    """{group: [hosts in inventory order]} for the given hosts."""
    groups = {}
    for host in hostnames:
        groups.setdefault(group_of.get(host, UNKNOWN_GROUP), []).append(host)
    return groups


def rotation(groups):
    """Hosts interleaved across groups: g1[0], g2[0], ..., g1[1], g2[1], ..."""
    queues = [list(members) for members in groups.values()]
    order = []
    while any(queues):
        for queue in queues:
            if queue:
                order.append(queue.pop(0))
    return order


class ServerGate:
    """Concurrent pulls from the ztp-server: at most `cap` (None = no cap), starts `gap` seconds apart."""

    def __init__(self, cap=None, gap=0.0):
        if cap is not None and cap < 1:
            raise ValueError("server pull cap must be positive")
        self.cap, self.gap, self.active, self.last = cap, gap, 0, None

    def available(self, now):
        return ((self.cap is None or self.active < self.cap)
                and (not self.gap or self.last is None or now - self.last >= self.gap))

    def start(self, now):
        self.active += 1
        self.last = now

    def finish(self):
        self.active -= 1

    def next_time(self):
        return self.last + self.gap if self.gap and self.last is not None else None


class RelayScheduler:
    def __init__(self, groups, gate, *, holders=(), fanout=4, max_transfers=32, retries=2,
                 holder_failures=2, breaker=4):
        if fanout < 1 or max_transfers < 1 or retries < 0 or holder_failures < 1 or breaker < 1:
            raise ValueError("positive relay limits required")
        self.gate = gate
        self.groups = {group: list(members) for group, members in groups.items()}
        self.group_of = {host: group for group, members in self.groups.items() for host in members}
        held = set(holders)
        self.holders = {group: [host for host in members if host in held] for group, members in self.groups.items()}
        self.waiting = {group: deque(host for host in members if host not in held) for group, members in self.groups.items()}
        self.fanout, self.max_transfers, self.retries = fanout, max_transfers, retries
        self.holder_failures, self.breaker = holder_failures, breaker
        self.load = {host: 0 for host in held}
        self.active = {}
        self.attempts, self.tried, self.source_failures = {}, {}, {}
        self.retired, self.failed, self.draining, self.released = set(), {}, set(), set()
        self.peer_success, self.peer_disabled = False, False
        self._peer_failures, self._peer_failed_sources = 0, set()

    def _sources(self, group):
        if self.peer_disabled:
            return []
        names = [name for name in self.groups if name not in self.draining] if group == UNKNOWN_GROUP else (
            [] if group in self.draining else [group])
        return [host for name in names for host in self.holders[name] if host not in self.retired]

    def _busy(self, group):
        return any(self.group_of[receiver] == group for receiver in self.active)

    def _pick(self, group, receiver):
        sources = self._sources(group)
        free = [host for host in sources if self.load[host] < self.fanout]
        tried = self.tried.get(receiver, set())
        fresh = [host for host in free if host not in tried]
        if not fresh and any(host not in tried for host in sources):
            return None                        # an untried source is busy; wait for it
        pool = fresh or free
        if not pool:
            return None
        return min(pool, key=lambda host: (self.load[host], sources.index(host)))

    def assignments(self, now):
        """Transfers to start now as (receiver, source); source SERVER means the ztp-server."""
        started = []
        for group in self.groups:
            queue = self.waiting[group]
            while queue and len(self.active) < self.max_transfers:
                receiver = queue[0]
                source = self._pick(group, receiver)
                if source is None:
                    if not self.peer_disabled:
                        if self._sources(group) or self._busy(group):
                            break
                        if group == UNKNOWN_GROUP and any(self._busy(name) for name in self.groups):
                            break              # wait for another queue's first copy
                    if not self.gate.available(now):
                        break
                    source = SERVER
                    self.gate.start(now)
                queue.popleft()
                self.active[receiver] = source
                if source != SERVER:
                    self.load[source] += 1
                started.append((receiver, source))
        self._drain()
        return started

    def finished(self, receiver, ok, *, error=UNCLEAR, reason="DISTRIBUTION_FAILED", abandon=False):
        source = self.active.pop(receiver)
        group = self.group_of[receiver]
        if source == SERVER:
            self.gate.finish()
        else:
            self.load[source] -= 1
        if ok:
            self.holders[group].append(receiver)
            self.load.setdefault(receiver, 0)
            if source != SERVER:
                self.peer_success = True
            self._drain()
            return
        if source != SERVER:
            if error == SOURCE:
                self.source_failures[source] = self.source_failures.get(source, 0) + 1
                if self.source_failures[source] >= self.holder_failures:
                    self.retired.add(source)
            if not self.peer_success:
                self._peer_failures += 1
                self._peer_failed_sources.add(source)
                if self._peer_failures >= self.breaker and len(self._peer_failed_sources) >= 2:
                    self.peer_disabled = True
        self.attempts[receiver] = self.attempts.get(receiver, 0) + 1
        self.tried.setdefault(receiver, set()).add(source)
        if abandon or self.attempts[receiver] > self.retries:
            self.failed[receiver] = reason
        else:
            queue, index = self.waiting[group], 0
            while index < len(queue) and queue[index] in self.attempts:
                index += 1                     # retries go first, in the order they failed
            queue.insert(index, receiver)
        self._drain()

    def holder_lost(self, host):
        self.retired.add(host)

    def drop(self, host, reason="DROPPED"):
        """A waiting receiver leaves the round (blocked or stopped); an active one is ended by finished()."""
        group = self.group_of.get(host)
        if group is not None and host in self.waiting[group]:
            self.waiting[group].remove(host)
            self.failed[host] = reason
        self._drain()

    def _drain(self):
        for group in self.groups:
            if not self.waiting[group] and not self._busy(group):
                self.draining.add(group)

    def complete(self, group):
        return not self.waiting[group] and not self._busy(group)

    def serving(self, host):
        return any(source == host for source in self.active.values())

    def releasable(self):
        """Groups whose receivers are done and whose holders serve nobody any more."""
        ready = []
        for group, members in self.groups.items():
            if group in self.released or not self.complete(group):
                continue
            if any(self.serving(host) for host in members):
                continue
            ready.append(group)
        return ready

    def release(self, group):
        self.released.add(group)
        return list(self.holders[group])

    def done(self):
        return all(group in self.released for group in self.groups)

    def snapshot(self):
        serving = [host for group in self.groups for host in self._sources(group) if self.group_of[host] == group]
        return dict(mode="relay", transfers=len(self.active), max_transfers=self.max_transfers,
                    holders=len(set(serving)), waiting=sum(len(queue) for queue in self.waiting.values()),
                    failed=len(self.failed), peer_disabled=self.peer_disabled,
                    groups={group: (len(self.holders[group]), len(members),
                                    "released" if group in self.released else "draining" if group in self.draining else "")
                            for group, members in self.groups.items()})


class DirectScheduler:
    def __init__(self, groups, gate, *, window, now, randbelow=secrets.randbelow):
        window = min(int(window or 0), MAX_WINDOW_SECONDS)
        self.gate = gate
        self.order = rotation(groups)
        self.group_of = {host: group for group, members in groups.items() for host in members}
        self.ready_at = {host: now + (randbelow(window) if window > 0 else 0) for host in self.order}
        self.pending = list(self.order)
        self.active, self.staged_hosts, self.failed = set(), [], {}

    def starts(self, now):
        started = []
        for host in list(self.pending):
            if self.ready_at[host] > now:
                continue
            if not self.gate.available(now):
                break
            self.pending.remove(host)
            self.active.add(host)
            self.gate.start(now)
            started.append(host)
        return started

    def drop(self, host, reason="DROPPED"):
        if host in self.pending:
            self.pending.remove(host)
            self.failed[host] = reason

    def next_wake(self, now):
        later = [self.ready_at[host] for host in self.pending if self.ready_at[host] > now]
        gap = self.gate.next_time()
        if gap is not None and self.pending and gap > now:
            later.append(gap)
        return min(later) if later else None

    def finished(self, host, ok, *, reason="DISTRIBUTION_FAILED"):
        self.active.remove(host)
        self.gate.finish()
        if ok:
            self.staged_hosts.append(host)
        else:
            self.failed[host] = reason

    def done(self):
        return not self.pending and not self.active

    def snapshot(self, now=None):
        staggering = len([h for h in self.pending if now is not None and self.ready_at[h] > now])
        return dict(mode="direct", downloads=len(self.active), cap=self.gate.cap, pending=len(self.pending),
                    staggering=staggering, staged=len(self.staged_hosts), failed=len(self.failed))
