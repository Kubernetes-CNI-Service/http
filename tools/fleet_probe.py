"""Reboot probing for switch fleet jobs (IB upgrade v2; reusable for nvl-sw; owner 2026-10-23, review 15.4-15.5, 15.12).

The tracker is pure state. The main loop asks it for due actions, a probe thread runs
each action (ping, TCP/22, SSH) and the main loop reports the result back. One action
per switch at a time; a result whose token is stale is ignored.

upgrading Q (right after the upgrade script started): ping at once and then every 30 s.
A reply means the switch is still installing; no reply means it is rebooting, so it
moves to rebooting Q three minutes later. Every two minutes an SSH check reads boot_id
and the script state, which catches a fast reboot between pings, a script that failed
before installing, or a late hand-off.

rebooting Q: ping every 15 s -> TCP/22 -> one SSH session reading boot_id, nvued state
and `nv show system version`. A failed connection goes back to ping; boot_id unchanged
goes back to upgrading Q; nvued or the CLI not ready retries the SSH step in 30 s.

Limits, all measured from dispatch or from the first readiness check and never reset:
the device deadline (60 min), the time in upgrading Q (30 min) and the readiness
checks (10 min).

A job that does not reboot (expect_reboot=False, e.g. a configuration step) is checked
over SSH every `config_check` seconds and comes back READY as soon as its script exits 0
on the same boot; an unexpected reboot still goes through the ladder.
"""
from __future__ import annotations

from dataclasses import dataclass, field

UPGRADING, REBOOT_WAIT, REBOOTING = "upgrading", "reboot-wait", "rebooting"
PING, TCP, STATUS, LADDER = "ping", "tcp", "status", "ladder"
READY, FAILED, UNKNOWN, REVIEW = "READY", "FAILED", "UNKNOWN", "REVIEW_REQUIRED"


@dataclass(frozen=True)
class Timings:
    upgrading_ping: float = 30.0
    reboot_wait: float = 180.0
    ladder_ping: float = 15.0
    ladder_retry: float = 30.0
    ssh_check: float = 120.0
    dwell: float = 1800.0
    ladder_budget: float = 600.0
    deadline: float = 3600.0
    config_check: float = 15.0


@dataclass(frozen=True)
class Handback:
    host: str
    outcome: str                 # READY | FAILED | UNKNOWN | REVIEW_REQUIRED
    reason: str
    boot_id: str | None = None
    version: str | None = None
    warnings: tuple[str, ...] = ()


@dataclass
class _Device:
    dispatched_at: float
    boot_before: str
    phase: str = UPGRADING
    step: str = PING
    next_at: float = 0.0
    ssh_next_at: float = 0.0
    inflight: int | None = None
    generation: int = 0
    ladder_started: float | None = None
    installing_seen: bool = False
    ping_errors: int = 0
    expect_reboot: bool = True
    warnings: list = field(default_factory=list)


class ProbeTracker:
    def __init__(self, timings: Timings = Timings()):
        self.timings = timings
        self.devices: dict[str, _Device] = {}

    def add(self, host, *, now, dispatched_at, boot_before, expect_reboot=True):
        """Enter upgrading Q right after the script started; first ping at once."""
        if host in self.devices:
            raise ValueError(f"{host} is already being probed")
        check = self.timings.ssh_check if expect_reboot else self.timings.config_check
        self.devices[host] = _Device(dispatched_at, boot_before, UPGRADING, PING, now, now + check,
                                     expect_reboot=expect_reboot)

    def requeue_rebooting(self, host, *, now, dispatched_at, boot_before, warnings=()):
        """Verification lost the switch (it rebooted again): back to the ladder, same deadline."""
        if host in self.devices:
            raise ValueError(f"{host} is already being probed")
        self.devices[host] = _Device(dispatched_at, boot_before, REBOOTING, PING, now, 0.0,
                                     warnings=list(warnings))

    def _done(self, host, outcome, reason, **extra):
        device = self.devices.pop(host)
        return Handback(host, outcome, reason, warnings=tuple(device.warnings), **extra)

    def due(self, now):
        """([(host, action, token)], [Handback]) for this moment."""
        actions, handbacks = [], []
        t = self.timings
        for host in list(self.devices):
            device = self.devices[host]
            if now - device.dispatched_at > t.deadline:
                handbacks.append(self._done(host, UNKNOWN, "DEVICE_DEADLINE_EXCEEDED"))
                continue
            if device.phase == UPGRADING and now - device.dispatched_at > t.dwell:
                handbacks.append(self._done(host, UNKNOWN, "REBOOT_NOT_OBSERVED" if device.expect_reboot
                                            else "SCRIPT_NOT_FINISHED"))
                continue
            if device.ladder_started is not None and now - device.ladder_started > t.ladder_budget:
                handbacks.append(self._done(host, UNKNOWN, "NVUE_NOT_READY"))
                continue
            if device.inflight is not None:
                continue
            action = None
            if device.phase == UPGRADING:
                if now >= device.ssh_next_at:
                    action = STATUS
                elif now >= device.next_at:
                    action = PING
            elif device.phase == REBOOT_WAIT:
                if now >= device.next_at:
                    device.phase, device.step = REBOOTING, PING
                    action = PING
            elif now >= device.next_at:
                action = device.step
            if action is not None:
                device.generation += 1
                device.inflight = device.generation
                actions.append((host, action, device.generation))
        return actions, handbacks

    def report(self, host, token, action, result, now):
        """Apply one action's result. Returns a Handback when the switch leaves probing, else None."""
        device = self.devices.get(host)
        if device is None or device.inflight != token:
            return None                                    # stale: the switch moved on
        device.inflight = None
        t = self.timings
        if device.phase == UPGRADING and action == PING:
            if result == "reply":
                device.installing_seen, device.ping_errors = True, 0
                device.next_at = now + t.upgrading_ping
            elif result == "no_reply":
                device.phase, device.next_at = REBOOT_WAIT, now + t.reboot_wait
            else:                                          # local ping error is not a reboot
                device.ping_errors += 1
                device.next_at = now + t.upgrading_ping
            return None
        if device.phase == UPGRADING and action == STATUS:
            device.ssh_next_at = now + (t.ssh_check if device.expect_reboot else t.config_check)
            kind = result.get("kind")
            if kind == "hostkey":
                return self._done(host, REVIEW, "HOST_KEY_MISMATCH")
            if kind != "ok":
                return None                                # shutting down or unreachable: keep pinging
            if result.get("boot_id") and result["boot_id"] != device.boot_before:
                device.phase, device.step, device.next_at = REBOOTING, PING, now
                return None
            outcome = result.get("outcome")
            if outcome == "exit_zero" and not device.expect_reboot:
                return self._done(host, READY, "COMPLETED_WITHOUT_REBOOT", boot_id=device.boot_before)
            if outcome == "preinstall_failed":
                return self._done(host, FAILED, result.get("reason") or "PREINSTALL_FAILED")
            if outcome == "exit_after_install" and "INSTALLER_EXIT_NONZERO_AFTER_INSTALL" not in device.warnings:
                device.warnings.append("INSTALLER_EXIT_NONZERO_AFTER_INSTALL")
            return None
        if device.phase == REBOOTING and action == PING:
            if result == "reply":
                device.step, device.next_at = TCP, now
            else:
                device.next_at = now + t.ladder_ping
            return None
        if device.phase == REBOOTING and action == TCP:
            device.step, device.next_at = (LADDER, now) if result else (PING, now + t.ladder_ping)
            return None
        if device.phase == REBOOTING and action == LADDER:
            kind = result.get("kind")
            if kind == "hostkey":
                return self._done(host, REVIEW, "HOST_KEY_MISMATCH")
            if kind in ("connect_fail", "auth_fail"):
                device.step, device.next_at = PING, now + t.ladder_ping
                return None
            if kind == "boot_same":
                device.phase, device.step = UPGRADING, PING
                device.next_at, device.ssh_next_at = now + t.upgrading_ping, now + t.ssh_check
                return None
            if kind in ("nvued_down", "cli_down"):
                if device.ladder_started is None:
                    device.ladder_started = now
                device.step, device.next_at = LADDER, now + t.ladder_retry
                return None
            if kind == "ready":
                return self._done(host, READY, "READY", boot_id=result.get("boot_id"), version=result.get("version"))
            device.step, device.next_at = PING, now + t.ladder_ping
            return None
        raise ValueError(f"{host}: action {action} does not belong to phase {device.phase}")

    def drop(self, host):
        """Forget a switch (operator abort); returns whether it was being probed."""
        return self.devices.pop(host, None) is not None

    def next_wake(self):
        times = []
        for device in self.devices.values():
            if device.inflight is not None:
                continue
            times.append(min(device.next_at, device.ssh_next_at) if device.phase == UPGRADING else device.next_at)
        return min(times) if times else None

    def snapshot(self, now):
        counts = {"upgrading": 0, "ssh_due": 0, "reboot_wait": 0, "ping": 0, "tcp": 0, "ladder": 0, "busy": 0}
        for device in self.devices.values():
            counts["busy"] += device.inflight is not None
            if device.phase == UPGRADING:
                counts["upgrading"] += 1
                counts["ssh_due"] += now >= device.ssh_next_at
            elif device.phase == REBOOT_WAIT:
                counts["reboot_wait"] += 1
            else:
                counts[device.step] += 1
        return counts
