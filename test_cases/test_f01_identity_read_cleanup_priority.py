"""Current-main tests-first identity read interruption contract.

Uses surviving full main modules, not lost F01 candidates. The original input
test's genuine full-module loader establishes its documented bare
project_contract import context; bare-package startup is NOT claimed repaired.
Only the three fixed command results are fake; project/lease parsers and
infra argv/_run dispatch are real. No subprocess/network/SDK/device is invoked.
"""
import datetime as dt
import errno
import hashlib
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from test_cases import test_ufm_input_contract as _original_input_load_context
from infra import ufm_jump_transport as transport
from tools import ufm_identity_binding as binding

NOW = dt.datetime(2026, 9, 26, tzinfo=dt.timezone.utc)
GLOBAL = (b"servers:\n"
          b"  - ufm:\n"
          b"      version: '2.5.1-8'\n"
          b"      interfaces:\n"
          b"        alias: {eth0: eno8303, eth1: eno8403}\n")
CSV = (b"hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
       b"EXAMPLE-UFM01,ufm,NA,192.0.2.21,24,192.0.2.1,02:00:00:00:00:21\n")
LEASE = (b"lease 192.0.2.21 {\n"
         b"  starts 3 2026/09/23 00:00:00;\n"
         b"  ends 3 2030/01/01 00:00:00;\n"
         b"  binding state active;\n"
         b"  hardware ethernet 02:00:00:00:00:21;\n"
         b"}\n")
KNOWN = (b"jump.example.invalid ssh-ed25519 c3ludGhldGljLWtleQ==\n"
         b"192.0.2.21 ssh-ed25519 c3ludGhldGljLWtleQ==\n")
PIN = hashlib.sha256(KNOWN).hexdigest()
DIRECT = b"literal private no-follow read\n"


class FixtureUnknown(KeyboardInterrupt):
    """Fixture HOLD: standard unittest must stop, never continue a subcase.

    This is not either injected original body object and cannot qualify as a
    behavior marker failure. Resources/TD remain retained; no numeric rescue.
    """


class OriginalReadFault:
    """Narrow fault on one real _read_regular_no_follow invocation only."""

    def __init__(self, test, target, primary, tail, *, armed):
        self.test, self.target = test, target
        self.primary, self.tail = primary, tail
        self.armed = armed
        self.original = binding._read_regular_no_follow
        self.raw_open, self.raw_read, self.raw_close = os.open, os.read, os.close
        self.raw_fstat = os.fstat
        self.rows, self.active = [], {}
        self.pending = None
        self.unknown = False
        self.fault_frame = None
        self.body_calls = self.tail_calls = 0

    def selected(self, frame):
        return (frame.f_code is self.original.__code__
                and frame.f_globals is self.original.__globals__)

    def fail(self, label):
        self.unknown = True
        raise FixtureUnknown(label)

    def opened(self, path, flags, *args, **kwargs):
        if self.unknown:
            raise FixtureUnknown("sticky UNKNOWN forbids any later open")
        frame = sys._getframe(1)
        if not self.selected(frame):
            return self.raw_open(path, flags, *args, **kwargs)
        try:
            fd = self.raw_open(path, flags, *args, **kwargs)
        except BaseException:
            self.unknown = True
            raise
        self.pending = fd
        try:
            if fd in self.active:
                self.fail("original read acquired a still-held numeric generation")
            row = {"fd": fd, "frame": frame, "path": frame.f_locals["path"],
                   "root": path == "/" and "dir_fd" not in kwargs,
                   "closed": False, "close_returned": False, "key": None}
            self.rows.append(row)
            self.active[fd] = row
            value = self.raw_fstat(fd)
            row["key"] = (value.st_dev, value.st_ino)
            self.pending = None
            return fd
        except BaseException:
            self.unknown = True
            raise

    def reading(self, fd, count):
        if self.unknown:
            raise FixtureUnknown("sticky UNKNOWN forbids any later read")
        frame = sys._getframe(1)
        if (self.selected(frame) and self.armed
                and frame.f_locals["path"] == self.target
                and frame.f_locals.get("fd") == fd
                and self.body_calls == 0):
            row = self.active.get(fd)
            if row is None or row["frame"] is not frame:
                self.fail("body fault lacks the original held leaf generation")
            self.fault_frame = frame
            self.body_calls += 1
            raise self.primary
        return self.raw_read(fd, count)

    def closing(self, fd):
        if self.unknown:
            raise FixtureUnknown("sticky UNKNOWN forbids any later close")
        frame = sys._getframe(1)
        if not self.selected(frame):
            return self.raw_close(fd)
        row = self.active.get(fd)
        if row is None or row["frame"] is not frame:
            self.fail("original close lacks its held generation")
        try:
            before = self.raw_fstat(fd)
            if (before.st_dev, before.st_ino) != row["key"]:
                self.fail("original close generation changed")
            result = self.raw_close(fd)
            row["close_returned"] = True
            try:
                self.raw_fstat(fd)
            except OSError as error:
                if error.errno != errno.EBADF:
                    raise
            else:
                self.fail("original close returned without immediate EBADF")
            row["closed"] = True
            if self.active.get(fd) is not row:
                self.fail("original close generation mapping changed")
            del self.active[fd]
        except BaseException:
            self.unknown = True
            raise
        if row["root"] and frame is self.fault_frame:
            if self.tail_calls or any(r["frame"] is frame and not r["closed"]
                                      for r in self.rows):
                self.fail("tail fault preceded another original close")
            self.tail_calls += 1
            raise self.tail
        return result

    def resource_known(self):
        return (not self.unknown and self.pending is None and not self.active
                and bool(self.rows) and all(r["closed"] and r["close_returned"]
                                            for r in self.rows))

    def facts_before_oracle(self):
        self.test.assertTrue(self.resource_known(), "FIXTURE_RESOURCE_UNKNOWN")
        self.test.assertEqual(1, self.body_calls)
        self.test.assertEqual(1, self.tail_calls)
        selected = [r for r in self.rows if r["frame"] is self.fault_frame]
        self.test.assertGreaterEqual(len(selected), 2)
        self.test.assertEqual(1, sum(r["root"] for r in selected))
        self.test.assertTrue(all(r["closed"] and r["close_returned"] for r in selected))


def _snapshot(paths):
    return tuple((path, path.stat().st_dev, path.stat().st_ino, path.stat().st_mode,
                  path.read_bytes()) for path in paths)


class CurrentMainIdentityOwnedReadCleanupTests(unittest.TestCase):
    def _exercise(self, primary_type, *, workflow):
        primary = primary_type("literal original body operator")
        preset = ValueError("literal pre-existing body cause")
        primary.__cause__ = preset
        tail = OSError(errno.EIO, "literal after-last-owned-close EIO")
        td = tempfile.TemporaryDirectory(prefix="f01-main-identity-cleanup-")
        root = Path(td.name).resolve()
        fault = None
        observed = None
        seen = []
        try:
            if workflow:
                project = root / "project"
                project.mkdir()
                global_path, csv_path = project / "01-global.yaml", project / "02-devices_config.csv"
                global_path.write_bytes(GLOBAL)
                csv_path.write_bytes(CSV)
                lease, known = root / "synthetic.leases", root / "known_hosts"
                lease.write_bytes(LEASE)
                known.write_bytes(KNOWN)
                known.chmod(0o600)
                paths = (global_path, csv_path, lease, known)
                target = global_path
                jump = transport.JumpEndpoint("jump.example.invalid", "synthetic", known)
                far = transport.BoundFarEndpoint("192.0.2.21", "synthetic", "declared", jump)
            else:
                target = root / "private-source"
                target.write_bytes(DIRECT)
                target.chmod(0o600)
                paths = (target,)
            before = _snapshot(paths)
            fault = OriginalReadFault(self, target, primary, tail, armed=not workflow)

            def runner(argv):
                seen.append(tuple(argv))
                if len(seen) == 1 and argv[-1] == "hostname":
                    return transport.CommandResult(0, "EXAMPLE-UFM01\n", "")
                if len(seen) == 2 and argv[-1] == "ip -j link show dev eno8303":
                    return transport.CommandResult(0,
                        '[{"ifname":"eno8303","address":"02:00:00:00:00:21"}]', "")
                if len(seen) == 3 and argv[-1] == "ip -j address show dev eno8303":
                    fault.armed = True
                    return transport.CommandResult(0,
                        '[{"ifname":"eno8303","addr_info":[{"family":"inet","local":"192.0.2.21"}]}]', "")
                self.fail("unexpected command instead of three literal identity observations")

            with mock.patch.object(binding.os, "open", new=fault.opened), \
                    mock.patch.object(binding.os, "read", new=fault.reading), \
                    mock.patch.object(binding.os, "close", new=fault.closing):
                try:
                    if workflow:
                        binding.verify_project_management_identity(
                            project, lease, jump, far, PIN, timeout=5, now=NOW,
                            runner=runner)
                    else:
                        binding._read_regular_no_follow(target, limit=1024, private=True)
                except BaseException as error:
                    observed = error
            if not fault.resource_known():
                fault.fail("original read resources did not naturally close")
            fault.facts_before_oracle()
            self.assertEqual(before, _snapshot(paths))
            self.assertFalse(any(p.name.startswith("99-output") for p in root.iterdir()))
            self.assertIs(tail, fault.tail)
            if workflow:
                self.assertEqual(("hostname", "ip -j link show dev eno8303",
                                  "ip -j address show dev eno8303"),
                                 tuple(argv[-1] for argv in seen))
                self.assertTrue(all(argv[0] == "ssh" for argv in seen))
            else:
                self.assertEqual([], seen)
        finally:
            if fault is not None and not fault.resource_known():
                td._finalizer.detach()
            else:
                td.cleanup()
        self.assertIs(primary, observed,
                      "ORIGINAL_IDENTITY_BODY_OPERATOR_REPLACED_BY_LAST_CLOSE")
        self.assertIs(preset, observed.__cause__,
                      "ORIGINAL_IDENTITY_BODY_PRESET_CAUSE_REPLACED")

    def test_original_private_read_keeps_body_operator_and_cause_after_last_close_eio(self):
        for primary_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(primary_type=primary_type.__name__):
                self._exercise(primary_type, workflow=False)

    def test_real_project_input_lease_and_transport_flow_keeps_final_read_operator(self):
        for primary_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(primary_type=primary_type.__name__):
                self._exercise(primary_type, workflow=True)
