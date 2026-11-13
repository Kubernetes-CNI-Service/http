"""Owned-file, fake-I/O fixture for real upgrade entry + IB adapter + fleet engine.

No subprocess, socket, private key parser, switch script or runtime guard is executed.
"""
from __future__ import annotations

import contextlib
import io
import json
from pathlib import Path
import tempfile
from unittest import mock

from test_cases import test_fleet_engine as fake
from test_cases import test_ibsw_upgrade_entry_runtime as entry_contract

import ibsw_v2_device as ib
from ibsw_upgrade_contract import InventoryDevice

HEADER = ("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,eth1_mac,lo_ip,bgp_asn,"
          "bgp_ports,bond_ports,bond_type,bond_mac,peerlink_ports,vrl")


class OwnedWorkflow:
    def __init__(self, test):
        temporary = tempfile.TemporaryDirectory()
        test.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.project = self.root / "repository/DAY0-Prepare/example-project"
        self.project.mkdir(parents=True)
        (self.project.parent / "activate-project").symlink_to("example-project")
        self.repository = self.project.parent.parent
        self.http = self.root / "http"
        (self.http / "image").mkdir(parents=True)
        for version in ("25.02.6077", "25.02.7002", "25.02.8008"):
            (self.http / "image" / ("nvos-amd64-" + version + ".bin")).write_bytes(b"synthetic-image\n" * 100)
        self.global_path = self.project / "01-global.yaml"
        self.global_path.write_text("""schema_version: 2
common:
  mgmt:
    http:
      status: enabled
      address: 192.0.2.10
      port: 8088
      http_root: %s
switches:
- ib:
    version: '25.02.8008'
    upgrade:
      package_dir: %s
      packages:
        os:
          sub_dir: image
          files:
          - file: nvos-amd64-25.02.6077.bin
          - file: nvos-amd64-25.02.7002.bin
          - file: nvos-amd64-25.02.8008.bin
""" % (self.http, self.http))
        self.devices = [InventoryDevice("example-ib01", "192.0.2.41", "02:00:00:00:00:29"),
                        InventoryDevice("example-ib02", "192.0.2.42", "02:00:00:00:00:2a")]
        self.rows = [",".join([d.hostname, "ib", "nvos", d.address, "24", "192.0.2.1", d.mac] + ["na"] * 12)
                     for d in self.devices]
        (self.project / "02-devices_config.csv").write_text(HEADER + "\n" + "\n".join(self.rows) + "\n")
        self.private, self.public, self.hosts = (self.root / name for name in ("management.key", "management.pub", "known_hosts"))
        self.private.write_bytes(b"synthetic-private-never-parsed")
        self.public.write_bytes(b"synthetic-public-never-sent\n")
        self.hosts.write_bytes(b"# synthetic public known-hosts snapshot\n")
        self.entry = entry_contract.load_entry()
        self.entry.REPOSITORY = self.repository
        self.ops, self.out = None, io.StringIO()
        self.change = None
        self.key_error = None
        self.use_real_key_reader = False
        self.captured = {}

    def ip(self, argv):
        if argv[:3] == ["ip", "route", "get"]:
            return argv[3] + " dev eth0 src 192.0.2.10 uid 0\n"
        if argv[:4] == ["ip", "-o", "addr", "show"]:
            return "2: eth0 inet 192.0.2.10/24 scope global eth0\n"
        raise AssertionError("unexpected network command")

    def factory(self, **kwargs):
        owner = self
        class Ops(fake.FakeOps):
            def password_login(self, device):
                self.note("password-check", device.hostname, "read-only")

            def bind_available_packages(self, available):
                self.available = available
                owner.captured["available"] = available

            def precheck(self, device, *, upgrade, staged_names, journal):
                self.note("precheck", device.hostname, upgrade)
                sim = self.sims[device.hostname]
                facts = ib.Facts(sim.boot, 1000, 10000, sim.version, None, None, None, True,
                                 b"nv set system hostname example\n", b"", [], dict(sim.files),
                                 free_bytes=10 ** 12)
                plan = ib.plan_device(kwargs["policy"], kwargs["selected"], facts, available=self.available)
                return dict(facts=facts, plan=plan, health=dict(observed="PASS", reason=None, admitted=True),
                            guard=(None, None), backup=object() if upgrade else None, key_rejected=False)

            def dispatch(self, device, step, **call):
                result = super().dispatch(device, step, **call)
                if owner.change:
                    owner.change(device, step)
                return result
        self.ops = Ops(self.devices, versions={d.hostname: "25.02.7002" for d in self.devices})
        self.ops.available = None          # matches LiveOps' backwards-compatible unbound default
        return self.ops

    def run(self, extra=()):
        import fleet_ssh
        import fleet_engine
        argv = ["--os", "--identity", str(self.private), "--management-public-key", str(self.public),
                "--known-hosts", str(self.hosts), "--server-link", "1G", "--progress-seconds", "1", *extra]
        with contextlib.ExitStack() as stack:
            original_init = fleet_engine.Engine.__init__
            def engine_init(engine, *args, **kwargs):
                self.captured["locked_inputs"] = kwargs.get("locked_inputs", ())
                self.captured["watched_inputs"] = kwargs.get("watched_inputs", ())
                self.captured["packages_ready"] = kwargs.get("packages_ready")
                return original_init(engine, *args, **kwargs)
            stack.enter_context(mock.patch.object(fleet_engine.Engine, "__init__", engine_init))
            if not self.use_real_key_reader:
                stack.enter_context(mock.patch.object(fleet_ssh, "load_private_key", return_value=(object(), "SHA256:synthetic"),
                                                      side_effect=self.key_error))
            stack.enter_context(mock.patch.object(self.entry, "_runtime_locked_files", return_value=[]))
            stack.enter_context(mock.patch("subprocess.run", side_effect=AssertionError("unexpected subprocess")))
            stack.enter_context(mock.patch("socket.create_connection", side_effect=AssertionError("unexpected connection")))
            code = self.entry.run(argv, out=self.out, password_reader=lambda _prompt: "synthetic-typed-value",
                                  ops_factory=self.factory, link_run=self.ip, timings=fake.FAST)
        return code

    def reports(self):
        root = self.project / "99-output-ib_nvl/bringup/xdr-upgrade-v2-logs"
        return [json.loads(path.read_text()) for path in root.glob("*/run-report.json")]
