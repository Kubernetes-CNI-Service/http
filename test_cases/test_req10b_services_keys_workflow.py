"""Real-script REQ-10-B P1 service/key RED workflow, without device operations."""

from __future__ import annotations

import base64
from contextlib import ExitStack
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
GENERATOR = ROOT / "ztp/config/nvos/template/90-c2-generate_configs.py"
LOADER = ROOT / "DAY0-Prepare/11-load.py"

GLOBAL = """\
schema_version: 2
common:
  switch:
    system:
      dns:
        server:
        - 192.0.2.53
        - 198.51.100.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.common.example.test
      date-time:
        timezone: Etc/UTC
switches:
- ib:
    system:
      dns:
        server:
        - 203.0.113.53
      ntp:
        server:
        - ntp.ubuntu.com
        - time.ib.example.test
      date-time:
        timezone: Asia/Taipei
- nvl:
    system:
      dns:
        server:
        - 203.0.113.54
"""
EXPECTED_IB = {
    "dns": ("203.0.113.53",),
    "ntp": ("ntp.ubuntu.com", "time.ib.example.test"),
    "timezone": "Asia/Taipei",
}


def public_key(seed: int, comment: str) -> str:
    """Build a deterministic valid OpenSSH public line, with no private key."""
    def field(value: bytes) -> bytes:
        return struct.pack(">I", len(value)) + value

    blob = field(b"ssh-ed25519") + field(bytes([seed]) * 32)
    return "ssh-ed25519 " + base64.b64encode(blob).decode() + " " + comment + "\n"


def fingerprint(public_line: str) -> str:
    blob = base64.b64decode(public_line.split()[1], validate=True)
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).rstrip(b"=").decode()


def scalar_strings(value: object):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for member in value.values():
            yield from scalar_strings(member)
    elif isinstance(value, list):
        for member in value:
            yield from scalar_strings(member)


class Req10BServicesKeysWorkflowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10b_services_keys_workflow_initial", INITIAL)
        with mock.patch.object(sys, "argv", ["90-c2-generate_configs.py"]):
            cls.generator = load_script("req10b_services_keys_workflow_generator", GENERATOR)
        cls.loader = load_script("req10b_services_keys_workflow_loader", LOADER)

    def test_f02_generated_profile_real_batch_shell_and_local_method_veto(self):
        """Real cache -> stdlib executor/shell -> V2 writer, no SSH/device I/O."""
        authority = load_script("f02_initial_shell_authority", ROOT / "ztp/config_sync_authority.py")
        with tempfile.TemporaryDirectory(prefix="f02-initial-batch-") as directory:
            root, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            root = root.resolve()
            tool, ib_csv, p2p = tool.resolve(), ib_csv.resolve(), p2p.resolve()
            cache = cache.parent.resolve() / cache.name
            ib_csv.write_text(ib_csv.read_text().replace("203.0.113.1,,,,", "203.0.113.1,02:00:00:00:00:01,,,"))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            candidate = self.initial.load_target_cache(cache, ib_csv, p2p, public_key_tool=tool)
            self.assertIsNotNone(candidate)
            target = candidate[1][0]
            profile = json.loads(cache.read_text())
            self.assertEqual(list(EXPECTED_IB["dns"]), profile["services"]["dns"])
            state = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n")
            remote = root / "remote"
            (remote / ".ssh").mkdir(parents=True)
            (remote / ".ssh/authorized_keys").write_text(laptop + management)
            (remote / "live.commands").write_text(state)
            private = root / "management-key"
            private.write_text("local fixture identity; never a real key")
            private.chmod(0o600)
            executables = root / "fixture-bin"
            executables.mkdir()
            programs = {
                "ssh": "#!" + sys.executable + "\nimport os,shlex,subprocess,sys\n"
                    "a=sys.argv[1:]\nassert 'BatchMode=yes' in a and 'PasswordAuthentication=no' in a\n"
                    "assert a[-2]=='admin@203.0.113.2'\n"
                    "assert open(a[a.index('-i')+1]).read()=='local fixture identity; never a real key'\n"
                    "r=subprocess.run(shlex.split(a[-1]), pass_fds=())\nsys.exit(r.returncode)\n",
                "hostname": "#!/bin/sh\nprintf 'EXAMPLE-IB01\\n'\n",
                "cat": "#!/bin/sh\nif [ \"$1\" = /sys/class/net/eth0/address ]; then "
                    "printf '02:00:00:00:00:01\\n'; else exec /bin/cat \"$@\"; fi\n",
                "nv": "#!/bin/sh\n[ \"$*\" = 'config show -o commands' ] || exit 97\n"
                    "exec /bin/cat \"$HOME/live.commands\"\n",
            }
            for name, source in programs.items():
                path = executables / name
                path.write_text(source)
                path.chmod(0o700)
            storage = root / "configuration-methods"
            for cycle in (1, 2):
                ticket = authority.begin_method(storage, target.ib.hostname, "initial-" + str(cycle),
                                                "own-initial-" + str(cycle), "initial_setup_managed")
                self.assertEqual("pending", authority.read_method_current(storage, target.ib.hostname)["state"])
                if cycle == 2:
                    (remote / ".ssh/authorized_keys").write_text(laptop)
                with mock.patch.dict(os.environ, {"PATH": str(executables) + ":/usr/bin:/bin", "HOME": str(remote)}):
                    observed = self.initial.observe_managed_initial_configuration(
                        target, "admin", private, 5, profile["services"], profile["public_keys"])
                self.assertIs(cycle == 1, observed["config_verified"],
                              "installed-key presence is checked in the actual batch shell, not an old log")
                result = {"schema_version": 2, "record_type": "configuration_method", "hostname": target.ib.hostname,
                          "type": "ib", "config_method": "initial-setup", **{name: ticket[name] for name in (
                            "generation", "source_identity", "operation_id", "trigger_id", "trigger_source")},
                          "state": "success" if cycle == 1 else "failed", "reason": observed["reason"]}
                if cycle == 1:
                    result.update({name: observed[name] for name in ("batch_identity_verified", "config_verified",
                        "interface", "transport_ip", "mac_plain", "live_state_sha256", "input_sha256")})
                    result["source_receipt_sha256"] = observed["observation_sha256"]
                    self.assertEqual(hashlib.sha256(state.encode()).hexdigest(), result["live_state_sha256"])
                authority.finish_method(storage, ticket, result)
                current = authority.read_method_current(storage, target.ib.hostname)
                self.assertEqual((cycle, cycle != 1), (current["generation"], current["veto"]))
                receipt = authority.read_method_receipt(storage, target.ib.hostname)
                self.assertEqual(result if cycle == 1 else None, receipt)
                self.assertNotIn("complete", result, "method proof never supplies missing bootstrap stages")
                if cycle == 1:
                    # Real same-shell observer -> read-only current input binder
                    # -> monitor consumer. No persisted report is an observer.
                    monitor = load_script("f02_initial_real_shell_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
                    reader = authority.InitialMethodMonitorInputs(root, self.initial, tool, cache, ib_csv, p2p)
                    device = {"hostname": "EXAMPLE-IB01", "type": "ib", "config_method": "initial-setup",
                        "ip": "203.0.113.2", "mac_plain": "020000000001", "ssh_user": "admin", "ztp_round": 1,
                        "stages": {name: monitor.stage("pending") for name in monitor.STAGE_NAMES}, "issues": [], "events": []}
                    captured = authority.read_method_current(storage, target.ib.hostname)
                    for drift in (False, True):
                        if drift: (remote / ".ssh/authorized_keys").write_text(laptop)
                        with mock.patch.dict(os.environ, {"PATH": str(executables) + ":/usr/bin:/bin", "HOME": str(remote)}):
                            proof, expected_input = reader.observe(device, private, 5)
                        monitor.apply_current_initial_method_authority(device, storage, captured, proof, expected_input)
                        self.assertEqual("warning" if drift else "success", device["stages"]["config_apply"]["status"])
                        current = authority.read_method_current(storage, target.ib.hostname)
                        self.assertEqual((1, "failed" if drift else "success"), (current["generation"], current["state"]))
                        self.assertFalse(monitor.completion_handoff_device_complete(device))

    def test_f02_monitor_entry_reads_initial_profile_and_rejects_mid_session_changes(self):
        from types import SimpleNamespace
        monitor = load_script("f02_initial_monitor_entry", ROOT / "DAY0-Prepare/12-ztp-monitor.py")
        authority = monitor.config_sync_authority
        from test_cases.test_config_sync_authority import ConfigSyncAuthorityTests
        for case in ("positive", "profile-change", "new-writer", "missing-profile", "deep-profile", "observer-error", "inventory-change", "late-receipt-change"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                project, tool, global_path, csv_path, p2p, _, cache, laptop, management = self.fixture(directory)
                project = project.resolve()
                csv_path.write_text("hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                    "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                    "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n")
                self.assertEqual(0, self.run_initial(tool, csv_path, p2p, cache, "--generate-json"))
                (project / "02-devices_config.csv").write_bytes(csv_path.read_bytes())
                (project / "01-global.yaml").write_text(GLOBAL)
                apache, dhcp, air = project / "apache.log", project / "dhcp.log", project / "air.json"
                apache.write_text(""); dhcp.write_text(""); air.write_text('{"nodes": {}}')
                key = project / "management-key"; key.write_text("fixture-only"); key.chmod(0o600)
                args = monitor.parser().parse_args([str(project), "--output-dir", str(project / "reports"),
                    "--apache-log", str(apache), "--dhcp-log", str(dhcp), "--identity", str(key),
                    "--initial-target-cache", str(cache), "--initial-device-csv", str(csv_path),
                    "--initial-p2p", str(p2p), "--initial-tool-inputs", str(tool)])
                expected = {"schema_version": 1, "type": "ib", "config_method": "initial-setup",
                    "hostname": "EXAMPLE-IB01", "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1",
                    "eth1": "", "eth1_gateway": "", "eth0_mac": "02:00:00:00:00:01",
                    "dns": ["203.0.113.53"], "ntp": ["ntp.ubuntu.com", "time.ib.example.test"],
                    "timezone": "Asia/Taipei", "key_fingerprints": sorted([fingerprint(laptop), fingerprint(management)])}
                digest = hashlib.sha256(json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
                storage = project / "99-output-ztp/configuration-methods"
                ticket = authority.begin_method(storage, "EXAMPLE-IB01", "writer-1", "initial-IB01", "initial_setup_managed")
                receipt = ConfigSyncAuthorityTests.method_receipt_v2(ticket, hostname="EXAMPLE-IB01", type="ib",
                    config_method="initial-setup", trigger_source="initial_setup_managed", transport_ip="203.0.113.2",
                    mac_plain="020000000001", live_state_sha256="a" * 64, input_sha256=digest, source_receipt_sha256="c" * 64)
                authority.finish_method(storage, ticket, receipt)
                if case == "missing-profile": cache.unlink()
                if case == "deep-profile": cache.write_text("[" * 1100 + "0" + "]" * 1100)
                def fresh_observer(target, user, private, timeout, services, keys):
                    self.assertEqual("EXAMPLE-IB01", target.ib.hostname)
                    self.assertEqual("admin", user)
                    self.assertEqual(key, private)
                    self.assertEqual(list(EXPECTED_IB["dns"]), services["dns"])
                    self.assertEqual(1, authority.read_method_current(storage, "EXAMPLE-IB01")["generation"])
                    if case == "profile-change": global_path.write_text(GLOBAL.replace("Asia/Taipei", "UTC"))
                    if case == "new-writer": authority.begin_method(storage, "EXAMPLE-IB01", "writer-2", "new-IB01", "initial_setup_managed")
                    if case == "observer-error": raise self.initial.SetupError("independent observer protocol error")
                    if case == "inventory-change":
                        inventory = project / "02-devices_config.csv"
                        inventory.write_text(inventory.read_text().replace("203.0.113.2", "203.0.113.3"))
                    return {"schema_version": 1, "hostname": "EXAMPLE-IB01", "batch_identity_verified": True,
                        "config_verified": True, "interface": "eth0", "transport_ip": "203.0.113.2", "mac_plain": "020000000001",
                        "live_state_sha256": "a" * 64, "input_sha256": digest, "observation_sha256": "c" * 64, "reason": ""}
                original_read = authority.read_method_receipt
                changed_at_read = False
                def held_receipt(*args):
                    nonlocal changed_at_read
                    value = original_read(*args)
                    if case == "late-receipt-change" and not changed_at_read:
                        changed_at_read = True
                        global_path.write_text(GLOBAL.replace("Asia/Taipei", "UTC"))
                    return value
                with mock.patch.object(authority, "load_initial_method_executor", return_value=self.initial), \
                        mock.patch.object(authority, "read_method_receipt", side_effect=held_receipt), \
                        mock.patch.object(self.initial, "observe_managed_initial_configuration", side_effect=fresh_observer) as observe, \
                        mock.patch.object(monitor, "load_release_identity", return_value={"dhcp_status": "disabled", "release_id": "fixture-release", "generated_at": "2026-10-07T07:00:00+08:00"}), \
                        mock.patch.object(monitor, "service_runtime_backend", return_value=SimpleNamespace(name="systemd")), \
                        mock.patch.object(monitor, "service_state", return_value={"active": "fixture", "enabled": "fixture", "error": ""}), \
                        mock.patch.object(monitor, "ACTIVE_AIR_JSON", air), \
                        mock.patch.object(monitor, "run_command", return_value={"returncode": 1, "stdout": "", "stderr": "fixture collection unavailable"}):
                    output = monitor.monitor_once(args, project)
                device = json.loads((output / "report.json").read_text())["devices"][0]
                self.assertEqual(0 if case in {"missing-profile", "deep-profile"} else 1, observe.call_count, device.get("configuration_method_observation"))
                self.assertEqual("success" if case == "positive" else "warning", device["stages"]["config_apply"]["status"])
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual("success" if case == "positive" else "pending" if case == "new-writer" else "failed", current["state"])
                self.assertEqual(2 if case == "new-writer" else 1, current["generation"])
                self.assertFalse(monitor.completion_handoff_device_complete(device))

    def fixture(self, directory: str):
        root = Path(directory)
        tool = root / "infiniband/bringup/xdr-initial-setup"
        tool.mkdir(parents=True)
        global_path = tool / "01-global.yaml"
        global_path.write_text(GLOBAL, encoding="utf-8")
        neutral = root / "infra/infra-neutral.conf"
        neutral.parent.mkdir(parents=True)
        neutral.write_text("DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n", encoding="ascii")
        ib_csv = root / "ib.csv"
        ib_csv.write_text(
            "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,"
            "eth1_ip,netmask,eth1_gw\n"
            "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
            "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,\n",
            encoding="utf-8",
        )
        p2p = root / "p2p.dot"
        p2p.write_text('"EXAMPLE-IB01":"eth0" -- "EXAMPLE-JUMP01":"7";\n', encoding="utf-8")
        pubdir = root / "infiniband/publickey"
        pubdir.mkdir(parents=True)
        (tool / "publickey").symlink_to("../../publickey")
        laptop = public_key(17, "laptop")
        management = public_key(18, "management")
        (pubdir / "laptop.pub").write_text(laptop, encoding="ascii")
        (pubdir / "mgmt-server.pub").write_text(management, encoding="ascii")
        cache = root / "out/targets.json"
        return root, tool, global_path, ib_csv, p2p, pubdir, cache, laptop, management

    def test_f02_initial_profile_parser_never_reopens_rebound_foreign_inputs(self):
        """A safe snapshot cannot authorize a later unguarded pathname read."""
        authority = load_script("f02_initial_parser_snapshot_boundary", ROOT / "ztp/config_sync_authority.py")
        for case in ("cache", "csv", "p2p", "global", "key", "fifo"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root, tool, global_file, csv_path, p2p, pubdir, cache, _, _ = self.fixture(str(base / "project"))
                self.assertEqual(0, self.run_initial(tool, csv_path, p2p, cache, "--generate-json"))
                paths = {"cache": cache, "csv": csv_path, "p2p": p2p,
                         "global": global_file, "key": pubdir / "mgmt-server.pub", "fifo": csv_path}
                victim = paths[case]
                original_stat = victim.stat()
                foreign = base / "foreign-input"
                foreign_bytes = b"INDEPENDENT FOREIGN INPUT: MUST NOT BE OPENED\n"
                foreign.write_bytes(foreign_bytes)
                # Do not accidentally short-circuit the original parser's
                # freshness checks; the fault is a read after safe capture.
                os.utime(foreign, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                original_parser = self.initial.load_target_cache
                original_open = Path.open
                rebound, forbidden_reads = [], []
                def rebind_then_parse(*args, **kwargs):
                    if not rebound:
                        rebound.append(True)
                        victim.unlink()
                        if case == "fifo":
                            os.mkfifo(victim)
                            os.utime(victim, ns=(original_stat.st_atime_ns, original_stat.st_mtime_ns))
                        else:
                            victim.symlink_to(foreign)
                    return original_parser(*args, **kwargs)
                def reject_foreign_open(path, *args, **kwargs):
                    if path.resolve() == foreign or (case == "fifo" and path == victim):
                        forbidden_reads.append(str(path))
                        raise AssertionError("profile parser reopened a foreign input after safe capture")
                    return original_open(path, *args, **kwargs)
                with mock.patch.object(self.initial, "load_target_cache", side_effect=rebind_then_parse), \
                        mock.patch.object(Path, "open", reject_foreign_open), \
                        self.assertRaises((authority.AuthorityError, OSError, ValueError)):
                    authority.InitialMethodMonitorInputs(root.resolve(), self.initial, tool.resolve(),
                                                         cache, csv_path, p2p)
                self.assertTrue(rebound, "the actual cache parser boundary must be exercised")
                self.assertEqual([], forbidden_reads)
                self.assertEqual(foreign_bytes, foreign.read_bytes())
                self.assertFalse((root / "99-output-ztp/configuration-methods").exists())

    def test_f02_managed_main_pending_precedes_writes_and_failed_cycle_revokes(self):
        authority = load_script("f02_managed_initial_main_authority", ROOT / "ztp/config_sync_authority.py")
        cycle_type = getattr(authority, "ManagedInitialMethodCycle", None)
        self.assertTrue(callable(cycle_type), "managed initial main must produce its own causal receipt")
        with tempfile.TemporaryDirectory(prefix="f02-managed-initial-main-") as directory:
            root, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            root = root.resolve()
            tool, ib_csv, p2p = tool.resolve(), ib_csv.resolve(), p2p.resolve()
            ib_csv.write_text("hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw,config_method\n"
                              "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,02:00:00:00:00:01,,,,initial-setup\n"
                              "EXAMPLE-JUMP01,eth_jump,192.0.2.10,,,,,,,\n")
            private = root / ".ssh/id_ed25519"
            private.parent.mkdir(mode=0o700)
            private.write_text("fixture identity")
            private.chmod(0o600)
            cache = cache.parent.resolve() / cache.name
            state = ("nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                     "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                     "nv set system hostname EXAMPLE-IB01\n"
                     "nv set system dns server 203.0.113.53\n"
                     "nv set system ntp server ntp.ubuntu.com\n"
                     "nv set system ntp server time.ib.example.test\n"
                     "nv set system date-time timezone Asia/Taipei\n")
            storage = root / "99-output-ztp/configuration-methods"
            basis = {"schema_version": 1, "type": "ib", "config_method": "initial-setup", "hostname": "EXAMPLE-IB01",
                     "eth0": "203.0.113.2/24", "eth0_gateway": "203.0.113.1", "eth1": "", "eth1_gateway": "",
                     "eth0_mac": "02:00:00:00:00:01", "dns": ["203.0.113.53"],
                     "ntp": ["ntp.ubuntu.com", "time.ib.example.test"], "timezone": "Asia/Taipei",
                     "key_fingerprints": sorted([fingerprint(laptop), fingerprint(management)])}
            expected_input = hashlib.sha256(json.dumps(basis, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
            for cycle in (1, 2, 3, 4, 5):
                if cycle == 4:
                    ib_csv.write_text(ib_csv.read_text().replace("203.0.113.3", "203.0.113.2"))
                executor = cycle_type(root, self.initial)
                current_tool = tool
                if cycle == 5:
                    current_tool = root / "99-output-ib_nvl/bringup/xdr-initial-setup"
                    current_tool.mkdir(parents=True)
                    (current_tool / "01-global.yaml").symlink_to((tool / "01-global.yaml").resolve())
                    (current_tool / "publickey").symlink_to((tool / "publickey").resolve())
                def device_boundary(*args, **kwargs):
                    current = authority.read_method_current(storage, "EXAMPLE-IB01")
                    self.assertEqual((cycle, "pending", True), tuple(current[name] for name in ("generation", "state", "veto")))
                    if cycle == 2:
                        raise self.initial.SetupError("independent transport failure")
                    return self.initial.SessionResult(state, 0)
                def batch_observer(target, user, key, timeout, services, keys):
                    if cycle == 3:
                        ib_csv.write_text(ib_csv.read_text().replace("203.0.113.2", "203.0.113.3"))
                    return {"schema_version": 1, "hostname": "EXAMPLE-IB01", "batch_identity_verified": True,
                            "config_verified": True, "interface": "eth0", "transport_ip": "203.0.113.2",
                            "mac_plain": "020000000001", "live_state_sha256": hashlib.sha256(state.encode()).hexdigest(),
                            "input_sha256": expected_input, "observation_sha256": "b" * 64, "reason": ""}
                neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:01")
                with ExitStack() as stack:
                    stack.enter_context(mock.patch.dict(os.environ, {"NVOS_INITIAL_PASSWORD": "fixture"}))
                    for name, value in (("local_ethernet_keys", set()), ("prompt_ethernet_passwords", {"example-jump01": "fixture"}),
                            ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "table")),
                            ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                            ("save_ethernet_snapshot", root / "snapshot"), ("interface_status_line", "swp7 up"),
                            ("interface_oper_status", "up"), ("fdb_port_for_interface", "swp7"),
                            ("neighbor_for_port", neighbor), ("interface_vrf", "default")):
                        stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                    stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))
                    stack.enter_context(mock.patch.object(self.initial, "verify_management_key_possession"))
                    stack.enter_context(mock.patch.object(self.initial, "observe_managed_initial_configuration", side_effect=batch_observer))
                    result = self.run_initial(current_tool, ib_csv, p2p, cache, "--apply", "--yes", "--execution-mode", "management",
                                              method_cycle=executor,
                                              managed_entry=authority.managed_initial_main if cycle in (4, 5) else None,
                                              managed_tool_inputs=current_tool if cycle == 5 else None)
                current = authority.read_method_current(storage, "EXAMPLE-IB01")
                self.assertEqual((cycle, "success" if cycle in (1, 4, 5) else "failed", cycle not in (1, 4, 5)),
                                 tuple(current[name] for name in ("generation", "state", "veto")))
                self.assertEqual(0 if cycle in (1, 4, 5) else 1, result)
                receipt = authority.read_method_receipt(storage, "EXAMPLE-IB01")
                self.assertEqual(cycle in (1, 4, 5), receipt is not None)
                if receipt:
                    self.assertEqual("initial_setup_managed", receipt["trigger_source"])
                    self.assertNotIn("complete", receipt)

    def test_f02_managed_input_and_output_scope_is_checked_before_leaf_outputs(self):
        authority = load_script("f02_managed_input_output_scope", ROOT / "ztp/config_sync_authority.py")
        for case in ("csv", "p2p", "cache", "snapshot"):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as directory:
                base = Path(directory).resolve()
                root, tool, _, csv_path, p2p, _, cache, _, _ = self.fixture(str(base / "project"))
                csv_path.write_text(csv_path.read_text().replace("eth1_gw\n", "eth1_gw,config_method\n")
                    .replace("203.0.113.1,,,,\n", "203.0.113.1,,,,,initial-setup\n")
                    .replace("192.0.2.10,,,,,,\n", "192.0.2.10,,,,,,,\n"))
                foreign = base / "foreign"
                foreign.mkdir()
                if case == "csv":
                    outside_csv = foreign / "ib.csv"
                    outside_csv.write_bytes(csv_path.read_bytes())
                    csv_path = outside_csv
                if case == "p2p":
                    outside_p2p = foreign / "p2p.dot"
                    outside_p2p.write_bytes(p2p.read_bytes())
                    p2p = outside_p2p
                if case == "cache": cache = foreign / "out/targets.json"
                extra = ["--snapshot-dir", str(foreign / "snapshots")] if case == "snapshot" else []
                before = {str(path.relative_to(foreign)): path.read_bytes() for path in foreign.rglob("*") if path.is_file()}
                cycle = authority.ManagedInitialMethodCycle(root.resolve(), self.initial)
                with self.assertRaises((self.initial.SetupError, authority.AuthorityError, ValueError)), \
                        mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()):
                    self.run_initial(tool, csv_path, p2p, cache, "--apply", "--yes", "--execution-mode", "management", *extra,
                                     method_cycle=cycle)
                self.assertFalse((root / "out").exists(), "reject before local report/cache publication")
                self.assertFalse((root / "99-output-ztp").exists(), "reject before minting a method era")
                self.assertEqual(before, {str(path.relative_to(foreign)): path.read_bytes() for path in foreign.rglob("*") if path.is_file()})

    def test_f02_managed_method_admission_rejects_before_outputs(self):
        authority = load_script("f02_managed_initial_admission", ROOT / "ztp/config_sync_authority.py")
        for method in ("ztp", "", "initial-setup"):
            with self.subTest(method=method), tempfile.TemporaryDirectory() as directory:
                root, tool, _, csv_path, p2p, _, cache, _, _ = self.fixture(directory)
                if method:
                    csv_path.write_text(csv_path.read_text().replace("eth1_gw\n", "eth1_gw,config_method\n")
                        .replace("203.0.113.1,,,,\n", "203.0.113.1,,,,," + method + "\n")
                        .replace("192.0.2.10,,,,,,\n", "192.0.2.10,,,,,,,\n"))
                # Neither an incompatible/default method nor check-only mode
                # may create the method namespace or ancillary output dirs.
                cycle = authority.ManagedInitialMethodCycle(root.resolve(), self.initial)
                with self.assertRaises(self.initial.SetupError):
                    self.run_initial(tool, csv_path, p2p, cache, "--plan" if method == "initial-setup" else "--apply", method_cycle=cycle)
                self.assertFalse(cache.parent.exists(), "admission must precede report/cache writes")
                self.assertFalse((root / "99-output-ztp").exists())

    def run_initial(self, tool: Path, ib_csv: Path, p2p: Path,
                    cache: Path, *extra: str, method_cycle=None, managed_entry=None, managed_tool_inputs=None) -> int:
        argv = [
            "initial-setup.py", "--ib-csv", str(ib_csv), "--p2p", str(p2p),
            "--target-cache", str(cache), "--report", str(cache.parent / "report.log"),
            "--snapshot-dir", str(cache.parent / "snapshots"), *extra,
        ]
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(sys, "argv", argv))
            if method_cycle is None:
                stack.enter_context(mock.patch.object(self.initial, "__file__", str(tool / "initial-setup.py")))
            else:
                self.assertEqual(ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
                                 Path(self.initial.__file__), "managed entry executes repository code, not a project copy")
            stack.enter_context(mock.patch.object(Path, "home", return_value=method_cycle.project if method_cycle else tool.parents[2]))
            stack.enter_context(redirect_stdout(io.StringIO()))
            if managed_entry is not None:
                # Execute the real CLI loader and freshly loaded main. Replace
                # ONLY device I/O boundaries, never __file__, profiles or main.
                from importlib.machinery import SourceFileLoader
                real_exec = SourceFileLoader.exec_module
                def isolated_device_io(loader, module):
                    real_exec(loader, module)
                    if module.__name__ == "_http_managed_initial_setup":
                        for name in ("local_ethernet_keys", "prompt_ethernet_passwords", "collect_ethernet_interfaces",
                                     "collect_ethernet_network_tables", "save_ethernet_snapshot", "interface_status_line",
                                     "interface_oper_status", "fdb_port_for_interface", "neighbor_for_port", "interface_vrf",
                                     "run_on_ib", "verify_management_key_possession", "observe_managed_initial_configuration"):
                            setattr(module, name, getattr(self.initial, name))
                stack.enter_context(mock.patch.object(SourceFileLoader, "exec_module", isolated_device_io))
            try:
                if managed_entry is not None:
                    profile_args = ["--tool-inputs", str(managed_tool_inputs)] if managed_tool_inputs is not None else []
                    return managed_entry(["--project", str(method_cycle.project), *profile_args, "--", *argv[1:]])
                return self.initial.main() if method_cycle is None else self.initial.main(method_cycle=method_cycle)
            finally:
                report = self.initial.REPORT_HANDLE
                if report is not None:
                    report.close()
                    self.initial.REPORT_HANDLE = None

    def drive_one_device(self, first_state: str, verified_state: str,
                         *extra: str, remove_global_before_p1: bool = False,
                         remove_global_before_p2: bool = False,
                         post_service_state: str | None = None):
        """Exercise real P1/cache/P2 control flow with only the network boundary faked."""
        with tempfile.TemporaryDirectory(prefix="req10b-device-flow-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            if remove_global_before_p1:
                global_path.unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            if remove_global_before_p2 and global_path.exists():
                global_path.unlink()
            commands: list[tuple[str, ...]] = []
            shows = 0

            def device_boundary(*args, **_kwargs):
                nonlocal shows
                command = tuple(args[7])
                commands.append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    shows += 1
                    output = first_state if shows == 1 else verified_state
                    if shows > 2 and post_service_state is not None:
                        output = post_service_state
                    return self.initial.SessionResult(output, 0)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            local_jump = {"example-jump01"} if "ethernet" in extra else set()
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", local_jump),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                    ("verify_ipv4_login", None),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary))
                try:
                    result = self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password", *extra,
                    )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            return result, commands, (cache.parent / "report.log").read_text(encoding="utf-8"), laptop, management

    @staticmethod
    def rewrite_cache_with_matching_sidecar(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii"
        )

    def test_real_generator_and_initial_p1_agree_on_whitelisted_ib_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-p1-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with mock.patch.object(self.generator, "_GLOBAL_FILE", str(global_path)):
                merged = self.generator.load_global("ib")
            self.assertEqual(list(EXPECTED_IB["dns"]), merged["system"]["dns"]["server"])
            self.assertEqual(list(EXPECTED_IB["ntp"]), merged["system"]["ntp"]["server"])
            self.assertEqual(EXPECTED_IB["timezone"], merged["system"]["date-time"]["timezone"])
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(4, payload["version"])
            values = set(scalar_strings(payload))
            for expected in (*EXPECTED_IB["dns"], *EXPECTED_IB["ntp"], EXPECTED_IB["timezone"]):
                self.assertIn(expected, values)
            for superseded in ("192.0.2.53", "198.51.100.53", "time.common.example.test"):
                self.assertNotIn(superseded, values, "deep merge replaces an entire key, not its members")
            self.assertNotIn("domain", json.dumps(payload))
            self.assertNotIn("search", json.dumps(payload))

    def test_p1_cache_bakes_full_valid_public_lines_and_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, management = self.fixture(directory)
            self.loader.validate_pubkey(pubdir / "laptop.pub")
            self.loader.validate_pubkey(pubdir / "mgmt-server.pub")
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            for line in (laptop, management):
                self.assertIn(line.strip(), {value.strip() for value in values})
                self.assertIn(fingerprint(line), values)

    def test_newer_project_public_key_invalidates_management_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-pubkey-freshness-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            old_cache = cache.read_bytes()
            replacement = public_key(25, "rotated-laptop")
            path = pubdir / "laptop.pub"
            path.write_text(replacement, encoding="ascii")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(old_cache, cache.read_bytes())
            values = set(scalar_strings(json.loads(cache.read_text(encoding="utf-8"))))
            self.assertIn(fingerprint(replacement), values)
            self.assertNotIn(fingerprint(laptop), values)

    def test_management_never_reuses_cache_baked_from_open_ssh_invalid_rsa(self) -> None:
        """A matching v4 checksum and old mtime do not waive P1 key validation."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        for mode in ("management", "auto"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory(
                prefix="req10b-rsa-cached-"
            ) as directory:
                _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
                rogue = pubdir / "other.pub"
                rogue.write_text(malformed, encoding="ascii")
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["public_keys"].append({
                    "name": "other.pub", "line": malformed.strip(),
                    "fingerprint": fingerprint(malformed),
                })
                self.rewrite_cache_with_matching_sidecar(cache, payload)
                older = cache.stat().st_mtime_ns - 2_000_000_000
                os.utime(rogue, ns=(older, older))
                before = (cache.stat().st_ino, cache.read_bytes())
                extra = ("--plan", "--execution-mode", "management") if mode == "management" else ("--plan",)
                with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                     mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                    with self.assertRaises(self.initial.SetupError):
                        self.run_initial(tool, ib_csv, p2p, cache, *extra)
                self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_newer_global_invalidates_management_cache_and_rebakes_services(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-freshness-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), original["global"])
            global_path.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.66"),
                                   encoding="utf-8")
            newer = cache.stat().st_mtime_ns + 2_000_000_000
            os.utime(global_path, ns=(newer, newer))
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(global_path.resolve()), payload["global"])
            self.assertIn("203.0.113.66", set(scalar_strings(payload)))
            self.assertNotIn("203.0.113.53", set(scalar_strings(payload)))

    def test_management_rejects_rechecksummed_cache_with_wrong_global_source(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-binding-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["global"] = str(global_path.with_name("different-global.yaml"))
            self.rewrite_cache_with_matching_sidecar(cache, payload)
            before = cache.read_bytes()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(before, cache.read_bytes())
            self.assertEqual(str(global_path.resolve()),
                             json.loads(cache.read_text(encoding="utf-8"))["global"])

    def test_global_retarget_to_older_project_file_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-global-retarget-") as directory:
            root, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            replacement = root / "old-project-global.yaml"
            replacement.write_text(GLOBAL.replace("203.0.113.53", "203.0.113.67"),
                                   encoding="utf-8")
            older = cache.stat().st_mtime_ns - 2_000_000_000
            os.utime(replacement, ns=(older, older))
            global_path.unlink()
            global_path.symlink_to(replacement)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "management"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertEqual(str(replacement.resolve()), payload["global"])
            self.assertIn("203.0.113.67", set(scalar_strings(payload)))

    def test_ethernet_leaf_keeps_baked_keys_when_project_key_link_is_unavailable(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-baked-keys-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            (tool / "publickey").unlink()
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache,
                                                 "--plan", "--execution-mode", "ethernet"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_ethernet_p2_reuses_baked_keys_without_ssh_keygen_even_if_source_is_visible(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-no-keygen-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            with mock.patch.object(self.initial.subprocess, "run", side_effect=AssertionError(
                "P2 cache consumption must not spawn ssh-keygen"
            )) as external:
                self.assertEqual(0, self.run_initial(
                    tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet"
                ))
            external.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)

    def test_auto_manager_missing_both_sources_rebakes_instead_of_using_stale_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-manager-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            original = cache.read_bytes()
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="MGMT-SERVER"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="MGMT-SERVER"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: generated", report)
            self.assertNotEqual(original, cache.read_bytes())
            payload = json.loads(cache.read_text(encoding="utf-8"))
            self.assertIsNone(payload["global"])
            self.assertIsNone(payload["services"])
            self.assertEqual([], payload["public_keys"])
            self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)

    def test_auto_leaf_missing_both_sources_reuses_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-auto-leaf-") as directory:
            _, tool, global_path, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            before = (cache.stat().st_ino, cache.read_bytes())
            global_path.unlink()
            (tool / "publickey").unlink()
            with mock.patch.object(self.initial.socket, "gethostname", return_value="EXAMPLE-JUMP01"), \
                 mock.patch.object(self.initial.socket, "getfqdn", return_value="EXAMPLE-JUMP01"):
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertIn("Target cache: reused", report)
            self.assertIn(fingerprint(laptop), report)
            self.assertIn(fingerprint(management), report)
            self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))

    def test_p1_rejects_a_public_key_rejected_by_real_loader(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-invalid-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            invalid = pubdir / "other.pub"
            invalid.write_text("ssh-ed25519 invalid!!!\n", encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(invalid)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "invalid project key must not publish a target cache")

    def test_p1_refuses_rsa_shape_rejected_by_real_loader_before_cache_publication(self) -> None:
        """Real load acceptance and real P1 publication must agree for RSA."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-rsa-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, _, _ = self.fixture(directory)
            key = pubdir / "other.pub"
            key.write_text(malformed, encoding="ascii")
            with self.assertRaises(self.loader.LoadError):
                self.loader.validate_pubkey(key)
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "P1 must not bake a key that load rejects")

    def test_p1_refuses_valid_then_invalid_multiline_key_before_cache_publication(self) -> None:
        """P1 must validate every public line before publishing a shared cache."""
        def field(data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + data

        malformed = "ssh-rsa " + base64.b64encode(
            field(b"ssh-rsa") + field(b"\x01")
        ).decode("ascii") + " malformed-rsa\n"
        with tempfile.TemporaryDirectory(prefix="req10b-mixed-p1-") as directory:
            _, tool, _, ib_csv, p2p, pubdir, cache, laptop, _ = self.fixture(directory)
            (pubdir / "laptop.pub").write_text(laptop + malformed, encoding="ascii")
            with self.assertRaises(self.initial.SetupError):
                self.run_initial(tool, ib_csv, p2p, cache, "--generate-json")
            self.assertFalse(cache.exists(), "a bad second line must not enter target cache")

    def test_plan_lists_day0_services_and_complete_key_install_without_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-plan-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            with mock.patch.object(self.initial, "run_on_ib") as network:
                self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--plan"))
            network.assert_not_called()
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            for command in (
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
                "nv set system dns server 203.0.113.53",
                "nv set system ntp server ntp.ubuntu.com",
                "nv set system ntp server time.ib.example.test",
                "nv set system date-time timezone Asia/Taipei",
                "nv config apply",
                "nv config save",
            ):
                with self.subTest(command=command):
                    self.assertIn(command, report)
            expected_public_payload = base64.b64encode(
                (laptop + management).encode("utf-8")
            ).decode("ascii")
            self.assertIn("authorized_keys", report)
            self.assertIn(expected_public_payload, report,
                          "the plan must retain both complete public lines, not just fingerprints")

    def test_configured_day0_still_enters_independent_service_transaction(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-configured-p2-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            commands: list[tuple[str, ...]] = []
            current = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                commands.append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    applied = ("nv", "config", "apply") in commands
                    return self.initial.SessionResult(current + (services if applied else ""), 0)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}), \
                 mock.patch.object(self.initial, "local_ethernet_keys", return_value=set()), \
                 mock.patch.object(self.initial, "prompt_ethernet_passwords", return_value={"example-jump01": "eth-password"}), \
                 mock.patch.object(self.initial, "collect_ethernet_interfaces", return_value=("EXAMPLE-JUMP01", "interface table")), \
                 mock.patch.object(self.initial, "collect_ethernet_network_tables", return_value=("links", "fdb", "neighbors")), \
                 mock.patch.object(self.initial, "save_ethernet_snapshot", return_value=cache.parent / "snapshot.txt"), \
                 mock.patch.object(self.initial, "interface_status_line", return_value="swp7 up"), \
                 mock.patch.object(self.initial, "interface_oper_status", return_value="up"), \
                 mock.patch.object(self.initial, "fdb_port_for_interface", return_value="swp7"), \
                 mock.patch.object(self.initial, "neighbor_for_port", return_value=neighbor), \
                 mock.patch.object(self.initial, "interface_vrf", return_value="default"), \
                 mock.patch.object(self.initial, "run_on_ib", side_effect=device_boundary):
                try:
                    self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password",
                    )
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertNotIn(
                ("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands,
                "configured Day-0 fields must not be rewritten",
            )
            self.assertIn(
                ("nv", "set", "system", "dns", "server", "203.0.113.53"), commands,
                "configured Day-0 must not skip missing services",
            )
            self.assertIn(("nv", "config", "apply"), commands)
            self.assertIn(("nv", "config", "save"), commands)
            self.assertIn("day0-skipped=1", (cache.parent / "report.log").read_text(encoding="utf-8"))
            self.assertIn("services-skipped=0", (cache.parent / "report.log").read_text(encoding="utf-8"))

    def _exercise_upgrade_rerun(self, missing_services: tuple[str, ...],
                                *, suppress_service_stage: bool = False,
                                wipe_day0: bool = False,
                                suppress_day0_detection: bool = False) -> None:
        """Run the real setup three times against one isolated device state."""
        with tempfile.TemporaryDirectory(prefix="req10b-upgrade-rerun-") as directory:
            root, tool, _, ib_csv, p2p, _, cache, laptop, management = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            day0 = [
                "nv set interface eth0 ipv4 address 203.0.113.2/24",
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1",
                "nv set system hostname EXAMPLE-IB01",
            ]
            day0_argv = [tuple(line.split()) for line in day0]
            service_argv = [
                ("nv", "set", "system", "dns", "server", "203.0.113.53"),
                ("nv", "set", "system", "ntp", "server", "ntp.ubuntu.com"),
                ("nv", "set", "system", "ntp", "server", "time.ib.example.test"),
                ("nv", "set", "system", "date-time", "timezone", "Asia/Taipei"),
            ]
            service_lines = [" ".join(command) for command in service_argv]
            self.assertTrue(set(missing_services) <= set(service_lines))
            running = day0 + service_lines
            pending: list[str] = []
            rounds: list[list[tuple[str, ...]]] = []
            device_home = root / "fake-device-home"
            device_home.mkdir()
            ssh_dir = device_home / ".ssh"
            ssh_dir.mkdir()
            authorized = ssh_dir / "authorized_keys"
            authorized.write_text(laptop + management, encoding="ascii")
            original_keys = (authorized.stat().st_ino, authorized.read_bytes())

            def device_boundary(*args, **_kwargs):
                command = tuple(args[7])
                rounds[-1].append(command)
                if command == ("nv", "config", "show", "-o", "commands"):
                    return self.initial.SessionResult("\n".join(running) + "\n", 0)
                if command in service_argv or command in day0_argv:
                    pending.append(" ".join(command))
                elif command == ("nv", "config", "apply"):
                    for line in pending:
                        if line not in running:
                            running.append(line)
                    pending.clear()
                elif command[:2] == ("sh", "-c"):
                    result = subprocess.run(
                        command, cwd=root,
                        env={"HOME": str(device_home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")},
                        capture_output=True, text=True, timeout=10, check=False,
                    )
                    self.assertEqual(0, result.returncode, result.stderr)
                return self.initial.SessionResult("", 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                ipv4_verify = stack.enter_context(mock.patch.object(self.initial, "verify_ipv4_login"))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                    ("run_on_ib", mock.DEFAULT),
                ):
                    if name == "run_on_ib":
                        stack.enter_context(mock.patch.object(self.initial, name, side_effect=device_boundary))
                    else:
                        stack.enter_context(mock.patch.object(self.initial, name, return_value=value))

                def invoke() -> str:
                    rounds.append([])
                    self.assertEqual(0, self.run_initial(
                        tool, ib_csv, p2p, cache, "--apply", "--yes",
                        "--ethernet-password", "eth-password",
                    ))
                    return (cache.parent / "report.log").read_text(encoding="utf-8")

                first_report = invoke()
                self.assertIn("day0-skipped=1", first_report)
                self.assertIn("services-skipped=1", first_report)
                self.assertFalse(any(command in day0_argv for command in rounds[0]))
                self.assertFalse(any(command in service_argv for command in rounds[0]))
                self.assertNotIn(("nv", "config", "apply"), rounds[0])
                self.assertNotIn(("nv", "config", "save"), rounds[0])
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                if wipe_day0:
                    running.clear()
                else:
                    running[:] = [line for line in running if line not in missing_services]
                if suppress_service_stage:
                    with mock.patch.object(self.initial, "run_service_stage", return_value=(True, True)):
                        second_report = invoke()
                elif suppress_day0_detection:
                    with mock.patch.object(self.initial, "state_is_unconfigured", return_value=False):
                        second_report = invoke()
                else:
                    second_report = invoke()
                self.assertEqual(day0, running[:len(day0)],
                                 "upgrade rerun did not restore Day-0 state")
                self.assertEqual(
                    set(service_lines), set(running) - set(day0),
                    "upgrade rerun did not restore all desired service state",
                )
                self.assertEqual(len(day0) + len(service_lines), len(running),
                                 "upgrade rerun must not duplicate desired service values")
                self.assertIn(f"day0-skipped={0 if wipe_day0 else 1}", second_report)
                self.assertIn("services-skipped=0", second_report)
                if wipe_day0:
                    self.assertEqual(day0_argv, [command for command in rounds[1]
                                                  if command in day0_argv])
                    transaction_commands = set(day0_argv + service_argv) | {
                        ("nv", "config", "apply"), ("nv", "config", "save")
                    }
                    self.assertEqual(
                        day0_argv + [("nv", "config", "apply"), ("nv", "config", "save")]
                        + service_argv + [("nv", "config", "apply"), ("nv", "config", "save")],
                        [command for command in rounds[1] if command in transaction_commands],
                        "upgrade rerun must commit Day-0 before the separate service transaction",
                    )
                    self.assertEqual(1, ipv4_verify.call_count)
                else:
                    self.assertFalse(any(command in day0_argv for command in rounds[1]))
                    self.assertEqual(0, ipv4_verify.call_count)
                self.assertEqual(
                    [command for command in service_argv if " ".join(command) in missing_services],
                    [command for command in rounds[1] if command in service_argv],
                    "upgrade rerun must write only missing service values",
                )
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "apply")))
                self.assertEqual(2 if wipe_day0 else 1,
                                 rounds[1].count(("nv", "config", "save")))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))

                third_report = invoke()
                self.assertIn("day0-skipped=1", third_report)
                self.assertIn("services-skipped=1", third_report)
                self.assertFalse(any(command in day0_argv for command in rounds[2]))
                self.assertFalse(any(command in service_argv for command in rounds[2]))
                self.assertNotIn(("nv", "config", "apply"), rounds[2])
                self.assertNotIn(("nv", "config", "save"), rounds[2])
                self.assertEqual(day0, running[:len(day0)])
                self.assertEqual(set(service_lines), set(running[len(day0):]))
                self.assertEqual(len(day0) + len(service_lines), len(running))
                self.assertEqual(original_keys, (authorized.stat().st_ino, authorized.read_bytes()))
                self.assertEqual(1 if wipe_day0 else 0, ipv4_verify.call_count)

    def test_upgrade_wipe_then_rerun_restores_only_missing_services_and_keeps_keys(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        for missing in (services, (services[0], services[-1])):
            with self.subTest(missing=missing):
                self._exercise_upgrade_rerun(missing)

    def test_upgrade_rerun_oracle_rejects_skipping_missing_services(self) -> None:
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore"):
            self._exercise_upgrade_rerun(
                ("nv set system dns server 203.0.113.53",),
                suppress_service_stage=True,
            )

    def test_upgrade_full_day0_and_services_wipe_restores_two_transactions_then_is_idempotent(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        self._exercise_upgrade_rerun(services, wipe_day0=True)

    def test_upgrade_full_wipe_oracle_rejects_skipping_day0_restoration(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53",
            "nv set system ntp server ntp.ubuntu.com",
            "nv set system ntp server time.ib.example.test",
            "nv set system date-time timezone Asia/Taipei",
        )
        with self.assertRaisesRegex(AssertionError, "upgrade rerun did not restore Day-0 state"):
            self._exercise_upgrade_rerun(
                services, wipe_day0=True, suppress_day0_detection=True,
            )

    def test_day0_verification_failure_never_enters_services(self) -> None:
        _, commands, report, _, _ = self.drive_one_device("", "")
        self.assertIn("post-configuration verification failed", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "ntp")
                             for command in commands))

    def test_fresh_day0_success_flows_into_service_transaction(self) -> None:
        day0 = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "", day0, post_service_state=day0 + services,
        )
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "interface", "eth0", "ipv4", "address",
                       "203.0.113.2/24"), commands)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)

    def test_missing_global_permits_day0_and_reports_service_skip(self) -> None:
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            "", verified, remove_global_before_p1=True,
        )
        self.assertEqual(0, result, report)
        self.assertIn("Services SKIP: 01-global.yaml was unavailable", report)
        self.assertIn("services-skipped=1", report)
        self.assertFalse(any(command[:4] == ("nv", "set", "system", "dns")
                             for command in commands))

    def test_ethernet_p2_uses_baked_services_without_global_or_yaml_library(self) -> None:
        configured = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
        )
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, _, _ = self.drive_one_device(
            configured, configured + services,
            "--execution-mode", "ethernet", remove_global_before_p2=True,
        )
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "system", "dns", "server", "203.0.113.53"), commands)
        self.assertIn("Services SUCCESS: desired values verified", report)
        self.assertIn("Local Ethernet execution: example-jump01", report)

    def test_ethernet_mode_names_stale_v3_cache_and_preserves_both_inodes(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-leaf-v3-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            payload["version"] = 3
            raw = (json.dumps(payload, sort_keys=True) + "\n").encode()
            cache.write_bytes(raw)
            sidecar = cache.with_name(cache.name + ".sha256")
            sidecar.write_text(f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n", encoding="ascii")
            before = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            with self.assertRaisesRegex(self.initial.SetupError, "(?i)version|版本"):
                self.run_initial(tool, ib_csv, p2p, cache, "--plan", "--execution-mode", "ethernet")
            after = (cache.stat().st_ino, cache.read_bytes(), sidecar.stat().st_ino, sidecar.read_bytes())
            self.assertEqual(before, after, "stale cache evidence must not be silently rewritten")

    def test_force_fills_missing_day0_fields_without_rewriting_matching_fields(self) -> None:
        services = (
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        first = "nv set interface eth0 ipv4 address 203.0.113.2/24\n" + services
        verified = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n" + services
        )
        result, commands, report, _, _ = self.drive_one_device(first, verified, "--force")
        self.assertEqual(0, result, report)
        self.assertIn(("nv", "set", "system", "hostname", "EXAMPLE-IB01"), commands)
        self.assertIn(("nv", "config", "apply"), commands)
        self.assertIn(("nv", "config", "save"), commands)

    def test_force_refuses_mismatching_existing_eth0_without_day0_writes(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 198.51.100.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        _, commands, report, _, _ = self.drive_one_device(state, state, "--force")
        self.assertFalse(any(command[:3] == ("nv", "set", "interface") for command in commands))
        self.assertNotIn(("nv", "config", "apply"), commands)
        self.assertNotIn(("nv", "config", "save"), commands)
        self.assertRegex(report.lower(), "mismatch|conflict|differs")

    def test_p2_installs_baked_keys_through_nested_device_boundary(self) -> None:
        state = (
            "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
            "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
            "nv set system hostname EXAMPLE-IB01\n"
            "nv set system dns server 203.0.113.53\n"
            "nv set system ntp server ntp.ubuntu.com\n"
            "nv set system ntp server time.ib.example.test\n"
            "nv set system date-time timezone Asia/Taipei\n"
        )
        result, commands, report, laptop, management = self.drive_one_device(state, state)
        self.assertEqual(0, result, report)
        self.assertTrue(any("authorized_keys" in " ".join(command) for command in commands),
                        "the keys must be installed over the existing nested SSH boundary")
        self.assertIn(fingerprint(laptop), report)
        self.assertIn(fingerprint(management), report)

    def test_key_stage_verifies_only_matching_local_management_private_key(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-possession-") as directory:
            private = Path(directory) / "id_ed25519"
            private.write_text("test-only private-key placeholder\n", encoding="ascii")
            laptop = public_key(17, "laptop").strip()
            management = public_key(18, "management").strip()
            keys = [
                {"name": "laptop.pub", "line": laptop, "fingerprint": fingerprint(laptop)},
                {"name": "mgmt-server.pub", "line": management,
                 "fingerprint": fingerprint(management)},
            ]
            ib = self.initial.Device("EXAMPLE-IB01", "ib", "203.0.113.2",
                                     "203.0.113.2/24", "203.0.113.1", "", "", "")
            transit = self.initial.Device("EXAMPLE-JUMP01", "eth_jump", "192.0.2.10",
                                          "192.0.2.10", "", "", "", "")
            target = self.initial.Target(ib, transit, "swp7", "eth0")
            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            calls: list[list[str]] = []

            def key_boundary(argv, **_kwargs):
                calls.append(argv)
                if argv[0] == "ssh-keygen":
                    return subprocess.CompletedProcess(argv, 0, management + "\n", "")
                if argv[0] == "ssh":
                    return subprocess.CompletedProcess(argv, 0, "", "")
                self.fail(f"unexpected local command {argv}")

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)) as installer, \
                 mock.patch.object(subprocess, "run", side_effect=key_boundary), \
                 redirect_stdout(io.StringIO()) as output:
                self.assertTrue(self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=private,
                ))
            installer.assert_called_once()
            self.assertEqual(["ssh-keygen", "ssh"], [call[0] for call in calls])
            ssh = calls[1]
            self.assertIn("BatchMode=yes", ssh)
            self.assertIn("PreferredAuthentications=publickey", ssh)
            self.assertIn("PasswordAuthentication=no", ssh)
            self.assertIn("IdentitiesOnly=yes", ssh)
            self.assertEqual("true", ssh[-1])
            self.assertIn("laptop.pub", output.getvalue())
            self.assertIn("已写入，未验证", output.getvalue())
            self.assertIn("mgmt-server.pub", output.getvalue())
            self.assertIn("已验证", output.getvalue())

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)), \
                 mock.patch.object(subprocess, "run") as local_command, \
                 redirect_stdout(io.StringIO()) as no_private_output:
                self.initial.run_key_stage(
                    target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                    keys, local=False, apply=True, authorized=True,
                    management_private_key=None,
                )
            local_command.assert_not_called()
            self.assertEqual(2, no_private_output.getvalue().count("已写入，未验证"))

            with mock.patch.object(self.initial, "run_on_ib", return_value=self.initial.SessionResult("", 0)), \
                 mock.patch.object(subprocess, "run", return_value=subprocess.CompletedProcess(
                     ["ssh-keygen"], 0, laptop + "\n", ""
                 )) as wrong_key:
                with self.assertRaises(self.initial.SetupError):
                    self.initial.run_key_stage(
                        target, neighbor, "cumulus", "ethernet-password", "admin", 10,
                        keys, local=False, apply=True, authorized=True,
                        management_private_key=private,
                    )
            self.assertEqual(1, wrong_key.call_count,
                             "mismatched local private identity must fail before SSH")

    def test_key_failure_on_first_device_does_not_block_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-key-continue-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            state = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                if "authorized_keys" in " ".join(command):
                    attempted.append(target.ib.hostname)
                    if target.ib.hostname == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected key installation failure")
                output = state.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", target.ib.hostname
                )
                return self.initial.SessionResult(output, 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                try:
                    self.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                     "--ethernet-password", "eth-password")
                finally:
                    report = self.initial.REPORT_HANDLE
                    if report is not None:
                        report.close()
                        self.initial.REPORT_HANDLE = None
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)

    def test_service_failure_on_first_device_continues_to_second_device(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-service-continue-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            with ib_csv.open("a", encoding="utf-8") as stream:
                stream.write("EXAMPLE-IB02,ib,203.0.113.3,24,203.0.113.1,,,,\n")
            with p2p.open("a", encoding="utf-8") as stream:
                stream.write('"EXAMPLE-IB02":"eth0" -- "EXAMPLE-JUMP01":"8";\n')
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            attempted: list[str] = []
            applied: set[str] = set()
            day0 = (
                "nv set interface eth0 ipv4 address 203.0.113.2/24\n"
                "nv set interface eth0-1 ipv4 gateway 203.0.113.1\n"
                "nv set system hostname EXAMPLE-IB01\n"
            )
            services = (
                "nv set system dns server 203.0.113.53\n"
                "nv set system ntp server ntp.ubuntu.com\n"
                "nv set system ntp server time.ib.example.test\n"
                "nv set system date-time timezone Asia/Taipei\n"
            )

            def boundary(target, *_args, **_kwargs):
                command = tuple(_args[6])
                name = target.ib.hostname
                if command[:5] == ("nv", "set", "system", "dns", "server"):
                    attempted.append(name)
                    if name == "EXAMPLE-IB01":
                        raise self.initial.SetupError("injected service failure")
                if command == ("nv", "config", "apply"):
                    applied.add(name)
                output = day0.replace("203.0.113.2/24", target.ib.eth0_prefix).replace(
                    "EXAMPLE-IB01", name
                )
                if name in applied:
                    output += services
                return self.initial.SessionResult(output, 0)

            neighbor = self.initial.Neighbor("fe80::1", "swp7", "02:00:00:00:00:17")
            with ExitStack() as stack:
                stack.enter_context(mock.patch.dict("os.environ", {"NVOS_INITIAL_PASSWORD": "initial-password"}))
                for name, value in (
                    ("local_ethernet_keys", set()),
                    ("prompt_ethernet_passwords", {"example-jump01": "eth-password"}),
                    ("collect_ethernet_interfaces", ("EXAMPLE-JUMP01", "interface table")),
                    ("collect_ethernet_network_tables", ("links", "fdb", "neighbors")),
                    ("save_ethernet_snapshot", cache.parent / "snapshot.txt"),
                    ("interface_status_line", "swp7 up"),
                    ("interface_oper_status", "up"),
                    ("fdb_port_for_interface", "swp7"),
                    ("neighbor_for_port", neighbor),
                    ("interface_vrf", "default"),
                ):
                    stack.enter_context(mock.patch.object(self.initial, name, return_value=value))
                stack.enter_context(mock.patch.object(self.initial, "run_on_ib", side_effect=boundary))
                result = self.run_initial(tool, ib_csv, p2p, cache, "--apply", "--yes",
                                          "--ethernet-password", "eth-password")
            report = (cache.parent / "report.log").read_text(encoding="utf-8")
            self.assertEqual(1, result, report)
            self.assertEqual(["EXAMPLE-IB01", "EXAMPLE-IB02"], attempted)
            self.assertIn("injected service failure", report)
            self.assertIn("[EXAMPLE-IB02]", report)
            self.assertIn("Services SUCCESS: desired values verified", report)

    def test_leaf_rejects_rechecksummed_semantically_invalid_v4_before_dispatch(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10b-hostile-cache-") as directory:
            _, tool, _, ib_csv, p2p, _, cache, _, _ = self.fixture(directory)
            self.assertEqual(0, self.run_initial(tool, ib_csv, p2p, cache, "--generate-json"))
            valid = json.loads(cache.read_text(encoding="utf-8"))
            cases = {
                "key_type_blob_mismatch": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"].replace("ssh-ed25519 ", "ssh-rsa ", 1)
                ),
                "key_comment_nul": lambda value: value["public_keys"][0].update(
                    line=value["public_keys"][0]["line"] + "\x00comment"
                ),
                "dns_control_carrier": lambda value: value["services"].update(
                    dns=["203.0.113.53\nnv set system aaa user admin"]
                ),
                "unexpected_service_category": lambda value: value["services"].update(
                    aaa={"user": "admin"}
                ),
            }
            for label, mutate in cases.items():
                with self.subTest(label=label):
                    payload = json.loads(json.dumps(valid))
                    mutate(payload)
                    self.rewrite_cache_with_matching_sidecar(cache, payload)
                    before = (cache.stat().st_ino, cache.read_bytes())
                    with mock.patch.object(self.initial, "run_on_ib") as network:
                        with self.assertRaises(self.initial.SetupError):
                            self.run_initial(tool, ib_csv, p2p, cache,
                                             "--apply", "--yes", "--execution-mode", "ethernet")
                    network.assert_not_called()
                    self.assertEqual(before, (cache.stat().st_ino, cache.read_bytes()))


if __name__ == "__main__":
    unittest.main()
