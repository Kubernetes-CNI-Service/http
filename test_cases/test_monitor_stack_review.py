#!/usr/bin/env python3
"""Focused contracts for the monitor/GUI/worker and bring-up review."""

from __future__ import annotations

import importlib.util
from importlib.machinery import SourceFileLoader
from datetime import datetime
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        spec = importlib.util.spec_from_loader(name, SourceFileLoader(name, str(path)))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    old = sys.modules.get(name)
    sys.path.insert(0, str(path.parent))
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
        if old is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = old
    return module


REVIEWED_ENTRYPOINTS = {
    "DAY0-Prepare/12-ztp-monitor.py": "ZTP evidence correlation and rounds",
    "monitor/dot_to_html.py": "DOT topology conversion",
    "monitor/generate-monitor-html.py": "unified static monitor publication",
    "monitor/manual-ztp-control.cgi": "per-device control endpoint",
    "monitor/manual-ztp-worker.py": "preview/confirm/time-sync worker",
    "monitor/switch-collection-control.cgi": "switch collection endpoint",
    "monitor/switch-collection-worker.py": "switch collector worker",
    "monitor/switch_collection_gate.py": "cross-collector lock/cooldown",
    "monitor/ztp-monitor-control.cgi": "monitor pause/resume endpoint",
    "ethernet/monitor/cron.sh": "shared collection orchestrator",
    "ethernet/monitor/post-collect.py": "Ethernet closed-loop publisher",
    "ethernet/monitor/sw-info.sh": "atomic switch info snapshot",
    "ethernet/monitor/sw-link.sh": "atomic link snapshot",
    "infiniband/monitor/cron.sh": "IB shared orchestrator link",
    "infiniband/monitor/sw-info.sh": "IB shared info collector link",
    "infiniband/monitor/sw-link.sh": "IB shared link collector link",
    "nvlink/monitor/cron.sh": "NVLink shared orchestrator link",
    "nvlink/monitor/sw-info.sh": "NVLink shared info collector link",
    "nvlink/monitor/sw-link.sh": "NVLink shared link collector link",
    "infiniband/bringup/ndr/data-collect-IB.sh": "legacy MLNX-OS read-only collection",
    "infiniband/bringup/ndr/OS-CPLD-upgrade.sh": "guarded legacy destructive upgrade",
    "infiniband/bringup/xdr-initial-setup/initial-setup.py": "NVOS Day-0 setup",
    "infiniband/bringup/xdr-upgrade/upgrade.sh": "NVOS upgrade orchestration",
}


class EntrypointInventoryTests(unittest.TestCase):
    def test_review_inventory_exists_and_all_sources_parse(self):
        failures = []
        for relative in REVIEWED_ENTRYPOINTS:
            path = ROOT / relative
            self.assertTrue(path.is_file(), relative)
            if path.suffix == ".sh":
                result = subprocess.run(
                    ["bash", "-n", str(path)], cwd=ROOT, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    timeout=10, check=False,
                )
                if result.returncode:
                    failures.append(f"{relative}: {result.stdout}")
            else:
                try:
                    compile(path.read_bytes(), str(path), "exec")
                except (SyntaxError, UnicodeError) as exc:
                    failures.append(f"{relative}: {exc}")
        self.assertEqual([], failures)

    def test_ib_and_nvlink_collectors_are_exact_shared_links(self):
        for domain in ("infiniband", "nvlink"):
            for name in ("cron.sh", "sw-info.sh", "sw-link.sh"):
                self.assertTrue((ROOT / domain / "monitor" / name).is_symlink())
                self.assertEqual(
                    (ROOT / "ethernet/monitor" / name).resolve(),
                    (ROOT / domain / "monitor" / name).resolve(),
                )


class UnknownAndTransitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module(
            "monitor_stack_ztp", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )

    def test_true_unknown_retains_audit_ip_but_has_no_ssh_identity(self):
        item = {
            "mac": "02:00:00:00:00:99", "mac_plain": "020000000099",
            "platform": "unknown", "lease_state": "active",
            "ip": "192.0.2.99", "last_seen": "2026-08-31T10:00:00+00:00",
            "fingerprints": {"option60": "unrecognized"},
        }
        with mock.patch.object(
            self.monitor, "unknown_dhcp_devices", return_value=[item],
        ):
            rows = self.monitor.runtime_unknown_devices(
                Path("unused.csv"), "", scope="prod", dhcp_leases=None,
            )
        self.assertEqual(1, len(rows))
        device = rows[0]
        self.assertEqual("192.0.2.99", device["ip"])
        self.assertEqual([], device["ssh_ips"])
        self.assertEqual({}, device["ssh_interfaces"])
        self.assertEqual({}, device["candidate_identity"])
        self.assertFalse(device["ssh_collect_enabled"])
        self.assertEqual([], self.monitor.devices_for_switch_collection([device], {}))
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(
            self.monitor, "run_command",
            side_effect=AssertionError("unknown device attempted SSH"),
        ):
            result = self.monitor.collect_switch(
                device, 1, None, Path(directory) / "known_hosts",
            )
        self.assertEqual("ssh_disabled", result["kind"])
        self.assertEqual([], result["attempts"])

    def test_recognized_pending_nvos_keeps_mac_bound_candidate(self):
        item = {
            "mac": "02:00:00:00:00:42", "mac_plain": "020000000042",
            "platform": "nvos", "product": "QM9700", "serial": "S42",
            "lease_state": "observed", "ip": "192.0.2.42",
            "last_seen": "2026-08-31T10:00:00+00:00", "fingerprints": {},
        }
        with mock.patch.object(
            self.monitor, "unknown_dhcp_devices", return_value=[item],
        ):
            device = self.monitor.runtime_unknown_devices(
                Path("unused.csv"), "", scope="prod", dhcp_leases=None,
            )[0]
        self.assertEqual(["192.0.2.42"], device["ssh_ips"])
        self.assertEqual(
            {"192.0.2.42": ("dhcp", "020000000042")},
            device["candidate_identity"],
        )
        self.assertTrue(device["ssh_collect_enabled"])

    def test_oob_air_row_inherits_production_same_subnet_svi_fallback(self):
        csv_text = (
            "hostname,type,template,eth0_ip,netmask,eth0_mac,vlan_id,svi_ip,netmask\n"
            "AIR-EXAMPLE-OOB-Leaf01,air,oob,192.0.2.34,25,02:00:00:00:00:aa,,,\n"
            "EXAMPLE-OOB-Leaf01,eth,oob,192.0.2.34,25,02:00:00:00:00:bb,100,192.0.2.3,25\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            inventory = Path(directory) / "devices.csv"
            inventory.write_text(csv_text, encoding="utf-8")
            with mock.patch.object(
                self.monitor, "static_air_lease_fallbacks", return_value=[],
            ), mock.patch.object(
                self.monitor, "dynamic_air_devices", return_value=[],
            ):
                devices = {
                    item["hostname"]: item
                    for item in self.monitor.read_devices(inventory, "all")
                }
        air = devices["AIR-EXAMPLE-OOB-Leaf01"]
        self.assertEqual(["192.0.2.34", "192.0.2.3"], air["ssh_ips"])
        self.assertEqual("vlan100", air["ssh_interfaces"]["192.0.2.3"])
        self.assertEqual(
            ("eth0", "0200000000aa"),
            air["candidate_identity"]["192.0.2.3"],
        )


class ControlPlaneTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manual_cgi = load_module(
            "review_manual_cgi", ROOT / "monitor/manual-ztp-control.cgi"
        )
        cls.switch_cgi = load_module(
            "review_switch_cgi", ROOT / "monitor/switch-collection-control.cgi"
        )
        cls.ztp_cgi = load_module(
            "review_ztp_cgi", ROOT / "monitor/ztp-monitor-control.cgi"
        )
        cls.manual_worker = load_module(
            "review_manual_worker", ROOT / "monitor/manual-ztp-worker.py"
        )
        cls.manual = load_module(
            "review_manual_time_sync", ROOT / "ztp/manual-ztp.py"
        )
        cls.monitor = load_module(
            "review_monitor_time_sync", ROOT / "DAY0-Prepare/12-ztp-monitor.py"
        )
        cls.switch_worker = load_module(
            "review_switch_worker", ROOT / "monitor/switch-collection-worker.py"
        )

    def test_all_mutating_cgis_require_same_origin_and_support_fail_closed_auth(self):
        for endpoint in (self.manual_cgi, self.switch_cgi, self.ztp_cgi):
            with self.subTest(endpoint=endpoint.__name__):
                with mock.patch.dict(os.environ, {
                    "HTTP_HOST": "monitor.example:8443",
                    "HTTP_ORIGIN": "https://monitor.example:8443",
                    "HTTP_SEC_FETCH_SITE": "same-origin",
                }, clear=True):
                    self.assertEqual((True, ""), endpoint.post_control_guard())
                with mock.patch.dict(os.environ, {
                    "HTTP_HOST": "monitor.example",
                    "HTTP_ORIGIN": "https://attacker.example",
                    "HTTP_SEC_FETCH_SITE": "cross-site",
                }, clear=True):
                    self.assertFalse(endpoint.post_control_guard()[0])
                with mock.patch.dict(os.environ, {
                    "HTTP_HOST": "monitor.example",
                    "HTTP_ORIGIN": "https://monitor.example",
                    "CONTROL_REQUIRE_AUTH": "1",
                }, clear=True):
                    self.assertFalse(endpoint.post_control_guard()[0])
                    os.environ["REMOTE_USER"] = "operator"
                    self.assertEqual((True, ""), endpoint.post_control_guard())

    def test_control_files_reject_hardlinks_before_truncating(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_text("original\n", encoding="utf-8")
            linked = root / "linked"
            os.link(victim, linked)
            with mock.patch.object(self.ztp_cgi, "CONTROL_FILE", linked):
                with self.assertRaises(OSError):
                    self.ztp_cgi.write_control("paused")
            self.assertEqual("original\n", victim.read_text(encoding="utf-8"))
            with mock.patch.object(self.switch_cgi, "REQUEST_FILE", linked):
                with self.assertRaises(OSError):
                    self.switch_cgi.write_request("collect")
            self.assertEqual("original\n", victim.read_text(encoding="utf-8"))

    def test_manual_queue_rejects_hardlink_and_oversized_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            victim = root / "victim"
            victim.write_text('{"requests": []}\n', encoding="utf-8")
            linked = root / "request.json"
            os.link(victim, linked)
            with mock.patch.object(self.manual_cgi, "REQUEST_FILE", linked):
                with self.assertRaises(OSError):
                    self.manual_cgi.enqueue_request("EXAMPLE-Leaf01")
            self.assertEqual('{"requests": []}\n', victim.read_text(encoding="utf-8"))
            oversized = root / "oversized.json"
            oversized.write_bytes(b" " * (1024 * 1024 + 1))
            with mock.patch.object(self.manual_cgi, "REQUEST_FILE", oversized):
                with self.assertRaises(OSError):
                    self.manual_cgi.enqueue_request("EXAMPLE-Leaf01")

    def test_manual_queue_retains_busy_host_and_releases_other_host(self):
        payload = {"requests": [
            {"hostname": "EXAMPLE-LeafA", "action": "trigger", "phase": "preview"},
            {"hostname": "EXAMPLE-LeafB", "action": "trigger", "phase": "preview"},
        ]}
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request.json"
            request.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.object(self.manual_worker, "REQUEST_FILE", request):
                runnable = self.manual_worker.pop_requests({"example-leafa"})
            self.assertEqual(["EXAMPLE-LeafB"], [item["hostname"] for item in runnable])
            retained = json.loads(request.read_text(encoding="utf-8"))["requests"]
            self.assertEqual(["EXAMPLE-LeafA"], [item["hostname"] for item in retained])

    def test_switch_request_claim_never_erases_a_newer_action(self):
        with tempfile.TemporaryDirectory() as directory:
            request = Path(directory) / "request"
            request.write_text("stop\n", encoding="utf-8")
            with mock.patch.object(self.switch_worker, "REQUEST_FILE", request):
                self.assertEqual("", self.switch_worker.claim_request("collect"))
                self.assertEqual("stop\n", request.read_text(encoding="utf-8"))
                self.assertEqual("stop", self.switch_worker.claim_request("stop"))
                self.assertEqual("idle\n", request.read_text(encoding="utf-8"))

    def test_time_sync_is_independent_and_never_writes_a_ztp_round(self):
        writes = []

        def record(_hostname, state, **values):
            writes.append((state, values))

        completed = subprocess.CompletedProcess(
            ["time-sync"], 0,
            stdout=(
                '[TIME_SYNC_RESULT] {"state":"success",'
                '"offset_seconds":0.1,"uncertainty_seconds":0.2, '
                '"transport_ip":"192.0.2.10","interface":"eth0"}\n'
            ),
            stderr="",
        )
        with mock.patch.object(
            self.manual_worker, "write_device_status", side_effect=record,
        ), mock.patch.object(
            self.manual_worker, "command_for", return_value=["fixed-helper"],
        ), mock.patch.object(
            self.manual_worker.subprocess, "run", return_value=completed,
        ):
            self.manual_worker.execute_time_sync(
                "EXAMPLE-Leaf01", "prod", 30, "operation-1", "trigger-1",
            )
        self.assertEqual("time_sync_running", writes[0][0])
        self.assertEqual("time_sync_success", writes[-1][0])
        for _state, values in writes:
            self.assertTrue({"ztp_round", "baseline_round", "expected_round"}.isdisjoint(values))

    def test_time_sync_rejects_high_measurement_uncertainty(self):
        client = mock.Mock()
        client.args = SimpleNamespace(command_timeout=30, connect_timeout=5)
        client.run.side_effect = [
            subprocess.CompletedProcess(["helper"], 0, stdout="ok\n", stderr=""),
            subprocess.CompletedProcess(["date"], 0, stdout="1010.0\n", stderr=""),
        ]
        times = [
            datetime.fromtimestamp(1000),
            datetime.fromtimestamp(1020),
        ]
        with mock.patch.object(self.manual, "datetime") as mocked_datetime:
            mocked_datetime.now.side_effect = times
            with self.assertRaisesRegex(
                self.manual.ManualZtpError, "无法证明时间偏移不超过 5 秒",
            ):
                self.manual.sync_management_time(
                    client, {"hostname": "EXAMPLE-Leaf01"}, "192.0.2.10", "eth0",
                )

    def test_worker_rejects_success_payload_with_unsafe_time_bound(self):
        writes = []

        def record(_hostname, state, **values):
            writes.append((state, values))

        completed = subprocess.CompletedProcess(
            ["time-sync"], 0,
            stdout=(
                '[TIME_SYNC_RESULT] {"state":"success",'
                '"offset_seconds":0.0,"uncertainty_seconds":10.5, '
                '"transport_ip":"192.0.2.10","interface":"eth0"}\n'
            ),
            stderr="",
        )
        with mock.patch.object(
            self.manual_worker, "write_device_status", side_effect=record,
        ), mock.patch.object(
            self.manual_worker, "command_for", return_value=["fixed-helper"],
        ), mock.patch.object(
            self.manual_worker.subprocess, "run", return_value=completed,
        ):
            self.manual_worker.execute_time_sync(
                "EXAMPLE-Leaf01", "prod", 30, "operation-unsafe", "trigger-unsafe",
            )
        self.assertEqual("time_sync_running", writes[0][0])
        self.assertEqual("failed", writes[-1][0])
        self.assertIn("最坏偏移不超过 5 秒", writes[-1][1]["reason"])

    def test_monitor_marks_zero_midpoint_offset_with_high_uncertainty_warning(self):
        device = {
            "hostname": "EXAMPLE-Leaf01", "type": "eth", "ip": "192.0.2.10",
            "ssh_ips": ["192.0.2.10"],
            "ssh_interfaces": {"192.0.2.10": "eth0"},
            "mac_plain": "020000000001",
            "stages": {
                name: self.monitor.stage() for name in self.monitor.STAGE_NAMES
            },
            "issues": [], "events": [],
        }
        self.monitor.analyze_switch(device, {
            "kind": "ok", "observed_at": "2026-08-31T12:00:20+00:00",
            "connected_ip": "192.0.2.10", "attempts": [],
            "remote_hostname": "EXAMPLE-Leaf01",
            "remote_eth0_mac": "02:00:00:00:00:01",
            "remote_eth1_mac": "", "remote_interface_macs": {
                "eth0": "02:00:00:00:00:01",
            },
            "local_started_epoch": "1000", "local_finished_epoch": "1020",
            "remote_time_start": "1010", "remote_time_end": "1010",
            "boot_id": "boot-1", "boot_time": "1", "ztp_log": "",
            "ifreload_log": "", "failed_yaml": "", "stderr": "",
            "host_key_refreshed": False,
        })
        self.assertEqual("warning", device["time_sync"]["status"])
        self.assertEqual(0.0, device["time_sync"]["offset_seconds"])
        self.assertEqual(10.0, device["time_sync"]["uncertainty_seconds"])


class PublicationAndCollectorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = load_module(
            "review_generate_html", ROOT / "monitor/generate-monitor-html.py"
        )
        cls.dot = load_module(
            "review_dot_html", ROOT / "monitor/dot_to_html.py"
        )
        cls.post = load_module(
            "review_post_collect", ROOT / "ethernet/monitor/post-collect.py"
        )
        cls.gate = load_module(
            "review_collection_gate", ROOT / "monitor/switch_collection_gate.py"
        )

    def test_monitor_html_publish_is_atomic_and_generation_is_serialized(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "monitor.html"
            self.html.atomic_write_text(output, "first")
            self.html.atomic_write_text(output, "second")
            self.assertEqual("second", output.read_text(encoding="utf-8"))
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual([], list(root.glob(".monitor.html.*.tmp")))

            lock = root / "generation.lock"
            first_entered = threading.Event()
            release = threading.Event()
            second_entered = threading.Event()

            def first():
                with self.html.generation_lock(lock):
                    first_entered.set()
                    release.wait(2)

            def second():
                first_entered.wait(2)
                with self.html.generation_lock(lock):
                    second_entered.set()

            one = threading.Thread(target=first)
            two = threading.Thread(target=second)
            one.start(); two.start()
            self.assertTrue(first_entered.wait(1))
            time.sleep(0.1)
            self.assertFalse(second_entered.is_set())
            release.set()
            one.join(2); two.join(2)
            self.assertTrue(second_entered.is_set())

    def test_dot_converter_aggregates_ports_and_escapes_script_end_tags(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dot_path = root / "fabric.dot"
            dot_path.write_text(
                'graph {\n'
                '"Leaf</script><script>alert(1)</script>":"swp1" -- "Spine01":"swp1"\n'
                '"Leaf</script><script>alert(1)</script>":"swp2" -- "Spine01":"swp2"\n'
                '}\n', encoding="utf-8",
            )
            nodes, edges = self.dot.parse_dot(dot_path)
            self.assertEqual(2, len(nodes))
            self.assertEqual(1, len(edges))
            self.assertEqual(2, edges[0]["count"])
            self.assertEqual("swp1-2", edges[0]["source_label"])
            output = self.dot.convert(dot_path)
            document = output.read_text(encoding="utf-8")
            self.assertIn(r"<\/script>", document)
            self.assertNotIn("</script><script>alert(1)</script>", document)
            self.assertEqual([], list(root.glob(".fabric.html.*.tmp")))

    def test_cron_csv_fallback_is_order_independent_and_archive_names_are_utc(self):
        source = (ROOT / "ethernet/monitor/cron.sh").read_text(encoding="utf-8")
        match = re.search(
            r"if ! awk -F',' '\n(.*?)\n    ' mode=", source, re.DOTALL,
        )
        self.assertIsNotNone(match)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "eth.csv"
            csv_path.write_text(
                "hostname,type,eth0_ip,netmask,vlan_id,svi_ip,netmask\n"
                "AIR-EXAMPLE-Leaf01,air,203.0.113.10,24,,,\n"
                "EXAMPLE-Leaf01,eth,203.0.113.10,24,100,203.0.113.20,24\n",
                encoding="utf-8",
            )
            outputs = {name: root / name for name in ("eth", "spx", "ib", "nv")}
            command = [
                "awk", "-F,", match.group(1), "mode=eth", "filter=air",
                f"eth_file={outputs['eth']}", f"spx_file={outputs['spx']}",
                f"ib_file={outputs['ib']}", f"nv_file={outputs['nv']}",
                str(csv_path),
            ]
            completed = subprocess.run(
                command, text=True, capture_output=True, check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(
                "AIR-EXAMPLE-Leaf01|203.0.113.10|203.0.113.20\n",
                outputs["eth"].read_text(encoding="utf-8"),
            )
        self.assertEqual(6, source.count('ts=$(date -u "+%Y%m%d-%H%M")'))
        self.assertIn("today=$(date -u '+%Y%m%d')", source)

    def _write_executable(self, path: Path, body: str) -> None:
        path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
        path.chmod(0o755)

    def test_sw_info_and_sw_link_publish_complete_nvlink_snapshots(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake_bin = root / "bin"; fake_bin.mkdir()
            temp_dir = root / "tmp"; temp_dir.mkdir()
            self._write_executable(fake_bin / "hostname", "printf '%s\\n' TestNV\n")
            self._write_executable(fake_bin / "nv", r'''
if [ "$1 $2" = "show platform" ] && [ "$#" -eq 2 ]; then
  printf '%s\n' 'system-type MNV4'
elif [ "$1 $2" = "show interface" ] && [ "$#" -eq 2 ]; then
  printf '%s\n' 'nvl1 up'
elif [ "$4 $5" = "link phy-detail" ]; then
  printf '%s\n' 'effective-ber 1e-12' 'effective-error 0'
elif [ "$4 $5" = "link counters" ]; then
  printf '%s\n' 'link-downed 2' 'qp1-drops 3'
else
  printf '%s\n' 'stub output'
fi
''')
            for command in ("timedatectl", "df", "free", "top", "uptime"):
                self._write_executable(fake_bin / command, "printf '%s\\n' stub\n")
            environment = dict(os.environ)
            environment.update({
                "PATH": f"{fake_bin}:/usr/bin:/bin", "TMPDIR": str(temp_dir),
            })
            for relative, suffix in (
                ("ethernet/monitor/sw-info.sh", ".info"),
                ("ethernet/monitor/sw-link.sh", ".link"),
            ):
                completed = subprocess.run(
                    ["bash", str((ROOT / relative).resolve())], cwd=root,
                    env=environment, text=True, capture_output=True, timeout=20,
                    check=False,
                )
                self.assertEqual(0, completed.returncode, completed.stderr)
                output = root / "monitor" / f"TestNV{suffix}"
                self.assertTrue(output.is_file(), relative)
                text = output.read_text(encoding="utf-8")
                if suffix == ".info":
                    self.assertIn("Switch Type:  NVLINK (MNV4)", text)
                    self.assertIn("# Collect complete", text)
                else:
                    self.assertIn("TestNV,nvl1,1e-12,0,2,3,up", text)

    def test_sw_collectors_reject_unknown_platform_and_unsafe_hostname(self):
        for hostname, platform in (("SafeHost", "UNKNOWN"), ("../escape", "MNV4")):
            with self.subTest(hostname=hostname, platform=platform), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                fake_bin = root / "bin"; fake_bin.mkdir()
                temp_dir = root / "tmp"; temp_dir.mkdir()
                self._write_executable(fake_bin / "hostname", f"printf '%s\\n' '{hostname}'\n")
                self._write_executable(fake_bin / "nv", f"printf '%s\\n' 'system-type {platform}'\n")
                environment = dict(os.environ)
                environment.update({"PATH": f"{fake_bin}:/usr/bin:/bin", "TMPDIR": str(temp_dir)})
                for script in ("sw-info.sh", "sw-link.sh"):
                    completed = subprocess.run(
                        ["bash", str((ROOT / "ethernet/monitor" / script).resolve())],
                        cwd=root, env=environment, text=True, capture_output=True,
                        timeout=10, check=False,
                    )
                    self.assertNotEqual(0, completed.returncode)
                self.assertFalse((root / "monitor").exists())

    def test_post_collect_selects_exact_environment_dot(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "99-output-p2p"; output.mkdir()
            (root / "p2p.xlsx").write_bytes(b"fixture")
            expected = output / "p2p-lldpq.dot"
            expected.write_text("graph {}", encoding="utf-8")
            self.assertEqual(expected.resolve(), self.post.select_expected_dot(output, "prod"))
            self.assertEqual("20260831-1200-prod", self.post.archive_stem(
                Path("20260831-1200-prod.tar.gz")
            ))

    def test_collection_gate_serializes_and_enforces_success_cooldown(self):
        with tempfile.TemporaryDirectory() as directory:
            status = Path(directory)
            with self.gate.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status,
                cooldown_seconds=60, clock=lambda: 1000.0,
            ) as first:
                self.assertTrue(first.decision.allowed)
                first.mark_success()
            with self.gate.CollectionGate(
                "project-a", "prod", collection_keys=("prod-ethernet",),
                status_dir=status,
                cooldown_seconds=60, clock=lambda: 1001.0,
            ) as second:
                self.assertFalse(second.decision.allowed)
                self.assertEqual("cooldown", second.decision.reason)


class BringupSafetyTests(unittest.TestCase):
    def test_ndr_scripts_have_no_builtin_password_and_key_auth_is_default(self):
        collect = (ROOT / "infiniband/bringup/ndr/data-collect-IB.sh").read_text(encoding="utf-8")
        upgrade = (ROOT / "infiniband/bringup/ndr/OS-CPLD-upgrade.sh").read_text(encoding="utf-8")
        combined = collect + upgrade
        self.assertNotRegex(combined, r"(?m)^\s*password=['\"]admin['\"]")
        self.assertNotIn("sshpass -p", combined)
        self.assertIn("sshpass -e", collect)
        self.assertIn("BatchMode=yes", collect)
        self.assertIn("PasswordAuthentication=no", collect)
        self.assertIn("IB_SWITCH_PASSWORD", combined)

    def test_ndr_collect_invalid_target_has_no_output_or_network_phase(self):
        script = ROOT / "infiniband/bringup/ndr/data-collect-IB.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets"
            targets.write_text("192.0.2.1;touch-pwned\n", encoding="utf-8")
            output = root / "show.log"; errors = root / "errors.log"
            completed = subprocess.run([
                "bash", str(script), "--switches", str(targets),
                "--output", str(output), "--error-output", str(errors),
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, completed.returncode)
            self.assertIn("invalid switch target", completed.stderr)
            self.assertFalse(output.exists())
            self.assertFalse(errors.exists())

    def test_ndr_upgrade_requires_yes_and_dry_run_has_no_side_effects(self):
        script = ROOT / "infiniband/bringup/ndr/OS-CPLD-upgrade.sh"
        refused = subprocess.run(
            ["bash", str(script)], cwd=ROOT, text=True,
            capture_output=True, timeout=10, check=False,
        )
        self.assertEqual(2, refused.returncode)
        self.assertIn("without --yes", refused.stderr)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            targets = root / "targets"
            targets.write_text("192.0.2.10\n192.0.2.10\n", encoding="utf-8")
            image = root / "image.img"; image.write_bytes(b"image")
            log = root / "upgrade.log"
            completed = subprocess.run([
                "bash", str(script), "--dry-run", "--switches", str(targets),
                "--image", str(image), "--cpld-tool", str(root / "unused-tool"),
                "--wait", "0", "--log", str(log),
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(0, completed.returncode, completed.stderr)
            self.assertEqual(1, completed.stdout.count("target=192.0.2.10"))
            self.assertFalse(log.exists())

    def test_initial_setup_rejects_option_injection_before_outputs(self):
        script = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            completed = subprocess.run([
                sys.executable, str(script), "--eth-user=-oProxyCommand=bad",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, completed.returncode)
            self.assertIn("invalid --eth-user", completed.stderr)
            self.assertFalse((root / "xdr-initial-setup-logs").exists())
            conflict = subprocess.run([
                sys.executable, str(script), "--plan", "--apply",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(2, conflict.returncode)
            self.assertFalse((root / "xdr-initial-setup-logs").exists())

    def test_initial_setup_password_comes_only_from_env_or_hidden_prompt(self):
        source_path = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
        source = source_path.read_text(encoding="utf-8")
        self.assertNotIn('DEFAULT_IB_PASSWORD = "admin"', source)
        self.assertNotIn("--ib-initial-password ", source)
        module = load_module("review_initial_password", source_path)
        with mock.patch.dict(os.environ, {"TEST_NVOS_PASSWORD": "secret-value"}, clear=True):
            self.assertEqual(
                "secret-value",
                module.resolve_initial_ib_password(
                    "TEST_NVOS_PASSWORD", interactive=False,
                ),
            )
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(module.SetupError, "export NVOS_INITIAL_PASSWORD"):
                module.resolve_initial_ib_password(
                    "NVOS_INITIAL_PASSWORD", interactive=False,
                )
            with mock.patch.object(module.getpass, "getpass", return_value="typed-secret"):
                self.assertEqual(
                    "typed-secret",
                    module.resolve_initial_ib_password(
                        "NVOS_INITIAL_PASSWORD", interactive=True,
                    ),
                )

    def test_initial_setup_duplicate_ib_address_is_rejected(self):
        module = load_module(
            "review_initial_setup",
            ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py",
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "ib.csv"
            path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_gw,eth0_mac,eth1_ip,netmask,eth1_gw\n"
                "EXAMPLE-IB01,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-IB02,ib,203.0.113.2,24,203.0.113.1,,,,\n"
                "EXAMPLE-OOB01,eth,192.0.2.10,,,,,,\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(module.SetupError, "duplicate IB address"):
                module.load_devices(path)

    def test_xdr_upgrade_invalid_option_does_not_create_output_tree(self):
        original = ROOT / "infiniband/bringup/xdr-upgrade/upgrade.sh"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / "upgrade.sh"
            shutil.copy2(original, script)
            completed = subprocess.run([
                "bash", str(script), "--method", "local", "--scripts-only",
                "--parallel-limit", "not-a-number",
            ], cwd=root, text=True, capture_output=True, timeout=10, check=False)
            self.assertEqual(1, completed.returncode)
            self.assertIn("Invalid --parallel-limit", completed.stderr)
            self.assertFalse((root / "xdr-upgrade-logs").exists())


if __name__ == "__main__":
    unittest.main()
