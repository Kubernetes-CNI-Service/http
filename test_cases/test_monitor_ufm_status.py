"""Direct tests: UFM servers in the monitor page's Switch Status, at the top of the InfiniBand group
(owner 2026-10-21; infiniband/monitor/UFM-MONITOR.md sections 8 and 12 map the columns)."""

import re
import shutil
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from test_cases.test_project_contracts import ROOT, load_module

SEP = "####################################################"
IBSTAT = """CA 'mlx5_0'
        CA type: MT4131
        Number of ports: 1
        Firmware version: 40.50.1002
        Port 1:
                State: Down
                Physical state: Disabled
                Rate: 10
CA 'mlx5_1'
        CA type: MT4131
        Number of ports: 1
        Firmware version: 40.50.1002
        Port 1:
                State: Active
                Physical state: LinkUp
                Rate: 400
CA 'smi0'
        CA type: MT4131
        Number of ports: 2
        Firmware version: 40.50.1002
        Port 1:
                State: Down
                Physical state: Disabled
        Port 2:
                State: Down
                Physical state: Disabled
"""
FANS = "\n".join(f"Fan{n}{side}            | 38h | ok  |  7.1 | 7560 RPM" for n in range(1, 5) for side in "ABCD")


def snapshot(hostname, server_type, sections):
    body = "".join(f"\n{SEP}\n# Execute Command: {command}\n{SEP}\n{output}\n" for command, output in sections)
    return (f"====================================================\nDevice:       {hostname}\n"
            f"Server Type:  {server_type}\nCollect Time: 2026-10-21 07:04:00\n"
            f"===================================================={body}\n"
            "====================================================\n# Collect complete\n"
            "====================================================\n")


def ufm_info(hostname="ufm02.example.test", enterprise="failed", fan_fail=False, ib_state="Disabled"):
    fans = FANS.replace("Fan1A            | 38h | ok ", "Fan1A            | 38h | cr ") if fan_fail else FANS
    assert not fan_fail or fans != FANS
    return snapshot(hostname, "UFM", [
        ("hostname", hostname),
        ("dmidecode -s system-serial-number", "SN00002"),
        ("dmidecode -s system-manufacturer", "NVIDIA"),
        ("dmidecode -s system-product-name", "UFM3.5"),
        ("dmidecode -s bios-version", "2.8.2"),
        ("cat /etc/ufm-release", "UFM_OS=26.07.24-9\nUFM_APPLIANCE=2.6.1-5\nUFM_ENTERPRISE=6.26.1-5\nUFM_HA=6.3.1-1"),
        ("cat /etc/os-release", 'PRETTY_NAME="Ubuntu 24.04.4 LTS"\nNAME="Ubuntu"'),
        ("uname -r", "6.8.0-test"),
        ("lsblk -d -o NAME,MODEL,SERIAL,REV,SIZE,TYPE",
         "NAME    MODEL                               SERIAL         REV  SIZE TYPE\n"
         "nvme0n1 Dell Ent NVMe CM7 FIPS U.2 MU 3.2TB SER0000001     3.0.1  2.9T disk\n"
         "nvme1n1 Dell Ent NVMe CM7 FIPS U.2 MU 3.2TB SER0000002     3.0.1  2.9T disk"),
        ("ibstat", IBSTAT.replace("Physical state: Disabled\n                Rate: 10",
                                  f"Physical state: {ib_state}\n                Rate: 10")),
        ("mget_temp -d mlx5_0", "64             "),
        ("mget_temp -d mlx5_1", "70             "),
        ("ipmitool sdr type Temperature",
         "Temp             | 01h | ok  |  3.1 | 45 degrees C\nInlet Temp       | 05h | ok  |  7.1 | 27 degrees C\n"
         "Temp 1           | 5Eh | ns  | 11.18 | Disabled\nExhaust Temp     | 06h | ok  |  7.1 | 43 degrees C"),
        ("ipmitool sdr type 'Power Supply'",
         "PS Redundancy    | 77h | ok  |  7.1 | Fully Redundant\n"
         "Status           | 85h | ok  | 10.1 | Presence detected\nStatus           | 86h | ok  | 10.2 | Presence detected"),
        ("ipmitool sdr type Fan", fans + "\nFan Redundancy   | 78h | ok  |  7.1 | Fully Redundant"),
        ("top -bn2 -d 1", "%Cpu(s):  1.0 us,  0.5 sy,  0.0 ni, 98.0 id\n%Cpu(s):  2.0 us,  1.5 sy,  0.0 ni, 96.0 id"),
        ("df -PT", "Filesystem Type 1024-blocks Used Available Capacity Mounted on\n"
                   "/dev/mapper/vg0-lv--0 ext4 1055762868 39979372 962080024 4% /\n"
                   "/dev/md0p1 ext4 153575896 7596 145694304 1% /opt/ha_data\n"
                   "/dev/nvme0n1p1 vfat 1098632 6288 1092344 1% /boot/efi\n"
                   "overlay overlay 1055762868 39979372 962080024 4% /var/lib/docker/overlay2/abc/merged\n"
                   "tmpfs tmpfs 13148652 2760 13145892 1% /run"),
        ("free -b", "               total        used        free      shared  buff/cache   available\n"
                    "Mem:      50000000000  2000000000 45000000000    55549952  2458382336 45000000000"),
        ("timedatectl", "System clock synchronized: no\n                Time zone: Etc/UTC (UTC, +0000)"),
        ("ip -br link", "eno12399np0      DOWN           02:00:00:00:02:05 <BROADCAST,MULTICAST>\n"
                        "eno8303          UP             02:00:00:00:02:01 <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
                        "eno8403          UP             02:00:00:00:02:02 <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
                        "idrac            UNKNOWN        02:00:00:00:02:09 <BROADCAST,MULTICAST,UP,LOWER_UP>\n"
                        "docker0          DOWN           02:00:00:00:02:0a <NO-CARRIER,BROADCAST,MULTICAST,UP>"),
        ("ip -br addr", "lo               UNKNOWN        127.0.0.1/8 ::1/128\n"
                        "eno12399np0      DOWN\n"
                        "eno8303          UP             198.51.101.132/23 fe80::ff:fe00:201/64\n"
                        "eno8403          UP             192.0.2.2/30\n"
                        "idrac            UNKNOWN        198.18.1.2/24\n"
                        "docker0          DOWN           198.18.0.1/16"),
        ("systemctl is-active ufm-enterprise", enterprise),
        ("systemctl list-units 'ufm*' --no-pager",
         "  UNIT                       LOAD   ACTIVE SUB     DESCRIPTION\n"
         "  ufm-chassis-health.service loaded active running UFM Enterprise Appliance Chassis Health\n"
         f"* ufm-enterprise.service     loaded {enterprise} {enterprise} ufm-enterprise"),
        ("uptime -p", "up 1 day, 17 hours, 47 minutes"),
    ])


def ha_snapshot(primary="ufm01", standby="ufm02", standby_online=True, enterprise="Started",
                drbd="Connected", peer_disk="UpToDate",
                sanity="Checking Service...\nDone\nChecking ufm REST server...\nDone\n"
                       "Sanity tests completed successfully!"):
    """`ufm_ha_cluster status` as the owner showed it (2026-10-21), with documentation addresses."""
    online = f"{primary} {standby}" if standby_online else primary
    offline = "" if standby_online else f"OFFLINE: [ {standby} ]\n"
    slaves = f"Slaves: [ {standby} ]" if standby_online else f"Stopped: [ {standby} ]"
    enterprise_line = f"Started {primary}" if enterprise == "Started" else enterprise
    status = f"""Cluster name: ufmcluster
WARNING: corosync and pacemaker node names do not match (IPs used in setup?)
Stack: corosync
Current DC: {standby if standby_online else primary} (version 1.1.18-2b07d5c5a9) - partition with quorum
Last updated: Thu Dec 28 06:28:13 2023
Last change: Tue Dec 26 07:58:16 2023 by root via crm_resource on {primary}

2 nodes configured
6 resources configured

Online: [ {online} ]
{offline}
Full list of resources:

 Master/Slave Set: ha_data_drbd_master [ha_data_drbd]
     Masters: [ {primary} ]
     {slaves}
 Resource Group: ufmcluster-grp
     ha_data_file_system        (ocf::heartbeat:Filesystem):    Started {primary}
     cluster_virtual_ip (ocf::heartbeat:IPaddr2):       Started {primary}
     ufm-ha-watcher     (systemd:ufm-ha-watcher):       Started {primary}
     ufm-enterprise     (systemd:ufm-enterprise):       {enterprise_line}

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled
DRBD_RESOURCE:     ha_data
DRBD_CONNECTIVITY: {drbd}
DISK_STATE:        UpToDate
DRBD_ROLE:         Primary
PEER_DISK_STATE:   {peer_disk}
PEER_DRBD_ROLE:    Secondary
DRBD Sync Status:
version: 8.4.10 (api:1/proto:86-101)
 0: cs:{drbd} ro:Primary/Secondary ds:UpToDate/{peer_disk} C r-----
    ns:11381648 nr:47336 dw:11428984 dr:18609 al:405 bm:0 lo:0 pe:0 ua:0 ap:0 ep:1 wo:d oos:0
VIRTUAL_IP:        198.51.101.133"""
    return snapshot(f"{primary}.example.test", "UFM-HA", [
        ("hostname", f"{primary}.example.test"),
        ("ip -br link", "eno8303          UP             02:00:00:00:01:01 <BROADCAST,MULTICAST,UP,LOWER_UP>"),
        ("ufm_ha_cluster status", status),
        ("ufm_enterprise_sanity.sh", sanity),
    ])


def ha_snapshot_pacemaker2(drbd="Connected", peer_disk="UpToDate"):
    """`ufm_ha_cluster status` as ufm01 printed it after `ufm_ha_cluster start` (owner 2026-10-22):
    Pacemaker 2 layout, DRBD lines indented and values in brackets; documentation VIP."""
    status = f"""Reading configuration from /var/lib/ufm_ha/ha_state
Loading enabled add-ons from registry
Cluster name: ufmcluster
Cluster Summary:
  * Stack: corosync (Pacemaker is running)
  * Current DC: ufm01 (version 2.1.6-6fdc9deea29) - partition with quorum
  * Last updated: Thu Oct 22 05:34:09 2026 on ufm01
  * Last change:  Thu Oct 22 05:30:59 2026 by root via cibadmin on ufm01
  * 2 nodes configured
  * 7 resource instances configured

Node List:
  * Online: [ ufm01 ufm02 ]

Full List of Resources:
  * Clone Set: ha_data_drbd-clone [ha_data_drbd] (promotable):
    * Promoted: [ ufm01 ]
    * Unpromoted: [ ufm02 ]
  * Resource Group: ufmcluster-grp:
    * ha_data_file_system       (ocf:heartbeat:Filesystem):      Started ufm01
    * cluster_virtual_ip_0      (ocf:heartbeat:IPaddr2):         Started ufm01
    * ufm-ha-watcher    (systemd:ufm-ha-watcher):        Started ufm01
    * ufm-enterprise    (systemd:ufm-enterprise):        Started ufm01
  * ha-monitor  (systemd:ha-monitor):    Started ufm01

Daemon Status:
  corosync: active/enabled
  pacemaker: active/enabled
  pcsd: active/enabled

DRBD Status:
  DRBD_RESOURCE:              [ha_data]
  DRBD_CONNECTIVITY:          [{drbd}]
  DISK_STATE:                 [UpToDate]
  DRBD_ROLE:                  [Primary]
  PEER_DISK_STATE:            [{peer_disk}]
  PEER_DRBD_ROLE:             [Secondary]
VIRTUAL_IP:                   [198.51.101.133]"""
    return snapshot("ufm01.example.test", "UFM-HA", [
        ("hostname", "ufm01.example.test"),
        ("ip -br link", "eno8303          UP             02:00:00:00:01:01 <BROADCAST,MULTICAST,UP,LOWER_UP>"),
        ("ufm_ha_cluster status", status),
        ("ufm_enterprise_sanity.sh", "Sanity tests completed successfully!"),
    ])


class UfmStatusTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module("monitor_ufm_status", ROOT / "monitor/generate-monitor-html.py")

    def parse(self, hostname="ufm02.example.test", **kwargs):
        return self.monitor.parse_ufm_info_file(hostname, ufm_info(hostname, **kwargs),
                                                datetime(2026, 10, 21, 7, 4, tzinfo=timezone.utc))

    def test_every_switch_status_column_is_read_from_the_snapshot(self):
        info = self.parse()
        expected = {
            "sw_type": "UFM", "device_kind": "ufm", "serial": "SN00002", "model": "NVIDIA UFM3.5",
            "version": "2.6.1-5", "bios_version": "2.8.2", "ssd_version": "3.0.1 ×2",
            "asic": "MT4131", "asic_version": "MT4131 40.50.1002 ×2",
            "asic_temperatures": [64.0, 70.0], "psu_ok": 2, "psu_fail": 0, "fan_ok": 16, "fan_fail": 0,
            "ntp_sync": False, "uptime": "up 1 day, 17 hours, 47 minutes",
            "interfaces_up": 3, "interfaces_total": 4, "ha_summary": "未就绪", "health": "error",
        }
        self.assertEqual({key: info[key] for key in expected}, expected)
        self.assertEqual(info["psu_temperatures"], [], "Dell reports no PSU temperature")
        self.assertEqual(info["cpu_use"], 4.0)
        self.assertEqual(sorted(info["disk_use"]), ["/", "/boot/efi", "/opt/ha_data"], "no docker overlay")
        self.assertAlmostEqual(info["mem_use"], 10.0)
        self.assertEqual(info["interfaces_down"], [],
                         "a Disabled HCA port counts like an admin-down switch port; smi views are not counted")
        self.assertIn("UFM_ENTERPRISE=6.26.1-5", info["ufm_release"])
        self.assertTrue(info["collect_time"])

    def test_a_port_waiting_for_the_subnet_manager_says_so(self):
        # ufm01 before HA (owner 2026-10-22): link is up but no SM has assigned a LID yet, because the
        # SM is UFM itself and ufm-enterprise is not running.
        def ca(name, ports, rate):
            body = (f"CA '{name}'\n        CA type: MT4131\n        Number of ports: {ports}\n"
                    "        Firmware version: 40.50.1002\n        Hardware version: 0\n"
                    "        Node GUID: 0x0200000000000001\n")
            for port in range(1, ports + 1):
                body += (f"        Port {port}:\n                State: Initializing\n"
                         f"                Physical state: LinkUp\n                Rate: {rate}\n"
                         "                Base lid: 65535\n                LMC: 0\n                SM lid: 0\n"
                         "                Link layer: InfiniBand\n")
            return body
        ibstat = ca("mlx5_0", 1, 400) + ca("mlx5_1", 1, 400) + ca("smi0", 4, 100) + ca("smi1", 4, 100)
        text = ufm_info().replace(IBSTAT, ibstat)
        self.assertIn("SM lid: 0", text)
        info = self.monitor.parse_ufm_info_file("ufm02.example.test", text,
                                                datetime(2026, 10, 21, 7, 4, tzinfo=timezone.utc))
        self.assertEqual((info["interfaces_up"], info["interfaces_total"]), (2, 4), "two Ethernet up, no IB")
        self.assertEqual(info["interfaces_down"],
                         ["mlx5_0/1 (Initializing / LinkUp，SM 未分配 LID)",
                          "mlx5_1/1 (Initializing / LinkUp，SM 未分配 LID)"], "smi views are not counted")

    def test_an_enabled_ib_port_without_link_is_flagged(self):
        info = self.parse(ib_state="Polling")
        self.assertEqual((info["interfaces_up"], info["interfaces_total"]), (3, 4))
        self.assertEqual(info["interfaces_down"], ["mlx5_0/1 (Polling)"])

    def test_without_the_ha_state_health_follows_the_node_service_and_the_fans(self):
        self.assertEqual(self.parse(enterprise="active")["health"], "ok")
        self.assertEqual(self.parse(enterprise="inactive")["health"], "warning")
        failed = self.parse(enterprise="active", fan_fail=True)
        self.assertEqual((failed["fan_ok"], failed["fan_fail"], failed["health"]), (15, 1, "warning"))

    # ── HA state from the primary (owner 2026-10-21: read only through the VIP) ──
    def pair(self, ha=None, standby_fan_fail=False):
        primary = self.parse("ufm01.example.test", enterprise="active")
        standby = self.parse("ufm02.example.test", enterprise="inactive", fan_fail=standby_fan_fail)
        self.monitor.apply_ufm_ha_status([primary, standby], ha if ha is not None else ha_snapshot())
        return primary, standby

    def test_a_healthy_cluster_makes_the_inactive_standby_normal(self):
        primary, standby = self.pair()
        self.assertEqual((primary["ha_summary"], primary["health"]), ("主 · 在线 2/2", "ok"))
        self.assertEqual((standby["ha_summary"], standby["health"]), ("备 · 在线 2/2", "ok"),
                         "ufm-enterprise is inactive on the standby by design")
        self.assertIn("Sanity tests completed successfully!", primary["ha_detail"])
        self.assertIn("DRBD", primary["ha_detail"])

    def test_a_failed_sanity_check_is_only_a_note(self):
        # Owner 2026-10-22: `ufm_ha_cluster status` decides HA; a failed ufm_enterprise_sanity.sh is
        # only pointed out, it changes no health.
        for sanity in ("Checking Service...\nFailed", ""):
            with self.subTest(sanity=sanity):
                primary, standby = self.pair(ha_snapshot(sanity=sanity))
                self.assertEqual((primary["health"], standby["health"]), ("ok", "ok"))
                self.assertEqual(primary["ha_summary"], "主 · 在线 2/2")
                self.assertIn("提示：ufm_enterprise_sanity", primary["ha_detail"])

    def test_a_stopped_ufm_in_the_cluster_status_is_an_error_on_the_primary(self):
        primary, standby = self.pair(ha_snapshot(enterprise="Stopped"))
        self.assertEqual((primary["health"], standby["health"]), ("error", "ok"))
        self.assertIn("ufm-enterprise Stopped", primary["ha_detail"])

    def test_the_pacemaker_2_layout_from_ufm01_is_read_in_full(self):
        status = self.monitor.parse_ufm_ha_status(ha_snapshot_pacemaker2())
        self.assertEqual(status["drbd"], {"DRBD_CONNECTIVITY": "Connected", "DISK_STATE": "UpToDate",
                                          "DRBD_ROLE": "Primary", "PEER_DISK_STATE": "UpToDate",
                                          "PEER_DRBD_ROLE": "Secondary", "VIRTUAL_IP": "198.51.101.133"})
        self.assertEqual((status["masters"], status["slaves"], status["online"], status["nodes"], status["quorum"]),
                         (["ufm01"], ["ufm02"], ["ufm01", "ufm02"], 2, True))
        self.assertEqual({item["name"]: (item["state"], item["node"]) for item in status["resources"]}, {
            "ha_data_file_system": ("Started", "ufm01"), "cluster_virtual_ip_0": ("Started", "ufm01"),
            "ufm-ha-watcher": ("Started", "ufm01"), "ufm-enterprise": ("Started", "ufm01"),
            "ha-monitor": ("Started", "ufm01")})
        primary, standby = self.pair(ha_snapshot_pacemaker2())
        self.assertEqual((primary["health"], standby["health"]), ("ok", "ok"))
        self.assertIn("VIRTUAL_IP: 198.51.101.133", primary["ha_detail"])

    def test_a_broken_replica_in_the_pacemaker_2_layout_is_not_missed(self):
        # The bracketed, indented DRBD lines must be read: unread, they would default to "healthy".
        primary, standby = self.pair(ha_snapshot_pacemaker2(drbd="StandAlone", peer_disk="Outdated"))
        self.assertEqual((primary["health"], standby["health"]), ("warning", "warning"))
        self.assertIn("DRBD StandAlone", primary["ha_detail"])

    def test_a_degraded_replica_warns_on_both_nodes(self):
        primary, standby = self.pair(ha_snapshot(drbd="StandAlone", peer_disk="Outdated"))
        self.assertEqual((primary["health"], standby["health"]), ("warning", "warning"))

    def test_an_offline_standby_is_an_error_and_the_primary_has_no_redundancy(self):
        primary, standby = self.pair(ha_snapshot(standby_online=False, drbd="WFConnection", peer_disk="DUnknown"))
        self.assertEqual((standby["ha_summary"], standby["health"]), ("离线 · 在线 1/2", "error"))
        self.assertEqual((primary["ha_summary"], primary["health"]), ("主 · 在线 1/2", "warning"))

    def test_a_hardware_fault_still_shows_on_a_healthy_standby(self):
        _primary, standby = self.pair(standby_fan_fail=True)
        self.assertEqual(standby["health"], "warning")

    def test_the_list_row_keeps_21_columns_and_shows_ha(self):
        row = self.monitor.render_sw_list_row(self.parse())
        self.assertEqual(row.count("<td"), 21)
        self.assertIn("HA: 未就绪", row)
        self.assertIn("MT4131 40.50.1002 ×2", row)
        self.assertIn("64°C", row)
        self.assertIn('data-cat="ib-ufm"', row)
        primary, _standby = self.pair()
        row = self.monitor.render_sw_list_row(primary)
        self.assertEqual(row.count("<td"), 21)
        self.assertIn("HA: 主 · 在线 2/2", row)
        self.assertIn("VIRTUAL_IP", row, "the cluster detail is in the cell title")

    def test_the_card_uses_the_infiniband_header_and_an_ha_row(self):
        card = self.monitor.render_eth_card(self.parse())
        self.assertIn("sw-hdr-ib", card)
        self.assertIn(">UFM<", card)
        self.assertIn('<span class="sw-k">HA</span>', card)

    def ib_switch(self, hostname="ew-spine001.example.test"):
        switch = self.monitor.make_missing_switch(hostname, "IB")
        switch.update(health="ok", model="QM9790")
        return switch

    def test_ufm_servers_lead_the_infiniband_group_missing_ones_included(self):
        missing = self.monitor.make_missing_switch("ufm01.example.test", "UFM")
        missing["device_kind"] = "ufm"
        switches = [self.ib_switch(), self.parse(), missing]
        for build in (self.monitor.build_switch_list_html, self.monitor.build_switch_cards_html):
            html = build(switches, self.monitor._IB_CATEGORIES, "IB")
            ufm_at = html.index("UFM Servers（2）")
            self.assertLess(ufm_at, html.index("Spine（1）"), build.__name__)
            self.assertNotIn("未采集 · 可能掉线", html, "a missing UFM stays in its own group")
            self.assertLess(html.index("ufm01.example.test"), html.index("Spine（1）"))

    def test_without_ufm_the_group_has_no_ufm_header(self):
        html = self.monitor.build_switch_list_html([self.ib_switch()], self.monitor._IB_CATEGORIES, "IB")
        self.assertNotIn("UFM Servers", html)

    def test_the_page_puts_ufm_servers_first_in_infiniband_and_only_in_production(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            ufm_dir = root / "ufm-info"
            ufm_dir.mkdir()
            batch = root / "20261021-0704"
            batch.mkdir()
            (batch / "ufm02.example.test.info").write_text(ufm_info(enterprise="inactive"), encoding="utf-8")
            (batch / "ufm01.example.test.ha").write_text(ha_snapshot(), encoding="utf-8")
            with tarfile.open(ufm_dir / "20261021-0704.tar.gz", "w:gz") as bundle:
                bundle.add(batch, arcname=batch.name)
            devices = root / "02-devices_config.csv"
            devices.write_text("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
                               "ufm01.example.test,server_ufm,NA,198.51.101.130,23,198.51.101.254,02:00:00:00:01:01\n"
                               "ufm02.example.test,server_ufm,NA,198.51.101.132,23,198.51.101.254,02:00:00:00:02:01\n",
                               encoding="utf-8")
            pages = {}
            for scope in ("prod", "air"):
                output = root / f"monitor-{scope}.html"
                with mock.patch.object(self.monitor, "load_dynamic_air_inventory", return_value=[]), \
                        mock.patch.multiple(self.monitor, ETH_INFO_DIR=empty, SPX_LINK_DIR=empty,
                                            IB_INFO_DIR=empty, IBL_LINK_DIR=empty, NV_INFO_DIR=empty,
                                            NVL_LINK_DIR=empty, P2P_OUTPUT_DIR=empty, UFM_INFO_DIR=ufm_dir,
                                            IB_LOG=devices, OUTPUT=output, LOG_FILE=root / "generate.log"):
                    self.monitor.main(scope)
                pages[scope] = output.read_text(encoding="utf-8")
            production = pages["prod"]
            self.assertRegex(production, r"InfiniBand Switches \(2\)", "the .ha file is not a device")
            self.assertIn("UFM Servers（2）", production)
            self.assertIn("ufm02.example.test", production)
            self.assertIn("HA: 备 · 在线 2/2", production, "the primary's HA state reaches the standby row")
            self.assertIn("ufm01.example.test", production, "the CSV UFM without a snapshot is shown missing")
            self.assertNotIn("UFM Servers", pages["air"])


def switch_info(hostname, switch_type):
    return snapshot(hostname, switch_type, [("nv show system health", "status  OK")]).replace(
        f"Server Type:  {switch_type}", f"Switch Type:  {switch_type}")


def ib_info(hostname):
    return switch_info(hostname, "IB (QM9790)")


def nvl_info(hostname):
    return switch_info(hostname, "NVLINK (MNV5000)")


class IbInventoryAlignmentTest(unittest.TestCase):
    """Owner 2026-10-21 ("参考 eth 来做 ib", NVL as well): the IB and NVLink groups follow the
    Ethernet inventory rules."""

    @classmethod
    def setUpClass(cls):
        cls.monitor = load_module("monitor_ib_alignment", ROOT / "monitor/generate-monitor-html.py")

    def page(self, ib_members, ufm_members=None, nvl_members=None):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            empty = root / "empty"
            empty.mkdir()
            dirs = {}
            # None: no archive at all (cron.sh never publishes an empty UFM batch)
            for kind, members in (("ib-info", ib_members), ("ufm-info", ufm_members),
                                  ("nvsw-info", nvl_members)):
                folder = root / kind
                folder.mkdir()
                dirs[kind] = folder
                if members is None:
                    continue
                batch = root / kind / "20261021-0704"
                batch.mkdir()
                for name, text in members.items():
                    (batch / name).write_text(text, encoding="utf-8")
                with tarfile.open(folder / "20261021-0704.tar.gz", "w:gz") as bundle:
                    bundle.add(batch, arcname=batch.name)
                shutil.rmtree(batch)
            devices = root / "02-devices_config.csv"
            devices.write_text("hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"
                               "ew-leaf01,ib,NA,198.51.101.11,23,198.51.101.254,02:00:00:00:04:01\n"
                               "ew-spine01,ib,NA,198.51.101.12,23,198.51.101.254,02:00:00:00:04:02\n"
                               "ufm02.example.test,server_ufm,NA,198.51.101.132,23,198.51.101.254,"
                               "02:00:00:00:02:01\n"
                               "rack1-nvsw01,nvl,NA,198.51.101.21,23,198.51.101.254,02:00:00:00:05:01\n"
                               "rack1-nvsw02,nvl,NA,198.51.101.22,23,198.51.101.254,02:00:00:00:05:02\n",
                               encoding="utf-8")
            output = root / "monitor.html"
            with mock.patch.object(self.monitor, "load_dynamic_air_inventory", return_value=[]), \
                    mock.patch.multiple(self.monitor, ETH_INFO_DIR=empty, SPX_LINK_DIR=empty,
                                        IB_INFO_DIR=dirs["ib-info"], IBL_LINK_DIR=empty,
                                        NV_INFO_DIR=dirs["nvsw-info"], NVL_LINK_DIR=empty,
                                        P2P_OUTPUT_DIR=empty, UFM_INFO_DIR=dirs["ufm-info"],
                                        IB_LOG=devices, NV_LOG=devices, OUTPUT=output,
                                        LOG_FILE=root / "generate.log"):
                self.monitor.main("prod")
            return output.read_text(encoding="utf-8")

    def test_a_device_no_longer_in_the_inventory_is_dropped_and_a_missing_one_is_shown(self):
        page = self.page({"ew-leaf01.info": ib_info("ew-leaf01"), "old-leaf09.info": ib_info("old-leaf09")},
                         {"ufm02.example.test.info": ufm_info(),
                          "ufm-retired.example.test.info": ufm_info("ufm-retired.example.test")})
        self.assertIn("ew-leaf01", page)
        self.assertIn("ew-spine01", page, "in the inventory, not in the batch: shown missing")
        self.assertNotIn("old-leaf09", page, "removed from the inventory: not shown, like Ethernet")
        self.assertNotIn("ufm-retired", page)
        self.assertIn("ufm02.example.test", page)
        self.assertRegex(page, r"InfiniBand Switches \(3\)")

    def test_an_empty_batch_still_lists_the_inventory_as_missing(self):
        page = self.page({}, nvl_members={})
        self.assertIn("ew-leaf01", page)
        self.assertIn("ew-spine01", page)
        self.assertRegex(page, r"InfiniBand Switches \(2\)")
        self.assertIn("rack1-nvsw01", page)
        self.assertRegex(page, r"NVLink Switches \(2\)")

    def test_nvlink_follows_the_same_inventory_rules(self):
        page = self.page(None, nvl_members={"rack1-nvsw01.info": nvl_info("rack1-nvsw01"),
                                            "rack9-nvsw07.info": nvl_info("rack9-nvsw07")})
        self.assertIn("rack1-nvsw01", page)
        self.assertIn("rack1-nvsw02", page, "in the inventory, not in the batch: shown missing")
        self.assertNotIn("rack9-nvsw07", page, "removed from the inventory: not shown")
        self.assertRegex(page, r"NVLink Switches \(2\)")


if __name__ == "__main__":
    unittest.main()
