#!/usr/bin/env python3
"""Workflow: one inventory with ``server_ufm``/``server_mgmt`` rows through the real chain.

11-load validation and its release inventory, the DHCP generator, the MAC-link
publisher, backup, manual ZTP, the ZTP monitor, the ZTP page, diagnostics and
infra all read the same ``02-devices_config.csv``.  The rows must partition
consistently: switches go to the ZTP side, ``server``/``server_mgmt`` go to
infra only, and ``server_ufm`` goes to none of these consumers.  The DHCP host
set must equal 11-load's release inventory, because load fails closed on any
drift between the two.
"""

from __future__ import annotations

import contextlib
import io
from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script
from test_cases.test_server_device_types import (
    BACKUP,
    DEPLOY,
    DHCP,
    DIAGNOSTICS,
    HTML,
    LEGACY,
    MANUAL,
    METHODS,
    MGMT,
    MONITOR,
    PUBLISHER,
    SWITCH,
    UFM1,
    UFM2,
    empty_leases,
    write_mixed,
)


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("server_types_workflow_load", ROOT / "DAY0-Prepare/11-load.py")
UFM_MACS = ("02:00:00:00:01:30", "02:00:00:00:01:32")
SERVER_MACS = UFM_MACS + ("02:00:00:00:01:40", "02:00:00:00:01:41")


class ServerDeviceTypesWorkflowTests(unittest.TestCase):
    def run_chain(self, *, config_methods=None):
        with tempfile.TemporaryDirectory() as directory, \
                contextlib.redirect_stdout(io.StringIO()):
            inventory = write_mixed(directory, config_methods=config_methods)
            leases = empty_leases(directory)

            # 11-load: input validation, then the release inventory it binds to DHCP.
            types = LOAD.load_device_types(inventory, 2)
            release = LOAD._inventory_for_release_scope(
                LOAD._release_inventory(inventory),
                deployment_scope="all", switch_scope="all",
            )

            # c1-generate_dhcp: the same CSV through validation and host rendering.
            records = DHCP.load_csv(str(inventory), schema_version=2)
            valid, errors = DHCP.validate(records)
            scoped = DHCP.records_for_release_scope(valid)
            hosts_file = Path(directory) / "dhcpd_eth.hosts"
            DHCP.write_hosts(str(hosts_file), scoped)
            hosts_text = hosts_file.read_text(encoding="utf-8")

            published = PUBLISHER.load_csv(str(inventory))
            backup = BACKUP.load_devices_csv(str(inventory))
            manual = MANUAL.read_devices(inventory, dhcp_leases=leases)
            monitored = MONITOR.read_devices(inventory, dhcp_leases=leases)
            excluded = HTML.ztp_report_excluded_hostnames(inventory)
            infra = DEPLOY.load_servers(inventory)
        return {
            "types": types, "release": release, "errors": errors, "scoped": scoped,
            "hosts_text": hosts_text, "published": published, "backup": backup,
            "manual": manual, "monitored": monitored, "excluded": excluded,
            "infra": infra,
        }

    def assert_partition(self, result):
        switch_key = SWITCH.casefold()
        self.assertEqual([], result["errors"])
        self.assertEqual(frozenset({"eth"}),
                         LOAD.filter_device_types_for_switch_scope(result["types"], "all"))
        # Load's release inventory and the DHCP release set agree exactly.
        self.assertEqual(
            {(item["hostname_key"], "eth0") for item in result["release"]},
            {(item["hostname"].casefold(), item["iface"]) for item in result["scoped"]},
        )
        self.assertEqual({switch_key}, {item["hostname_key"] for item in result["release"]})
        self.assertIn(f"host {SWITCH} {{", result["hosts_text"])
        for hostname in (UFM1, UFM2, MGMT, LEGACY):
            self.assertNotIn(hostname, result["hosts_text"])
        for mac in SERVER_MACS:
            self.assertNotIn(mac, result["hosts_text"])
        # Every switch-side consumer sees exactly the switch.
        self.assertEqual({switch_key}, set(result["published"]))
        self.assertEqual([SWITCH], [item["hostname"] for item in result["backup"]])
        self.assertEqual([SWITCH], [item["hostname"] for item in result["manual"]])
        self.assertEqual([SWITCH], [item["hostname"] for item in result["monitored"]])
        # The ZTP page and diagnostics see the monitor's report minus every server.
        report = {"devices": [
            dict(item, environment="production") for item in result["monitored"]
        ] + [
            {"hostname": UFM1, "type": "server_ufm", "environment": "production"},
            {"hostname": MGMT, "type": "server_mgmt", "environment": "production"},
        ]}
        self.assertEqual(
            [SWITCH],
            [item["hostname"] for item in HTML.ztp_report_devices(report["devices"], result["excluded"])],
        )
        self.assertEqual(
            [SWITCH],
            [item["hostname"] for item in DIAGNOSTICS.select_devices(report, [SWITCH], "all")],
        )
        for hostname in (UFM1, MGMT):
            with self.assertRaises(DIAGNOSTICS.DiagnosticError):
                DIAGNOSTICS.select_devices(report, [hostname], "all")
        # Infra deploys server and server_mgmt, never server_ufm; disjoint from switches.
        infra_hosts = {item["hostname"] for item in result["infra"]}
        self.assertEqual({MGMT, LEGACY}, infra_hosts)
        self.assertFalse(infra_hosts & {SWITCH, UFM1, UFM2})

    def test_v2_inventory_partitions_consistently_across_scripts(self):
        self.assert_partition(self.run_chain())

    def test_declared_config_method_column_partitions_the_same_way(self):
        result = self.run_chain(config_methods=METHODS)
        self.assert_partition(result)
        self.assertEqual(["ztp"], [item["config_method"] for item in result["scoped"]])
        self.assertEqual(["ztp"], [item["config_method"] for item in result["monitored"]])


if __name__ == "__main__":
    unittest.main()
