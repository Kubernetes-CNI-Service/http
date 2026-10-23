#!/usr/bin/env python3
"""Direct contracts: every type-column reader accepts ``server_ufm``/``server_mgmt``.

Owner rulings 2026-10-19..22 (``infiniband/bringup/ufm-setup-upgrade/README.md``,
section "CSV 新增 type"): ``server_ufm`` is a UFM appliance that fills only the
first seven columns (the rest of a schema v2 row is empty but present);
``server_mgmt`` is the new spelling of ``server``.  A script that does not
handle these types skips the rows silently: no error, never a switch, DHCP
host, ZTP/SSH monitor target, backup target or diagnostics target.  Where a
script treats ``server`` specially, ``server_mgmt`` behaves exactly the same.
Infra deploys ``server``/``server_mgmt`` and never ``server_ufm``.
"""

from __future__ import annotations

import contextlib
import csv
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
LOAD = load_script("server_types_direct_load", ROOT / "DAY0-Prepare/11-load.py")
PUBLISHER = load_script(
    "server_types_direct_publisher", ROOT / "ztp/config/cumulus/d-hostname2mac.py",
)
DHCP = load_script(
    "server_types_direct_dhcp", ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
BACKUP = load_script("server_types_direct_backup", ROOT / "ztp/backup/yaml-collect.py")
MANUAL = load_script("server_types_direct_manual", ROOT / "ztp/manual-ztp.py")
MONITOR = load_script(
    "server_types_direct_monitor", ROOT / "DAY0-Prepare/12-ztp-monitor.py",
)
DIAGNOSTICS = load_script(
    "server_types_direct_diagnostics", ROOT / "tools/collect-ztp-diagnostics.py",
)
HTML = load_script(
    "server_types_direct_html", ROOT / "monitor/generate-monitor-html.py",
)
DEPLOY = load_script("server_types_direct_deploy", ROOT / "infra/deploy_infra.py")
CHECK = load_script("server_types_direct_check", ROOT / "infra/check_infra.py")
CONTRACT = load_script("server_types_direct_contract", ROOT / "tools/project_contract.py")
GENERATOR = load_script(
    "server_types_direct_generator",
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py",
)


# Schema v2 layout as shipped in DAY0-Prepare/template/02-devices_config.csv:
# base(12) + 2 VLAN groups + fixed(7) + 4 EVPN groups.
_BASE = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw", "eth0_mac",
    "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
)
_VLAN = ("vlan_id", "svi_ip", "netmask", "vlan_ports")
_FIXED = (
    "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
    "peerlink_ports", "vrl",
)
_EVPN = (
    "evpn_vrf", "evpn_l3vni", "evpn_l3vlan", "dhcp_relay", "evpn_l2vni",
    "evpn_l2vlan", "svi_ip", "netmask", "vlan_ports",
)
V2_HEADER = _BASE + _VLAN * 2 + _FIXED + _EVPN * 4

SWITCH = "leaf01.example.test"
UFM1 = "ufm01.example.test"
UFM2 = "ufm02.example.test"
MGMT = "mgmt01.example.test"
LEGACY = "srv01.example.test"
SERVER_HOSTS = {UFM1, UFM2, MGMT, LEGACY}


def switch_row(width: int) -> list[str]:
    row = ["NA"] * width
    row[0:7] = [SWITCH, "eth", "leaf", "192.0.2.11", "24", "192.0.2.1", "02:00:00:00:00:11"]
    return row


def ufm_row(hostname: str, address: str, netmask: str, mac: str, width: int) -> list[str]:
    """Only the first seven columns are filled; the rest are present and empty."""
    row = [""] * width
    row[0:7] = [hostname, "server_ufm", "NA", address, netmask, "198.51.100.1", mac]
    return row


def server_row(hostname: str, kind: str, address: str, mac: str, width: int) -> list[str]:
    row = ["NA"] * width
    row[0:7] = [hostname, kind, "NA", address, "24", "198.51.100.1", mac]
    return row


def mixed_rows(width: int) -> list[list[str]]:
    return [
        switch_row(width),
        ufm_row(UFM1, "198.51.100.30", "/23", "02:00:00:00:01:30", width),
        ufm_row(UFM2, "198.51.100.32", "23", "02:00:00:00:01:32", width),
        server_row(MGMT, "server_mgmt", "198.51.100.40", "02:00:00:00:01:40", width),
        server_row(LEGACY, "server", "198.51.100.41", "02:00:00:00:01:41", width),
    ]


def write_csv(path: Path, header, rows) -> Path:
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(header)
        writer.writerows(rows)
    return path


def write_mixed(directory: str, *, config_methods: dict[str, str] | None = None) -> Path:
    """Write the mixed v2 inventory; optionally with a trailing config_method column."""
    header = list(V2_HEADER)
    rows = mixed_rows(len(header))
    if config_methods is not None:
        header.append("config_method")
        for row in rows:
            row.append(config_methods.get(row[0], ""))
    return write_csv(Path(directory) / "02-devices_config.csv", header, rows)


def write_short_v1(directory: str) -> Path:
    """Schema v1 keeps tolerance for omitted trailing cells: a 7-cell UFM row."""
    width = len(V2_HEADER)
    rows = [switch_row(width), [UFM1, "server_ufm", "NA", "198.51.100.30", "/23",
                                "198.51.100.1", "02:00:00:00:01:30"]]
    return write_csv(Path(directory) / "02-devices_config.csv", V2_HEADER, rows)


def empty_leases(directory: str) -> Path:
    path = Path(directory) / "dhcpd.leases"
    path.write_text("", encoding="utf-8")
    return path


METHODS = {SWITCH: "ztp", MGMT: "deploy_infra", LEGACY: "deploy_infra", UFM1: "", UFM2: ""}


class LoadServerTypesTests(unittest.TestCase):
    """DAY0-Prepare/11-load.py::load_device_types and _release_inventory."""

    def test_v2_inventory_validates_and_selects_only_the_switch_family(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_mixed(directory)
            methods: dict[str, str] = {}
            types = LOAD.load_device_types(path, 2, methods_out=methods)
            self.assertEqual(
                frozenset({"eth"}), LOAD.filter_device_types_for_switch_scope(types, "all"),
            )
            self.assertEqual(frozenset({"eth"}), LOAD.load_device_types(path, 2, switch_scope="eth"))
            self.assertEqual(frozenset(), LOAD.load_device_types(path, 2, switch_scope="ib"))
            self.assertEqual("ztp", methods[SWITCH.casefold()])
            self.assertEqual(methods[LEGACY.casefold()], methods[MGMT.casefold()],
                             "server_mgmt must bind the same executor as server")
            self.assertEqual("deploy_infra", methods[MGMT.casefold()])
            self.assertNotIn(UFM1.casefold(), methods)
            self.assertNotIn(UFM2.casefold(), methods)

    def test_declared_config_method_column_server_mgmt_matches_server(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_mixed(directory, config_methods=METHODS)
            methods: dict[str, str] = {}
            LOAD.load_device_types(path, 2, methods_out=methods)
            self.assertEqual("deploy_infra", methods[MGMT.casefold()])
            self.assertNotIn(UFM1.casefold(), methods)
        for kind in ("server", "server_mgmt"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                wrong = dict(METHODS, **{MGMT if kind == "server_mgmt" else LEGACY: "ztp"})
                path = write_mixed(directory, config_methods=wrong)
                with self.assertRaisesRegex(LOAD.LoadError, "config_method"):
                    LOAD.load_device_types(path, 2)

    def test_release_inventory_skips_every_server_row(self):
        with tempfile.TemporaryDirectory() as directory:
            records = LOAD._release_inventory(write_mixed(directory))
            self.assertEqual([SWITCH], [item["hostname"] for item in records])

    def test_short_v1_ufm_row_raises_no_column_count_error(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_short_v1(directory)
            types = LOAD.load_device_types(path, 1)
            self.assertEqual(frozenset({"eth"}),
                             LOAD.filter_device_types_for_switch_scope(types, "all"))
            self.assertEqual([SWITCH], [item["hostname"] for item in LOAD._release_inventory(path)])

    def test_unknown_type_is_still_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            rows = mixed_rows(len(V2_HEADER))
            rows[1][1] = "ufm"
            path = write_csv(Path(directory) / "02-devices_config.csv", V2_HEADER, rows)
            with self.assertRaisesRegex(LOAD.LoadError, "type='ufm' 无效"):
                LOAD.load_device_types(path, 2)


class PublisherServerTypesTests(unittest.TestCase):
    """ztp/config/cumulus/d-hostname2mac.py::load_csv."""

    def test_only_the_switch_is_published(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(write_mixed(directory))
            with contextlib.redirect_stdout(io.StringIO()) as output:
                devices = PUBLISHER.load_csv(path)
                self.assertEqual({}, PUBLISHER.load_csv(path, switch_scope="ib"))
            self.assertEqual({SWITCH.casefold()}, set(devices))
            for hostname in SERVER_HOSTS:
                self.assertNotIn(hostname, output.getvalue())

    def test_short_v1_ufm_row_raises_no_column_count_error(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = PUBLISHER.load_csv(str(write_short_v1(directory)))
            self.assertEqual({SWITCH.casefold()}, set(devices))


class DhcpServerTypesTests(unittest.TestCase):
    """ztp/config/isc-dhcp-server/c1-generate_dhcp.py::load_csv."""

    def test_no_dhcp_host_for_server_rows(self):
        with tempfile.TemporaryDirectory() as directory:
            records = DHCP.load_csv(str(write_mixed(directory)), schema_version=2)
            self.assertEqual([(SWITCH, "eth0")], [(r["hostname"], r["iface"]) for r in records])

    def test_declared_config_method_column_server_mgmt_matches_server(self):
        with tempfile.TemporaryDirectory() as directory:
            records = DHCP.load_csv(
                str(write_mixed(directory, config_methods=METHODS)), schema_version=2,
            )
            self.assertEqual([(SWITCH, "ztp")], [(r["hostname"], r["config_method"]) for r in records])
        for hostname in (LEGACY, MGMT):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as directory:
                path = write_mixed(directory, config_methods=dict(METHODS, **{hostname: "ztp"}))
                with self.assertRaisesRegex(ValueError, "config_method"):
                    DHCP.load_csv(str(path), schema_version=2)

    def test_short_v1_ufm_row_raises_no_column_count_error(self):
        with tempfile.TemporaryDirectory() as directory:
            records = DHCP.load_csv(str(write_short_v1(directory)), schema_version=1)
            self.assertEqual([SWITCH], [r["hostname"] for r in records])


class BackupServerTypesTests(unittest.TestCase):
    """ztp/backup/yaml-collect.py::load_devices_csv."""

    def test_only_the_switch_is_a_backup_target(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = BACKUP.load_devices_csv(str(write_mixed(directory)))
            self.assertEqual([SWITCH], [item["hostname"] for item in devices])


class ManualZtpServerTypesTests(unittest.TestCase):
    """ztp/manual-ztp.py::read_devices."""

    def test_only_the_switch_is_a_manual_ztp_target(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = MANUAL.read_devices(
                write_mixed(directory), dhcp_leases=empty_leases(directory),
            )
            self.assertEqual([SWITCH], [item["hostname"] for item in devices])


class ZtpMonitorServerTypesTests(unittest.TestCase):
    """DAY0-Prepare/12-ztp-monitor.py::read_devices (never SSH a server as cumulus@)."""

    def test_only_the_switch_is_monitored(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = MONITOR.read_devices(
                write_mixed(directory), dhcp_leases=empty_leases(directory),
            )
            self.assertEqual([(SWITCH, "cumulus")],
                             [(item["hostname"], item["ssh_user"]) for item in devices])
            addresses = {address for item in devices for address in item["ssh_ips"]}
            self.assertIn("192.0.2.11", addresses)
            for server_address in ("198.51.100.30", "198.51.100.32",
                                   "198.51.100.40", "198.51.100.41"):
                self.assertNotIn(server_address, addresses)

    def test_declared_config_method_column_server_mgmt_matches_server(self):
        with tempfile.TemporaryDirectory() as directory:
            devices = MONITOR.read_devices(
                write_mixed(directory, config_methods=METHODS),
                dhcp_leases=empty_leases(directory),
            )
            self.assertEqual([(SWITCH, "ztp")],
                             [(item["hostname"], item["config_method"]) for item in devices])
        for hostname in (LEGACY, MGMT):
            with self.subTest(hostname=hostname), tempfile.TemporaryDirectory() as directory:
                path = write_mixed(directory, config_methods=dict(METHODS, **{hostname: "ztp"}))
                with self.assertRaisesRegex(ValueError, "config_method"):
                    MONITOR.read_devices(path, dhcp_leases=empty_leases(directory))


def report_with_servers() -> dict:
    return {"devices": [
        {"hostname": SWITCH, "type": "eth", "environment": "production"},
        {"hostname": UFM1, "type": "server_ufm", "environment": "production"},
        {"hostname": MGMT, "type": "server_mgmt", "environment": "production"},
        {"hostname": LEGACY, "type": "server", "environment": "production"},
    ]}


class DiagnosticsServerTypesTests(unittest.TestCase):
    """tools/collect-ztp-diagnostics.py::select_devices."""

    def test_server_rows_are_never_diagnostic_targets(self):
        report = report_with_servers()
        self.assertEqual([SWITCH], [item["hostname"] for item in
                                    DIAGNOSTICS.select_devices(report, [SWITCH], "prod")])
        for hostname in (UFM1, MGMT, LEGACY):
            for scope in ("prod", "all"):
                with self.subTest(hostname=hostname, scope=scope):
                    with self.assertRaisesRegex(DIAGNOSTICS.DiagnosticError, "not unique"):
                        DIAGNOSTICS.select_devices(report, [hostname], scope)


class _StopAfterZtpFilter(Exception):
    pass


class MonitorHtmlZtpServerTypesTests(unittest.TestCase):
    """monitor/generate-monitor-html.py ZTP report device selection."""

    def test_csv_server_hostnames_are_excluded(self):
        with tempfile.TemporaryDirectory() as directory:
            excluded = HTML.ztp_report_excluded_hostnames(write_mixed(directory))
        self.assertEqual({name.casefold() for name in SERVER_HOSTS}, excluded)

    def test_report_rows_typed_or_named_as_servers_are_dropped(self):
        devices = report_with_servers()["devices"] + [
            # An older report row that carries no type but is a CSV server_ufm.
            {"hostname": UFM2, "type": "", "environment": "production"},
            {"hostname": "ufm09.example.test", "type": "SERVER_UFM"},
        ]
        kept = HTML.ztp_report_devices(devices, {UFM2.casefold()})
        self.assertEqual([SWITCH], [item["hostname"] for item in kept])

    def test_page_generation_filters_the_loaded_report(self):
        seen: list[str] = []

        def record(device):
            seen.append(device["hostname"])
            return "production"

        rows = report_with_servers()["devices"] + [
            # Untyped stale row: only the CSV hostname marks it as a server_ufm.
            {"hostname": UFM2, "type": "", "environment": "production"},
        ]
        report = {"available": True, "source": "fixture", "devices": [
            dict(item, unbound_identity=True, managed_ztp=True, platform_family="cumulus")
            for item in rows
        ]}
        stop = mock.Mock()
        stop.is_dir.side_effect = _StopAfterZtpFilter
        with tempfile.TemporaryDirectory() as directory:
            inventory = write_mixed(directory)
            with mock.patch.object(HTML, "DEVICES_CSV", inventory), \
                 mock.patch.object(HTML, "rotate_own_log"), \
                 mock.patch.object(HTML, "log"), \
                 mock.patch.object(HTML, "load_ztp_status", return_value=report), \
                 mock.patch.object(HTML, "ztp_environment", side_effect=record), \
                 mock.patch.object(HTML, "ETH_INFO_DIR", stop), \
                 mock.patch.object(HTML, "ENVIRONMENT_SCOPE", HTML.ENVIRONMENT_SCOPE):
                with self.assertRaises(_StopAfterZtpFilter):
                    HTML._generate_monitor_html("prod")
        self.assertEqual([SWITCH], seen)


class ProjectContractServerTypesTests(unittest.TestCase):
    """tools/project_contract.py config-method executor tables."""

    def test_server_mgmt_binds_the_server_executor(self):
        self.assertEqual("deploy_infra", CONTRACT.resolve_device_config_method("server_mgmt"))
        self.assertEqual(CONTRACT.resolve_device_config_method("server"),
                         CONTRACT.resolve_device_config_method("server_mgmt"))
        self.assertEqual("deploy_infra",
                         CONTRACT.validate_device_config_method("server_mgmt", "deploy_infra"))
        for method in ("ztp", "initial-setup", ""):
            with self.subTest(method=method):
                with self.assertRaises(ValueError):
                    CONTRACT.validate_device_config_method("server_mgmt", method)

    def test_server_ufm_has_no_config_executor(self):
        for method in ("deploy_infra", "ztp", "initial-setup", ""):
            with self.subTest(method=method):
                with self.assertRaises(ValueError):
                    CONTRACT.validate_device_config_method("server_ufm", method)
        with self.assertRaises(ValueError):
            CONTRACT.resolve_device_config_method("server_ufm")


def method_header() -> list[str]:
    return list(V2_HEADER) + ["config_method"]


def method_rows(**overrides: str) -> list[list[str]]:
    width = len(V2_HEADER)
    methods = dict(METHODS, **overrides)
    rows = []
    for row in mixed_rows(width):
        rows.append(row + [methods[row[0]]])
    ib = ["ib01.example.test", "ib", "NA", "203.0.113.11", "24", "203.0.113.1",
          "02:00:00:00:02:11"] + ["NA"] * (width - 7) + ["ztp"]
    rows.append(ib)
    return rows


class GeneratorServerTypesTests(unittest.TestCase):
    """ztp/config/cumulus/template/90-c2-generate_configs.py with a config_method column."""

    def triage(self, rows):
        header = method_header()
        context = GENERATOR._device_csv_header_context(header, 2)
        errors: list[str] = []
        skipped: dict[str, int] = {}
        triaged = {}
        for lineno, row in enumerate(rows, start=2):
            result = GENERATOR._triage_device_csv_row(
                row, lineno, len(header), 2, context["type_col"], errors, skipped, {},
                method_index=context["layout"].config_method_index,
            )
            triaged[row[0]] = result
        return triaged, errors, skipped

    def load_ib(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            inventory = write_csv(Path(directory) / "02-devices_config.csv", method_header(), rows)
            with mock.patch.multiple(
                GENERATOR, _CSV_FILE=str(inventory), _load_global_document=mock.DEFAULT,
            ) as patched, contextlib.redirect_stdout(io.StringIO()) as output:
                patched["_load_global_document"].return_value = ({}, 2)
                devices, errors = GENERATOR._load_csv_ib()
        return devices, errors, output.getvalue()

    def test_eth_triage_keeps_the_switch_and_skips_server_rows(self):
        triaged, errors, skipped = self.triage(method_rows())
        self.assertEqual([], errors)
        self.assertEqual("ztp", triaged[SWITCH][4])
        self.assertEqual("eth", triaged[SWITCH][1])
        for hostname in SERVER_HOSTS:
            self.assertIsNone(triaged[hostname], hostname)
        self.assertEqual({"server_ufm": 2}, skipped)

    def test_eth_triage_rejects_a_wrong_server_mgmt_method(self):
        for method in ("ztp", "initial-setup", "unknown-method", ""):
            with self.subTest(method=method):
                _triaged, errors, _skipped = self.triage(method_rows(**{MGMT: method}))
                self.assertEqual(1, len(errors), errors)
                self.assertIn(MGMT, errors[0])
                self.assertIn("config_method", errors[0])

    def test_generation_with_method_column_renders_only_the_switch(self):
        from test_cases.test_v2_project_schema import (
            generate_v2_redundancy_project,
            v2_header,
            v2_mlag_global,
            v2_redundant_row,
        )

        width = len(v2_header(vlan_groups=0, evpn_groups=1))
        leaf = v2_redundant_row(
            "EXAMPLE-Leaf01", 11, "198.51.100.11", "evpn", "02:00:00:20:00:03",
        ) + ["ztp"]
        ufm = [UFM1, "server_ufm", "NA", "198.51.100.30", "/23", "198.51.100.1",
               "02:00:00:00:01:30"] + [""] * (width - 7) + [""]
        mgmt = [MGMT, "server_mgmt", "NA", "198.51.100.40", "24", "198.51.100.1",
                "02:00:00:00:01:40"] + ["NA"] * (width - 7) + ["deploy_infra"]
        model, output = generate_v2_redundancy_project(
            [leaf, ufm, mgmt], v2_mlag_global(), method_column=True,
        )
        self.assertEqual({"EXAMPLE-Leaf01"}, set(model["devices"]))
        self.assertEqual("ztp", model["devices"]["EXAMPLE-Leaf01"]["config_method"])
        self.assertIn("type=server_ufm: 1", output)

    def test_ib_loader_keeps_the_switch_and_skips_server_rows(self):
        devices, errors, output = self.load_ib(method_rows())
        self.assertEqual([], errors)
        self.assertEqual([("ib01.example.test", "ztp")],
                         [(item["hostname"], item["config_method"]) for item in devices])
        self.assertIn("type=server_ufm: 2", output)

    def test_ib_loader_rejects_a_wrong_server_mgmt_method(self):
        for method in ("ztp", "unknown-method"):
            with self.subTest(method=method):
                _devices, errors, _output = self.load_ib(method_rows(**{MGMT: method}))
                self.assertEqual(1, len(errors), errors)
                self.assertIn(MGMT, errors[0])
                self.assertIn("config_method", errors[0])


class InfraServerTypesTests(unittest.TestCase):
    """infra/deploy_infra.py::load_servers, shared by infra/check_infra.py."""

    def test_server_and_server_mgmt_are_deployed_server_ufm_is_not(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_mixed(directory)
            with contextlib.redirect_stdout(io.StringIO()):
                deploy = DEPLOY.load_servers(path)
                check = CHECK.load_servers(path)
                only_ufm = DEPLOY.load_servers(path, {UFM1, "198.51.100.30"})
        expected = [
            {"hostname": MGMT, "address": "198.51.100.40"},
            {"hostname": LEGACY, "address": "198.51.100.41"},
        ]
        self.assertEqual(expected, deploy)
        self.assertEqual(expected, check)
        self.assertEqual([], only_ufm)


if __name__ == "__main__":
    unittest.main()
