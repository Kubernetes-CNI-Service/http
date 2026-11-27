"""WP-C4 r617 §8.2–8.5 independent PUBLIC format contracts.

Expected literals below come from the approved C4 contracts, not parser output.
All temporary roots are explicitly runner-owned. No device, customer input or
native service is used; fake commands operate on this test's own JSON files.
"""
from __future__ import annotations

import csv
import copy
from datetime import datetime, timedelta
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.native_cpld_physical_io import owned_test_root

ROOT = Path(__file__).resolve().parents[1]
PAGE = ROOT / "monitor/generate-monitor-html.py"
ALIASES = (
    ("ethernet/monitor/sw-link.sh", "ethernet/monitor/sw-info.sh"),
    ("infiniband/monitor/sw-link.sh", "infiniband/monitor/sw-info.sh"),
    ("nvlink/monitor/sw-link.sh", "nvlink/monitor/sw-info.sh"),
)
NVL_HEADERS = ("Hostname", "Interface", "Effective-BER", "Effective-Error",
               "Link-Downed", "QP1-Drops", "State")


def load_page():
    name = "_c4_monitor_page"
    spec = importlib.util.spec_from_file_location(name, PAGE)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    before = list(sys.path)
    sys.modules[name] = module
    sys.path.insert(0, str(PAGE.parent))
    try:
        with mock.patch.dict(os.environ, {"MONITOR_TIMEZONE": "UTC"}):
            spec.loader.exec_module(module)
    finally:
        sys.path[:] = before
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def info_text(kind="IB", *, health="OK", inventory="", interfaces="", firmware=""):
    return ("Switch Type: " + kind + " (PUBLIC-MODEL)\n"
            "Collect Time: 2026-01-02 03:04:05\n" +
            "".join("\n####################################################\n"
                    "# Execute Command: " + command +
                    "\n####################################################\n" + body + "\n"
                    for command, body in (
                        ("nv show platform inventory", inventory),
                        ("nv show system health", "status  " + health),
                        ("nv show interface", interfaces),
                        ("nv show platform firmware", firmware))))


def psu_inventory(*, absent=True, explicit=False, reverse=False, absent_first=False):
    header = ("Component HW Version Model Serial State Type\n" if explicit else
              "        HW Version Model Serial State Type\n"
              "------- ---------- ----- ------ ----- ----\n")
    rows = ["FAN%d N/A N/A N/A ok fan" % n for n in range(1, 21)]
    rows += ["PSU%d A1 %s %s ok psu" %
             (n, "N/A" if absent and n == 6 else "PUBLIC-MODEL",
              "N/A" if absent and n == 6 else "PUBLIC-SERIAL")
             for n in range(1, 9)]
    if absent_first:
        rows.sort(key=lambda row: not row.startswith("PSU6 "))
    return header + "\n".join(reversed(rows) if reverse else rows) + "\n"


def firmware_table(rows, *, width=28):
    return ("Name      " + "Actual FW".ljust(width) + "Part Number        FW Source\n" +
            "--------  " + ("-" * (width - 2)).ljust(width) +
            "-----------------  ---------\n" +
            "".join(name.ljust(10) + value.ljust(width) + part.ljust(19) + "default\n"
                    for name, value, part in rows))


def collector_world(root, platform, interfaces, *, hostname="public-switch.example.test"):
    """Closed PUBLIC on-device model: collector commands only, no real nv/service."""
    bin_dir, temp, home = root / "bin", root / "tmp", root / "home"
    for directory in (bin_dir, temp, home):
        directory.mkdir(mode=0o700)
    mapping = {
        "show platform": "system-type  " + platform + "\n",
        "show platform inventory": psu_inventory(),
        "show platform firmware": firmware_table((
            ("BIOS", "Not Specified", "PUBLIC-BOARD"),
            ("SSD", "PUBLIC SSD RELEASE", "PUBLIC-DISK"),
            ("ASIC", "PUBLIC ASIC RELEASE", "PUBLIC-ASIC"))),
        "show system health": "status  FATAL\n",
        "show interface": interfaces,
        "show ib device": "Device  Device Type\n------  -----------\nASIC1  PUBLIC-ASIC switch  PUBLIC-FABRIC  PUBLIC-GUID  1\nASIC2  PUBLIC-ASIC switch  PUBLIC-FABRIC  PUBLIC-GUID  4\n",
    }
    for port in ("swp1s0", "swp2s0", "swp3s0", "sw1p1", "acp1"):
        mapping["show interface " + port + " link phy health"] = (
            "effective-ber 1E-12\neffective-errors 17\n")
        mapping["show interface " + port + " link phy-detail"] = (
            "effective-ber 1E-12\neffective-errors 19\n")
        mapping["show interface " + port] = (
            "carrier-transitions 31\noper-status-last-change 2026-01-02 03:04:05\n")
        mapping["show interface " + port + " counter"] = (
            "link\n  carrier-down-count 37\n\nDrop Counters\n"
            " Counter Receive Transmit\n ------- ------- --------\n qp1-drops 23 29\n"
            "\nPFC Statistics\n switch-priority rx-pause-frames rx-pause-duration tx-pause-frames tx-pause-duration\n 0 901 902 903 904\n\nQos Port Statistics\n"
            " Counter Receive Transmit\n ECN Marked Packets n/a 41\n Pause Frames 43 47\n")
        mapping["show interface " + port + " link counters"] = "link-downed 53\nqp1-drops 59\n"
    data = root / "commands.json"
    data.write_text(json.dumps(mapping), encoding="utf-8")
    log = root / "commands.jsonl"
    nv_source = """import json, os, sys
with open(os.environ['C4_COMMANDS'], encoding='utf-8') as f:
    values = json.load(f)
args = sys.argv[1:]
with open(os.environ['C4_COMMAND_LOG'], 'a', encoding='utf-8') as f:
    f.write(json.dumps(args) + '\\n')
key = ' '.join(args)
if key in values:
    print(values[key], end='')
elif key in ('show platform environment temperature', 'show platform transceiver detail',
             'show system image', 'show system version', 'config show',
             'show evpn multihoming esi', 'show vrf default router bgp neighbor'):
    print('PUBLIC unavailable')
else:
    print('PUBLIC unsupported command', file=sys.stderr)
    sys.exit(1)
"""
    # These are fake commands. The macOS /usr/bin dispatcher creates xcrun_db
    # in the collector's scratch before Python starts. Keep the exact scratch
    # assertion and run the fixture with this unittest's actual interpreter.
    interpreter = shlex.quote(str(Path(sys.executable).resolve(strict=True)))
    body = bin_dir / "nv_fixture.py"
    body.write_text(nv_source, encoding="utf-8")
    launcher = bin_dir / "nv"
    launcher.write_text(f'#!/bin/sh\nexec {interpreter} {shlex.quote(str(body))} "$@"\n', encoding="utf-8")
    launcher.chmod(0o700)
    for command in ("hostname", "timedatectl", "df", "free", "top", "uptime", "clagctl"):
        (bin_dir / command).write_text(
            "#!/bin/sh\nprintf '%s\\n' " +
            (hostname if command == "hostname" else "PUBLIC-unavailable") + "\n",
            encoding="utf-8")
        (bin_dir / command).chmod(0o700)
    env = {key: os.environ[key] for key in ("USER", "LOGNAME", "HTTP_TEST_OWNED_ROOT") if key in os.environ}
    env.update(HOME=str(home), TMPDIR=str(temp), PATH=str(bin_dir) + ":/usr/bin:/bin",
               LANG="C", LC_ALL="C", C4_HOSTNAME=hostname,
               C4_COMMANDS=str(data), C4_COMMAND_LOG=str(log),
               PYTHONPYCACHEPREFIX=str(root / "pyc"))
    return env, log


def run_collector(test, root, env, relative, suffix):
    completed = subprocess.run(["/bin/bash", str(ROOT / relative)], cwd=root, env=env,
                               stdin=subprocess.DEVNULL, capture_output=True, text=True,
                               timeout=20, check=False)
    test.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
    output = root / "monitor" / (env["C4_HOSTNAME"] + suffix)
    test.assertTrue(output.is_file())
    test.assertEqual([], list((root / "tmp").iterdir()), "collector left its own lock/scratch")
    return output


class CollectorC4Contracts(unittest.TestCase):
    def test_spx_summary_never_becomes_lldp_and_qos_pause_columns_are_exact(self):
        table = (
            "Interface Admin Status Oper Status Speed MTU Type Remote Host Remote Port Summary\n"
            "swp1s0 up up 400G 9216 swp public-peer.example.test swp7 IPv4 Address: 192.0.2.1/24\n"
            "swp2s0 up up 400G 9216 swp IPv6 Address: fe80::1/64\n"
            "swp3s0 up down 400G 9216 swp IPv4 Address: 192.0.2.2/24\n")
        with tempfile.TemporaryDirectory(prefix="c4-spx-", dir=owned_test_root()) as folder:
            root = Path(folder)
            env, _ = collector_world(root, "SN5610", table)
            output = run_collector(self, root, env, ALIASES[0][0], ".link")
            with output.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(["swp1s0", "swp2s0", "swp3s0"], [r["Interface"] for r in rows])
            self.assertEqual(("17", "43", "47"), tuple(rows[0][k] for k in
                             ("Effective-Error", "PFC-Receive", "PFC-Send")))
            self.assertEqual(("public-peer.example.test", "swp7"),
                             (rows[0]["Peer"], rows[0]["Peer-Interface"]))
            self.assertEqual(("", ""), (rows[1]["Peer"], rows[1]["Peer-Interface"]))
            self.assertEqual(("down", "", ""), tuple(rows[2][k] for k in
                             ("Oper-Status", "Peer", "Peer-Interface")))

    def test_ib_qp1_receive_and_transmit_are_distinct_columns(self):
        with tempfile.TemporaryDirectory(prefix="c4-ib-", dir=owned_test_root()) as folder:
            root = Path(folder)
            env, _ = collector_world(root, "Q3400_RA", "sw1p1 up 800G 4096 ib Active LinkUp\n")
            output = run_collector(self, root, env, ALIASES[1][0], ".link")
            with output.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(1, len(rows))
            self.assertEqual(("17", "37", "23", "29", "up"),
                             tuple(rows[0][k] for k in ("Effective-Error", "Carrier-Down-Count",
                                   "QP1-Drops-Receive", "QP1-Drops-Transmit", "State")))

    def test_nvlink_acp_type_and_supported_asic_command_are_published(self):
        with tempfile.TemporaryDirectory(prefix="c4-nvl-", dir=owned_test_root()) as folder:
            root = Path(folder)
            env, log = collector_world(root, "N5500_LD", "acp1 up 400G 256 nvl Active LinkUp\n")
            link = run_collector(self, root, env, ALIASES[2][0], ".link")
            with link.open(newline="") as stream:
                rows = list(csv.DictReader(stream))
            self.assertEqual(("acp1", "19", "53", "59", "up"), tuple(rows[0][k] for k in
                             ("Interface", "Effective-Error", "Link-Downed", "QP1-Drops", "State")))
            info = run_collector(self, root, env, ALIASES[2][1], ".info").read_text()
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            self.assertIn(["show", "ib", "device"], calls)
            self.assertNotIn(["show", "nvlink", "device"], calls)
            self.assertNotIn(["show", "nvlink", "port"], calls)
            self.assertIn("# Execute Command: nv show ib device\n", info)
            self.assertIn("# Collect complete\n", info)
            parsed = load_page().parse_info_file(env["C4_HOSTNAME"], info)
            self.assertEqual((2, "PUBLIC-ASIC"),
                             (parsed["ib_asic_count"], parsed["ib_asic_type"]))
            self.assertEqual(ROOT / ALIASES[0][0], (ROOT / ALIASES[2][0]).resolve())
            self.assertEqual(ROOT / ALIASES[0][1], (ROOT / ALIASES[1][1]).resolve())


class MonitorC4ParserContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.page = load_page()

    def test_psu_absence_is_order_independent_typed_and_public_shape_only(self):
        for explicit in (False, True):
            for reverse, absent_first in ((False, False), (True, False), (False, True)):
                with self.subTest(explicit=explicit, reverse=reverse, absent_first=absent_first):
                    result = self.page.parse_inventory(psu_inventory(
                        explicit=explicit, reverse=reverse, absent_first=absent_first))
                    self.assertEqual((7, 1, 20, 0), tuple(result[k] for k in
                                     ("psu_ok", "psu_fail", "fan_ok", "fan_fail")))
                    absent = next(c for c in result["inventory_components"] if c["name"] == "PSU6")
                    self.assertEqual({"name": "PSU6", "type": "psu", "state": "absent"}, absent)
                    self.assertTrue(all(set(c) == {"name", "type", "state"}
                                        for c in result["inventory_components"]))
        header = "Component HW Version Model Serial State Type\n"
        for evidence in ("A1 PUBLIC-MODEL N/A", "A1 N/A PUBLIC-SERIAL"):
            with self.subTest(evidence=evidence):
                value = self.page.parse_inventory(
                    header + "PSU1 " + evidence + " ok psu\nPSU2 N/A N/A N/A ok psu\n")
                self.assertEqual((1, 1), (value["psu_ok"], value["psu_fail"]))

    def test_all_na_hw_and_fan_cannot_invent_missing_psu_or_erase_bad_state(self):
        header = "Component HW Version Model Serial State Type\n"
        for count in (2, 8):
            text = header + "".join("PSU%d N/A N/A N/A ok psu\n" % n for n in range(count))
            text += "HW A1 PUBLIC-MODEL PUBLIC-SERIAL ok module\nFAN1 A1 MODEL SERIAL ok fan\n"
            parsed = self.page.parse_inventory(text)
            self.assertEqual((count, 0), (parsed["psu_ok"], parsed["psu_fail"]))
        text = header + "PSU1 A1 MODEL SERIAL ok psu\nPSU2 N/A N/A N/A failed psu\n"
        value = self.page.parse_inventory(text)
        self.assertEqual((1, 1), (value["psu_ok"], value["psu_fail"]))
        self.assertNotEqual("ok", value["inventory_components"][1]["state"])

    def test_explicit_non_ok_health_is_normalized_but_unknown_is_not_high(self):
        for health, expected in (("OK", "ok"), ("ok", "ok"), ("Not OK", "not ok"),
                                 ("FATAL", "not ok"), ("DEGRADED", "not ok"),
                                 ("", "unknown"), ("unknown", "unknown"), ("N/A", "n/a")):
            with self.subTest(health=health):
                result = self.page.parse_info_file("public-switch.example.test", info_text(health=health))
                self.assertEqual(expected, result["health"])
        parsed = self.page.parse_info_file("public-switch.example.test",
                                          info_text(health="OK", inventory=psu_inventory()))
        self.assertEqual("ok", parsed["health"])
        missing = self.page.parse_info_file("public-switch.example.test", "Switch Type: IB\n")
        self.assertEqual("unknown", missing["health"])

    def test_non_ok_health_badges_are_display_only_per_device(self):
        # r627 §8.2: binary ordinary-switch label, not a new raw/High verdict.
        host = "public-switch.example.test"

        def check_badge(device, css, label):
            # v3.1.6 R-027 (guide 8.13 :2223) removed the card view.  Its half of this
            # loop becomes the same per-device assertion on the list row's V2 pie
            # bucket: green OK, yellow missing, red for every other value (:2216).
            bucket = {"h-ok": "ok", "h-miss": "offline"}.get(css, "notok")
            for view in ("pie_bucket", "render_sw_list_row"):
                with self.subTest(view=view):
                    before = copy.deepcopy(device)
                    rendered = self.page.render_sw_list_row(device)
                    self.assertEqual(before, device, "a display must not rewrite raw facts")
                    if view == "pie_bucket":
                        self.assertEqual([bucket], re.findall(
                            r'<tr class="lst-row[^"]*"[^>]*\bdata-bucket="([^"]+)"', rendered))
                        continue
                    self.assertEqual([(css, label)], re.findall(
                        r'<span class="h-badge ([^"]+)">([^<]*)</span>', rendered))
                    if device["health"] == "missing":
                        self.assertIn("lst-row-miss", rendered)
                        self.assertIn("collect-fail" if device["collection_attempted"]
                                      else "collect-pending", rendered)
                        self.assertIn(device["collection_error"], rendered)

        for kind, raw_type in (("ETH", "ETH"), ("IB", "IB"), ("NVLINK", "NVL")):
            for source, raw, css, label in (
                    ("OK", "ok", "h-ok", "OK"), ("ok", "ok", "h-ok", "OK"),
                    ("Not OK", "not ok", "h-err", "NOT OK"),
                    ("FATAL", "not ok", "h-err", "NOT OK"),
                    ("DEGRADED", "not ok", "h-err", "NOT OK"),
                    ("", "unknown", "h-unk", "NOT OK"),
                    ("unknown", "unknown", "h-unk", "NOT OK"),
                    ("N/A", "n/a", "h-unk", "NOT OK")):
                with self.subTest(kind=kind, source=source):
                    device = self.page.parse_info_file(host, info_text(kind, health=source))
                    self.assertEqual(raw, device["health"])
                    check_badge(device, css, label)
            with self.subTest(kind=kind, source="no health section"):
                device = self.page.parse_info_file(host, "Switch Type: " + kind + "\n")
                self.assertEqual("unknown", device["health"])
                check_badge(device, "h-unk", "NOT OK")
                device["health"] = ""
                check_badge(device, "h-unk", "NOT OK")
            for attempted in (True, False):
                with self.subTest(kind=kind, source="missing", attempted=attempted):
                    device = self.page.make_missing_switch(host, raw_type)
                    device.update(collection_attempted=attempted,
                                  collection_error="PUBLIC collection evidence")
                    check_badge(device, "h-miss", "NOT OK")

        for raw, css, label in (("ok", "h-ok", "OK"), ("warning", "h-warn", "WARNING"),
                                ("error", "h-err", "ERROR"), ("unknown", "h-unk", "UNKNOWN"),
                                ("", "h-unk", "N/A"), ("missing", "h-miss", "MISSING")):
            with self.subTest(kind="UFM", raw=raw):
                device = self.page.make_missing_switch("public-ufm.example.test", "UFM")
                device.update(device_kind="ufm", health=raw)
                check_badge(device, css, label)

    def test_ib_and_nvlink_interface_state_matrix_and_view_title(self):
        cases = (
            ("up", "Active", "LinkUp", True), ("up", "Init", "", False),
            ("up", "Armed", "", False), ("down", "Down", "Polling", False),
            ("down", "Down", "Disabled", False), ("down", "Down", "", False),
            ("down", "Active", "LinkUp", False))
        for kind, port in (("IB", "sw1p1"), ("NVLINK", "acp1")):
            for state, logical, physical, up in cases:
                with self.subTest(kind=kind, state=state, logical=logical, physical=physical):
                    parsed = self.page.parse_info_file("public-switch.example.test",
                        info_text(kind, interfaces=" ".join((port, state, "400G", "256", "nvl" if kind == "NVLINK" else "ib",
                                                            logical, physical))))
                    self.assertEqual((int(up), 1, int(not up)), tuple(parsed[k] for k in
                                     ("interfaces_up", "interfaces_total", "interfaces_down_count")))
                    # R-027 (guide :2223): the card renderer is gone; the list keeps the title.
                    for render in (self.page.render_sw_list_row,):
                        text = render(parsed)
                        if not up:
                            self.assertIn("Down接口", text)
                            self.assertNotIn("Admin up / Oper down", text)
        eth = self.page.parse_info_file("public-switch.example.test", info_text("ETH",
            interfaces="swp1s0 down down 400G 9216 swp\nswp2s0 up down 400G 9216 swp\n"))
        self.assertEqual((0, 2, 1), tuple(eth[k] for k in
                         ("interfaces_up", "interfaces_total", "interfaces_down_count")))

    def test_full_nvlink_and_ib_counts_and_more_than_twenty_names(self):
        for kind, prefix in (("NVLINK", "acp"), ("IB", "sw")):
            lines = []
            for n in range(1, 145):
                port = "acp%d" % n if prefix == "acp" else "sw%dp1" % n
                state = "down 400G 256 nvl Down Polling" if n in (3, 34) else "up 400G 256 nvl Active LinkUp"
                lines.append(port + " " + state)
            if kind == "NVLINK":
                lines += ["eth0 up 100G 1500 eth Active LinkUp", "fnm1 up 100G 1500 fnm Active LinkUp",
                          "lo up 0 65536 loopback Active LinkUp", "sw1p1 up 400G 256 ib Active LinkUp"]
            parsed = self.page.parse_info_file("public-switch.example.test", info_text(kind, interfaces="\n".join(lines)))
            self.assertEqual((142, 144, 2), tuple(parsed[k] for k in
                             ("interfaces_up", "interfaces_total", "interfaces_down_count")))
        clean = "\n".join("acp%d up 400G 256 nvl Active LinkUp" % n for n in range(1, 145))
        parsed = self.page.parse_info_file("public-switch.example.test", info_text("NVLINK", interfaces=clean))
        self.assertEqual((144, 144, 0), tuple(parsed[k] for k in
                         ("interfaces_up", "interfaces_total", "interfaces_down_count")))
        crowded = "\n".join("acp%d down 400G 256 nvl Down Disabled" % n for n in range(1, 26))
        parsed = self.page.parse_info_file("public-switch.example.test", info_text("NVLINK", interfaces=crowded))
        self.assertEqual(25, parsed["interfaces_down_count"])
        self.assertEqual(20, len(parsed["interfaces_down"]))
        # R-027 (guide :2223): the card renderer is gone; the list keeps the truncation note.
        for render in (self.page.render_sw_list_row,):
            self.assertIn("plus 5 more", render(parsed))

    def test_firmware_column_boundaries_multiword_and_bios_only_na(self):
        rows = (("BIOS", "nOt SpEcIfIeD", "PUBLIC-BOARD"),
                ("SSD", "Not Specified", "PUBLIC-DISK"),
                ("ASIC", "PUBLIC ASIC RELEASE", "PUBLIC-ASIC"))
        for width in (28, 43):
            with self.subTest(width=width):
                self.assertEqual(("NA", "Not Specified", "PUBLIC ASIC RELEASE"),
                                 self.page.parse_firmware_versions(firmware_table(rows, width=width)))
        ordinary = firmware_table((("BIOS", "PUBLIC-V1", "BOARD"),
                                   ("Spectrum-4", "PUBLIC ASIC FIRST", "ASIC"),
                                   ("ASIC", "PUBLIC ASIC LAST", "ASIC")))
        self.assertEqual(("PUBLIC-V1", "", "PUBLIC ASIC LAST"),
                         self.page.parse_firmware_versions(ordinary))
        repeated = firmware_table(rows, width=28) + "\n" + firmware_table((
            ("BIOS", "PUBLIC-V2", "BOARD"),
            ("ASIC", "PUBLIC ASIC RELEASE BUILD 2026 LONG", "ASIC")), width=43)
        self.assertEqual(("PUBLIC-V2", "Not Specified", "PUBLIC ASIC RELEASE BUILD 2026 LONG"),
                         self.page.parse_firmware_versions(repeated))

    def test_n24_three_watch_fields_each_drive_history_delta_and_changed(self):
        self.assertEqual(["Effective-Error", "Link-Downed", "QP1-Drops"], self.page.NVL_WATCH_FIELDS)
        now = datetime(2026, 1, 2, 4)
        old = ["public-switch.example.test", "acp1", "1E-12", "11", "13", "17", "up"]
        for index, delta in ((3, 4), (4, 5), (5, 7)):
            with self.subTest(field=NVL_HEADERS[index]):
                current = list(old)
                current[index] = str(int(current[index]) + delta)
                key = (old[0], old[1])
                latest, previous = {key: current}, {key: old}
                head, body, stats, history = self.page.build_link_content(
                    [(now, Path("current.csv"), latest),
                     (now - timedelta(hours=1), Path("old.csv"), previous)],
                    list(NVL_HEADERS), latest, now, [1], self.page.NVL_WATCH_FIELDS,
                    show_transceiver_temp=False)
                self.assertEqual((1, 0), (stats["changed"], stats["same"]))
                self.assertEqual(3, head.count('class="diff-sub"'))
                self.assertIn("Link↓", head)
                self.assertIn("QP1", head)
                self.assertIn('colspan="10"', body)
                self.assertIn('class="r-chg"', body)
                self.assertIn("+" + str(delta), body)
                self.assertEqual(now - timedelta(hours=1), history[0][1])
        key = (old[0], old[1])
        head, body, stats, _ = self.page.build_link_content(
            [(now, Path("current.csv"), {key: old})], list(NVL_HEADERS), {key: old},
            now, [1], self.page.NVL_WATCH_FIELDS, show_transceiver_temp=False)
        self.assertEqual((0, 1), (stats["changed"], stats["same"]))
        self.assertEqual(3, body.count('class="inc-na">n/a'))
        self.assertNotIn('class="r-chg"', body)
