"""WP-C4 r617 §8.4 real collectors -> original cron fragment -> page/status.

No whole cron is sourced. Only its actual merge and archive function are run on
new owned fixture paths. Business expectations are PUBLIC independent literals.
The CLI writes only the synthetic project's local JSON; it cannot contact Tracker.
"""
from __future__ import annotations

from contextlib import ExitStack
from datetime import datetime, timedelta
import csv
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.native_cpld_physical_io import owned_test_root
from test_cases.test_monitor_c4_contract import (
    ALIASES, ROOT, collector_world, load_page, psu_inventory, run_collector,
)


def original_cron_parts():
    source = (ROOT / "ethernet/monitor/cron.sh").read_text()
    function = re.search(r"(?ms)^archive_collection_dir\(\) \{\n.*?^\}", source)
    if function is None:
        raise AssertionError("original archive function is missing")
    anchor = "    # Merge all .link files into one CSV; keep only the first header line\n"
    start = source.index(anchor)
    end = source.index('    LINK_ARCHIVE="${dir}.tar.gz"', start)
    # Original merge, no-clobber publication, temporary removal and archive call.
    return function.group(0), source[start:end]


def archive_original(test, directory, env, *, links):
    function, merge = original_cron_parts()
    script = ("set -eu\nlog() { printf '%s\\n' \"$*\"; }\n" + function +
              "\nc4_merge_original() {\nlocal dir=\"$1\"\n" + merge + "\n}\n" +
              ('c4_merge_original "$1"\n' if links else 'archive_collection_dir "$1" "[C4]"\n'))
    completed = subprocess.run(["/bin/bash", "-c", script, "c4-owned-archive", str(directory)],
                               cwd=directory.parent, env=env, stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, timeout=20, check=False)
    test.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
    test.assertTrue(Path(str(directory) + ".tar.gz").is_file())
    test.assertFalse(directory.exists(), "original successful archive cleanup was not reached")
    if links:
        test.assertTrue(Path(str(directory) + ".csv").is_file())
    return function, merge


def write_inventory(project, hosts):
    (project / "02-devices_config.csv").write_text(
        "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n" +
        "".join("%s,%s,NA,192.0.2.%d,24,192.0.2.1,02:00:00:00:00:%02x\n" %
                (host, kind, index + 10, index + 10)
                for index, (host, kind) in enumerate(hosts)), encoding="utf-8")
    (project / "01-global.yaml").write_text(
        "common:\n  mgmt:\n    timezone: UTC\n", encoding="utf-8")


def page_paths(page, project):
    output = project / "99-output-monitor"
    monitor = project / "monitor"
    monitor.mkdir(exist_ok=True)
    return dict(
        BASE_DIR=monitor, GLOBAL_FILE=project / "01-global.yaml",
        DEVICES_CSV=project / "02-devices_config.csv",
        ETH_LOG=project / "02-devices_config.csv", IB_LOG=project / "02-devices_config.csv",
        NV_LOG=project / "02-devices_config.csv",
        ETH_MON_DIR=output / "ethernet", IB_MON_DIR=output / "infiniband",
        NV_MON_DIR=output / "nvlink",
        ETH_INFO_DIR=output / "ethernet/eth-info", SPX_LINK_DIR=output / "ethernet/spx-link",
        IB_INFO_DIR=output / "infiniband/ib-info", IBL_LINK_DIR=output / "infiniband/ib-link",
        UFM_INFO_DIR=output / "infiniband/ufm-info", NV_INFO_DIR=output / "nvlink/nvsw-info",
        NVL_LINK_DIR=output / "nvlink/nvsw-link",
        OUTPUT=monitor / "monitor.html", LOG_FILE=monitor / "generate-monitor.log",
        GENERATION_LOCK=monitor / ".generate-monitor-html.lock",
        P2P_OUTPUT_DIR=project / "99-output-p2p", ZTP_STATUS_DIR=project / "ztp-status",
        ACTIVE_AIR_JSON=project / "absent-public-p2p-air.json",
        P2P_INPUT_LINK=project / "absent-public-p2p.xlsx")


def generate_page(test, page, project):
    real_lock = page.generation_lock
    with mock.patch.multiple(page, **page_paths(page, project)), \
            mock.patch.dict(os.environ, {"MONITOR_TIMEZONE": "UTC"}), \
            mock.patch.object(page, "generation_lock", side_effect=lambda: real_lock(
                project / "monitor/.generate-monitor-html.lock")), \
            mock.patch("sys.stdout", new_callable=io.StringIO):
        page.main("prod")
        html = page.OUTPUT.read_text()
        test.assertTrue(page.LOG_FILE.is_file())
        test.assertTrue(page.GENERATION_LOCK.is_file())
        test.assertEqual(0o600, page.GENERATION_LOCK.stat().st_mode & 0o777)
    return html


def status_cli(test, project, kind, archive, env):
    child_env = dict(env, PYTHONPATH=str(Path(yaml.__file__).resolve().parents[1]))
    provider = Path(yaml.__file__).resolve()
    print("C4_PUBLIC_RUNTIME_PROVIDER " + json.dumps({
        "module": "yaml", "file": str(provider), "version": yaml.__version__,
        "sha256": hashlib.sha256(provider.read_bytes()).hexdigest(),
        "child_runtime_site": child_env["PYTHONPATH"]}, sort_keys=True))
    completed = subprocess.run(
        [sys.executable, "-B", str(ROOT / "monitor/issue-tracker/switch-status.py"),
         "--project-dir", str(project), "--type", kind, "--archive", str(archive)],
        cwd=project, env=child_env, stdin=subprocess.DEVNULL,
        capture_output=True, text=True, timeout=30, check=False)
    test.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)
    network = {"eth": "ethernet", "ib": "infiniband", "nvl": "nvlink"}[kind]
    result = project / "99-output-monitor" / network / "issue-tracker" / (kind + "-switch-status.json")
    return json.loads(result.read_text()) if result.is_file() else None


class MonitorC4RealWorkflow(unittest.TestCase):
    def test_three_platform_collectors_archive_page_and_status_use_the_same_facts(self):
        with tempfile.TemporaryDirectory(prefix="c4-workflow-", dir=owned_test_root()) as folder:
            root = Path(folder)
            project = root / "project"
            project.mkdir()
            page = load_page()
            current_time = datetime.utcnow().replace(second=0, microsecond=0)
            stamp = current_time.strftime("%Y%m%d-%H%M")
            fixtures = (
                ("eth", "SN5610", "swp1s0 up up 400G 9216 swp IPv6 Address: fe80::1/64\n",
                 "ethernet", "eth-info", "spx-link", ALIASES[0]),
                ("ib", "Q3400_RA", "sw1p1 down 800G 4096 ib Down Polling\n",
                 "infiniband", "ib-info", "ib-link", ALIASES[1]),
                ("nvl", "N5500_LD", "acp1 down 400G 256 nvl Down Disabled\n",
                 "nvlink", "nvsw-info", "nvsw-link", ALIASES[2]))
            hosts, archives, environments = [], {}, {}
            for kind, platform, interfaces, network, info_dir, link_dir, entries in fixtures:
                info_batch = project / "99-output-monitor" / network / info_dir / stamp
                link_batch = project / "99-output-monitor" / network / link_dir / stamp
                info_batch.mkdir(parents=True)
                link_batch.mkdir(parents=True)
                old_link_batch = link_batch.parent / (current_time - timedelta(hours=1)).strftime("%Y%m%d-%H%M")
                if kind == "nvl":
                    old_link_batch.mkdir()
                for index in (1, 2):
                    host = "public-%s%d.example.test" % (kind, index)
                    hosts.append((host, kind))
                    work = root / ("%s-%d" % (kind, index))
                    work.mkdir()
                    env, _ = collector_world(work, platform, interfaces, hostname=host)
                    environments[kind] = env
                    if kind == "nvl":
                        commands_path = Path(env["C4_COMMANDS"])
                        current_commands = json.loads(commands_path.read_text())
                        old_commands = dict(current_commands)
                        old_commands["show interface acp1 link phy-detail"] = "effective-ber 1E-12\neffective-errors 11\n"
                        old_commands["show interface acp1 link counters"] = "link-downed 13\nqp1-drops 17\n"
                        commands_path.write_text(json.dumps(old_commands))
                        old_link = run_collector(self, work, env, entries[0], ".link")
                        shutil.copyfile(old_link, old_link_batch / (host + ".link"))
                        commands_path.write_text(json.dumps(current_commands))
                    for relative, suffix, batch in ((entries[0], ".link", link_batch),
                                                     (entries[1], ".info", info_batch)):
                        produced = run_collector(self, work, env, relative, suffix)
                        shutil.copyfile(produced, batch / (host + suffix))
                archive_original(self, info_batch, env, links=False)
                if kind == "nvl":
                    archive_original(self, old_link_batch, env, links=True)
                archive_original(self, link_batch, env, links=True)
                csv_path = Path(str(link_batch) + ".csv")
                with csv_path.open(newline="") as stream:
                    rows = list(csv.reader(stream))
                self.assertEqual(3, len(rows), "one real header plus two complete device rows")
                self.assertEqual(1, sum(row[0] == "Hostname" for row in rows))
                self.assertFalse(Path(str(csv_path) + ".part").exists())
                self.assertFalse(Path(str(csv_path) + ".raw.part").exists())
                before = csv_path.read_bytes()
                archive_before = Path(str(link_batch) + ".tar.gz").read_bytes()
                # Re-execute the exact merge on a newly recreated owned source dir:
                # a same-minute batch must not overwrite the published CSV or archive.
                link_batch.mkdir()
                (link_batch / "public-retry.link").write_bytes(before)
                function, merge = original_cron_parts()
                retry = subprocess.run(
                    ["/bin/bash", "-c", "log(){ :; };\n" + function +
                     "\nc4_merge_original() {\nlocal dir=\"$1\"\n" + merge +
                     "\n}\nc4_merge_original \"$1\"\n",
                     "c4-owned-no-clobber", str(link_batch)],
                    cwd=root, env=env, stdin=subprocess.DEVNULL,
                    capture_output=True, text=True, timeout=20, check=False)
                self.assertEqual(1, retry.returncode, retry.stdout + retry.stderr)
                self.assertEqual(before, csv_path.read_bytes())
                self.assertEqual(archive_before, Path(str(link_batch) + ".tar.gz").read_bytes())
                archives[kind] = Path(str(info_batch) + ".tar.gz")
            write_inventory(project, hosts)
            html = generate_page(self, page, project)
            for host, _kind in hosts:
                self.assertIn(host, html)
            self.assertIn("PSU6 (absent)", html)
            self.assertIn("PUBLIC SSD RELEASE", html)
            self.assertIn("PUBLIC ASIC RELEASE", html)
            self.assertIn("NOT OK", html)
            self.assertIn("Down接口", html)
            self.assertIn("Link↓", html)
            nvl_body = re.search(r'<tbody id="nvl-tbody">(.*?)</tbody>', html, re.S)
            self.assertIsNotNone(nvl_body)
            changed_rows = re.findall(r'<tr\b[^>]*class="r-chg"[^>]*>.*?</tr>', nvl_body.group(1), re.S)
            self.assertEqual(2, len(changed_rows))
            for row in changed_rows:
                for delta in ("+8", "+40", "+42"):
                    self.assertIn(delta, row)
            for kind in ("eth", "ib", "nvl"):
                report = status_cli(self, project, kind, archives[kind], environments[kind])
                self.assertEqual((2, 2, 2), tuple(report[k] for k in
                                 ("expected", "collected", "with_problems")))
                self.assertEqual(archives[kind].name, report["source"]["archive"])
                for row in report["rows"]:
                    self.assertEqual("High", row["Priority"])
                    self.assertIn("PSU6", row["Issue Description"])
                    self.assertIn("absent", row["Issue Description"])
                    self.assertIn("System health: not ok", row["Issue Description"])
                    self.assertNotIn("interface", row["Issue Description"].lower())

            # Same real NVL chain, ordinary OK plus bad PSU stays health OK:
            # only the independent PSU issue may propagate to Tracker JSON.
            env = environments["nvl"]
            commands_path = Path(env["C4_COMMANDS"])
            commands = json.loads(commands_path.read_text())
            commands["show system health"] = "status  OK\n"
            commands_path.write_text(json.dumps(commands))
            work = commands_path.parent
            batch = archives["nvl"].parent / (current_time + timedelta(minutes=1)).strftime("%Y%m%d-%H%M")
            batch.mkdir()
            produced = run_collector(self, work, env, ALIASES[2][1], ".info")
            shutil.copyfile(produced, batch / (env["C4_HOSTNAME"] + ".info"))
            archive_original(self, batch, env, links=False)
            write_inventory(project, [(env["C4_HOSTNAME"], "nvl")])
            report = status_cli(self, project, "nvl", Path(str(batch) + ".tar.gz"), env)
            self.assertEqual(1, report["with_problems"])
            self.assertEqual(1, len(report["rows"]))
            self.assertIn("PSU6", report["rows"][0]["Issue Description"])
            self.assertNotIn("System health", report["rows"][0]["Issue Description"])
            self.assertNotIn("WARNING", report["rows"][0]["Issue Description"])

    def test_current_inventory_filter_and_unknown_health_remain_authoritative(self):
        with tempfile.TemporaryDirectory(prefix="c4-filter-", dir=owned_test_root()) as folder:
            root = Path(folder)
            project = root / "project"
            project.mkdir()
            work = root / "collector"
            work.mkdir()
            env, _ = collector_world(work, "N5500_LD", "acp1 down 400G 256 nvl Down Disabled\n")
            data = Path(env["C4_COMMANDS"])
            original = json.loads(data.read_text())
            original["show platform inventory"] = psu_inventory(absent=False)
            page = load_page()
            host = env["C4_HOSTNAME"]
            info_root = project / "99-output-monitor/nvlink/nvsw-info"
            info_root.mkdir(parents=True)
            for index, health in enumerate(("unknown", "N/A", "", None, "OK")):
                with self.subTest(health=health):
                    commands = dict(original)
                    commands["show system health"] = ("PUBLIC status unavailable\n" if health is None
                                                       else "status  " + health + "\n")
                    data.write_text(json.dumps(commands))
                    produced = run_collector(self, work, env, ALIASES[2][1], ".info")
                    batch = info_root / ("20260102-030%d" % index)
                    batch.mkdir()
                    shutil.copyfile(produced, batch / (host + ".info"))
                    archive_original(self, batch, env, links=False)
                    write_inventory(project, [(host, "nvl")])
                    archive = Path(str(batch) + ".tar.gz")
                    report = status_cli(self, project, "nvl", archive, env)
                    self.assertEqual((1, 1, 0), tuple(report[k] for k in
                                     ("expected", "collected", "with_problems")))
                    self.assertEqual([], report["rows"], "port down alone is not a Tracker High")
                    # The same archive feeds real page main and the status CLI.
                    # Match only this device's card header/list row Health node.
                    current_html = generate_page(self, page, project)
                    name = re.escape(host.lower())
                    views = (
                        ("card", re.search(
                            r'<div class="sw-card(?: sw-card-miss)?"[^>]*\bdata-hn="' + name +
                            r'"[^>]*>(.*?)<div class="sw-(?:miss-)?body">', current_html, re.S)),
                        ("list", re.search(
                            r'<tr class="lst-row(?: lst-row-miss)?"[^>]*\bdata-hn="' + name +
                            r'"[^>]*>(.*?)</tr>', current_html, re.S)))
                    expected = ("h-ok", "OK") if health == "OK" else ("h-unk", "NOT OK")
                    for view, match in views:
                        with self.subTest(view=view):
                            self.assertIsNotNone(match, "the current inventory's device disappeared")
                            self.assertEqual([expected], re.findall(
                                r'<span class="h-badge ([^"]+)">([^<]*)</span>', match.group(1)))
            html = generate_page(self, page, project)
            self.assertIn(host, html)
            write_inventory(project, [])
            hidden = generate_page(self, page, project)
            self.assertNotIn('data-hn="' + host + '"', hidden)
            self.assertNotIn('data-hn="' + host.lower() + '"', hidden)
            status_path = project / "99-output-monitor/nvlink/issue-tracker/nvl-switch-status.json"
            self.assertTrue(status_path.is_file(), "qualified status CLI did not publish its JSON")
            status_path.unlink()
            self.assertIsNone(status_cli(self, project, "nvl", archive, env),
                              "no current NVL inventory must not revive an archived device")
