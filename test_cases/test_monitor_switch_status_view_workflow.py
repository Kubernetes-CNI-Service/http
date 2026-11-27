"""v3.1.6 C1 V2-V5 real workflow: PUBLIC archives -> real page main -> switch-status CLI.

The synthetic .info reports and the project CSV/YAML are PUBLIC fixtures owned
by this test.  The real page generator (``monitor/generate-monitor-html.py``
``main``) and the real ``monitor/issue-tracker/switch-status.py`` CLI both read
the same archives; the page is parsed with ``html.parser`` only (no page
JavaScript runs).  Expected values come from the approved v3.1.6 guide
sections 8.13 and 8.15-8.17, never from the generator's output.
"""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest import mock

from test_cases.native_cpld_physical_io import owned_test_root
from test_cases import test_monitor_c4_workflow as C4
from test_cases.test_monitor_c4_workflow import status_cli
from test_cases import test_monitor_switch_status_view as V
from test_cases.test_monitor_switch_status_view import (
    ROOT, badge_of, buttons_of, button_number, info_text, load_page, parse_html, pie_counts,
    pies_of, row_for, rows_of,
)

CSV_HEADER = "hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac\n"


def write_project(project, rows, global_yaml="common:\n  mgmt:\n    timezone: UTC\n"):
    (project / "02-devices_config.csv").write_text(
        CSV_HEADER + "".join(
            "%s,%s,%s,192.0.2.%d,24,192.0.2.1,02:00:00:00:00:%02x\n"
            % (host, kind, template, index + 10, index + 10)
            for index, (host, kind, template) in enumerate(rows)),
        encoding="utf-8")
    (project / "01-global.yaml").write_text(global_yaml, encoding="utf-8")


def write_archive(directory, stamp, reports):
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / (stamp + ".tar.gz")
    with tarfile.open(archive, "w:gz") as bundle:
        for host, text in reports.items():
            data = text.encode("utf-8")
            member = tarfile.TarInfo(stamp + "/" + host + ".info")
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
    return archive


def child_env(root):
    home = root / "home"
    home.mkdir(mode=0o700, exist_ok=True)
    return {"HOME": str(home), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8",
            "TMPDIR": str(root)}


def generate_page(test, page, project, **overrides):
    """The C4 workflow's real page main on this project, with extra module paths overridden."""
    paths = C4.page_paths(page, project)
    paths.update(overrides)
    real_lock = page.generation_lock
    with mock.patch.multiple(page, **paths), \
            mock.patch.dict(os.environ, {"MONITOR_TIMEZONE": "UTC"}), \
            mock.patch.object(page, "generation_lock", side_effect=lambda: real_lock(
                project / "monitor/.generate-monitor-html.lock")), \
            mock.patch("sys.stdout", new_callable=io.StringIO):
        page.main("prod")
        return page.OUTPUT.read_text(encoding="utf-8")


class SwitchStatusV2Workflow(unittest.TestCase):
    """8.13 real workflow: archives -> page -> rows/pies -> switch-status CLI."""

    def test_csv_family_buckets_and_raw_health_flow_from_archives_to_page_and_status(self):
        with tempfile.TemporaryDirectory(prefix="v2-workflow-", dir=owned_test_root()) as folder:
            root = Path(folder)
            project = root / "project"
            project.mkdir()
            page = load_page("_switch_status_v2_workflow_page")
            stamp = "20260102-0304"
            ib_ports = ("sw1p1 up 800G 4096 ib Active LinkUp\n"
                        "sw2p1 down 800G 4096 ib Down Disabled\n"
                        "acp1 up 400G 256 nvl Active LinkUp\n")
            write_project(project, [
                ("public-ib-spine01", "ib", "NA"), ("public-ib-spine02", "ib", "NA"),
                ("public-ib-leaf01", "ib", "NA"), ("public-ib-leaf02", "ib", "NA"),
                ("public-ib-leaf03", "ib", "NA"),
                ("public-eth-tan01", "eth", "tan-leaf"), ("public-eth-oob01", "eth", "oob-leaf"),
                ("public-eth-odd01", "eth", "NA"),
                ("pod1-nvsw01", "nvl", "NA")])
            output = project / "99-output-monitor"
            ib_archive = write_archive(output / "infiniband/ib-info", stamp, {
                "public-ib-spine01": info_text("IB", health="OK", interfaces=ib_ports),
                "public-ib-leaf01": info_text("IB", health="OK", interfaces=ib_ports),
                # Issue 13.2: CSV ib, collector header NVLINK, raw FATAL.
                "public-ib-leaf02": info_text("NVLINK", health="FATAL", interfaces=ib_ports),
                "public-ib-leaf03": info_text("IB", health="unknown", interfaces=ib_ports),
            })
            write_archive(output / "ethernet/eth-info", stamp, {
                "public-eth-tan01": info_text("ETH", health="OK"),
                "public-eth-oob01": info_text("ETH", health="Not OK"),
                "public-eth-odd01": info_text("ETH", health="OK"),
            })
            write_archive(output / "nvlink/nvsw-info", stamp, {
                "pod1-nvsw01": info_text("NVLINK", health="OK"),
            })
            document = parse_html(generate_page(self, page, project))

            expected = {
                "public-ib-spine01": ("ib", "ib-spine", "ok", ("h-ok", "OK")),
                "public-ib-spine02": ("ib", "ib-spine", "offline", ("h-miss", "NOT OK")),
                "public-ib-leaf01": ("ib", "ib-leaf", "ok", ("h-ok", "OK")),
                "public-ib-leaf02": ("ib", "ib-leaf", "notok", ("h-err", "NOT OK")),
                "public-ib-leaf03": ("ib", "ib-leaf", "notok", ("h-unk", "NOT OK")),
                "public-eth-tan01": ("eth", "tan", "ok", ("h-ok", "OK")),
                "public-eth-oob01": ("eth", "oob", "notok", ("h-err", "NOT OK")),
                "pod1-nvsw01": ("nvl", "nv-group-pod1", "ok", ("h-ok", "OK")),
            }
            for host, (family, cat, bucket, badge) in expected.items():
                with self.subTest(host=host):
                    row = row_for(document, host)
                    self.assertEqual((family, cat, bucket),
                                     (row.attrs.get("data-family"), row.attrs.get("data-cat"),
                                      row.attrs.get("data-bucket")))
                    self.assertEqual("production-" + family, row.attrs.get("data-group"))
                    self.assertEqual(badge, badge_of(row)[:2])
            self.assertIn("FATAL", badge_of(row_for(document, "public-ib-leaf02"))[2].attrs.get("title", ""))
            # CSV ib + header NVLINK counts the sw* ports (guide :2202).
            leaf02 = row_for(document, "public-ib-leaf02").text()
            self.assertIn("(1↓)", leaf02)
            self.assertIn("Down接口", "".join(node.attrs.get("title", "") for node in
                                               row_for(document, "public-ib-leaf02").iter()))
            missing = row_for(document, "public-ib-spine02")
            self.assertIn("lst-row-miss", missing.classes())
            self.assertIn("本批次未返回采集文件", missing.text())
            # The CSV row without a classifiable template stays out of the pies.
            self.assertIsNone(row_for(document, "public-eth-odd01").attrs.get("data-group"))
            notice = document.find("div", cls="pie-unclassified")
            self.assertIsNotNone(notice)
            self.assertIn("public-eth-odd01", notice.text())

            ib_pies = pies_of(document, "production-ib")
            self.assertEqual({"ib-spine": (1, 0, 1), "ib-leaf": (1, 2, 0)},
                             {key: pie_counts(figure) for key, figure in ib_pies.items()})
            self.assertEqual({"tan": (1, 0, 0), "oob": (0, 1, 0)},
                             {key: pie_counts(figure)
                              for key, figure in pies_of(document, "production-eth").items()})
            self.assertEqual({"nv-group-pod1": (1, 0, 0)},
                             {key: pie_counts(figure)
                              for key, figure in pies_of(document, "production-nvl").items()})
            for group, total, check in (("production-ib", 5, 3), ("production-eth", 2, 1),
                                        ("production-nvl", 1, 0)):
                buttons = {b.attrs["data-button"]: b for b in buttons_of(document, group)}
                self.assertEqual(total, button_number(buttons["all"]), group)
                self.assertEqual(check, button_number(buttons["check"]), group)
                self.assertEqual(total, sum(row.attrs.get("data-group") == group
                                            for row in rows_of(document)), group)

            # The same archive through the real switch-status CLI: raw health
            # unchanged, unknown is not a Tracker High, missing stays not collected.
            report = status_cli(self, project, "ib", ib_archive, child_env(root))
            issues = {row["Host Name"]: row["Issue Description"] for row in report["rows"]}
            self.assertEqual({"public-ib-leaf02", "public-ib-spine02"}, set(issues))
            self.assertIn("System health: not ok", issues["public-ib-leaf02"])
            self.assertIn("Not collected", issues["public-ib-spine02"])


class SwitchStatusV3Workflow(unittest.TestCase):
    """8.15 real workflow: PUBLIC firmware tables -> real page main -> switch-status CLI."""

    def test_cpld_slots_flow_from_the_archive_to_the_page_and_leave_status_alone(self):
        with tempfile.TemporaryDirectory(prefix="v3-workflow-", dir=owned_test_root()) as folder:
            root = Path(folder)
            project = root / "project"
            project.mkdir()
            page = load_page("_switch_status_v3_workflow_page")
            write_project(project, [("public-ib-leaf01", "ib", "NA"), ("public-ib-leaf02", "ib", "NA")])
            partial = V.OWNER_SIX[:2] + ("N/A",) + V.OWNER_SIX[3:]
            archive = write_archive(project / "99-output-monitor/infiniband/ib-info", "20260102-0304", {
                "public-ib-leaf01": info_text("IB", firmware=V.cpld_table(list(V.OWNER_SIX))),
                "public-ib-leaf02": info_text("IB", firmware=V.cpld_table(list(partial))),
            })
            document = parse_html(generate_page(self, page, project))
            heads = [node.text() for node in document.find_all("th")]
            self.assertEqual("CPLD 版本", heads[heads.index("SSD 版本") + 1])
            leaf01 = V.cpld_cell(row_for(document, "public-ib-leaf01"))
            self.assertEqual("232_0900/383_1001/389_0600/368_0300", V.cpld_short(leaf01))
            self.assertEqual(" ".join("CPLD%d=%s" % (n, value) for n, value in enumerate(V.OWNER_SIX, 1)),
                             leaf01.attrs.get("data-cpld-full"))
            self.assertEqual([("CPLD%d" % n, value) for n, value in enumerate(V.OWNER_SIX, 1)],
                             [(node.attrs.get("data-slot"), node.attrs.get("data-actual")) for node in
                              leaf01.find("div", cls="cpld-detail").find_all("div", cls="cpld-slot")])
            leaf02 = V.cpld_cell(row_for(document, "public-ib-leaf02"))
            self.assertEqual("232_0900/383_1001/CPLD3=N/A/368_0300/389_0600", V.cpld_short(leaf02))
            # The BIOS/SSD/ASIC triple still reaches its own columns.
            self.assertIn("PUBLIC-BIOS-FW", row_for(document, "public-ib-leaf01").text())
            self.assertIn("PUBLIC-SSD-FW", row_for(document, "public-ib-leaf01").text())
            # The same archive through the real switch-status CLI: CPLD values are no issue.
            status = status_cli(self, project, "ib", archive, child_env(root))
            self.assertEqual([], status["rows"])
            self.assertEqual((2, 2), (status["expected"], status["collected"]))


class SwitchStatusV3V4Workflow(unittest.TestCase):
    """8.15/8.16 real workflow: global targets + firmware tables -> page -> switch-status CLI."""

    def test_cpld_slots_and_component_targets_flow_from_archives_to_page(self):
        with tempfile.TemporaryDirectory(prefix="v34-workflow-", dir=owned_test_root()) as folder:
            root = Path(folder)
            project = root / "project"
            project.mkdir()
            page = load_page("_switch_status_v34_workflow_page")
            stamp = "20260102-0304"
            write_project(project, [
                ("public-ib-leaf01", "ib", "NA"), ("public-ib-leaf02", "ib", "NA"),
                ("public-ib-leaf03", "ib", "NA")], global_yaml=V.global_yaml(ib='"25-03-1014"'))
            def report(version, slots):
                return (info_text("IB", health="OK", firmware=V.cpld_table(list(slots)))
                        + V.section("nv show system version", "product-release  " + version))
            partial = V.OWNER_SIX[:2] + ("N/A",) + V.OWNER_SIX[3:]
            archive = write_archive(project / "99-output-monitor/infiniband/ib-info", stamp, {
                "public-ib-leaf01": report("25.03.1014", V.OWNER_SIX),
                "public-ib-leaf02": report("25.02.0001", partial),
            })
            html = generate_page(self, page, project)
            document = parse_html(html)
            heads = [node.text() for node in document.find_all("th")]
            self.assertEqual("CPLD 版本", heads[heads.index("SSD 版本") + 1])
            self.assertEqual("组件需升级", heads[heads.index("健康") - 1])
            leaf01 = row_for(document, "public-ib-leaf01")
            leaf02 = row_for(document, "public-ib-leaf02")
            leaf03 = row_for(document, "public-ib-leaf03")
            self.assertEqual("232_0900/383_1001/389_0600/368_0300",
                             V.cpld_short(V.cpld_cell(leaf01)))
            self.assertEqual(" ".join("CPLD%d=%s" % (n, value) for n, value in enumerate(V.OWNER_SIX, 1)),
                             V.cpld_cell(leaf01).attrs.get("data-cpld-full"))
            self.assertEqual("232_0900/383_1001/CPLD3=N/A/368_0300/389_0600",
                             V.cpld_short(V.cpld_cell(leaf02)))
            # BIOS/SSD come from the same tables; the fixture's values are not targets.
            self.assertEqual([("SW", "upg-warn"), ("BIOS", "upg-warn"), ("SSD", "upg-warn"),
                              ("CPLD Unknown", "upg-warn")], V.upgrade_tags(leaf02))
            self.assertEqual([("BIOS", "upg-warn"), ("SSD", "upg-warn")], V.upgrade_tags(leaf01))
            self.assertEqual([("Unknown", "upg-warn")], V.upgrade_tags(leaf03))
            buttons = {b.attrs["data-button"]: b for b in buttons_of(document, "production-ib")}
            self.assertEqual({"all": 3, "sw": 1, "bios": 2, "ssd": 2, "cpld": 0, "upgrade": 2, "check": 1},
                             {name: button_number(button) for name, button in buttons.items()})
            self.assertEqual(sum(row.attrs.get("data-upgrade") == "1" for row in rows_of(document)
                                 if row.attrs.get("data-group") == "production-ib"),
                             button_number(buttons["upgrade"]))
            # The same archive through the real switch-status CLI: versions never become issues.
            status = status_cli(self, project, "ib", archive, child_env(root))
            self.assertEqual(["public-ib-leaf03"], [row["Host Name"] for row in status["rows"]])
            self.assertIn("Not collected", status["rows"][0]["Issue Description"])


class SwitchStatusV5Workflow(unittest.TestCase):
    """8.17 real workflow: the real IB converter publishes a CVT -> page counts P -> no page writes."""

    def run_converter(self, root, project):
        converter = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
        config = root / "ztp/config"
        p2p_dir = config / "nvos/template/P2P"
        p2p_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(converter, p2p_dir / "p2p-to-validation.py")
        for name in ("topology_rules.py", "ib_topology_provenance.py"):
            shutil.copy2(ROOT / "ztp/config" / name, config / name)
        day0 = root / "DAY0-Prepare"
        day0.mkdir(exist_ok=True)
        if not (day0 / "activate-project").is_symlink():
            (day0 / "activate-project").symlink_to(project)
            (p2p_dir / "p2p.xlsx").symlink_to(day0 / "activate-project/p2p.xlsx")
            (p2p_dir / "output-p2p").symlink_to(day0 / "activate-project/99-output-p2p")
        for name, text in (("01-inventory.log", "[IB-SW]\n*leaf*\n*spine*\n\n[server]\n*server*\n"),
                           ("02-port-mapping.log", ""), ("03-splitter.log", "")):
            (p2p_dir / name).write_text(text, encoding="utf-8")
        completed = subprocess.run(
            [sys.executable, "-B", str(p2p_dir / "p2p-to-validation.py")],
            cwd=p2p_dir, text=True, capture_output=True, timeout=120, check=False,
            stdin=subprocess.DEVNULL, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        self.assertEqual(0, completed.returncode, completed.stdout + completed.stderr)

    def test_real_cvt_gives_the_planned_count_and_a_stale_cvt_gives_a_dash(self):
        import xlsxwriter

        with tempfile.TemporaryDirectory(prefix="v5-workflow-", dir=owned_test_root()) as folder:
            root = Path(folder).resolve()
            project = root / "DAY0-Prepare/fabric-a"
            (project / "99-output-p2p").mkdir(parents=True)
            workbook = project / "fabric-blue.xlsx"
            book = xlsxwriter.Workbook(str(workbook))
            sheet = book.add_worksheet("CL links")
            for number, row in enumerate((("Name", "Port", "Name", "Port"),
                                          ("leaf01", "sw1p1", "spine01", "sw1p1"),
                                          ("leaf01", "sw2p1", "spine01", "sw2p1"),
                                          ("leaf01", "sw3p1", "server01", "mlx5_0"))):
                for column, value in enumerate(row):
                    sheet.write(number, column, value)
            book.close()
            (project / "p2p.xlsx").symlink_to("fabric-blue.xlsx")
            self.run_converter(root, project)
            cvt = project / "99-output-p2p/fabric-blue-cvt.xlsx"
            self.assertTrue(cvt.is_file())
            write_project(project, [("leaf01", "ib", "NA"), ("leaf02", "ib", "NA")])
            ports = ("sw1p1 up 800G 4096 ib Active LinkUp\nsw2p1 up 800G 4096 ib Active LinkUp\n"
                     "sw3p1 up 800G 4096 ib Active LinkUp\nsw4p1 up 800G 4096 ib Active LinkUp\n")
            write_archive(project / "99-output-monitor/infiniband/ib-info", "20260102-0304", {
                "leaf01": info_text("IB", interfaces=ports), "leaf02": info_text("IB", interfaces=ports)})
            page = load_page("_switch_status_v5_workflow_page")
            listing = lambda: sorted((path.name, hashlib.sha256(path.read_bytes()).hexdigest())
                                     for path in (project / "99-output-p2p").iterdir())
            before = listing()
            document = parse_html(generate_page(self, page, project,
                                                P2P_INPUT_LINK=project / "p2p.xlsx"))
            self.assertEqual(before, listing(), "the page never writes P2P products")
            numbers = V.interface_numbers(V.interface_cell(row_for(document, "leaf01")))
            self.assertEqual(("4/3/4", ["i-mid"]), numbers)
            other = V.interface_cell(row_for(document, "leaf02"))
            self.assertEqual("4/—/4", V.interface_numbers(other)[0])
            self.assertIn("设备不在 P2P 里", other.attrs.get("title", ""))
            # The P2P changes after the CVT was published: the CVT is stale, P is a dash.
            workbook.write_bytes(workbook.read_bytes() + b"\n")
            stale = parse_html(generate_page(self, page, project, P2P_INPUT_LINK=project / "p2p.xlsx"))
            cell = V.interface_cell(row_for(stale, "leaf01"))
            self.assertEqual("4/—/4", V.interface_numbers(cell)[0])
            self.assertIn("CVT", cell.attrs.get("title", ""))
            self.assertEqual(before[:1], listing()[:1])


if __name__ == "__main__":
    unittest.main()
