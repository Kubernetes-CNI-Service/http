"""Direct tests for monitor/issue-tracker/switch-status.py (owner 2026-10-23).

The script prepares, from one collection, the production ETH/IB/NVL switches and UFM servers that have a
problem as rows of the online Issue Tracker's ETH&IB Switch sheet. Expectations below come from the sheet
template (header row 2, Priority list "Critical,High,Medium,Low", Status from BasicData "HW - NV Status",
Fabric from BasicData "Fabric", RU and Model are template formulas) and from the owner's problem list:
not collected, PSU/FAN state, ASIC/PSU temperature state or Max/Crit, system health.
"""
from __future__ import annotations

import importlib.util
import io
import json
import os
import subprocess
import sys
import tarfile
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "monitor/issue-tracker/switch-status.py"

COLUMNS = [
    "Issue#", "Submit Date", "Submitor", "Rack", "RU", "Host Name", "OOB IP", "SN", "Model", "Fabric",
    "Priority", "Issue Description", "NVEX Case ID", "Status", "Owner", "Action Description", "P-Status",
    "Replacement SN", "Replacement ETH0 MAC", "Remark \n(Partner)", "Remark\n(NV)",
]
PRIORITIES = {"Critical", "High", "Medium", "Low"}
FABRICS = {"OOB", "Inband", "Compute", "Storage", ""}
FORMULAS = ["RU", "Model"]          # VLOOKUP by Host Name in the template: a row must never carry them
SEP = "#" * 60
TEMPLATES = ROOT / "ztp/config/cumulus/template/03-templates-j2"


def load_script():
    spec = importlib.util.spec_from_file_location("switch_status_under_test", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def section(command: str, output: str) -> str:
    return f"{SEP}\n# Execute Command: {command}\n{SEP}\n{output}\n"


def switch_info(host: str, *, kind: str = "ETH", system_type: str = "SN5600", serial: str = "SER-TEST-0001",
                psus=(("PSU1", "ok"), ("PSU2", "ok")), fans=(("PSU1/FAN1", "ok"), ("FAN1/1", "ok")),
                sensors=(("Asic-Temp-Sensor", "64", "105", "95", "ok"),
                         ("PSU1-Temp-Sensor", "40", "90", "70", "ok")),
                health: str | None = "OK") -> str:
    """One sw-info.sh snapshot in the format the monitor page parses."""
    inventory = ["Component  HW Version  Model  Serial  State  Type",
                 "---------  ----------  -----  ------  -----  ----"]
    inventory += [f"{name}  A1  M1  S1  {state}  psu" for name, state in psus]
    inventory += [f"{name}  A1  M2  S2  {state}  fan" for name, state in fans]
    temperature = ["Name  Cur Temp (C)  Crit Temp  Max Temp  Min Temp  State",
                   "----  ------------  ---------  --------  --------  -----"]
    temperature += [f"{name}  {cur}  {crit}  {maximum}  5  {state}" for name, cur, crit, maximum, state in sensors]
    text = (f"Device: {host}\nSwitch Type: {kind} ({system_type})\nCollect Time: 2026-10-23 03:00:00\n"
            + section("nv show platform", f"serial-number  {serial}\nsystem-type    {system_type}")
            + section("nv show platform inventory", "\n".join(inventory))
            + section("nv show platform environment temperature", "\n".join(temperature)))
    if health is not None:
        text += section("nv show system health", f"status      {health}\nstatus-led  green")
    return text + "# Collect complete\n"


def ufm_info(host: str, *, enterprise: str = "active", psu_reading: str = "Presence detected",
             fan_state: str = "ok", psu_temp_state: str = "ok", hca_temp: str = "64") -> str:
    return (f"Device:       {host}\nServer Type:  UFM\nCollect Time: 2026-10-23 03:00:00\n"
            + section("hostname", host)
            + section("dmidecode -s system-serial-number", "SER-UFM-0001")
            + section("dmidecode -s system-manufacturer", "NVIDIA")
            + section("dmidecode -s system-product-name", "UFM3.5")
            + section("mget_temp -d mlx5_0", f"{hca_temp}             ")
            + section("ipmitool sdr type Temperature",
                      "Inlet Temp       | 05h | ok  |  7.1 | 27 degrees C\n"
                      f"PSU1 Temp        | 07h | {psu_temp_state:<3} | 10.1 | 52 degrees C")
            + section("ipmitool sdr type 'Power Supply'",
                      "PS Redundancy    | 77h | ok  |  7.1 | Fully Redundant\n"
                      "Status           | 85h | ok  | 10.1 | Presence detected\n"
                      f"Status           | 86h | ok  | 10.2 | {psu_reading}")
            + section("ipmitool sdr type Fan",
                      "Fan1A            | 38h | ok  |  7.1 | 7560 RPM\n"
                      f"Fan2A            | 39h | {fan_state:<3} |  7.1 | 7440 RPM\n"
                      "Fan Redundancy   | 78h | ok  |  7.1 | Fully Redundant")
            + section("systemctl is-active ufm-enterprise", enterprise)
            + "# Collect complete\n")


def write_archive(path: Path, members: dict, environment: str | None = None) -> Path:
    """A cron.sh archive: one timestamp directory with <host>.info members (and collection.json for ETH)."""
    stamp = path.name[:-len(".tar.gz")]
    with tarfile.open(path, "w:gz") as bundle:
        entries = dict(members)
        if environment is not None:
            entries["collection.json"] = json.dumps({"schema_version": 1, "environment": environment,
                                                     "collector": "cron.sh", "device_count": len(members)})
        for name, text in entries.items():
            data = text.encode("utf-8")
            member = tarfile.TarInfo(f"{stamp}/{name}")
            member.size = len(data)
            bundle.addfile(member, io.BytesIO(data))
    return path


INVENTORY = [
    # hostname, type, template, eth0_ip
    ("leaf-oob-01", "eth", "border-leaf", "192.0.2.11"),
    ("leaf-tan-01", "eth", "tan-leaf", "192.0.2.12"),
    ("leaf-spx-01", "eth_spx", "spx-leaf", "192.0.2.13"),
    ("leaf-store-01", "eth", "storage-leaf", "192.0.2.14"),
    ("leaf-misc-01", "eth", "misc", "192.0.2.15"),
    ("air-leaf-01", "air", "tan-leaf", "192.0.2.16"),
    ("ib-leaf-01", "ib", "NA", "198.51.100.21"),
    ("ib-leaf-02", "ib", "NA", "198.51.100.22"),
    ("nvl-tray-01", "nvl", "NA", "198.51.100.31"),
    ("ufm01", "server_ufm", "NA", "203.0.113.41"),
    ("ufm02", "server_ufm", "NA", "203.0.113.42"),
    ("mgmt01", "server_mgmt", "NA", "203.0.113.50"),
]


class SwitchStatusCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.project = Path(self.tmp.name) / "DAY0-Prepare/site"
        self.output = self.project / "99-output-monitor"
        for directory in ("ethernet/eth-info", "infiniband/ib-info", "infiniband/ufm-info", "nvlink/nvsw-info"):
            (self.output / directory).mkdir(parents=True)
        rows = ["hostname,type,template,eth0_ip,netmask,eth0_gw,eth0_mac"]
        rows += [f"{name},{kind},{template},{ip},24,192.0.2.254,02:00:00:00:00:{index:02x}"
                 for index, (name, kind, template, ip) in enumerate(INVENTORY, start=1)]
        (self.project / "02-devices_config.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")
        (self.project / "01-global.yaml").write_text(
            "common:\n  mgmt:\n    timezone: Asia/Shanghai\n", encoding="utf-8")
        self.module = load_script()

    def tearDown(self):
        self.tmp.cleanup()

    def run_script(self, *args):
        result = subprocess.run([sys.executable, "-B", str(SCRIPT), "--project-dir", str(self.project), *args],
                                capture_output=True, text=True, timeout=120,
                                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
        return result

    def document(self, kind):
        network = {"eth": "ethernet", "ib": "infiniband", "ufm": "infiniband", "nvl": "nvlink"}[kind]
        path = self.output / network / "issue-tracker" / f"{kind}-switch-status.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def eth_archive(self, members, name="20261023-0300-prod.tar.gz", environment="prod"):
        return write_archive(self.output / "ethernet/eth-info" / name, members, environment)

    def planned(self, *names):
        path = Path(self.tmp.name) / "planned.txt"
        path.write_text("".join(f"{name}\n" for name in names), encoding="utf-8")
        return path

    def add_inventory(self, *rows):
        with (self.project / "02-devices_config.csv").open("a", encoding="utf-8") as stream:
            for name, kind, template, ip in rows:
                stream.write(f"{name},{kind},{template},{ip},24,192.0.2.254,02:00:00:00:01:01\n")

    def row(self, document, host):
        rows = [row for row in document["rows"] if row["Host Name"] == host]
        self.assertEqual(len(rows), 1, document["rows"])
        return rows[0]


class SheetFormatTest(SwitchStatusCase):
    def test_rows_use_the_sheet_columns_and_value_lists(self):
        archive = self.eth_archive({
            "leaf-oob-01.info": switch_info("leaf-oob-01", psus=(("PSU1", "ok"), ("PSU2", "fail"))),
            "leaf-tan-01.info": switch_info("leaf-tan-01"),
            "leaf-spx-01.info": switch_info("leaf-spx-01"),
            "leaf-store-01.info": switch_info("leaf-store-01"),
            "leaf-misc-01.info": switch_info("leaf-misc-01"),
        }, name="20261023-1700-prod.tar.gz")
        result = self.run_script("--type", "eth", "--archive", str(archive))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        self.assertEqual(document["schema"], "switch-status-v1")
        self.assertEqual(document["sheet"], "ETH&IB Switch")
        self.assertEqual(document["columns"], COLUMNS)
        self.assertEqual(document["formula_columns"], FORMULAS)
        row = self.row(document, "leaf-oob-01")
        self.assertEqual(list(row), [column for column in COLUMNS if column not in FORMULAS],
                         "the sheet's columns in order, without the two formula columns")
        self.assertEqual(row["Submitor"], "CVT")
        self.assertEqual(row["Status"], "New")
        self.assertEqual(row["Submit Date"], "2026-10-24", "17:00 UTC is already the next day in Asia/Shanghai")
        self.assertEqual(row["OOB IP"], "192.0.2.11")
        self.assertEqual(row["SN"], "SER-TEST-0001")
        self.assertEqual((row["Issue#"], row["NVEX Case ID"], row["Owner"], row["P-Status"]), ("", "", "", ""))
        self.assertEqual(row["Fabric"], "OOB")
        self.assertEqual(row["Priority"], "High")
        self.assertIn("PSU2", row["Issue Description"])
        self.assertIn("fail", row["Issue Description"])
        self.assertEqual([row["Host Name"] for row in document["rows"]], ["leaf-oob-01"],
                         "healthy devices get no row")
        self.assertEqual((document["expected"], document["collected"], document["with_problems"]), (5, 5, 1))
        self.assertEqual(document["source"]["archive"], archive.name)
        self.assertEqual(document["source"]["collected_at_utc"], "2026-10-23T17:00:00Z")
        for row in document["rows"]:
            self.assertIn(row["Priority"], PRIORITIES)
            self.assertIn(row["Fabric"], FABRICS)

    def test_every_cumulus_template_family_has_its_fabric(self):
        # The Cumulus templates name the network: border, oob-*, oobofoob-* are the OOB network, tan-* the
        # inband (TAN) network; eth and eth_spx switches use them (ethernet/monitor/README.md).
        families = {"border": "OOB", "oob": "OOB", "oobofoob": "OOB", "tan": "Inband"}
        templates = sorted(path.name[:-len(".yaml.j2")] for path in TEMPLATES.glob("*.yaml.j2")
                           if not path.name.startswith("_"))
        self.assertTrue(templates)
        for template in templates:
            family = template.split("-", 1)[0]
            self.assertIn(family, families, f"a template family without a documented network: {template}")
            for kind in ("eth", "eth_spx"):
                with self.subTest(template=template, kind=kind):
                    self.assertEqual(self.module.fabric(kind, template, "leaf-01"), families[family])

    def test_fabric_by_type_then_hostname(self):
        cases = {("ib", "NA", "ib-leaf-01"): "Compute", ("nvl", "NA", "nvl-tray-01"): "Compute",
                 ("spx", "NA", "spx-leaf-01"): "Compute", ("server_ufm", "NA", "ufm01"): "Compute",
                 ("eth", "NA", "rack1-oob-leaf"): "OOB", ("eth", "NA", "rack1-tan-leaf"): "Inband",
                 ("eth", "NA", "storage-leaf-01"): "Storage", ("eth", "NA", "leaf-e"): ""}
        for (kind, template, host), fabric in cases.items():
            with self.subTest(host=host):
                self.assertEqual(self.module.fabric(kind, template, host), fabric)


class ProblemTest(SwitchStatusCase):
    def test_each_problem_kind_and_its_priority(self):
        archive = self.eth_archive({
            "leaf-oob-01.info": switch_info("leaf-oob-01", fans=(("FAN1/1", "ok"), ("FAN2/1", "fail"))),
            "leaf-tan-01.info": switch_info("leaf-tan-01", sensors=(
                ("Asic-Temp-Sensor", "96", "105", "95", "ok"), ("PSU1-Temp-Sensor", "40", "90", "70", "ok"))),
            "leaf-spx-01.info": switch_info("leaf-spx-01", sensors=(
                ("Asic-Temp-Sensor", "64", "105", "95", "ok"), ("PSU1-Temp-Sensor", "50", "90", "70", "critical"))),
            "leaf-store-01.info": switch_info("leaf-store-01", health="Not OK"),
            "leaf-misc-01.info": switch_info("leaf-misc-01", sensors=(
                ("Asic-Temp-Sensor", "106", "105", "95", "ok"),), health="N/A"),
        })
        result = self.run_script("--type", "eth", "--archive", str(archive))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        expected = {
            "leaf-oob-01": ("High", "FAN2/1"),
            "leaf-tan-01": ("High", "Asic-Temp-Sensor"),      # at or above Max
            "leaf-spx-01": ("Critical", "PSU1-Temp-Sensor"),  # state not ok
            "leaf-store-01": ("High", "health"),
            "leaf-misc-01": ("Critical", "Asic-Temp-Sensor"),  # at or above Crit; N/A health is no problem
        }
        self.assertEqual({row["Host Name"] for row in document["rows"]}, set(expected))
        for host, (priority, word) in expected.items():
            with self.subTest(host=host):
                row = self.row(document, host)
                self.assertEqual(row["Priority"], priority)
                self.assertIn(word, row["Issue Description"])
        devices = {device["hostname"]: device for device in document["devices"]}
        self.assertEqual([issue["kind"] for issue in devices["leaf-misc-01"]["issues"]], ["temperature"])
        self.assertEqual(devices["leaf-tan-01"]["issues"][0]["maximum_c"], 95.0)

    def test_several_problems_share_one_row_with_the_highest_priority(self):
        archive = self.eth_archive({"leaf-oob-01.info": switch_info(
            "leaf-oob-01", psus=(("PSU1", "fail"), ("PSU2", "ok")),
            sensors=(("Asic-Temp-Sensor", "64", "105", "95", "ok"), ("PSU1-Temp-Sensor", "95", "90", "70", "ok")))})
        planned = self.planned("leaf-oob-01")
        result = self.run_script("--type", "eth", "--archive", str(archive), "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = self.row(self.document("eth"), "leaf-oob-01")
        self.assertEqual(row["Priority"], "Critical")
        self.assertIn("PSU1: state=fail", row["Issue Description"])
        self.assertIn("PSU1-Temp-Sensor", row["Issue Description"])

    def test_a_planned_device_without_information_is_not_collected(self):
        archive = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01")})
        planned = self.planned("leaf-oob-01", "leaf-tan-01", "ib-leaf-01")
        result = self.run_script("--type", "eth", "--archive", str(archive), "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        self.assertEqual(document["expected"], 2, "only planned ETH devices are expected")
        row = self.row(document, "leaf-tan-01")
        self.assertEqual(row["Priority"], "High")
        self.assertIn("Not collected", row["Issue Description"])
        self.assertEqual(row["SN"], "", "nothing was read from it")
        self.assertEqual(row["OOB IP"], "192.0.2.12")
        self.assertEqual(row["Fabric"], "Inband")

    def test_a_device_never_takes_another_devices_snapshot(self):
        # leaf-01 is a suffix of gpu-leaf-01; both are devices of the list
        self.add_inventory(("leaf-01", "eth", "tan-leaf", "192.0.2.21"), ("gpu-leaf-01", "eth", "tan-leaf", "192.0.2.22"))
        archive = self.eth_archive({"gpu-leaf-01.info": switch_info("gpu-leaf-01", serial="SER-GPU-0001",
                                                                    health="Not OK")})
        planned = self.planned("leaf-01", "gpu-leaf-01")
        result = self.run_script("--type", "eth", "--archive", str(archive), "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        self.assertIn("Not collected", self.row(document, "leaf-01")["Issue Description"])
        self.assertEqual(self.row(document, "leaf-01")["SN"], "")
        self.assertEqual(self.row(document, "gpu-leaf-01")["SN"], "SER-GPU-0001")
        self.assertEqual(document["collected"], 1)

    def test_a_rack_prefixed_snapshot_still_belongs_to_its_device(self):
        archive = self.eth_archive({"r12-leaf-oob-01.info": switch_info("r12-leaf-oob-01", health="Not OK")})
        planned = self.planned("leaf-oob-01")
        result = self.run_script("--type", "eth", "--archive", str(archive), "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        row = self.row(self.document("eth"), "leaf-oob-01")
        self.assertIn("System health: not ok", row["Issue Description"])

    def test_a_partial_run_keeps_the_last_rows_of_the_devices_it_did_not_plan(self):
        first = self.eth_archive({
            "leaf-oob-01.info": switch_info("leaf-oob-01", psus=(("PSU1", "fail"),)),
            "leaf-spx-01.info": switch_info("leaf-spx-01", health="Not OK")})
        planned = self.planned("leaf-oob-01", "leaf-spx-01")
        self.assertEqual(self.run_script("--type", "eth", "--archive", str(first),
                                         "--planned", str(planned)).returncode, 0)
        # cron.sh --type eth_spx: only leaf-spx-01 is planned, and it is healthy now
        second = self.eth_archive({"leaf-spx-01.info": switch_info("leaf-spx-01")},
                                  name="20261023-0400-prod.tar.gz")
        planned = self.planned("leaf-spx-01")
        result = self.run_script("--type", "eth", "--archive", str(second), "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        self.assertEqual([row["Host Name"] for row in document["rows"]], ["leaf-oob-01"])
        self.assertEqual(document["carried"], 1)
        self.assertEqual(document["devices"][0]["carried_from"], first.name)
        self.assertIn("PSU1", self.row(document, "leaf-oob-01")["Issue Description"])
        # a run that plans leaf-oob-01 again replaces its row
        third = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01")}, name="20261023-0500-prod.tar.gz")
        planned = self.planned("leaf-oob-01")
        self.assertEqual(self.run_script("--type", "eth", "--archive", str(third),
                                         "--planned", str(planned)).returncode, 0)
        self.assertEqual(self.document("eth")["rows"], [])

    def test_no_archive_in_this_run_makes_every_planned_device_not_collected(self):
        planned = self.planned("ib-leaf-01", "ib-leaf-02")
        result = self.run_script("--type", "ib", "--no-archive", "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("ib")
        self.assertEqual(sorted(row["Host Name"] for row in document["rows"]), ["ib-leaf-01", "ib-leaf-02"])
        self.assertIsNone(document["source"]["archive"])
        self.assertTrue(all("Not collected" in row["Issue Description"] for row in document["rows"]))

    def test_nothing_planned_of_a_type_writes_nothing(self):
        planned = self.planned("leaf-oob-01")
        result = self.run_script("--type", "nvl", "--no-archive", "--planned", str(planned))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.output / "nvlink/issue-tracker/nvl-switch-status.json").exists())

    def test_air_devices_and_air_archives_are_never_reported(self):
        self.eth_archive({"air-leaf-01.info": switch_info("air-leaf-01", health="Not OK")},
                         name="20261023-0400-air.tar.gz", environment="air")
        prod = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01")})
        result = self.run_script("--type", "eth")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("eth")
        self.assertEqual(document["source"]["archive"], prod.name, "the newest production archive")
        self.assertNotIn("air-leaf-01", {row["Host Name"] for row in document["rows"]})

    def test_nvl_has_no_psu_or_fan_rows_and_ib_reads_its_own_directory(self):
        nvl = write_archive(self.output / "nvlink/nvsw-info/20261023-0300.tar.gz", {
            "nvl-tray-01.info": switch_info("nvl-tray-01", kind="NVLINK", system_type="MNV72", psus=(), fans=(),
                                           sensors=(("ASIC1", "60", "105", "95", "ok"),))})
        ib = write_archive(self.output / "infiniband/ib-info/20261023-0300.tar.gz", {
            "ib-leaf-01.info": switch_info("ib-leaf-01", kind="IB", system_type="Q3400-RA"),
            "ib-leaf-02.info": switch_info("ib-leaf-02", kind="IB", system_type="Q3400-RA", health="Not OK")})
        result = self.run_script("--type", "nvl", "--archive", str(nvl), "--type", "ib", "--archive", str(ib))
        self.assertEqual(result.returncode, 2, "one --archive belongs to one --type")
        self.assertEqual(self.run_script("--type", "nvl", "--archive", str(nvl)).returncode, 0)
        self.assertEqual(self.document("nvl")["rows"], [])
        self.assertEqual(self.run_script("--type", "ib").returncode, 0)
        document = self.document("ib")
        self.assertEqual([row["Host Name"] for row in document["rows"]], ["ib-leaf-02"])
        self.assertEqual(self.row(document, "ib-leaf-02")["Fabric"], "Compute")


class UfmTest(SwitchStatusCase):
    def archive(self, members):
        return write_archive(self.output / "infiniband/ufm-info/20261023-0300.tar.gz", members)

    def test_ufm_psu_fan_and_bmc_psu_temperature(self):
        archive = self.archive({
            "ufm01.info": ufm_info("ufm01", psu_reading="Power Supply AC lost", fan_state="cr"),
            "ufm02.info": ufm_info("ufm02", psu_temp_state="cr", hca_temp="88"),
        })
        result = self.run_script("--type", "ufm", "--archive", str(archive))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("ufm")
        first = self.row(document, "ufm01")
        self.assertEqual(first["Priority"], "High")
        self.assertIn("PSU2", first["Issue Description"])
        self.assertIn("Fan2A", first["Issue Description"])
        self.assertNotIn("ufm-enterprise", first["Issue Description"],
                         "the page's warning that only repeats the PSU/FAN failure is not a second problem")
        self.assertNotIn("mlx5_0", first["Issue Description"], "64 C without thresholds is not red on the page")
        self.assertEqual(first["SN"], "SER-UFM-0001")
        self.assertEqual(first["OOB IP"], "203.0.113.41")
        self.assertEqual(first["Fabric"], "Compute")
        second = self.row(document, "ufm02")
        self.assertEqual(second["Priority"], "Critical")
        self.assertIn("PSU1 Temp", second["Issue Description"])
        self.assertIn("mlx5_0", second["Issue Description"], "88 C without thresholds is red on the page")

    def test_ufm_service_without_ha_state(self):
        archive = self.archive({"ufm01.info": ufm_info("ufm01", enterprise="failed"),
                                "ufm02.info": ufm_info("ufm02", enterprise="activating")})
        result = self.run_script("--type", "ufm", "--archive", str(archive))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("ufm")
        self.assertEqual(self.row(document, "ufm01")["Priority"], "High")
        self.assertIn("ufm-enterprise: failed", self.row(document, "ufm01")["Issue Description"])
        self.assertEqual(self.row(document, "ufm02")["Priority"], "Medium")
        self.assertIn("ufm-enterprise: not active", self.row(document, "ufm02")["Issue Description"])

    def test_ufm_ha_state_from_the_vip_holder(self):
        # ufm02 is offline: the primary sees 1/2 online (warning), the offline node is an error. ufm01 also
        # lost a PSU: the HA warning is still reported. A standby's inactive ufm-enterprise is normal.
        from test_cases.test_monitor_ufm_status import ha_snapshot
        archive = self.archive({
            "ufm01.info": ufm_info("ufm01", psu_reading="Power Supply AC lost"),
            "ufm02.info": ufm_info("ufm02", enterprise="inactive"),
            "ufm01.example.test.ha": ha_snapshot(standby_online=False),
        })
        result = self.run_script("--type", "ufm", "--archive", str(archive))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        document = self.document("ufm")
        first = self.row(document, "ufm01")
        self.assertIn("PSU2", first["Issue Description"])
        self.assertIn("UFM HA warning: primary, online 1/2", first["Issue Description"])
        second = self.row(document, "ufm02")
        self.assertEqual(second["Priority"], "High")
        self.assertIn("UFM HA error: offline", second["Issue Description"])
        self.assertNotIn("ufm-enterprise", second["Issue Description"])
        # both online and healthy: no HA problem, and the standby's inactive service is no problem either
        healthy = self.archive({"ufm01.info": ufm_info("ufm01"), "ufm02.info": ufm_info("ufm02", enterprise="inactive"),
                                "ufm01.example.test.ha": ha_snapshot()})
        self.assertEqual(self.run_script("--type", "ufm", "--archive", str(healthy)).returncode, 0)
        self.assertEqual(self.document("ufm")["rows"], [])


class IsolationTest(SwitchStatusCase):
    def test_the_page_generator_log_is_never_written(self):
        parser = self.module.monitor_parser()
        page_log = Path(parser.LOG_FILE)

        def stamp():
            return page_log.stat().st_mtime_ns if page_log.exists() else None
        before = stamp()
        parser.log("probe from test_switch_status")
        # a whole run, with a not-collected device (the page itself logs a missing device)
        archive = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01")})
        self.assertEqual(self.run_script("--type", "eth", "--archive", str(archive)).returncode, 0)
        self.assertEqual(stamp(), before, "the page's own log belongs to the page generator")

    def test_the_document_is_replaced_whole(self):
        directory = self.output / "ethernet/issue-tracker"
        directory.mkdir()
        stale = {"schema": "switch-status-v1", "device_type": "eth", "source": {"archive": "old.tar.gz"},
                 "rows": [{"Host Name": "leaf-oob-01", "Issue Description": "stale"}],
                 "devices": [{"hostname": "leaf-oob-01"}]}
        (directory / "eth-switch-status.json").write_text(json.dumps(stale), encoding="utf-8")
        archive = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01")})
        planned = self.planned("leaf-oob-01")
        self.assertEqual(self.run_script("--type", "eth", "--archive", str(archive),
                                         "--planned", str(planned)).returncode, 0)
        self.assertEqual(self.document("eth")["rows"], [], "a planned device's old row is replaced, not kept")
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["eth-switch-status.json"],
                         "no temporary file is left behind")

    def test_the_project_is_found_through_setups_monitor_link(self):
        # a published tree: the script beside the real page parser, and setup's monitor/01-global.yaml link
        tree = Path(self.tmp.name) / "http"
        (tree / "monitor/issue-tracker").mkdir(parents=True)
        (tree / "monitor/issue-tracker/switch-status.py").write_bytes(SCRIPT.read_bytes())
        (tree / "monitor/generate-monitor-html.py").symlink_to(ROOT / "monitor/generate-monitor-html.py")
        (tree / "monitor/01-global.yaml").symlink_to(self.project / "01-global.yaml")
        archive = self.eth_archive({"leaf-oob-01.info": switch_info("leaf-oob-01", health="Not OK")})
        result = subprocess.run([sys.executable, "-B", str(tree / "monitor/issue-tracker/switch-status.py"),
                                 "--type", "eth", "--archive", str(archive)],
                                capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("leaf-oob-01", {row["Host Name"] for row in self.document("eth")["rows"]})
        (tree / "monitor/01-global.yaml").unlink()
        result = subprocess.run([sys.executable, "-B", str(tree / "monitor/issue-tracker/switch-status.py"),
                                 "--type", "eth"], capture_output=True, text=True, timeout=120)
        self.assertEqual(result.returncode, 2, "without setup's link and without --project-dir")

    def test_input_errors_exit_2_and_write_nothing(self):
        result = self.run_script("--type", "eth", "--archive", str(self.output / "ethernet/eth-info/none.tar.gz"))
        self.assertEqual(result.returncode, 2)
        bad = self.output / "ethernet/eth-info/20261023-0500-prod.tar.gz"
        bad.write_bytes(b"not a tar")
        self.assertEqual(self.run_script("--type", "eth", "--archive", str(bad)).returncode, 2)
        self.assertEqual(self.run_script("--type", "eth", "--no-archive").returncode, 2,
                         "--no-archive needs the planned devices")
        self.assertFalse((self.output / "ethernet/issue-tracker").exists())


if __name__ == "__main__":
    unittest.main()
