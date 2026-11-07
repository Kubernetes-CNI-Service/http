"""Direct contract: setup validates the global sections of the switch families in use (I-023).

Expected behaviour comes from 问题文档 I-023 (owner 2026-11-02「11-load批我们需要修复掉这个问题」):
- without ``--switch`` the strictly validated global sections follow the switch types that
  actually appear in 02-devices_config.csv: ``ib`` -> ib, ``nvl`` -> nvl,
  ``eth``/``eth_spx``/``spx`` -> eth; a project whose only ethernet rows are ``eth_jump``
  is not held to the Cumulus requirements (``bridge``, ``system``, schema-2 VRR);
- an explicit ``--switch`` wins over the inference;
- v3.1.1 详细工作指导 WP-5 (owner 2026-11-07「同意你的建议。」): ``air`` counts as the
  eth family, the same as 11-load ``SWITCH_SCOPE_TYPES``.

The cases drive the real ``main`` argument handling into the real ``_validate_project`` and
the real validators; only the deployment lock and the link-writing body are stubbed.  They
assert which sections were validated and which errors were reported, not the exit status
or write ordering (those move with the WP-3 rewrite of ``_setup_impl``).
"""

from __future__ import annotations

from contextlib import nullcontext, redirect_stdout
import csv
import io
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock

import yaml

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
TEMPLATE = ROOT / "DAY0-Prepare" / "template"
SETUP = load_script("switch_scope_setup_under_test", ROOT / "DAY0-Prepare/01-a-setup.py")

# Schema-2 devices CSV without repeated VLAN/EVPN groups: 12 base + 7 fixed columns.
HEADER = (
    "hostname", "type", "template", "eth0_ip", "netmask", "eth0_gw",
    "eth0_mac", "eth1_ip", "netmask", "eth1_gw", "eth1_mac", "lo_ip",
    "bgp_asn", "bgp_ports", "bond_ports", "bond_type", "bond_mac",
    "peerlink_ports", "vrl",
)
BRIDGE_ERROR = "缺少顶层 key：'bridge'"


def device_row(hostname: str, kind: str, host: int) -> list[str]:
    row = [
        hostname, kind, "NA", f"192.0.2.{host}", "24", "192.0.2.1",
        f"02:00:00:00:00:{host:02x}",
    ] + ["NA"] * (len(HEADER) - 7)
    if kind in {"eth", "eth_spx", "spx"}:
        row[2] = "tan-leaf"
        row[11] = f"198.51.100.{host}"
        row[12:14] = ["65001", "swp49"]
        row[18] = "false"
    return row


# 问题文档 I-023「项目情况」: 192 ib, 14 eth_jump, 2 server_ufm (reduced to the same shape).
B300_ROWS = (
    device_row("ib-leaf01", "ib", 21),
    device_row("ib-leaf02", "ib", 22),
    device_row("jump01", "eth_jump", 31),
    device_row("jump02", "eth_jump", 32),
    device_row("ufm01", "server_ufm", 41),
)


def global_without(*eth_keys: str) -> dict:
    """The project template's merged global with keys removed from its eth section."""
    document = yaml.safe_load((TEMPLATE / "01-global.yaml").read_text(encoding="utf-8"))
    for item in document["switches"]:
        if isinstance(item, dict) and "eth" in item:
            for key in eth_keys:
                item["eth"].pop(key)
    return document


class SetupSwitchScopeContractTests(unittest.TestCase):
    """I-023: the validated global sections follow --switch, else the CSV types."""

    def make_project(self, rows, global_document) -> Path:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        project = Path(directory.name)
        (project / "01-global.yaml").write_text(
            yaml.safe_dump(global_document, sort_keys=False),
            encoding="utf-8",
        )
        shutil.copyfile(
            TEMPLATE / "02-dhcp-subnet_config.csv",
            project / "02-dhcp-subnet_config.csv",
        )
        with (project / "02-devices_config.csv").open(
            "w", newline="", encoding="utf-8",
        ) as stream:
            csv.writer(stream).writerows([HEADER, *rows])
        return project

    def validate(self, project: Path, *switch_args: str) -> dict:
        """Run setup's own argument handling, then its project validation, and observe it."""
        real_global = SETUP._validate_global_yaml
        real_csv = SETUP._validate_eth_csv
        real_mlag = SETUP._validate_v2_mlag_project
        observed = {"sections": [], "csv_errors": [], "mlag_calls": 0, "results": []}

        def global_spy(path, section_key="eth"):
            observed["sections"].append(section_key)
            return real_global(path, section_key)

        def csv_spy(path):
            errors, warnings = real_csv(path)
            observed["csv_errors"].extend(errors)
            return errors, warnings

        def mlag_spy(global_path, csv_path):
            observed["mlag_calls"] += 1
            return real_mlag(global_path, csv_path)

        def locked_body(_args):
            observed["results"].append(SETUP._validate_project(str(project)))
            return 0

        output = io.StringIO()
        with mock.patch.multiple(
            SETUP,
            _AUTO_YES=SETUP._AUTO_YES, _DRY_RUN=SETUP._DRY_RUN, _FORCE=SETUP._FORCE,
            _STRICT=SETUP._STRICT, _NO_UPGRADE=SETUP._NO_UPGRADE,
            _CONFIRM_PROJECT_SWITCH=SETUP._CONFIRM_PROJECT_SWITCH,
            _SWITCH_SCOPE=SETUP._SWITCH_SCOPE,
            _P2P_SOURCE=None,
            IMAGE_DIR=str(project / "no-shared-images"),
        ), mock.patch.object(
            SETUP, "deployment_lock", lambda *_args, **_kwargs: nullcontext(),
        ), mock.patch.object(
            SETUP, "_main_locked", locked_body,
        ), mock.patch.object(
            SETUP, "_validate_global_yaml", global_spy,
        ), mock.patch.object(
            SETUP, "_validate_eth_csv", csv_spy,
        ), mock.patch.object(
            SETUP, "_validate_v2_mlag_project", mlag_spy,
        ), mock.patch.dict(
            os.environ, {"HTTP_SETUP_KEY_MODE": ""},
        ), redirect_stdout(output):
            status = SETUP.main([
                "--dry-run", "--no-upgrade", "--host-role=workstation",
                *switch_args, str(project),
            ])
        self.assertEqual(0, status, output.getvalue())
        self.assertEqual(1, len(observed["results"]), output.getvalue())
        observed["passed"] = observed["results"][0]
        observed["output"] = output.getvalue()
        return observed

    def test_ib_and_eth_jump_project_without_switch_is_not_held_to_cumulus_rules(self):
        # I-023 验收：纯 IB 加 eth_jump 的 CSV 不再要求 bridge。期望的修复 2：只有 eth_jump
        # 时 eth 段不按 Cumulus 交换机的要求校验（schema 2 的 VRR 也是 Cumulus 的要求）。
        for removed in (("bridge",), ("bridge", "vrr")):
            with self.subTest(removed_from_eth=removed):
                project = self.make_project(B300_ROWS, global_without(*removed))
                observed = self.validate(project)
                self.assertNotIn(BRIDGE_ERROR, observed["output"])
                self.assertEqual(["ib"], observed["sections"], observed["output"])
                self.assertEqual([], observed["csv_errors"], observed["output"])
                self.assertEqual(0, observed["mlag_calls"])
                self.assertTrue(observed["passed"], observed["output"])

    def test_ethernet_switch_rows_keep_strict_eth_validation(self):
        # I-023 验收：含 eth 交换机的项目仍然严格校验 eth 段；期望的修复 2：
        # eth/eth_spx/spx → eth 段。
        for kind in ("eth", "eth_spx", "spx"):
            with self.subTest(kind=kind):
                rows = B300_ROWS + (device_row("leaf01", kind, 10),)
                observed = self.validate(self.make_project(rows, global_without("bridge")))
                self.assertIn("eth", observed["sections"], observed["output"])
                self.assertIn(BRIDGE_ERROR, observed["output"])
                self.assertEqual(1, observed["mlag_calls"])
                self.assertFalse(observed["passed"], observed["output"])

        # The CSV-side schema-2 VRR policy stays a Cumulus requirement for eth projects.
        rows = B300_ROWS + (device_row("leaf01", "eth", 10),)
        observed = self.validate(self.make_project(rows, global_without("vrr")))
        self.assertTrue(
            any("switches.eth.vrr" in error for error in observed["csv_errors"]),
            observed["output"],
        )
        self.assertFalse(observed["passed"], observed["output"])

    def test_explicit_switch_overrides_the_inferred_families(self):
        # I-023 期望的修复 2：显式给了 --switch 时，以参数为准；验收：--switch 覆盖推断的结果。
        rows = B300_ROWS + (device_row("leaf01", "eth", 10),)
        observed = self.validate(
            self.make_project(rows, global_without("bridge", "vrr")), "--switch", "ib",
        )
        self.assertNotIn(BRIDGE_ERROR, observed["output"])
        self.assertEqual(["ib"], observed["sections"], observed["output"])
        self.assertEqual([], observed["csv_errors"], observed["output"])
        self.assertEqual(0, observed["mlag_calls"])
        self.assertTrue(observed["passed"], observed["output"])

        # The other direction: an ib + eth_jump inventory is held to eth when asked for.
        observed = self.validate(
            self.make_project(B300_ROWS, global_without("bridge")), "--switch=eth",
        )
        self.assertEqual(["eth"], observed["sections"], observed["output"])
        self.assertIn(BRIDGE_ERROR, observed["output"])
        self.assertFalse(observed["passed"], observed["output"])

    def test_ib_and_nvl_inventory_validates_both_nvos_sections_only(self):
        # I-023 期望的修复 2：ib → ib 段，nvl → nvl 段；没有以太网交换机类型就不校验 eth 段。
        rows = (
            device_row("ib-leaf01", "ib", 21),
            device_row("nvl-sw01", "nvl", 61),
            device_row("jump01", "eth_jump", 31),
        )
        observed = self.validate(self.make_project(rows, global_without("bridge")))
        self.assertNotIn(BRIDGE_ERROR, observed["output"])
        self.assertCountEqual(["ib", "nvl"], observed["sections"], observed["output"])
        self.assertEqual(0, observed["mlag_calls"])
        self.assertTrue(observed["passed"], observed["output"])

    def test_air_rows_count_as_the_ethernet_family(self):
        # 详细工作指导 WP-5：air 按 load 的口径（11-load SWITCH_SCOPE_TYPES["eth"]）算 eth 族。
        rows = (
            device_row("ib-leaf01", "ib", 21),
            device_row("leaf01-air", "air", 51),
        )
        observed = self.validate(self.make_project(rows, global_without("bridge")))
        self.assertIn("eth", observed["sections"], observed["output"])
        self.assertIn(BRIDGE_ERROR, observed["output"])
        self.assertFalse(observed["passed"], observed["output"])


if __name__ == "__main__":
    unittest.main()
