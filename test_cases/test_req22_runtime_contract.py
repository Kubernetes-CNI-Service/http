"""Independent REQ22 DHCP runtime input and mode expectations."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = load_script("req22_runtime_contract", ROOT / "tools/ztp_service_runtime.py")
HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)


class Req22RuntimeInputTests(unittest.TestCase):
    def test_disabled_header_only_csv_produces_no_local_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            plan = RUNTIME.plan_dhcp_runtime(
                source, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), plan.listener_names)
            self.assertEqual((), plan.endpoint_ips)

    def test_enabled_header_only_csv_is_not_a_runnable_dhcp_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "subnet row"):
                RUNTIME.plan_dhcp_runtime(
                    source, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=True, ztp_enabled=False,
                )

    def test_delimiter_only_record_is_not_a_blank_physical_line(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER + ",,,,,,,,\n", encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "empty delimiter"):
                RUNTIME._read_dhcp_networks(source)

    def test_symlink_csv_cannot_supply_runtime_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.csv"
            target.write_text(HEADER, encoding="utf-8")
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.symlink_to(target.name)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "non-symlink"):
                RUNTIME._read_dhcp_networks(source)


if __name__ == "__main__":
    unittest.main()
