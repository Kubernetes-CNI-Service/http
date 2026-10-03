"""Independent REQ22 setup input expectations."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
SETUP = load_script("req22_setup_contract", ROOT / "DAY0-Prepare/01-a-setup.py")
HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)


class Req22SetupInputTests(unittest.TestCase):
    def test_disabled_mode_accepts_canonical_header_only_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER + "\n", encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual([], errors)

    def test_enabled_mode_rejects_canonical_header_only_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=True, ztp_enabled=False,
            )
            self.assertTrue(any("没有 subnet 记录" in item for item in errors), errors)

    def test_disabled_mode_rejects_physically_blank_csv(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(" \n\t\n", encoding="utf-8")
            errors, _ = SETUP._validate_subnet_csv(
                str(source), dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertTrue(errors)


if __name__ == "__main__":
    unittest.main()
