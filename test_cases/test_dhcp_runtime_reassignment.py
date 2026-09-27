"""DHCP lease expiry, release, and address-reassignment regressions."""

import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "ztp/dhcp_runtime_inventory.py"
SPEC = importlib.util.spec_from_file_location("dhcp_runtime_reassignment", MODULE_PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot load {MODULE_PATH}")
RUNTIME = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNTIME)


def lease(address: str, mac: str, state: str, starts: str, ends: str) -> str:
    hardware = f"  hardware ethernet {mac};\n" if mac else ""
    return (
        f"lease {address} {{\n"
        f"  starts 1 {starts};\n"
        f"  ends 1 {ends};\n"
        f"  binding state {state};\n"
        f"{hardware}"
        "}\n"
    )


class DhcpRuntimeLeaseReassignmentTests(unittest.TestCase):
    NOW = dt.datetime(2026, 8, 31, 12, 0, tzinfo=dt.timezone.utc)

    def test_inventory_publish_replaces_existing_file_and_cleans_stage(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dhcp-runtime-inventory.json"
            output.write_text("GENUINE-OLD\n", encoding="utf-8")
            RUNTIME._atomic_json(output, {"devices": [], "count": 0})
            self.assertEqual(
                {"count": 0, "devices": []},
                json.loads(output.read_text(encoding="utf-8")),
            )
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual([output.name], [p.name for p in output.parent.iterdir()])

    def test_inventory_publish_replace_failure_preserves_existing_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dhcp-runtime-inventory.json"
            output.write_text("GENUINE-OLD\n", encoding="utf-8")
            with mock.patch.object(
                RUNTIME.os, "replace", side_effect=OSError("injected rename failure"),
            ), self.assertRaisesRegex(OSError, "injected rename failure"):
                RUNTIME._atomic_json(output, {"devices": []})
            self.assertEqual("GENUINE-OLD\n", output.read_text())
            self.assertEqual([output.name], [p.name for p in output.parent.iterdir()])

    def test_inventory_publish_refuses_rebound_parent_without_foreign_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = root / "legitimate"
            parent.mkdir()
            output = parent / "dhcp-runtime-inventory.json"
            output.write_text("GENUINE-OLD\n", encoding="utf-8")
            foreign = root / "foreign"
            foreign.mkdir()
            foreign_output = foreign / output.name
            foreign_output.write_text("FOREIGN-SENTINEL\n", encoding="utf-8")
            detached = root / "detached"
            original_replace = os.replace
            rebound = False

            def replace_after_rebind(source, target, *args, **kwargs):
                nonlocal rebound
                if not rebound:
                    rebound = True
                    parent.rename(detached)
                    parent.symlink_to(foreign, target_is_directory=True)
                    (foreign / Path(source).name).write_text(
                        "ATTACKER-STAGED\n", encoding="utf-8",
                    )
                return original_replace(source, target, *args, **kwargs)

            with mock.patch.object(
                RUNTIME.os, "replace", side_effect=replace_after_rebind,
            ), self.assertRaises(OSError):
                RUNTIME._atomic_json(output, {"devices": []})
            self.assertTrue(rebound)
            self.assertEqual("FOREIGN-SENTINEL\n", foreign_output.read_text())
            self.assertEqual(
                "GENUINE-OLD\n", (detached / output.name).read_text(),
            )

    def test_last_record_by_address_removes_previous_mac_owner(self):
        text = lease(
            "192.0.2.10", "aa:00:00:00:00:01", "active",
            "2026/08/31 10:00:00", "2026/08/31 13:00:00",
        ) + lease(
            "192.0.2.10", "bb:00:00:00:00:02", "active",
            "2026/08/31 11:00:00", "2026/08/31 14:00:00",
        )

        records = RUNTIME.parse_leases(text, self.NOW)

        self.assertNotIn("aa:00:00:00:00:01", records)
        self.assertEqual("192.0.2.10", records["bb:00:00:00:00:02"]["ip"])
        self.assertEqual("active", records["bb:00:00:00:00:02"]["lease_state"])

    def test_final_free_block_without_mac_invalidates_old_owner(self):
        text = lease(
            "192.0.2.10", "aa:00:00:00:00:01", "active",
            "2026/08/31 10:00:00", "2026/08/31 13:00:00",
        ) + lease(
            "192.0.2.10", "", "free",
            "2026/08/31 11:00:00", "2026/08/31 11:00:00",
        )

        self.assertEqual({}, RUNTIME.parse_leases(text, self.NOW))

    def test_active_record_past_its_end_is_reported_expired(self):
        text = lease(
            "192.0.2.20", "02:00:00:00:00:03", "active",
            "2026/08/31 09:00:00", "2026/08/31 10:00:00",
        )

        records = RUNTIME.parse_leases(text, self.NOW)

        self.assertEqual("expired", records["02:00:00:00:00:03"]["lease_state"])

    def test_final_lease_owner_invalidates_older_journal_owner(self):
        journal = (
            "2026-08-31T10:00:00+00:00 ZTP_DHCP_EVENT_V1 "
            "event=commit msg=5 mac=aa:00:00:00:00:01 ip=192.0.2.10 "
            "known=0 lease_state=active vendor60_hex=- client61_hex=- user77_hex=-\n"
        )
        text = lease(
            "192.0.2.10", "bb:00:00:00:00:02", "active",
            "2026/08/31 11:00:00", "2099/08/31 14:00:00",
        )
        with tempfile.TemporaryDirectory() as directory:
            leases = Path(directory) / "dhcpd.leases"
            leases.write_text(text, encoding="utf-8")
            devices = RUNTIME.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, include_known=True,
            )
        by_mac = {item["mac"]: item for item in devices}
        self.assertIsNone(by_mac["aa:00:00:00:00:01"]["ip"])
        self.assertEqual(
            "reassigned", by_mac["aa:00:00:00:00:01"]["lease_state"],
        )
        self.assertEqual("192.0.2.10", by_mac["bb:00:00:00:00:02"]["ip"])

    def test_final_free_block_invalidates_journal_owner_without_hardware(self):
        journal = (
            "2026-08-31T10:00:00+00:00 ZTP_DHCP_EVENT_V1 "
            "event=commit msg=5 mac=aa:00:00:00:00:01 ip=192.0.2.10 "
            "known=0 lease_state=active vendor60_hex=- client61_hex=- user77_hex=-\n"
        )
        text = lease(
            "192.0.2.10", "", "free",
            "2026/08/31 11:00:00", "2026/08/31 11:00:00",
        )
        with tempfile.TemporaryDirectory() as directory:
            leases = Path(directory) / "dhcpd.leases"
            leases.write_text(text, encoding="utf-8")
            devices = RUNTIME.unknown_dhcp_devices(
                journal_text=journal, lease_path=leases, include_known=True,
            )
        self.assertEqual(1, len(devices))
        self.assertIsNone(devices[0]["ip"])
        self.assertEqual("free", devices[0]["lease_state"])


if __name__ == "__main__":
    unittest.main()
