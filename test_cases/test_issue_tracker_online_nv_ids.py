"""C-17 shared numeric reservation planning, not durable allocation authority."""

import importlib.util
from pathlib import Path
import sys
import unittest
from unittest import mock


ETH = ("eth_cabling", "leaf01", "swp1", "Link Down")
IB = ("ib_cabling", "ib-leaf01", "1/1", "Link Down")


def load():
    path = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_online_nv_ids.py"
    if not path.is_file(): raise AssertionError("shared online NV allocator is missing")
    spec = importlib.util.spec_from_file_location("isolated_online_nv_ids", path)
    module = importlib.util.module_from_spec(spec); sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class OnlineNvIdDirectTests(unittest.TestCase):
    def setUp(self): self.module = load()

    def test_highest_id_from_both_sheets_and_all_prior_reservations_is_never_reused(self):
        old = ("eth_cabling", "old-leaf", "swp1", "Mis-wiring")
        plan = self.module.plan_nv_reservations(("NV30001", "NV30008"), ("NV30009", "NV30016"), (), (IB, ETH))
        self.assertEqual(((ETH, "NV30017"), (IB, "NV30018")), plan.reservations)
        self.assertFalse(hasattr(plan, "permit"))
        self.assertFalse(hasattr(plan, "receipt"))
        prior = ((old, "NV30022"), (ETH, "NV30017"))
        planned = self.module.plan_nv_reservations(("NV30001",), ("NV30016",), prior, (ETH, IB))
        self.assertEqual(((ETH, "NV30017"), (old, "NV30022"), (IB, "NV30023")), planned.reservations)
        self.assertEqual(((ETH, "NV30017"), (IB, "NV30023")), planned.requested)
        self.assertEqual(prior, ((old, "NV30022"), (ETH, "NV30017")))

    def test_no_magic_seed_empty_rows_unknown_units_and_capacity_stop(self):
        plan = self.module.plan_nv_reservations(("NV41000",), ("NV72000",), (), (ETH,))
        self.assertEqual(((ETH, "NV72001"),), plan.requested)
        for args, kwargs in (
            (((), (), (), (ETH,)), {}),
            ((("NV30016",), (), (), (ETH,)), {"unknown_units": ("unit-unresolved",)}),
            ((("NV99999",), (), (), (ETH,)), {}),
            ((("NV99998",), (), (), (ETH, IB)), {}),
            ((("NV30016",), (), (), (ETH,)), {"unknown_units": True}),
        ):
            with self.subTest(args=args, kwargs=kwargs), self.assertRaises(self.module.OnlineNvIdHold):
                self.module.plan_nv_reservations(*args, **kwargs)
        self.assertEqual((), self.module.plan_nv_reservations(("NV99999",), (), (), ()).requested)

    def test_duplicates_malformed_ids_and_activity_shapes_do_not_allocate_or_repair(self):
        invalid = (
            (("NV30016", "NV30016"), (), (), (ETH,)),
            (("NV30016",), ("NV30016",), (), (ETH,)),
            (("NV30016",), (), ((ETH, "NV30017"), (IB, "NV30017")), (ETH,)),
            (("NV30016",), (), ((ETH, "NV30017"), (ETH, "NV30018")), (ETH,)),
            (("NV30016",), (), (), (ETH, ETH)),
            ((True,), (), (), (ETH,)),
            ((" nv30016",), (), (), (ETH,)),
            (("NV30016",), (), (), (("switch", "leaf", "fan", "fan1"),)),
            (("NV30016",), (), (), (("eth_cabling", "leaf", "swp1", "Unapproved"),)),
        )
        for args in invalid:
            with self.subTest(args=args), self.assertRaises(self.module.OnlineNvIdHold):
                self.module.plan_nv_reservations(*args)


class OnlineNvSourceWorkflowTests(unittest.TestCase):
    def test_two_actual_local_projection_sheets_feed_one_shared_online_literal_plan(self):
        from monitor.issue_tracker_local_workbook import CablingSourceRow, project_cabling_workbook_image
        from test_cases.test_issue_tracker_local_workbook import fake_workbook
        from test_cases.test_issue_tracker_cabling_projection import _sheet, _set, _repack, _value
        from test_cases.test_issue_tracker_online_cells import load as load_cells
        import json
        import xml.etree.ElementTree as ET
        module, cells = load(), load_cells()
        raw = fake_workbook()
        eth, ib = _sheet(raw, 3), _sheet(raw, 4)
        _set(eth, 3, "A3", "NV30008"); _set(ib, 3, "A3", "NV30016")
        seeded = _repack(raw, {"xl/worksheets/sheet3.xml": ET.tostring(eth),
                               "xl/worksheets/sheet4.xml": ET.tostring(ib)})
        source_rows = (
            CablingSourceRow("IB Cabling", IB, ("ib-leaf01", "1/1", "ib-spine01", "2/1"), (),
                             "MISSING_DEVICE", "peer absent", "2026-10-07T01:00:00Z"),
            CablingSourceRow("ETH Cabling", ETH, ("leaf01", "swp1", "spine01", "swp9"),
                             ("observed-peer", "swp8", "leaf01", "swp1"), "DOWN", "peer changed", "2026-10-07T01:00:00Z"),
        )
        with mock.patch("socket.socket", side_effect=AssertionError("network forbidden")):
            projected = project_cabling_workbook_image(seeded, source_rows)
            self.assertEqual("NV30017", _value(_sheet(projected, 3), "A4"))
            self.assertEqual("NV30018", _value(_sheet(projected, 4), "A4"))
            plan = module.plan_nv_reservations((_value(eth, "A3"),), (_value(ib, "A3"),), (),
                                               tuple(row.activity_key for row in source_rows))
            self.assertEqual(((ETH, "NV30017"), (IB, "NV30018")), plan.requested)
            for row in source_rows:
                identifier = dict(plan.requested)[row.activity_key]
                values = cells.source_tool_values(row, "insert", reserved_id=identifier)
                encoded = cells.encode_tool_cells(row.sheet, 8 if row.sheet == "ETH Cabling" else 9,
                                                  "insert", values)
                append = json.loads(encoded.requests_json)[0]["appendCells"]
                self.assertEqual({"userEnteredValue": {"stringValue": identifier}}, append["rows"][0]["values"][0])
                self.assertNotIn("start", append)
                self.assertNotIn("range", append)
                self.assertFalse(hasattr(encoded, "permit"))
        self.assertEqual("NV30008", _value(eth, "A3"))
        self.assertEqual("NV30016", _value(ib, "A3"))


if __name__ == "__main__": unittest.main()
