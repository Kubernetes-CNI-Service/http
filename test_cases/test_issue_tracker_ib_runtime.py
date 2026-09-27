"""REQ7: a byte-bound local IB report is evidence, never cycle authority."""

from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import xlsxwriter

from monitor.issue_tracker_ib_runtime import (
    IbBoundCycleReport, IbKWindow, IbReportLink, IbRuntimeHoldError,
    intersect_ib_report_rows, parse_ib_validation_rows,
    read_completed_ib_cycle_report, read_ib_k_window, read_ib_local_report,
    read_whitelisted_ib_k_window,
    require_completed_ib_cycle,
)
from monitor.collection_ib_cycle_binding import IbCycleRoleSource
from ztp.config.ib_topology_provenance import (
    write_cvt_provenance, write_report_provenance,
)


class IbRuntimeDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory(prefix="req7-ib-report-")
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.root = root
        self.sources = {role: root / f"{role}.txt" for role in (
            "p2p", "inventory", "port_map", "splitter", "converter", "topology_rules",
        )}
        for role, path in self.sources.items():
            path.write_text(f"independent {role} fixture\n", encoding="utf-8")
        self.cvt = root / "expected-cvt.xlsx"
        self.actual = root / "iblinkinfo.log"
        self.profile = root / "profiles.csv"
        self.report = root / "iblinkinfo-topology-validation.xlsx"
        self.actual.write_text("actual link fixture\n", encoding="utf-8")
        self.profile.write_text("profile\n", encoding="utf-8")
        with xlsxwriter.Workbook(str(self.cvt)) as book:
            book.add_worksheet("P2P")
        self._report_rows(duplicate=False, formula=False)
        write_cvt_provenance(self.cvt, self.sources)
        write_report_provenance(self.report, self.cvt, self.actual, self.profile)

    def _report_rows(self, *, duplicate: bool, formula: bool) -> None:
        with xlsxwriter.Workbook(str(self.report)) as book:
            book.add_worksheet("Summary")
            missing = book.add_worksheet("Missing_Links")
            for column, name in enumerate((
                "SrcDevice", "SrcPort", "Expected_DstDevice", "Expected_DstPort",
            )):
                missing.write(0, column, name)
            for row in range(1, 3 if duplicate else 2):
                for column, value in enumerate((
                    "leaf01", "1/1", "server01", "mlx5_0",
                )):
                    if formula and column == 0:
                        missing.write_formula(row, column, '=HYPERLINK("https://example.invalid","leaf01")')
                    else:
                        missing.write(row, column, value)
            miswired = book.add_worksheet("Miswired_Links")
            for column, name in enumerate((
                "SrcDevice", "SrcPort", "Expected_DstDevice", "Expected_DstPort",
                "Actual_DstDevice", "Actual_DstPort",
            )):
                miswired.write(0, column, name)
            for column, value in enumerate((
                "leaf02", "1/2", "server02", "mlx5_0", "server03", "mlx5_1",
            )):
                miswired.write(1, column, value)

    def test_exact_report_values_and_expected_topology_digest(self) -> None:
        rows = parse_ib_validation_rows(self.report.read_bytes())
        self.assertEqual(("Link Down", "Mis-wiring"), tuple(row.issue_type for row in rows))
        self.assertEqual(("", ""), rows[0].actual_destination)
        self.assertEqual(("server03", "mlx5_1"), rows[1].actual_destination)
        witness = read_ib_local_report(self.report)
        self.assertEqual(hashlib.sha256(self.cvt.read_bytes()).hexdigest(),
                         witness.expected_topology_sha256)
        self.assertFalse(witness.qualified)

    def test_completed_role_source_replays_report_without_granting_publish(self) -> None:
        witness = read_ib_local_report(self.report)
        source = IbCycleRoleSource(
            cycle_id="cycle-1", sequence=1, completion_sha256="a" * 64,
            evidence_sha256="b" * 64,
            roles=("info_archive", "link_archive", "link_csv",
                   "ufm_actual_archive", "ufm_actual_log", "expected_cvt",
                   "validation_report", "report_provenance", "ufm_completion_receipt"),
            report_relative_path=self.report.relative_to(self.root).as_posix(),
            report_sha256=witness.report_sha256,
            expected_topology_sha256=witness.expected_topology_sha256,
            attestation_sha256="c" * 64,
        )
        store = object()
        with mock.patch(
            "monitor.collection_ib_cycle_binding.inspect_completed_ib_cycle_roles",
            return_value=source,
        ) as replay:
            result = read_completed_ib_cycle_report(
                store, http_root=self.root, sequence=1,
            )
            self.assertIsInstance(result, IbBoundCycleReport)
            self.assertEqual(("Link Down", "Mis-wiring"),
                             tuple(row.issue_type for row in result.rows))
            self.assertEqual(source.cycle_id, result.cycle_id)
            self.assertFalse(result.qualified)
            self.assertGreaterEqual(replay.call_count, 2)
            self.report.write_bytes(b"changed-report")
            with self.assertRaises(IbRuntimeHoldError):
                read_completed_ib_cycle_report(
                    store, http_root=self.root, sequence=1,
                )

    def test_duplicate_or_formula_report_rows_hold(self) -> None:
        self._report_rows(duplicate=True, formula=False)
        with self.assertRaises(IbRuntimeHoldError):
            parse_ib_validation_rows(self.report.read_bytes())
        self._report_rows(duplicate=False, formula=True)
        with self.assertRaises(IbRuntimeHoldError):
            parse_ib_validation_rows(self.report.read_bytes())

    def test_stale_source_and_claimed_cycle_cannot_promote_local_report(self) -> None:
        witness = read_ib_local_report(self.report)
        with self.assertRaisesRegex(IbRuntimeHoldError, "no IB analyzer artifact role"):
            require_completed_ib_cycle(witness, {
                "cycle_id": "fabricated", "scope": "prod", "qualifying": True,
                "source_slots": ("ethernet/prod", "infiniband/prod", "nvlink/prod"),
            })
        self.sources["p2p"].write_text("changed P2P bytes\n", encoding="utf-8")
        with self.assertRaises(IbRuntimeHoldError):
            read_ib_local_report(self.report)

    def test_k_intersection_keeps_only_stable_issue_type_and_latest_actual(self) -> None:
        first = IbReportLink(
            "Mis-wiring", ("leaf01", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        latest = IbReportLink(
            "Mis-wiring", first.expected_endpoints,
            ("server03", "mlx5_2"), "Miswired_Links", 7,
        )
        missing = IbReportLink(
            "Link Down", first.expected_endpoints, ("", ""), "Missing_Links", 3,
        )
        digest = "a" * 64
        self.assertEqual((latest,), intersect_ib_report_rows(
            ((first,), (latest,)), (digest, digest),
        ))
        self.assertEqual((), intersect_ib_report_rows(
            ((first,), (missing,)), (digest, digest),
        ))

    def test_k_intersection_holds_on_topology_drift_or_ambiguous_key(self) -> None:
        row = IbReportLink(
            "Link Down", ("leaf01", "1/1", "server01", "mlx5_0"),
            ("", ""), "Missing_Links", 2,
        )
        digest = "a" * 64
        with self.assertRaises(IbRuntimeHoldError):
            intersect_ib_report_rows(((row,), (row,)), (digest, "b" * 64))
        with self.assertRaises(IbRuntimeHoldError):
            intersect_ib_report_rows(((row, row),), (digest,))
        with self.assertRaises(IbRuntimeHoldError):
            intersect_ib_report_rows(((row,),), ())
        forged = IbReportLink(
            "Link Down", row.expected_endpoints, ("invented", "peer"),
            "Missing_Links", 2,
        )
        with self.assertRaises(IbRuntimeHoldError):
            intersect_ib_report_rows(((forged,),), (digest,))

    def test_fabricated_k_token_or_cycle_mapping_cannot_issue_a_window(self) -> None:
        self.assertFalse(IbKWindow(
            "pending", "cold_start", 0, 3, (), (), None, (),
        ).qualified)
        with self.assertRaises(IbRuntimeHoldError):
            read_ib_k_window(
                {"scope": "prod", "cycles": (), "qualifying": True},
                http_root=self.root, token=object(),
            )
        with self.assertRaises(IbRuntimeHoldError):
            read_whitelisted_ib_k_window(
                {"scope": "prod", "cycles": (), "qualifying": True},
                http_root=self.root, token=object(),
                workbook_path=self.report,
            )

    def test_prod_ib_k_adapter_rejects_forged_or_untrusted_windows(self) -> None:
        from monitor.issue_tracker_ib_runtime import (
            ProdIbKWindow, read_prod_ib_k_window, validate_prod_ib_k_window,
        )

        forged = ProdIbKWindow(
            ("a" * 64,), ("b" * 64,), ("c" * 64,), "d" * 64,
            (), (), "e" * 64, "f" * 64, "0" * 64, qualified=True,
        )
        with self.assertRaises(IbRuntimeHoldError):
            validate_prod_ib_k_window(
                forged, object(), http_root=self.root, settings=None,
                whitelist_snapshot=None, whitelist_path=self.report,
            )
        with self.assertRaises(IbRuntimeHoldError):
            read_prod_ib_k_window(
                {"scope": "prod", "cycles": (), "qualifying": True},
                http_root=self.root, settings=None,
                whitelist_snapshot=None, whitelist_path=self.report,
            )


if __name__ == "__main__":
    unittest.main()
