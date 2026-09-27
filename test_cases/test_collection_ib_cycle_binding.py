"""Direct REQ7 IB cycle-role gate: no caller claim supplies worker authority."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from monitor.collection_ib_cycle_binding import (
    IbCycleRoleHold, inspect_completed_ib_cycle_roles,
)


class IbCycleRoleDirectTests(unittest.TestCase):
    def test_unbound_store_or_sequence_never_yields_a_role_preview(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for store, sequence in ((None, 1), ({}, 1), (object(), 1),
                                    (None, 0), (None, True), (None, "1")):
                with self.subTest(store=store, sequence=sequence):
                    with self.assertRaises(IbCycleRoleHold):
                        inspect_completed_ib_cycle_roles(
                            store, http_root=root, sequence=sequence,
                        )

    def test_no_scoped_root_is_inferred_from_the_caller(self) -> None:
        for root in (None, "", Path("relative"), Path("/nonexistent/req7-root")):
            with self.subTest(root=root), self.assertRaises(IbCycleRoleHold):
                inspect_completed_ib_cycle_roles(
                    object(), http_root=root, sequence=1,
                )


if __name__ == "__main__":
    unittest.main()
