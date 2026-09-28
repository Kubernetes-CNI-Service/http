#!/usr/bin/env python3
"""Direct contract for matching a child hostname to current P2P authority."""

from __future__ import annotations

import unittest

from test_cases.test_xlsx_zero_row_workflow import LOAD


class Req14SplitterHostnameBinding(unittest.TestCase):
    def test_exact_and_one_boundary_suffix_bind(self):
        profiles = {"swp9": "1to8"}
        self.assertEqual(profiles, LOAD._sidecar_profiles_for_child(
            {"oob-core01": profiles}, "oob-core01",
        ))
        self.assertEqual(profiles, LOAD._sidecar_profiles_for_child(
            {"g04-oob-core01": profiles}, "oob-core01",
        ))

    def test_air_child_binds_to_production_topology_owner(self):
        profiles = {"swp1": "1to2", "swp44": "1to2"}
        self.assertEqual(profiles, LOAD._sidecar_profiles_for_child(
            {"a05-tan-pod3-leaf05": profiles},
            "air-a05-tan-pod3-leaf05",
        ))

    def test_ambiguous_site_owners_fail_closed_even_if_profiles_agree(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            LOAD._sidecar_profiles_for_child({
                "g04-oob-core01": {"swp9": "1to8"},
                "g05-oob-core01": {"swp9": "1to8"},
            }, "oob-core01")

    def test_exact_and_site_owner_together_are_ambiguous(self):
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            LOAD._sidecar_profiles_for_child({
                "oob-core01": {"swp9": "1to8"},
                "g04-oob-core01": {"swp9": "1to8"},
            }, "oob-core01")

    def test_near_name_is_not_a_boundary_match(self):
        self.assertIsNone(LOAD._sidecar_profiles_for_child(
            {"g04-foob-core01": {"swp9": "1to8"}}, "oob-core01",
        ))


if __name__ == "__main__":
    unittest.main()
