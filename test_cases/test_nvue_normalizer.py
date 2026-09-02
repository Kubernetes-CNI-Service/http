#!/usr/bin/env python3
"""Regression tests for the shared NVUE selector normalizer."""

import importlib.util
from pathlib import Path
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ztp.nvue_normalizer import (
    expand_nvue_selector,
    normalize_nvue_selectors,
)


def load_script(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MANUAL = load_script("manual_ztp_shared_normalizer", ROOT / "ztp/manual-ztp.py")
FEEDBACK = load_script("feedback_shared_normalizer", ROOT / "ztp/optimize/feedback.py")


class NvueNormalizerTests(unittest.TestCase):
    def test_all_consumers_use_the_shared_implementation(self):
        self.assertIs(MANUAL._expand_nvue_selector, expand_nvue_selector)
        self.assertIs(FEEDBACK._expand_nvue_selector, expand_nvue_selector)
        self.assertIs(MANUAL._normalize_nvue_selectors, normalize_nvue_selectors)
        self.assertIs(FEEDBACK.normalize_nvue_selectors, normalize_nvue_selectors)

    def test_breakout_selectors_expand_both_numeric_axes(self):
        self.assertEqual(
            expand_nvue_selector("bond11s0-3"),
            [f"bond11s{lane}" for lane in range(4)],
        )
        self.assertEqual(
            expand_nvue_selector("bond1-6s0-3"),
            [f"bond{port}s{lane}" for port in range(1, 7) for lane in range(4)],
        )
        self.assertEqual(
            expand_nvue_selector("bond1-36s0-1"),
            [f"bond{port}s{lane}" for port in range(1, 37) for lane in range(2)],
        )
        self.assertEqual(
            expand_nvue_selector("swp1-8s0-3"),
            [f"swp{port}s{lane}" for port in range(1, 9) for lane in range(4)],
        )

    def test_common_selector_attributes_merge_into_specific_interfaces(self):
        value = {
            "interface": {
                "bond11s0-3": {
                    "bridge": {"domain": {"br_default": {"access": 10}}},
                    "evpn": {"multihoming": {"segment": {
                        "mac-address": "02:00:00:00:00:12",
                    }}},
                    "type": "bond",
                },
                "bond11s0": {"bond": {"member": {"swp11s0": {}}}},
            },
        }
        normalized = normalize_nvue_selectors(value)
        for lane in range(4):
            bond = normalized["interface"][f"bond11s{lane}"]
            self.assertEqual(bond["bridge"]["domain"]["br_default"]["access"], 10)
            self.assertEqual(
                bond["evpn"]["multihoming"]["segment"]["mac-address"],
                "02:00:00:00:00:12",
            )
        self.assertIn("swp11s0", normalized["interface"]["bond11s0"]["bond"]["member"])


if __name__ == "__main__":
    unittest.main()
