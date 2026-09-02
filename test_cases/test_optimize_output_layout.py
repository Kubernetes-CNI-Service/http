#!/usr/bin/env python3
"""Regression tests for optimize sample/comparison output placement."""

from __future__ import annotations

import importlib.util
import ipaddress
import os
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
OPTIMIZE = ROOT / "ztp/optimize"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


SAMPLE_LINKS = load_module(
    "optimize_output_sample_links", OPTIMIZE / "sample_links.py"
)
FEEDBACK = load_module("optimize_output_feedback", OPTIMIZE / "feedback.py")


class OptimizeOutputLayoutTests(unittest.TestCase):
    def test_split_cidr_docstring_uses_reserved_documentation_address(self):
        docstring = FEEDBACK.split_cidr.__doc__ or ""
        addresses = {
            ipaddress.ip_address(value)
            for value in re.findall(
                r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])", docstring,
            )
        }

        self.assertIn("192.0.2.3/26", docstring)
        self.assertTrue(addresses)
        self.assertTrue(
            all(address in ipaddress.ip_network("192.0.2.0/24") for address in addresses)
        )

    def test_managed_comparison_link_targets_project_output_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            optimize = root / "ztp/optimize"
            project = root / "DAY0-Prepare/demo"
            project.mkdir(parents=True)

            sample = SAMPLE_LINKS.update_sample_links(
                optimize, project, report=lambda _message: None,
            )
            target = project / "99-output-ztp/optimize"
            link = sample / "comparison"

            self.assertTrue(target.is_dir())
            self.assertTrue(link.is_symlink())
            self.assertEqual(
                os.readlink(link),
                "../../../DAY0-Prepare/demo/99-output-ztp/optimize",
            )
            self.assertEqual(link.resolve(), target.resolve())

    def test_feedback_defaults_write_through_managed_comparison_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project_output = root / "DAY0-Prepare/demo/99-output-ztp/optimize"
            project_output.mkdir(parents=True)
            sample = root / "ztp/optimize/demo-sample"
            sample.mkdir(parents=True)
            (sample / "comparison").symlink_to(
                os.path.relpath(project_output, sample)
            )
            source = sample / "generated-latest"
            source.mkdir()
            (sample / "01-global.yaml").write_text(
                "common: {}\n", encoding="utf-8",
            )
            (sample / "02-devices_config.csv").write_text(
                "hostname,type\nleaf01,eth\n", encoding="utf-8",
            )

            with (
                mock.patch.object(
                    FEEDBACK, "prepare_sample_inputs",
                    return_value=([source], sample),
                ),
                mock.patch.object(
                    FEEDBACK, "discover_comparison_sources", return_value=[],
                ),
                mock.patch.object(
                    FEEDBACK, "convert_one",
                    side_effect=lambda _source, destination, *_args, **_kwargs: destination,
                ) as convert,
            ):
                self.assertEqual(FEEDBACK.main([str(source)]), 0)

            destinations = [Path(call.args[1]).resolve() for call in convert.call_args_list]
            self.assertEqual(len(destinations), 2)
            self.assertTrue(all(project_output.resolve() in path.parents for path in destinations))
            self.assertEqual({path.parent.name for path in destinations}, {"prod", "air"})

    def test_real_legacy_comparison_directory_is_migrated_without_data_loss(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            optimize = root / "ztp/optimize"
            project = root / "DAY0-Prepare/demo"
            project.mkdir(parents=True)
            sample = optimize / "demo-sample"
            legacy_result = sample / "comparison/air/report.md"
            legacy_result.parent.mkdir(parents=True)
            legacy_result.write_text("historic\n", encoding="utf-8")

            SAMPLE_LINKS.update_sample_links(
                optimize, project, report=lambda _message: None,
            )

            link = sample / "comparison"
            target = project / "99-output-ztp/optimize"
            self.assertTrue(link.is_symlink())
            self.assertEqual(link.resolve(), target.resolve())
            self.assertEqual(
                (target / "air/report.md").read_text(encoding="utf-8"),
                "historic\n",
            )

    def test_obsolete_generated_root_outputs_are_removed_only_at_exact_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory)
            comparison = sample / "comparison/air"
            comparison.mkdir(parents=True)
            for name in SAMPLE_LINKS.LEGACY_ROOT_OUTPUT_NAMES:
                (sample / name).write_text("obsolete\n", encoding="utf-8")
                (comparison / name).write_text("current\n", encoding="utf-8")

            messages = []
            SAMPLE_LINKS.cleanup_legacy_root_outputs(sample, report=messages.append)

            for name in SAMPLE_LINKS.LEGACY_ROOT_OUTPUT_NAMES:
                self.assertFalse((sample / name).exists())
                self.assertEqual(
                    (comparison / name).read_text(encoding="utf-8"), "current\n"
                )
            self.assertEqual(len(messages), 2)

    def test_cleanup_refuses_symlink_or_directory_at_managed_filename(self):
        with tempfile.TemporaryDirectory() as directory:
            sample = Path(directory)
            target = sample / "operator-owned.csv"
            target.write_text("keep\n", encoding="utf-8")
            link = sample / "generated-latest.csv"
            link.symlink_to(target.name)
            unexpected = sample / "generated-latest-global.yaml"
            unexpected.mkdir()

            messages = []
            SAMPLE_LINKS.cleanup_legacy_root_outputs(sample, report=messages.append)

            self.assertTrue(link.is_symlink())
            self.assertTrue(unexpected.is_dir())
            self.assertEqual(target.read_text(encoding="utf-8"), "keep\n")
            self.assertEqual(sum("[WARN]" in item for item in messages), 2)

    def test_single_available_scope_writes_below_requested_comparison_dir(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sample = root / "project-sample"
            source = sample / "generated-latest"
            output = sample / "comparison/prod"
            source.mkdir(parents=True)
            (sample / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
            (sample / "02-devices_config.csv").write_text(
                "hostname,type\nleaf01,eth\n", encoding="utf-8"
            )

            with (
                mock.patch.object(
                    FEEDBACK, "prepare_sample_inputs",
                    return_value=([source], sample),
                ),
                mock.patch.object(FEEDBACK, "discover_comparison_sources", return_value=[]),
                mock.patch.object(FEEDBACK, "convert_one", return_value=output / "generated-latest.csv") as convert,
            ):
                result = FEEDBACK.main([
                    str(source), "--type", "prod", "--output-dir", str(output),
                ])

            self.assertEqual(result, 0)
            self.assertEqual(
                Path(convert.call_args.args[1]), output / "generated-latest.csv"
            )
            self.assertFalse((sample / "generated-latest.csv").exists())
            self.assertFalse((sample / "generated-latest-global.yaml").exists())


if __name__ == "__main__":
    unittest.main()
