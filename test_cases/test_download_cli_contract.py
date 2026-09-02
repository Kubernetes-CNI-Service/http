#!/usr/bin/env python3
"""CLI and final-mode contracts for the management-server download archive."""

from __future__ import annotations

import importlib.util
import io
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/tar-for-download.py"
SPEC = importlib.util.spec_from_file_location("download_cli_contract", SCRIPT)
assert SPEC and SPEC.loader
DOWNLOAD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DOWNLOAD)


class DownloadCliContractTests(unittest.TestCase):
    def test_project_folder_is_the_default_positional_argument(self):
        expected = "DAY0-Prepare/2099-example-site/"
        self.assertEqual(expected, DOWNLOAD.parse_args([expected]).project)
        self.assertEqual(
            "2099-example-site",
            DOWNLOAD.parse_args(["-p", "2099-example-site"]).project,
        )

    def test_positional_and_project_option_are_mutually_exclusive(self):
        with (
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit),
        ):
            DOWNLOAD.parse_args(["customer", "-p", "other"])

    def test_all_day0_rejects_a_positional_project(self):
        args = DOWNLOAD.parse_args(["customer", "--all-day0"])
        with self.assertRaisesRegex(ValueError, "--all-day0"):
            DOWNLOAD.validate_scope_options(args)

    def test_validated_final_archive_is_world_readable(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            output = root / "customer-download.tar.gz"
            args = DOWNLOAD.parse_args(["customer", "-o", str(output)])
            with (
                mock.patch.object(
                    DOWNLOAD.package_core, "resolve_project", return_value=project,
                ),
                mock.patch.object(
                    DOWNLOAD.package_core, "managed_pubkey_paths", return_value=[],
                ),
                redirect_stdout(io.StringIO()),
            ):
                DOWNLOAD.create_day0_archive(args)
            self.assertEqual(0o644, stat.S_IMODE(output.stat().st_mode))


if __name__ == "__main__":
    unittest.main()
