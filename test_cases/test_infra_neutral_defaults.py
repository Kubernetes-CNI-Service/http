#!/usr/bin/env python3
"""Direct contracts for the unified infra DNS/NTP/timezone fallback."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "infra_neutral_direct_deploy", ROOT / "infra/deploy_infra.py",
)
assert SPEC is not None and SPEC.loader is not None
DEPLOY = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DEPLOY
SPEC.loader.exec_module(DEPLOY)


class InfraNeutralDefaultsTests(unittest.TestCase):
    def test_authority_is_strict_and_global_keys_replace_it(self):
        neutral_file = ROOT / "infra/infra-neutral.conf"
        self.assertEqual(
            b"DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
            neutral_file.read_bytes(),
        )
        self.assertEqual(
            (["8.8.8.8"], ["ntp.ubuntu.com"], "Etc/UTC"),
            DEPLOY.load_neutral_defaults(neutral_file),
        )
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            global_file = temp / "01-global.yaml"
            global_file.write_text(
                "common:\n  switch:\n    system:\n"
                "      ntp:\n        server: [ntp.ubuntu.com, ntp.site.example]\n",
                encoding="utf-8",
            )
            self.assertEqual(
                (["8.8.8.8"], ["ntp.ubuntu.com", "ntp.site.example"], "Etc/UTC"),
                DEPLOY.load_common(global_file, neutral_file),
            )
            global_file.write_text(
                "common:\n  switch:\n    system:\n"
                "      dns:\n        server: []\n",
                encoding="utf-8",
            )
            with self.assertRaises(DEPLOY.DeployError):
                DEPLOY.load_common(global_file, neutral_file)

            malformed = temp / "bad-neutral.conf"
            for payload in (
                "DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\nEXTRA=no\n",
                "DNS=8.8.8.8 1.1.1.1\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
                "DNS=8.8.8.8\nNTP=$(id)\nTIMEZONE=Etc/UTC\n",
                "DNS=999.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
            ):
                malformed.write_text(payload, encoding="utf-8")
                with self.subTest(payload=payload), self.assertRaises(DEPLOY.DeployError):
                    DEPLOY.load_neutral_defaults(malformed)

        setup_source = (ROOT / "infra/infra-setup.sh").read_text(encoding="utf-8")
        self.assertIn('neutral_config="${source_dir}/infra-neutral.conf"', setup_source)
        self.assertIn('while IFS="=" read -r key value', setup_source)
        self.assertNotIn('source "$neutral_config"', setup_source)
        for site_value in ("208.67.220.220", "118.163.81.61", "time.stdtime.gov.tw"):
            self.assertNotIn(site_value, setup_source)
        deploy_source = (ROOT / "infra/deploy_infra.py").read_text(encoding="utf-8")
        self.assertIn('neutral_stage = f"{release_dir}/infra-neutral.conf"', deploy_source)
        self.assertIn("current/infra-neutral.conf", deploy_source)

    def test_zero_target_boundaries_fail_but_prepare_only_writes_config(self):
        base_args = dict(
            global_file=ROOT / "DAY0-Prepare/template/01-global.yaml",
            devices_file=ROOT / "DAY0-Prepare/template/02-devices_config.csv",
            setup_script=ROOT / "infra/infra-setup.sh",
            teardown_script=ROOT / "infra/infra-teardown.sh",
            teardown=False,
            http_server_ip="192.0.2.10",
            user="operator",
            identity=None,
            hosts=None,
            prepare_only=False,
            dry_run=False,
            max_workers=1,
        )
        with mock.patch.object(DEPLOY, "parse_args", return_value=SimpleNamespace(**base_args)), \
             mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(1, DEPLOY.main())
        explicit_args = dict(base_args, hosts=["missing-server"])
        with mock.patch.object(
            DEPLOY, "parse_args", return_value=SimpleNamespace(**explicit_args)
        ), mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
             redirect_stderr(io.StringIO()):
            self.assertEqual(1, DEPLOY.main())
        teardown_prepare_args = dict(base_args, teardown=True, prepare_only=True)
        with mock.patch.object(
            DEPLOY, "parse_args", return_value=SimpleNamespace(**teardown_prepare_args)
        ), redirect_stderr(io.StringIO()):
            self.assertEqual(1, DEPLOY.main())

        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            setup = temp / "infra-setup.sh"
            teardown = temp / "infra-teardown.sh"
            setup.write_text("#!/bin/bash\n", encoding="utf-8")
            teardown.write_text("#!/bin/bash\n", encoding="utf-8")
            (temp / "infra-neutral.conf").write_text(
                "DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
                encoding="utf-8",
            )
            global_file = temp / "01-global.yaml"
            global_file.write_text("common:\n  switch:\n    system: {}\n", encoding="utf-8")
            prepared_args = dict(base_args)
            prepared_args.update(
                global_file=global_file,
                setup_script=setup,
                teardown_script=teardown,
                prepare_only=True,
            )
            with mock.patch.object(
                DEPLOY, "parse_args", return_value=SimpleNamespace(**prepared_args)
            ), mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
                 mock.patch.object(DEPLOY, "http_service_works", return_value=False), \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(0, DEPLOY.main())
            rendered = (temp / "infra-runtime.conf").read_text(encoding="utf-8")
            self.assertIn("dns_servers=(8.8.8.8)", rendered)
            self.assertIn("ntp_servers=(ntp.ubuntu.com)", rendered)
            self.assertIn("time_zone=Etc/UTC", rendered)


if __name__ == "__main__":
    unittest.main()
