#!/usr/bin/env python3
"""Apache static publication boundary and load activation contracts."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SETUP = ROOT / "infra/infra-setup.sh"
TEARDOWN = ROOT / "infra/infra-teardown.sh"
LOAD_PATH = ROOT / "DAY0-Prepare/11-load.py"
PROJECT_SETUP_PATH = ROOT / "DAY0-Prepare/01-a-setup.py"
DHCP_PATH = ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"
MANUAL_ZTP_PATH = ROOT / "ztp/manual-ztp.py"
CONTRACT_PATH = ROOT / "tools/project_contract.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


LOAD = load_module("apache_boundary_day0_load", LOAD_PATH)
PROJECT_SETUP = load_module("apache_boundary_project_setup", PROJECT_SETUP_PATH)
DHCP = load_module("apache_boundary_dhcp", DHCP_PATH)
MANUAL_ZTP = load_module("apache_boundary_manual_ztp", MANUAL_ZTP_PATH)
CONTRACT = load_module("apache_boundary_project_contract", CONTRACT_PATH)


def rendered_boundary() -> str:
    source = SETUP.read_text(encoding="utf-8")
    match = re.search(
        r"cat <<'APACHE_PUBLIC_BOUNDARY_EOF'\n(.*?)"
        r"^APACHE_PUBLIC_BOUNDARY_EOF$",
        source,
        re.MULTILINE | re.DOTALL,
    )
    if match is None:
        raise AssertionError("Apache publication boundary heredoc is missing")
    return match.group(1)


def location_patterns(config: str) -> tuple[re.Pattern[str], ...]:
    patterns = re.findall(r'^<LocationMatch "([^"]+)">$', config, re.MULTILINE)
    return tuple(re.compile(pattern) for pattern in patterns)


def section_patterns(config: str, section: str) -> tuple[re.Pattern[str], ...]:
    patterns = re.findall(
        rf'^\s*<{section} "([^"]+)">$', config, re.MULTILINE,
    )
    return tuple(re.compile(pattern) for pattern in patterns)


class ApachePublicationBoundaryTests(unittest.TestCase):
    def test_every_prefix_validator_rejects_apache_reserved_paths(self) -> None:
        reserved = (
            "/status",
            "/nested/BACKUP/release",
            "/monitor/ztp-status",
            "/x/config/isc-dhcp-server",
            "/config/cumulus/template",
            "/nested/config/nvos/template",
        )
        for prefix in reserved:
            with self.subTest(prefix=prefix, validator="contract"):
                with self.assertRaisesRegex(ValueError, "Apache 保留发布路径"):
                    CONTRACT.validate_ztp_url_prefix(prefix)
            with self.subTest(prefix=prefix, validator="load"):
                with self.assertRaisesRegex(LOAD.LoadError, "Apache 保留发布路径"):
                    LOAD._validate_ztp_prefix(prefix)
            with self.subTest(prefix=prefix, validator="dhcp"):
                with self.assertRaisesRegex(ValueError, "Apache 保留发布路径"):
                    DHCP._validate_ztp_url_prefix(prefix)

        for prefix in ("/ztp", "/custom/status-page", "/monitor", "/nested/public"):
            with self.subTest(prefix=prefix, validator="allowed"):
                self.assertEqual(prefix, CONTRACT.validate_ztp_url_prefix(prefix))
                self.assertEqual(prefix, LOAD._validate_ztp_prefix(prefix))
                self.assertEqual(prefix, DHCP._validate_ztp_url_prefix(prefix))

        with tempfile.TemporaryDirectory() as directory:
            global_yaml = Path(directory) / "01-global.yaml"
            global_yaml.write_text(
                "schema_version: 1\n"
                "common:\n"
                "  mgmt:\n"
                "    ztp:\n"
                "      ztp_url_prefix: /nested/status\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                MANUAL_ZTP.ManualZtpError, "Apache 保留发布路径",
            ):
                MANUAL_ZTP.global_ztp_url_prefix(global_yaml)
            errors, _warnings = PROJECT_SETUP._validate_global_yaml(global_yaml)
            self.assertTrue(any("Apache 保留发布路径" in item for item in errors))

    def test_generated_config_denies_internal_static_paths(self) -> None:
        patterns = location_patterns(rendered_boundary())
        self.assertEqual(4, len(patterns))
        denied = (
            "/DAY0-Prepare/11-load.py",
            "/day0-prepare/project/01-global.yaml",
            "/monitor/status/manual-ztp.status.json",
            "/monitor/ztp-status/latest/report.json",
            "/ztp/status/latest/devices.csv",
            "/ztp/backup/yaml-backup/device.yaml",
            "/ztp/optimize/sample/generated-latest/device.yaml",
            "/ztp/config/isc-dhcp-server/dhcpd.conf",
            "/ztp/config/isc-dhcp-server/dhcp-release-manifest.json",
            "/ztp/config/cumulus/template/90-c2-generate_configs.py",
            "/ztp/config/nvos/template/02-devices_config.csv",
            "/ztp/manual-ztp.py",
            "/monitor/manual-ztp-control.cgi",
            "/foo/release-manifest.json",
            "/foo/current-release.json",
            "/foo/dhcpd_eth.hosts",
            "/foo/p2p-air.json",
            "/foo/02-dhcp-subnet_config.csv",
            "/.setup_manifest",
            "/.ztp-prefix-publication.json",
            "/.deployment.lock",
            "/infra/logs/infra-setup.log",
            # ztp_url_prefix may be any one or more URL segments pointing at
            # the real ztp/ tree.  These must not depend on the literal /ztp.
            "/custom/status/latest/report.json",
            "/custom/config/isc-dhcp-server/dhcpd.conf",
            "/nested/custom/config/cumulus/template/01-global.yaml",
            "/nested/custom/backup/device.yaml",
        )
        for path in denied:
            with self.subTest(path=path):
                self.assertTrue(any(pattern.search(path) for pattern in patterns))

    def test_generated_config_keeps_required_public_paths_reachable(self) -> None:
        config = rendered_boundary()
        patterns = location_patterns(config)
        self.assertIn('Options -Indexes', config)
        public = (
            "/monitor/monitor.html",
            "/monitor/ethernet/Diagram.html",
            "/ztp/ztp-bootstrap_oob.sh",
            "/ztp/ztp-bootstrap_oobofoob.sh",
            "/ztp/ztp.json",
            "/ztp/config/publickey/mgmt-server.pub",
            "/ztp/config/cumulus/latest_yaml/0200000000cc.yaml",
            "/ztp/config/cumulus/latest_yaml/0200000000cc.mode",
            "/ztp/config/cumulus/latest_yaml/0200000000cc.spx",
            "/ztp/config/nvos/latest_yaml/0200000000cc.yaml",
            "/ztp/config/nvos/disable-password-hardening.nv",
            "/ztp/image/cumulus/cumulus-linux.bin",
            "/ztp/image/nvos/nvos.bin",
            "/apps/ubuntu-24.04/amd64/Packages.gz",
            "/infra/infra-setup.sh",
            "/cgi-bin/ztp-monitor-control",
            "/cgi-bin/switch-collection-control",
            "/cgi-bin/manual-ztp-control",
            "/custom/config/cumulus/latest_yaml/0200000000cc.yaml",
            "/nested/custom/config/nvos/latest_yaml/0200000000cc.yaml",
        )
        for path in public:
            with self.subTest(path=path):
                self.assertFalse(any(pattern.search(path) for pattern in patterns))

    def test_filesystem_and_filename_rules_survive_url_aliases(self) -> None:
        config = rendered_boundary()
        directories = section_patterns(config, "DirectoryMatch")
        files = section_patterns(config, "FilesMatch")
        self.assertEqual(1, len(directories))
        self.assertEqual(3, len(files))

        real_targets = (
            "/var/www/html/DAY0-Prepare/project/11-load.py",
            "/var/www/html/monitor/status/manual-ztp.status.json",
            "/var/www/html/ztp/status/latest/report.json",
            "/var/www/html/ztp/config/isc-dhcp-server/dhcpd.conf",
            "/var/www/html/ztp/config/cumulus/template/01-global.yaml",
            "/var/www/html/ztp/config/nvos/template/02-devices_config.csv",
        )
        for target in real_targets:
            with self.subTest(target=target):
                self.assertTrue(any(pattern.search(target) for pattern in directories))

        for basename in (
            "manual-ztp.py", "control.cgi", "release-manifest.json",
            "01-global.yaml", "dhcpd_nvl.hosts", ".deployment.lock",
        ):
            with self.subTest(basename=basename):
                self.assertTrue(any(pattern.search(basename) for pattern in files))
        for basename in (
            "monitor.html", "ztp.json", "0200000000cc.yaml", "laptop.pub",
        ):
            with self.subTest(basename=basename):
                self.assertFalse(any(pattern.search(basename) for pattern in files))

    def test_load_requires_exact_infra_managed_policy(self) -> None:
        payload = rendered_boundary().encode()
        self.assertEqual(
            LOAD.APACHE_PUBLIC_BOUNDARY_SHA256,
            hashlib.sha256(payload).hexdigest(),
        )
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "boundary.conf"
            destination.write_bytes(payload)
            with mock.patch.object(
                LOAD, "APACHE_PUBLIC_BOUNDARY_CONF", destination,
            ), contextlib.redirect_stdout(io.StringIO()):
                LOAD.verify_apache_publication_boundary()
                destination.write_bytes(payload + b"# drift\n")
                with self.assertRaisesRegex(LOAD.LoadError, "不一致"):
                    LOAD.verify_apache_publication_boundary()

    def test_missing_policy_is_a_pre_start_failure_but_dry_run_is_read_only(self) -> None:
        missing = ROOT / "test_cases/.does-not-exist-apache-boundary"
        with mock.patch.object(
            LOAD, "APACHE_PUBLIC_BOUNDARY_CONF", missing,
        ), contextlib.redirect_stdout(io.StringIO()):
            LOAD.verify_apache_publication_boundary(dry_run=True)
            with self.assertRaisesRegex(LOAD.LoadError, "缺少 Apache 静态发布边界"):
                LOAD.verify_apache_publication_boundary()

    def test_infra_configtests_before_restart_and_teardown_tracks_policy(self) -> None:
        setup = SETUP.read_text(encoding="utf-8")
        install_call = setup.index("  install_apache_publication_boundary\n")
        restart_call = setup.index("    restart_systemd_service apache2", install_call)
        self.assertLess(install_call, restart_call)
        installer = setup[
            setup.index("install_apache_publication_boundary() {"):
            setup.index("\nwrite_run_info()", setup.index(
                "install_apache_publication_boundary() {"
            ))
        ]
        self.assertIn("apache2ctl configtest", installer)
        self.assertIn("previous configuration restored", installer)
        self.assertIn("--defer-services", setup)

        teardown = TEARDOWN.read_text(encoding="utf-8")
        self.assertIn(
            "/etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
            teardown,
        )


if __name__ == "__main__":
    unittest.main()
