#!/usr/bin/env python3
"""Apache static publication boundary and load activation contracts."""

from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
from pathlib import Path
import re
import subprocess
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
APACHE_CONFIG = ROOT / "infra/docker/apache-ztp.conf"
APACHE_CONFIG_SHA256 = (
    "616629333ac16e4bc0c076a499d98864959372b5a24bee3c0d4257c1aa9d15fb"
)
CONTROL_AUTH_SOURCE = ROOT / "tools/control-auth.py"
CONTROL_AUTH_SHA256 = (
    "5a133a353cb7ac7af5be0be71b4ef85b41345716103d6e28590140638ee11038"
)
CONTROL_REALM = "HTTP ZTP Monitor Control"
CONTROL_USERS = "nvis cumulus"
CONTROL_ENDPOINTS = {
    "ztp-monitor": "/usr/lib/cgi-bin/ztp-monitor-control",
    "switch-collection": "/usr/lib/cgi-bin/switch-collection-control",
    "manual-ztp": "/usr/lib/cgi-bin/manual-ztp-control",
}


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
    patterns = []
    for match in re.finditer(
        r'^<LocationMatch "([^"]+)">\n(.*?)^</LocationMatch>$',
        config,
        re.MULTILINE | re.DOTALL,
    ):
        if "Require all denied" in match.group(2):
            patterns.append(match.group(1))
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

    def test_setup_and_docker_share_exact_v2_authenticated_policy(self) -> None:
        config = APACHE_CONFIG.read_text(encoding="utf-8")
        self.assertEqual(config, rendered_boundary())
        self.assertIn("# HTTP-ZTP-PUBLIC-BOUNDARY-V2", config)
        self.assertNotIn("HTTP-ZTP-PUBLIC-BOUNDARY-V1", config)
        self.assertNotIn("Require valid-user", config)
        self.assertEqual(
            [CONTROL_REALM] * 3,
            re.findall(r'^\s*AuthName "([^"]+)"$', config, re.MULTILINE),
        )
        self.assertEqual(
            ["/etc/http-ztp/control-users.htpasswd"] * 3,
            re.findall(r"^\s*AuthUserFile (\S+)$", config, re.MULTILINE),
        )
        self.assertEqual(
            [CONTROL_USERS] * 3,
            re.findall(r"^\s*Require user (.+)$", config, re.MULTILINE),
        )
        self.assertEqual(1, config.count('Header always set Cache-Control "no-store"'))

        page = re.search(
            r'<Directory "/var/www/html/monitor">\n(.*?)^</Directory>$',
            config,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(page)
        self.assertIn('<Files "monitor.html">', page.group(1))
        self.assertIn(f'AuthName "{CONTROL_REALM}"', page.group(1))
        self.assertIn("AuthType Basic", page.group(1))
        self.assertIn("AuthBasicProvider file", page.group(1))
        self.assertIn(
            "AuthUserFile /etc/http-ztp/control-users.htpasswd", page.group(1),
        )
        self.assertIn(f"Require user {CONTROL_USERS}", page.group(1))
        self.assertIn('Header always set Cache-Control "no-store"', page.group(1))

        cgi_files = re.search(
            r'<Directory "/usr/lib/cgi-bin">\n(.*?)^</Directory>$',
            config,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(cgi_files)
        self.assertIn(
            '<FilesMatch "^(?:ztp-monitor-control|switch-collection-control|manual-ztp-control)$">',
            cgi_files.group(1),
        )
        self.assertIn(f'AuthName "{CONTROL_REALM}"', cgi_files.group(1))
        self.assertIn(f"Require user {CONTROL_USERS}", cgi_files.group(1))
        self.assertIn("SetEnv CONTROL_REQUIRE_AUTH 1", cgi_files.group(1))
        self.assertIn("AcceptPathInfo Off", cgi_files.group(1))

        for endpoint, target in CONTROL_ENDPOINTS.items():
            self.assertIn(
                f'ScriptAliasMatch "^/monitor/control/{endpoint}$" "{target}"',
                config,
            )
        authenticated_urls = re.search(
            r'^<LocationMatch "([^"]*monitor/control[^"]*cgi-bin[^"]*)">\n'
            r'(.*?)^</LocationMatch>$',
            config,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(authenticated_urls)
        for endpoint in CONTROL_ENDPOINTS:
            self.assertRegex(
                f"/monitor/control/{endpoint}", authenticated_urls.group(1),
            )
            self.assertRegex(
                f"/cgi-bin/{endpoint}-control", authenticated_urls.group(1),
            )
        self.assertIn(f'AuthName "{CONTROL_REALM}"', authenticated_urls.group(2))
        self.assertIn(f"Require user {CONTROL_USERS}", authenticated_urls.group(2))
        self.assertIn("SetEnv CONTROL_REQUIRE_AUTH 1", authenticated_urls.group(2))

    def test_filesystem_and_filename_rules_survive_url_aliases(self) -> None:
        config = rendered_boundary()
        directories = section_patterns(config, "DirectoryMatch")
        files = section_patterns(config, "FilesMatch")
        self.assertEqual(1, len(directories))
        self.assertEqual(4, len(files))

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
        self.assertEqual(APACHE_CONFIG_SHA256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(
            APACHE_CONFIG_SHA256, LOAD.APACHE_PUBLIC_BOUNDARY_SHA256,
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
        apache_step = setup[
            setup.index('if [[ "$configure_apache2" == "true" ]]'):
            setup.index("if dpkg -s isc-dhcp-server", setup.index(
                'if [[ "$configure_apache2" == "true" ]]'
            ))
        ]
        install_call = apache_step.index("  install_apache_publication_boundary\n")
        configtest_call = apache_step.index("  apache2ctl configtest", install_call)
        deferred_call = apache_step.index(
            "apache2 wildcard listeners disabled; service activation deferred until load",
            configtest_call,
        )
        self.assertLess(install_call, configtest_call)
        self.assertLess(configtest_call, deferred_call)
        self.assertNotRegex(
            apache_step,
            r"(?:restart_systemd_service|systemctl\s+(?:start|restart))\s+apache2",
        )
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

    def test_native_setup_binds_helper_dependencies_modules_and_order(self) -> None:
        setup = SETUP.read_text(encoding="utf-8")
        self.assertIn(
            f'control_auth_source_sha256="{CONTROL_AUTH_SHA256}"', setup,
        )
        self.assertIn(
            'control_auth_source="${mgmt_http_root}/tools/control-auth.py"',
            setup,
        )
        source_gate = setup.index("Control auth helper source hash mismatch")
        self.assertLess(source_gate, setup.index("if [[ $EUID -ne 0 ]]"))

        packages = re.search(
            r"optional_service_packages=\((.*?)\)", setup, re.DOTALL,
        )
        self.assertIsNotNone(packages)
        self.assertEqual(
            ["apache2", "apache2-utils", "ssl-cert", "isc-dhcp-server"],
            re.findall(r"[a-z0-9][a-z0-9-]*", packages.group(1)),
        )
        modules = re.search(r"apache_auth_modules=\((.*?)\)", setup, re.DOTALL)
        self.assertIsNotNone(modules)
        self.assertEqual(
            [
                "auth_basic", "authn_file", "authn_core", "authz_user",
                "authz_core", "env", "alias", "cgid", "headers",
            ],
            re.findall(r"[a-z][a-z0-9_]*", modules.group(1)),
        )

        install_helper = setup[
            setup.index("install_control_auth_helper() {"):
            setup.index("\nrender_apache_publication_boundary() {")
        ]
        self.assertIn(
            'control_auth_helper="/usr/local/lib/http-ztp/control-auth.py"',
            setup,
        )
        self.assertIn('mv -f -- "$candidate" "$control_auth_helper"', install_helper)
        self.assertLess(
            install_helper.index('"$control_auth_helper" ensure'),
            install_helper.index('"$control_auth_helper" validate'),
        )
        apache_step = setup[
            setup.index('if [[ "$configure_apache2" == "true" ]]'):
            setup.index("if dpkg -s isc-dhcp-server", setup.index(
                'if [[ "$configure_apache2" == "true" ]]'
            ))
        ]
        self.assertLess(
            apache_step.index('if [[ "$mgmt_mode" != "true" ]]'),
            apache_step.index("apache_packages_to_install=()"),
        )
        self.assertLess(
            apache_step.index("systemctl stop apache2"),
            apache_step.index("install_control_auth_helper"),
        )
        self.assertLess(
            apache_step.index("install_control_auth_helper"),
            apache_step.index('a2enmod "$module"'),
        )
        self.assertLess(
            install_helper.index(
                "run_native_monitor_authority_routine monitor-authority-provision"
            ),
            install_helper.index(
                "run_native_monitor_authority_routine monitor-authority-attest"
            ),
        )
        self.assertLess(
            apache_step.index('a2enmod "$module"'),
            apache_step.index("install_apache_publication_boundary"),
        )
        self.assertLess(
            apache_step.index("install_apache_publication_boundary"),
            apache_step.index("apache2ctl configtest"),
        )
        self.assertLess(
            apache_step.index("apache2ctl configtest"),
            apache_step.index(
                "apache2 wildcard listeners disabled; service activation deferred until load"
            ),
        )
        self.assertNotRegex(
            apache_step,
            r"(?:restart_systemd_service|systemctl\s+(?:start|restart))\s+apache2",
        )
        boundary_installer = setup[
            setup.index("install_apache_publication_boundary() {"):
            setup.index("\nwrite_run_info() {")
        ]
        failure = boundary_installer[boundary_installer.index("if ! apache2ctl configtest"):]
        self.assertIn("systemctl stop apache2", failure)
        self.assertIn("Apache remains stopped", failure)

    def test_load_binds_source_and_backend_helper_before_every_activation(self) -> None:
        self.assertEqual(CONTROL_AUTH_SHA256, LOAD.CONTROL_AUTH_SOURCE_SHA256)
        self.assertEqual(CONTROL_AUTH_SOURCE, LOAD.CONTROL_AUTH_SOURCE)
        self.assertEqual(
            Path("/usr/local/lib/http-ztp/control-auth.py"),
            LOAD.CONTROL_AUTH_NATIVE_HELPER,
        )
        self.assertEqual(
            Path("/opt/http-ztp/control-auth.py"),
            LOAD.CONTROL_AUTH_CONTAINER_HELPER,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.py"
            helper = root / "installed.py"
            payload = CONTROL_AUTH_SOURCE.read_bytes()
            source.write_bytes(payload)
            helper.write_bytes(payload)
            backend = mock.Mock(name="backend")
            backend.name = "systemd"
            runner = mock.Mock()
            with mock.patch.object(LOAD, "CONTROL_AUTH_SOURCE", source), \
                    mock.patch.object(LOAD, "CONTROL_AUTH_NATIVE_HELPER", helper), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *x: list(x)), \
                    mock.patch.object(LOAD, "run", runner):
                LOAD.verify_control_auth(runtime_backend=backend)
            runner.assert_called_once_with([str(helper), "validate"], dry_run=False)

            runner.reset_mock()
            with mock.patch.object(LOAD, "CONTROL_AUTH_NATIVE_HELPER", helper), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *x: list(x)), \
                    mock.patch.object(
                        LOAD,
                        "_run_subprocess",
                        return_value=subprocess.CompletedProcess(
                            [], 0, stdout="", stderr="",
                        ),
                    ) as execute:
                LOAD.verify_monitor_authority(runtime_backend=backend)
            execute.assert_called_once_with(
                [str(helper), "monitor-authority-attest"],
                capture_output=True,
                text=True,
                check=False,
            )

            runner.reset_mock()
            backend.name = "supervisor"
            with mock.patch.object(LOAD, "CONTROL_AUTH_SOURCE", source), \
                    mock.patch.object(LOAD, "CONTROL_AUTH_CONTAINER_HELPER", helper), \
                    mock.patch.object(LOAD, "sudo_command", side_effect=lambda *x: list(x)), \
                    mock.patch.object(LOAD, "run", runner):
                LOAD.verify_control_auth(runtime_backend=backend)
            runner.assert_called_once_with([str(helper), "validate"], dry_run=False)

            source.write_bytes(b"drift\n")
            backend.name = "systemd"
            with mock.patch.object(LOAD, "CONTROL_AUTH_SOURCE", source), \
                    mock.patch.object(LOAD, "CONTROL_AUTH_NATIVE_HELPER", helper), \
                    mock.patch.object(LOAD, "run", runner):
                with self.assertRaisesRegex(LOAD.LoadError, "source.*hash|源码.*hash"):
                    LOAD.verify_control_auth(runtime_backend=backend)

            source.unlink()
            source.symlink_to(CONTROL_AUTH_SOURCE)
            with mock.patch.object(LOAD, "CONTROL_AUTH_SOURCE", source), \
                    mock.patch.object(LOAD, "CONTROL_AUTH_NATIVE_HELPER", helper), \
                    mock.patch.object(LOAD, "run", runner):
                with self.assertRaisesRegex(LOAD.LoadError, "源码.*不可用"):
                    LOAD.verify_control_auth(runtime_backend=backend)

        load_source = LOAD_PATH.read_text(encoding="utf-8")
        preflight = load_source[
            load_source.index("def preflight_services("):
            load_source.index("\ndef ztp_url_network_requirements(")
        ]
        self.assertLess(
            preflight.index("verify_control_auth("),
            preflight.index('sudo_command("apache2ctl", "configtest")'),
        )
        start = load_source[
            load_source.index("def start_services("):
            load_source.index("\ndef validate_inputs(")
        ]
        self.assertNotIn("verify_control_auth(", start)
        main = load_source[load_source.index("def main("):]
        self.assertLess(
            main.index("preflight_services("), main.index("start_services("),
        )
        for function_name in (
            "start_ztp_monitor", "start_switch_collection_worker",
            "start_manual_ztp_worker",
        ):
            begin = load_source.index(f"def {function_name}(")
            end = load_source.find("\ndef ", begin + 5)
            function = load_source[begin:end]
            self.assertLess(
                function.index("verify_control_auth("),
                function.index('sudo_command("install"'),
            )

    def test_teardown_preserves_v2_and_auth_or_stops_apache_fail_closed(self) -> None:
        teardown = TEARDOWN.read_text(encoding="utf-8")
        self.assertIn(
            f'apache_public_boundary_sha256="{APACHE_CONFIG_SHA256}"',
            teardown,
        )
        self.assertIn(
            f'control_auth_helper_sha256="{CONTROL_AUTH_SHA256}"', teardown,
        )
        self.assertIn("/etc/http-ztp/control-users.htpasswd", teardown)
        self.assertNotIn(
            "restore_file /etc/apache2/conf-enabled/http-ztp-public-boundary.conf",
            teardown,
        )
        self.assertNotRegex(
            teardown,
            r"rm\s+-[^\n]*\s/etc/http-ztp/control-users\.htpasswd",
        )
        self.assertIn("preserve_apache_control_boundary", teardown)
        self.assertIn("protected_monitor_content_present", teardown)
        security_gate = teardown.index("preserve_apache_control_boundary")
        restore = teardown.index("restore_managed_files", security_gate)
        restart = teardown.index("systemctl restart apache2", restore)
        self.assertLess(security_gate, restore)
        self.assertLess(restore, restart)
        self.assertIn("systemctl stop apache2", teardown[security_gate:restart])

    def test_shell_syntax_and_cross_script_no_anonymous_window_contract(self) -> None:
        for script in (SETUP, TEARDOWN):
            with self.subTest(script=script.name):
                subprocess.run(
                    ["bash", "-n", str(script)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

        setup = SETUP.read_text(encoding="utf-8")
        load = LOAD_PATH.read_text(encoding="utf-8")
        teardown = TEARDOWN.read_text(encoding="utf-8")
        # Setup creates/validates credentials before publishing V2. Load checks
        # those exact bytes even with --skip-infra. Teardown never restores V1.
        self.assertLess(
            setup.index('"$control_auth_helper" validate'),
            setup.index("render_apache_publication_boundary > \"$candidate\""),
        )
        self.assertIn("verify_control_auth(", load)
        self.assertIn("verify_monitor_authority(", load)
        self.assertIn("CONTROL_AUTH_SOURCE_SHA256", load)
        self.assertIn("--skip-infra", load)
        self.assertIn("Preserving authenticated Apache boundary V2", teardown)
        self.assertNotIn("HTTP-ZTP-PUBLIC-BOUNDARY-V1", teardown)

    def test_native_monitor_authority_is_attested_before_cgi_or_apache_activation(self) -> None:
        setup = SETUP.read_text(encoding="utf-8")
        apache_step = setup[
            setup.index('if [[ "$configure_apache2" == "true" ]]'):
            setup.index("if dpkg -s isc-dhcp-server", setup.index(
                'if [[ "$configure_apache2" == "true" ]]'
            ))
        ]
        self.assertLess(
            apache_step.index("systemctl stop apache2"),
            apache_step.index("install_control_auth_helper"),
        )
        self.assertLess(
            apache_step.index("install_control_auth_helper"),
            apache_step.index("install_apache_publication_boundary"),
        )
        helper_install = setup[
            setup.index("install_control_auth_helper() {"):
            setup.index("\nrender_apache_publication_boundary() {")
        ]
        self.assertIn("monitor-authority-provision", helper_install)
        self.assertIn("monitor-authority-attest", helper_install)

        load = LOAD_PATH.read_text(encoding="utf-8")
        main = load[load.index("def main("):]
        authority = main.index("verify_monitor_authority(")
        generation = main.index("generate_configs(")
        service_preflight = main.index("preflight_services(")
        self.assertLess(authority, generation)
        self.assertLess(authority, service_preflight)
        skip_branch = main.index('warn("已按参数跳过 infra 安装")')
        self.assertLess(skip_branch, authority)

        teardown = TEARDOWN.read_text(encoding="utf-8")
        preserve = teardown[
            teardown.index("preserve_apache_control_boundary() {"):
            teardown.index("\nrestore_preserved_apache_boundary() {")
        ]
        self.assertIn('"$control_auth_helper" monitor-authority-attest', preserve)
        restart = teardown.index("systemctl restart apache2")
        self.assertLess(
            teardown.rindex("preserve_apache_control_boundary", 0, restart), restart,
        )
        self.assertNotRegex(
            teardown,
            r"rm\s+-[^\n]*\s/var/lib/http-ztp-monitor-auth(?:\s|$)",
        )


if __name__ == "__main__":
    unittest.main()
