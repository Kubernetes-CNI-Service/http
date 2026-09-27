"""Direct contracts for the optional project HTTP service port."""

from __future__ import annotations

import ast
import importlib.machinery
import importlib.util
import inspect
import io
from pathlib import Path
import shlex
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    path = ROOT / relative
    loader = (
        importlib.machinery.SourceFileLoader(name, str(path))
        if path.suffix == ".cgi" else None
    )
    spec = (
        importlib.util.spec_from_loader(name, loader)
        if loader else importlib.util.spec_from_file_location(name, path)
    )
    assert spec is not None and spec.loader is not None
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


LOAD = load_module("http_port_load", "DAY0-Prepare/11-load.py")
ACTIVATE = load_module("http_port_activate", "infra/docker/activate.py")
COLLECTOR = load_module("http_port_collector", "tools/collect-ztp-diagnostics.py")
SETUP = load_module("http_port_setup", "DAY0-Prepare/01-a-setup.py")
DEPLOY = load_module("http_port_deploy", "infra/deploy_infra.py")
DHCP = load_module(
    "http_port_dhcp", "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"
)
MANUAL = load_module("http_port_manual", "ztp/manual-ztp.py")


class HttpPortDirectTests(unittest.TestCase):
    def test_ztp_cgi_native_recovery_command_declares_linux_management_role(self):
        cgi = load_module(
            "http_port_ztp_control", "monitor/ztp-monitor-control.cgi"
        )
        body = "action=start"
        environment = {
            "REQUEST_METHOD": "POST",
            "CONTROL_REQUIRE_AUTH": "1",
            "AUTH_TYPE": "Basic",
            "REMOTE_USER": "nvis",
            "PATH_INFO": "",
            "SCRIPT_NAME": "/monitor/control/ztp-monitor",
            "HTTP_X_REQUESTED_WITH": "ZTPMonitorControl",
            "SERVER_ADDR": "192.0.2.40",
            "SERVER_PORT": "80",
            "REQUEST_SCHEME": "http",
            "HTTPS": "off",
            "HTTP_HOST": "192.0.2.40",
            "HTTP_ORIGIN": "http://192.0.2.40",
            "HTTP_SEC_FETCH_SITE": "same-origin",
            "CONTENT_LENGTH": str(len(body)),
        }
        with mock.patch.dict(cgi.os.environ, environment, clear=True), \
                mock.patch.object(sys, "stdin", io.StringIO(body)), \
                mock.patch.object(cgi, "process_state", return_value=(False, None)), \
                mock.patch.object(cgi, "control_auth_status", return_value=True), \
                mock.patch.object(cgi, "respond") as respond:
            cgi.main()
        payload, status = respond.call_args.args
        self.assertEqual("409 Conflict", status)
        native = payload["error"].split("Native/systemd 执行 ", 1)[1].split(
            "；Docker/Supervisor", 1
        )[0]
        argv = shlex.split(native)
        self.assertEqual(
            [
                "sudo", "python3", "DAY0-Prepare/11-load.py",
                "DAY0-Prepare/<project>", "--start-ztp-monitor",
                "--host-role=management-server",
            ],
            argv,
        )
        parsed = LOAD.parse_args(argv[3:])
        self.assertEqual(
            "management-server", LOAD.resolve_host_role(parsed.host_role, "Linux")
        )
        deleted_role_argv = [
            item for item in argv[3:] if item != "--host-role=management-server"
        ]
        with self.assertRaisesRegex(LOAD.LoadError, "requires explicit --host-role"):
            LOAD.resolve_host_role(
                LOAD.parse_args(deleted_role_argv).host_role, "Linux"
            )

    def test_p2_python_sources_have_no_dynamic_http_host_literals(self):
        def dynamic_host_sites(source: str):
            tree = ast.parse(source)
            sites = []
            for node in ast.walk(tree):
                if not isinstance(node, ast.JoinedStr):
                    continue
                for index, part in enumerate(node.values[:-1]):
                    if (
                        isinstance(part, ast.Constant)
                        and isinstance(part.value, str)
                        and part.value.endswith("http://")
                        and isinstance(node.values[index + 1], ast.FormattedValue)
                    ):
                        sites.append(node.lineno)
            return sites

        self.assertEqual(
            [1], dynamic_host_sites('url = f"http://{address}/ztp"\n')
        )
        for relative in (
            "DAY0-Prepare/11-load.py",
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
            "ztp/manual-ztp.py",
            "infra/deploy_infra.py",
        ):
            with self.subTest(path=relative):
                source = (ROOT / relative).read_text(encoding="utf-8")
                self.assertEqual([], dynamic_host_sites(source))

    def test_infra_apt_url_uses_channelled_service_endpoint(self):
        self.assertEqual(
            "http://192.0.2.10/apps", DEPLOY.local_http_url("192.0.2.10")
        )
        self.assertEqual(
            "http://192.0.2.10:8080/apps",
            DEPLOY.local_http_url("192.0.2.10", port=8080),
        )
        with self.assertRaises(ValueError):
            DEPLOY.local_http_url("192.0.2.10", port=65536)

    def test_infra_actual_apt_probe_uses_configured_port_and_head(self):
        response = mock.MagicMock()
        response.__enter__.return_value.status = 204
        with mock.patch.object(
            DEPLOY.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            self.assertTrue(DEPLOY.http_service_works("192.0.2.10", port=8080))
        urlopen.assert_called_once()
        request = urlopen.call_args.args[0]
        self.assertEqual("HEAD", request.get_method())
        self.assertEqual(
            "http://192.0.2.10:8080/apps/ubuntu-22.04/amd64/Packages.gz",
            request.full_url,
        )

        with mock.patch.object(
            DEPLOY.urllib.request, "urlopen", return_value=response
        ) as urlopen:
            self.assertTrue(DEPLOY.http_service_works("192.0.2.10"))
        self.assertEqual(
            "http://192.0.2.10/apps/ubuntu-22.04/amd64/Packages.gz",
            urlopen.call_args.args[0].full_url,
        )
        with mock.patch.object(DEPLOY.urllib.request, "urlopen") as urlopen:
            with self.assertRaises(ValueError):
                DEPLOY.http_service_works("192.0.2.10", port=65536)
        urlopen.assert_not_called()

    def test_infra_actual_managed_block_uses_configured_apt_port(self):
        arguments = ("192.0.2.10", ["192.0.2.53"], ["ntp.example"], "Etc/UTC")
        configured = DEPLOY.render_managed_block(*arguments, port=8080)
        self.assertIn("http_server=http://192.0.2.10:8080/apps", configured)
        self.assertEqual(
            1, configured.count("http_server=http://192.0.2.10:8080/apps")
        )
        self.assertNotIn("http://192.0.2.10/apps", configured)
        default = DEPLOY.render_managed_block(*arguments)
        self.assertIn("http_server=http://192.0.2.10/apps", default)
        with self.assertRaises(ValueError):
            DEPLOY.render_managed_block(*arguments, port=65536)

    def test_service_url_call_sites_declare_literal_known_channels(self):
        from tools.project_contract import CHANNELS

        for relative in (
            "tools/project_contract.py",
            "DAY0-Prepare/11-load.py",
            "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
            "ztp/manual-ztp.py",
            "infra/deploy_infra.py",
        ):
            with self.subTest(path=relative):
                tree = ast.parse((ROOT / relative).read_text(encoding="utf-8"))
                calls = [
                    node for node in ast.walk(tree)
                    if isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id == "service_url"
                ]
                self.assertTrue(calls, relative)
                for node in calls:
                    keywords = {item.arg: item.value for item in node.keywords}
                    channel = keywords.get("channel")
                    self.assertIsInstance(
                        channel, ast.Constant,
                        f"{relative}:{node.lineno} lacks a literal channel",
                    )
                    self.assertIn(channel.value, CHANNELS)

    def test_service_url_requires_an_enumerated_channel_and_preserves_host_origin_split(self):
        from tools.project_contract import CHANNELS, service_url, validate_service_endpoint

        endpoint = validate_service_endpoint(
            "192.0.2.10", 8080, field="test HTTP service"
        )
        self.assertEqual("192.0.2.10", endpoint.host)
        self.assertEqual("http://192.0.2.10:8080", endpoint.origin)
        self.assertIn("dhcp-provision-url", CHANNELS)
        self.assertEqual(
            "http://192.0.2.10:8080/ztp/ztp-bootstrap_oob.sh",
            service_url(
                endpoint, "/ztp-bootstrap_oob.sh", prefix="/ztp",
                channel="dhcp-provision-url",
            ),
        )
        with self.assertRaises(ValueError):
            service_url(endpoint, "/ztp", channel="unknown-channel")

    def test_device_visible_url_enumeration_covers_every_declared_channel(self):
        from tools.project_contract import (
            AUDIENCE_DEVICE, CHANNELS, PublicationPlan,
            device_visible_urls, validate_service_endpoint,
        )

        endpoint = validate_service_endpoint(
            "192.0.2.10", 8080, field="test HTTP service"
        )
        plan = PublicationPlan(
            endpoints_by_role=(
                ("air_oob", (endpoint,)),
                ("air_oobofoob", (endpoint,)),
            ),
            boot_endpoints=(endpoint,), ztp_prefix="/ztp",
            pubkey_names=("operator.pub",),
            image_names=(("cumulus", "image.bin"),),
            apt_endpoint=endpoint,
        )
        urls = device_visible_urls(plan)
        self.assertEqual(set(CHANNELS), {item.channel for item in urls})
        self.assertEqual(
            {endpoint},
            {item.endpoint for item in urls if item.audience == AUDIENCE_DEVICE},
        )
        self.assertTrue(
            all(item.url.startswith(endpoint.origin) for item in urls), urls
        )
        self.assertEqual(len(urls), len(set(urls)))

    def test_publication_probes_use_the_same_port_as_switch_urls(self):
        settings = SimpleNamespace(
            ztp_ips={"air_oob": ("192.0.2.10",)},
            boot_ips=("192.0.2.10",),
            service_ips=("192.0.2.10",),
            ztp_prefix="/ztp", http_port=8080,
        )
        inputs = SimpleNamespace(settings=settings, pubkeys=(Path("operator.pub"),))
        with mock.patch.object(
            LOAD, "deployable_pubkeys", return_value=(Path("operator.pub"),)
        ), mock.patch.object(LOAD, "run") as runner:
            LOAD.verify_http_publication(
                inputs, {"eth": Path("image.bin")}, dry_run=True
            )
        urls = [call.args[0][-1] for call in runner.call_args_list]
        self.assertGreaterEqual(len(urls), 3)
        self.assertTrue(
            all(url.startswith("http://192.0.2.10:8080/") for url in urls),
            urls,
        )

    def test_setup_rejects_invalid_http_port_before_load(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            for value in (True, "8080", 0, 65536):
                with self.subTest(value=value):
                    document["common"]["mgmt"]["http"]["port"] = value
                    path.write_text(yaml.safe_dump(document), encoding="utf-8")
                    errors, _warnings = SETUP._validate_global_yaml(path)
                    self.assertTrue(
                        any("common.mgmt.http.port" in item for item in errors),
                        errors,
                    )
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.load_global(path)

    def test_legacy_global_without_http_section_preserves_port_80_in_consumers(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        document["common"]["mgmt"].pop("http")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_yaml = root / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(global_yaml)
            self.assertEqual([], errors)
            self.assertEqual(80, DHCP.load_project_global(global_yaml)[2])
            self.assertEqual(80, MANUAL.global_ztp_http_policy(global_yaml)[1])
            container_root = root / "container"
            project = container_root / "DAY0-Prepare" / "fixture"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(global_yaml.read_bytes())
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=container_root
            )
            self.assertEqual(80, ACTIVATE.project_http_port(settings))

    def test_malformed_http_policy_fails_closed_in_all_port_consumers(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        document["common"]["mgmt"]["http"] = "8080"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_yaml = root / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(global_yaml)
            self.assertTrue(
                any("common.mgmt.http" in item for item in errors), errors
            )
            with self.assertRaises(LOAD.LoadError):
                LOAD.load_global(global_yaml)
            with self.assertRaises(ValueError):
                DHCP.load_project_global(global_yaml)
            with self.assertRaises(MANUAL.ManualZtpError):
                MANUAL.global_ztp_http_policy(global_yaml)
            container_root = root / "container"
            project = container_root / "DAY0-Prepare" / "fixture"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_bytes(global_yaml.read_bytes())
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=container_root
            )
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.project_http_port(settings)

    def test_both_apache_renderers_use_one_configured_port_without_changing_host(self):
        for renderer in (
            LOAD.render_native_apache_listener_config,
            ACTIVATE.render_apache_listener_config,
        ):
            with self.subTest(renderer=renderer.__name__):
                output = renderer(("192.0.2.10",), port=8080)
                self.assertIn("Listen 192.0.2.10:8080\n", output)
                self.assertIn("<VirtualHost 192.0.2.10:8080>", output)
                self.assertIn("ServerName 192.0.2.10\n", output)
                self.assertNotIn("192.0.2.10:8080:8080", output)

    def test_bootstrap_renderer_separates_origin_from_host_and_fails_missing_host_slot(self):
        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )
        output = LOAD.render_bootstrap_script_text(
            template,
            address="192.0.2.10",
            port=8080,
            prefix="/ztp",
            manual_urls={"ztp-bootstrap_oob.sh":
                         "http://192.0.2.10:8080/ztp/ztp-bootstrap_oob.sh"},
            upgrade_enabled=True,
            key_names=("mgmt-server.pub",),
            eth_version="5.16.4",
            script_name="ztp-bootstrap_oob.sh",
        )
        self.assertIn('ZTP_SERVER="http://192.0.2.10:8080"', output)
        self.assertIn('ZTP_SERVER_HOST="192.0.2.10"', output)
        self.assertEqual(0, output.count("${ZTP_SERVER##*/}"))
        self.assertEqual(18, output.count("##*/"))
        expected_host_consumers = (
            'route=$(ip -4 route get "${ZTP_SERVER_HOST}" 2>/dev/null | head -n 1 || true)',
            'route=$(ip -4 route get "${ZTP_SERVER_HOST}" vrf "${ZTP_VRF}" 2>/dev/null | head -n 1 || true)',
            'if ! check_network "${ZTP_SERVER_HOST}"; then',
        )

        def host_consumers(script):
            return tuple(
                line.strip()
                for line in script.splitlines()
                if not line.lstrip().startswith("#")
                and (
                    'ip -4 route get "' in line
                    or 'check_network "' in line
                )
            )

        self.assertEqual(expected_host_consumers, host_consumers(output))
        route_anchor = '        ' + expected_host_consumers[0]
        network_anchor = expected_host_consumers[2]
        extra_sites = (
            ('route, different expansion', route_anchor,
             route_anchor + '\n        route=$(ip -4 route get "${ZTP_SERVER#*://}" 2>/dev/null | head -n 1 || true)'),
            ('network, whole origin', network_anchor,
             'if ! check_network "${ZTP_SERVER}"; then\n    exit 1\nfi\n\n' + network_anchor),
            ('route, forbidden literal', route_anchor,
             route_anchor + '\n        route=$(ip -4 route get "${ZTP_SERVER##*/}" 2>/dev/null | head -n 1 || true)'),
        )
        for name, anchor, replacement in extra_sites:
            with self.subTest(extra_site=name):
                mutated_template = template.replace(anchor, replacement, 1)
                self.assertNotEqual(template, mutated_template)
                mutated_output = LOAD.render_bootstrap_script_text(
                    mutated_template,
                    address="192.0.2.10", port=8080, prefix="/ztp",
                    manual_urls={"ztp-bootstrap_oob.sh":
                                 "http://192.0.2.10:8080/ztp/ztp-bootstrap_oob.sh"},
                    upgrade_enabled=True,
                    key_names=("mgmt-server.pub",),
                    eth_version="5.16.4",
                    script_name="ztp-bootstrap_oob.sh",
                )
                with self.assertRaises(AssertionError):
                    self.assertEqual(
                        expected_host_consumers, host_consumers(mutated_output)
                    )
        with self.assertRaises(LOAD.LoadError):
            LOAD.render_bootstrap_script_text(
                template.replace('ZTP_SERVER_HOST="127.0.0.1"\n', ""),
                address="192.0.2.10", port=8080, prefix="/ztp",
                manual_urls={}, upgrade_enabled=True,
                key_names=("mgmt-server.pub",), eth_version="5.16.4",
                script_name="ztp-bootstrap_oob.sh",
            )

    def test_bootstrap_route_and_reachability_use_bare_host_in_each_branch(self):
        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )

        def render(source):
            return LOAD.render_bootstrap_script_text(
                source,
                address="192.0.2.10", port=8080, prefix="/ztp",
                manual_urls={}, upgrade_enabled=True,
                key_names=("mgmt-server.pub",), eth_version="5.16.4",
                script_name="ztp-bootstrap_oob.sh",
            )

        branches = (
            (
                "default VRF route",
                'route=$(ip -4 route get "${ZTP_SERVER_HOST}" 2>/dev/null | head -n 1 || true)',
                'route=$(ip -4 route get "${ZTP_SERVER##*/}" 2>/dev/null | head -n 1 || true)',
            ),
            (
                "named VRF route",
                'route=$(ip -4 route get "${ZTP_SERVER_HOST}" vrf "${ZTP_VRF}" 2>/dev/null | head -n 1 || true)',
                'route=$(ip -4 route get "${ZTP_SERVER##*/}" vrf "${ZTP_VRF}" 2>/dev/null | head -n 1 || true)',
            ),
            (
                "reachability guard",
                'if ! check_network "${ZTP_SERVER_HOST}"; then',
                'if ! check_network "${ZTP_SERVER##*/}"; then',
            ),
        )
        baseline = render(template)
        self.assertIn('ZTP_SERVER="http://192.0.2.10:8080"', baseline)
        self.assertIn('ZTP_SERVER_HOST="192.0.2.10"', baseline)
        for name, expected, reverted in branches:
            with self.subTest(branch=name):
                self.assertEqual(1, baseline.count(expected))
                self.assertNotIn(reverted, baseline)
                mutated_template = template.replace(expected, reverted, 1)
                self.assertNotEqual(template, mutated_template, "mutation was a no-op")
                mutated_output = render(mutated_template)
                self.assertIn(reverted, mutated_output)
                with self.assertRaises(AssertionError):
                    self.assertEqual(1, mutated_output.count(expected))

    def test_control_guards_bind_host_origin_to_configured_listener_port(self):
        baseline = {
            "SERVER_ADDR": "192.0.2.10", "SERVER_PORT": "8080",
            "CONTROL_SERVICE_PORT": "8080", "REQUEST_SCHEME": "http",
            "HTTP_HOST": "192.0.2.10:8080",
            "HTTP_ORIGIN": "http://192.0.2.10:8080",
            "HTTP_SEC_FETCH_SITE": "same-origin",
        }
        for path in (
            "monitor/ztp-monitor-control.cgi",
            "monitor/manual-ztp-control.cgi",
            "monitor/switch-collection-control.cgi",
        ):
            module = load_module("http_port_" + path.split("/")[-1], path)
            with self.subTest(path=path):
                with mock.patch.dict(module.os.environ, baseline, clear=True):
                    self.assertEqual((True, ""), module.post_control_guard())
                for key, value in (
                    ("SERVER_PORT", "80"),
                    ("HTTP_HOST", "192.0.2.10:80"),
                    ("HTTP_ORIGIN", "http://192.0.2.10:80"),
                ):
                    with self.subTest(key=key), mock.patch.dict(
                        module.os.environ, {**baseline, key: value}, clear=True
                    ):
                        self.assertFalse(module.post_control_guard()[0])

    def test_cgi_service_address_exception_stays_bound_to_renderer_rejection(self):
        from tools import project_contract

        vectors = (
            ("unspecified", "0.0.0.0", False),
            ("multicast", "224.0.0.1", False),
            ("all-ones", "255.255.255.255", False),
            ("loopback", "127.0.0.1", True),
            ("link-local", "169.254.23.8", True),
            ("service", "192.0.2.10", True),
        )

        def environment(address):
            return {
                "SERVER_ADDR": address, "SERVER_PORT": "8080",
                "CONTROL_SERVICE_PORT": "8080", "REQUEST_SCHEME": "http",
                "HTTP_HOST": f"{address}:8080",
                "HTTP_ORIGIN": f"http://{address}:8080",
                "HTTP_SEC_FETCH_SITE": "same-origin",
            }

        cgi_mutations = (
            ("unspecified", "0.0.0.0", "        or address.is_unspecified\n", ""),
            ("multicast", "224.0.0.1", "        or address.is_multicast\n", ""),
            ("all-ones", "255.255.255.255", "        or int(address) == 0xFFFFFFFF\n", ""),
            (
                "loopback", "127.0.0.1",
                "        or address.is_multicast\n",
                "        or address.is_multicast\n        or address.is_loopback\n",
            ),
            (
                "link-local", "169.254.23.8",
                "        or address.is_multicast\n",
                "        or address.is_multicast\n        or address.is_link_local\n",
            ),
        )
        for path in (
            "monitor/ztp-monitor-control.cgi",
            "monitor/manual-ztp-control.cgi",
            "monitor/switch-collection-control.cgi",
        ):
            module = load_module("http_port_" + path.split("/")[-1], path)
            source = inspect.getsource(module.post_control_guard)
            for name, address, accepted in vectors:
                with self.subTest(path=path, vector=name), mock.patch.dict(
                    module.os.environ, environment(address), clear=True
                ):
                    self.assertEqual(accepted, module.post_control_guard()[0])
            for name, address, before, after in cgi_mutations:
                with self.subTest(path=path, mutation=name):
                    self.assertEqual(1, source.count(before))
                    mutated = source.replace(before, after, 1)
                    self.assertNotEqual(source, mutated, "mutation was a no-op")
                    scope = dict(module.__dict__)
                    exec(mutated, scope)
                    with mock.patch.dict(module.os.environ, environment(address), clear=True):
                        self.assertNotEqual(
                            module.post_control_guard()[0],
                            scope["post_control_guard"]()[0],
                        )

        contract_source = inspect.getsource(project_contract.validate_service_endpoint)
        for name, address in (
            ("loopback", "127.0.0.1"),
            ("link_local", "169.254.23.8"),
        ):
            with self.subTest(contract_mutation=name):
                with self.assertRaises(ValueError):
                    project_contract.validate_service_endpoint(
                        address, 8080, field="CGI exception dependency"
                    )
                clause = f"        or parsed.is_{name}\n"
                self.assertEqual(1, contract_source.count(clause))
                mutated = contract_source.replace(clause, "", 1)
                self.assertNotEqual(contract_source, mutated, "mutation was a no-op")
                scope = dict(project_contract.__dict__)
                exec(mutated, scope)
                self.assertEqual(
                    address,
                    scope["validate_service_endpoint"](
                        address, 8080, field="CGI exception dependency"
                    ).host,
                )

    def test_diagnostics_preserve_only_benign_numeric_port_setenv(self):
        self.assertEqual(
            "SetEnv CONTROL_SERVICE_PORT 8080",
            COLLECTOR.redact_apache_setenv_line(
                "SetEnv CONTROL_SERVICE_PORT 8080"
            ),
        )
        self.assertIn(
            "<redacted:secret>",
            COLLECTOR.redact_apache_setenv_line(
                "SetEnv CONTROL_SERVICE_PORT not-a-port"
            ),
        )


if __name__ == "__main__":
    unittest.main()
