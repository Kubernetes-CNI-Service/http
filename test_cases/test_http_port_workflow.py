"""Cross-script HTTP-port agreement from project YAML to switch handout."""

from __future__ import annotations

from dataclasses import replace
from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import re
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlsplit

import yaml

from test_cases.test_http_port_contract import DEPLOY, load_module, ROOT


LOAD = load_module("http_port_workflow_load", "DAY0-Prepare/11-load.py")
ACTIVATE = load_module("http_port_workflow_activate", "infra/docker/activate.py")
DHCP = load_module(
    "http_port_workflow_dhcp",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
MANUAL = load_module("http_port_workflow_manual", "ztp/manual-ztp.py")


SUBNET = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
    "management,192.0.2.0,255.255.255.0,192.0.2.50,192.0.2.99,"
    "192.0.2.1,192.0.2.10,oob,yes\n"
)

SUBNET_TWO = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
    "management-a,192.0.2.0,255.255.255.0,192.0.2.50,192.0.2.99,"
    "192.0.2.1,192.0.2.10,oob,yes\n"
    "management-b,198.51.100.0,255.255.255.0,198.51.100.50,198.51.100.99,"
    "198.51.100.1,198.51.100.10,oobofoob,no\n"
)


class HttpPortWorkflowTests(unittest.TestCase):
    def test_project_http_port_reaches_actual_infra_probe_and_render_before_write(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            global_yaml = root / "01-global.yaml"
            subnet_csv = root / "02-dhcp-subnet_config.csv"
            subnet_csv.write_text(SUBNET, encoding="utf-8")
            setup = root / "infra-setup.sh"
            teardown = root / "infra-teardown.sh"
            setup.write_text("#!/bin/bash\n", encoding="utf-8")
            teardown.write_text("#!/bin/bash\n", encoding="utf-8")
            (root / "infra-neutral.conf").write_text(
                "DNS=8.8.8.8\nNTP=ntp.ubuntu.com\nTIMEZONE=Etc/UTC\n",
                encoding="utf-8",
            )
            args = SimpleNamespace(
                global_file=global_yaml, devices_file=root / "unused.csv",
                setup_script=setup, teardown_script=teardown,
                teardown=False, http_server_ip="192.0.2.10", user="operator",
                identity=None, hosts=None, prepare_only=True, dry_run=False,
                max_workers=1,
            )

            def run_infra():
                response = mock.MagicMock()
                response.__enter__.return_value.status = 204
                with mock.patch.object(DEPLOY, "parse_args", return_value=args), \
                     mock.patch.object(DEPLOY, "load_servers", return_value=[]), \
                     mock.patch.object(
                         DEPLOY, "determine_http_source_ip",
                         return_value="192.0.2.10",
                     ), \
                     mock.patch.object(
                         DEPLOY.urllib.request, "urlopen", return_value=response,
                     ) as urlopen, \
                     mock.patch.object(DEPLOY, "update_runtime_config") as update, \
                     redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                    status = DEPLOY.main()
                return status, urlopen, update

            for configured_port in (8080, None):
                with self.subTest(configured_port=configured_port):
                    if configured_port is None:
                        document["common"]["mgmt"]["http"].pop("port", None)
                    else:
                        document["common"]["mgmt"]["http"]["port"] = configured_port
                    global_yaml.write_text(
                        yaml.safe_dump(document), encoding="utf-8"
                    )
                    settings = LOAD.load_global(global_yaml)
                    self.assertEqual(configured_port or 80, settings.http_port)
                    dhcp = DHCP.load_subnet_csv(
                        subnet_csv, settings.ztp_prefix, port=settings.http_port
                    )
                    status, urlopen, update = run_infra()
                    self.assertEqual(0, status)
                    urlopen.assert_called_once()
                    request = urlopen.call_args.args[0]
                    self.assertEqual("HEAD", request.get_method())
                    origin = (
                        "http://192.0.2.10:8080" if configured_port == 8080
                        else "http://192.0.2.10"
                    )
                    self.assertEqual(
                        f"{origin}/apps/ubuntu-22.04/amd64/Packages.gz",
                        request.full_url,
                    )
                    self.assertEqual(
                        origin, urlsplit(dhcp[0]["cumulus_provision_url"]).scheme
                        + "://" + urlsplit(dhcp[0]["cumulus_provision_url"]).netloc,
                    )
                    update.assert_called_once()
                    self.assertIn(
                        f"http_server={origin}/apps", update.call_args.args[1]
                    )
                    self.assertFalse((root / "infra-runtime.conf").exists())

            for invalid_port in (True, "8080", 0, 65536):
                with self.subTest(invalid_port=invalid_port):
                    document["common"]["mgmt"]["http"]["port"] = invalid_port
                    global_yaml.write_text(
                        yaml.safe_dump(document), encoding="utf-8"
                    )
                    status, urlopen, update = run_infra()
                    self.assertEqual(1, status)
                    urlopen.assert_not_called()
                    update.assert_not_called()
                    self.assertFalse((root / "infra-runtime.conf").exists())

    def test_nondefault_port_executes_bare_host_route_and_reachability(self):
        """Execute the rendered shell decisions with inert command substitutes."""
        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )
        rendered = LOAD.render_bootstrap_script_text(
            template, address="192.0.2.10", port=8080, prefix="/ztp",
            manual_urls={}, upgrade_enabled=True,
            key_names=("operator.pub",), eth_version="5.16.4",
            script_name="ztp-bootstrap_oob.sh",
        )

        def execute_decisions(source, vrf):
            assignments = []
            for name in ("ZTP_SERVER", "ZTP_SERVER_HOST"):
                matches = re.findall(rf"^{name}=\"[^\n]*\"$", source, re.MULTILINE)
                self.assertEqual(1, len(matches), (name, matches))
                assignments.append(matches[0])
            self.assertEqual(
                ['ZTP_SERVER="http://192.0.2.10:8080"',
                 'ZTP_SERVER_HOST="192.0.2.10"'],
                assignments,
            )
            route_start = source.index(
                '    if [[ "${ZTP_VRF}" == "default" ]]; then\n'
            )
            route_end = source.index("    ZTP_ROUTE_DEV=", route_start)
            route_clause = source[route_start:route_end]
            route_lines = [line.strip() for line in route_clause.splitlines() if line.strip()]
            self.assertEqual(5, len(route_lines), route_lines)
            self.assertEqual(
                ('if [[ "${ZTP_VRF}" == "default" ]]; then', "else", "fi"),
                (route_lines[0], route_lines[2], route_lines[4]),
            )
            for index, suffix in ((1, ""), (3, ' vrf "${ZTP_VRF}"')):
                self.assertRegex(
                    route_lines[index],
                    r'^route=\$\(ip -4 route get "\$\{(?:ZTP_SERVER_HOST|ZTP_SERVER##\*/)\}'
                    + re.escape('"' + suffix)
                    + r' 2>/dev/null \| head -n 1 \|\| true\)$',
                )
            reachability = re.findall(
                r"^if ! check_network .+; then$", source, re.MULTILINE
            )
            self.assertEqual(1, len(reachability), reachability)
            self.assertRegex(
                reachability[0],
                r'^if ! check_network "\$\{(?:ZTP_SERVER_HOST|ZTP_SERVER##\*/|ZTP_SERVER)\}"; then$',
            )
            with tempfile.TemporaryDirectory() as directory:
                trace = Path(directory) / "argv.txt"
                shell = "\n".join((
                    "set -euo pipefail",
                    *assignments,
                    f'ZTP_VRF="{vrf}"',
                    f'TRACE_PATH="{trace}"',
                    'ip() { printf "ip:%s\\n" "$*" >> "$TRACE_PATH"; '
                    'printf "192.0.2.10 via 192.0.2.1 dev eth0\\n"; }',
                    'check_network() { printf "check:%s\\n" "$1" >> "$TRACE_PATH"; return 0; }',
                    route_clause,
                    reachability[0],
                    "    exit 99",
                    "fi",
                ))
                result = subprocess.run(
                    ["bash", "-c", shell], text=True, capture_output=True,
                )
                self.assertEqual(0, result.returncode, result.stderr)
                return trace.read_text(encoding="utf-8").splitlines()

        expected = {
            "default": [
                "ip:-4 route get 192.0.2.10",
                "check:192.0.2.10",
            ],
            "mgmt": [
                "ip:-4 route get 192.0.2.10 vrf mgmt",
                "check:192.0.2.10",
            ],
        }
        for vrf, trace in expected.items():
            with self.subTest(vrf=vrf):
                self.assertEqual(trace, execute_decisions(rendered, vrf))

        # Each mutation changes one executed host argument, not merely source text.
        mutations = (
            (
                "D2 default route",
                'ip -4 route get "${ZTP_SERVER_HOST}" 2>/dev/null',
                'ip -4 route get "${ZTP_SERVER##*/}" 2>/dev/null',
                "default",
            ),
            (
                "D3 named route",
                'ip -4 route get "${ZTP_SERVER_HOST}" vrf "${ZTP_VRF}"',
                'ip -4 route get "${ZTP_SERVER##*/}" vrf "${ZTP_VRF}"',
                "mgmt",
            ),
            (
                "D4 reachability",
                'if ! check_network "${ZTP_SERVER_HOST}"; then',
                'if ! check_network "${ZTP_SERVER##*/}"; then',
                "default",
            ),
        )
        for name, old, new, vrf in mutations:
            with self.subTest(mutation=name):
                self.assertEqual(1, rendered.count(old))
                mutant = rendered.replace(old, new, 1)
                self.assertNotEqual(rendered, mutant)
                observed = execute_decisions(mutant, vrf)
                self.assertNotEqual(expected[vrf], observed)
                self.assertIn("192.0.2.10:8080", "\n".join(observed))

    def test_five_port_producers_agree_and_each_mutation_is_detected(self):
        from project_contract import AUDIENCE_DEVICE
        device_visible_urls = LOAD.device_visible_urls
        validate_service_endpoint = LOAD.validate_service_endpoint

        def from_url(value):
            parsed = urlsplit(value)
            return validate_service_endpoint(
                parsed.hostname, parsed.port or 80, field="test URL endpoint"
            )

        def listen_endpoints(text):
            return {
                validate_service_endpoint(host, int(port), field="test listener")
                for host, port in re.findall(
                    r"^Listen ([0-9.]+):([0-9]+)$", text, re.MULTILINE
                )
            }

        def assert_converged(a, b, c, d, e, b_container):
            self.assertEqual(a, b)
            self.assertEqual(b, b_container)
            self.assertEqual({endpoint.origin for endpoint in a}, c)
            self.assertEqual(c, d)
            self.assertEqual({endpoint.port for endpoint in a}, e)

        template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
            encoding="utf-8"
        )
        for port in (80, 1024, 8080, 65535):
            with self.subTest(port=port), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                document = yaml.safe_load(
                    (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                        encoding="utf-8"
                    )
                )
                document["common"]["mgmt"]["http"]["port"] = port
                global_yaml = root / "01-global.yaml"
                global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
                subnet_csv = root / "02-dhcp-subnet_config.csv"
                subnet_csv.write_text(SUBNET_TWO, encoding="utf-8")
                settings = replace(
                    LOAD.load_global(global_yaml),
                    ztp_ips={
                        "air_oob": ("192.0.2.10",),
                        "air_oobofoob": ("198.51.100.10",),
                    },
                    boot_ips=("192.0.2.10",),
                )
                plan = LOAD.publication_plan_for(
                    settings, pubkey_names=("operator.pub",),
                    image_names=(("cumulus", "image.bin"),),
                )
                a = {
                    item.endpoint for item in device_visible_urls(plan)
                    if item.audience == AUDIENCE_DEVICE
                }
                native = LOAD.render_native_apache_listener_config(
                    settings.service_ips, port=port
                )
                container = ACTIVATE.render_apache_listener_config(
                    settings.service_ips, port=port
                )
                b = listen_endpoints(native)
                b_container = listen_endpoints(container)
                c = set()
                for role, addresses in settings.ztp_ips.items():
                    script = (
                        "ztp-bootstrap_oobofoob.sh" if role.endswith("oobofoob")
                        else "ztp-bootstrap_oob.sh"
                    )
                    rendered = LOAD.render_bootstrap_script_text(
                        template, address=addresses[0], port=port,
                        prefix=settings.ztp_prefix, manual_urls={},
                        upgrade_enabled=True, key_names=("operator.pub",),
                        eth_version=None, script_name=script,
                    )
                    c.add(re.search(
                        r'^ZTP_SERVER="([^"]+)"$', rendered, re.MULTILINE
                    ).group(1))
                dhcp_rows = DHCP.load_subnet_csv(
                    subnet_csv, settings.ztp_prefix, port=port
                )
                d = {
                    from_url(row[key]).origin for row in dhcp_rows
                    for key in ("cumulus_provision_url", "bootfile_name")
                    if row[key]
                }
                configured_ports = {
                    int(value) for value in re.findall(
                        r"^\s*SetEnv CONTROL_SERVICE_PORT ([0-9]+)$",
                        native, re.MULTILINE,
                    )
                }
                e = configured_ports or {80}
                assert_converged(a, b, c, d, e, b_container)

                wrong = validate_service_endpoint(
                    "203.0.113.10", port, field="mutation endpoint"
                )
                for producer, values in (
                    ("a", ({wrong}, b, c, d, e, b_container)),
                    ("b", (a, {wrong}, c, d, e, b_container)),
                    ("c", (a, b, {wrong.origin}, d, e, b_container)),
                    ("d", (a, b, c, {wrong.origin}, e, b_container)),
                    ("e", (a, b, c, d, {9090}, b_container)),
                ):
                    with self.subTest(port=port, producer=producer):
                        with self.assertRaises(AssertionError):
                            assert_converged(*values)

    def test_yaml_port_converges_in_listener_bootstrap_dhcp_and_manual_urls(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            document = yaml.safe_load(
                (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                    encoding="utf-8"
                )
            )
            document["common"]["mgmt"]["http"]["port"] = 8080
            global_yaml = root / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            subnet_csv = root / "02-dhcp-subnet_config.csv"
            subnet_csv.write_text(SUBNET, encoding="utf-8")

            settings = replace(
                LOAD.load_global(global_yaml),
                ztp_ips={"air_oob": ("192.0.2.10",)},
            )
            self.assertEqual(8080, settings.http_port)
            native = LOAD.render_native_apache_listener_config(
                settings.service_ips, port=settings.http_port
            )
            container = ACTIVATE.render_apache_listener_config(
                settings.service_ips, port=settings.http_port
            )
            template = (ROOT / "ztp/templates/ztp-bootstrap.sh").read_text(
                encoding="utf-8"
            )
            bootstrap = LOAD.render_bootstrap_script_text(
                template, address="192.0.2.10", port=settings.http_port,
                prefix=settings.ztp_prefix, manual_urls={},
                upgrade_enabled=True, key_names=("mgmt-server.pub",),
                eth_version=None, script_name="ztp-bootstrap_oob.sh",
            )
            dhcp_rows = DHCP.load_subnet_csv(
                subnet_csv, settings.ztp_prefix, port=settings.http_port
            )
            manual = MANUAL.provision_urls(subnet_csv, global_yaml)

            origin = "http://192.0.2.10:8080"
            self.assertIn("Listen 192.0.2.10:8080", native)
            self.assertIn("Listen 192.0.2.10:8080", container)
            self.assertIn("SetEnv CONTROL_SERVICE_PORT 8080", native)
            self.assertIn("SetEnv CONTROL_SERVICE_PORT 8080", container)
            self.assertIn(f'ZTP_SERVER="{origin}"', bootstrap)
            self.assertEqual(
                f"{origin}/ztp/ztp-bootstrap_oob.sh",
                dhcp_rows[0]["cumulus_provision_url"],
            )
            self.assertEqual(
                f"{origin}/ztp/ztp-bootstrap_oob.sh", manual[0][1]
            )
            self.assertEqual(
                f"{origin}/ztp/ztp.json", dhcp_rows[0]["bootfile_name"]
            )

            container_root = root / "container-root"
            container_project = container_root / "DAY0-Prepare" / "test-project"
            container_project.mkdir(parents=True)
            (container_project / "01-global.yaml").write_bytes(global_yaml.read_bytes())
            container_settings = ACTIVATE.Settings(
                project_name="test-project", scope="prod", http_root=container_root
            )
            selected = SimpleNamespace(endpoint_ips=("192.0.2.10",))
            with mock.patch.object(
                ACTIVATE, "build_runtime_plan",
                return_value=(selected, [], [], SimpleNamespace()),
            ), mock.patch.object(
                ACTIVATE, "runtime_plan_payload", return_value={}
            ):
                _selected, _runtime, _payload, observed_apache = (
                    ACTIVATE.observe_runtime(container_settings)
                )
            self.assertIn("Listen 192.0.2.10:8080", observed_apache)

    def test_missing_key_preserves_default_origin_and_listener(self):
        with tempfile.TemporaryDirectory() as directory:
            global_yaml = Path(directory) / "01-global.yaml"
            document = yaml.safe_load(
                (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                    encoding="utf-8"
                )
            )
            document["common"]["mgmt"]["http"].pop("port")
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            settings = LOAD.load_global(global_yaml)
            self.assertEqual(80, settings.http_port)
            native = LOAD.render_native_apache_listener_config(
                ("192.0.2.10",), port=settings.http_port
            )
            self.assertIn("Listen 192.0.2.10:80", native)
            self.assertNotIn("SetEnv CONTROL_SERVICE_PORT", native)


if __name__ == "__main__":
    unittest.main()
