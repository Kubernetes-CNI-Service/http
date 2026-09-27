"""Shared HTTP service-endpoint and caller convergence contracts."""

from __future__ import annotations

import importlib.util
import ipaddress
from dataclasses import replace
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, relative: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
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


LOAD = load_module("service_endpoint_load", "DAY0-Prepare/11-load.py")
ACTIVATE = load_module("service_endpoint_activate", "infra/docker/activate.py")
SETUP = load_module("service_endpoint_setup", "DAY0-Prepare/01-a-setup.py")
DHCP = load_module(
    "service_endpoint_dhcp",
    "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
MANUAL = load_module("service_endpoint_manual", "ztp/manual-ztp.py")
DEPLOY = load_module("service_endpoint_deploy", "infra/deploy_infra.py")
CONTRACT = load_module("service_endpoint_contract", "tools/project_contract.py")
RUNTIME = load_module("service_endpoint_runtime", "tools/ztp_service_runtime.py")


INVALID_SERVICE_ADDRESSES = (
    "",
    "0.0.0.0",
    "127.0.0.1",
    "169.254.23.8",
    "224.0.0.1",
    "255.255.255.255",
    "192.0.2.010",
    "2001:db8::10",
    "fe80::1%en0",
)


STRICT_INVALID_SERVICE_VALUES = INVALID_SERVICE_ADDRESSES + (
    ["192.0.2.10"],
    True,
    3221225994,
    192.0,
)


def subnet_csv(service_ip: str) -> str:
    return (
        "shared_network,subnet,netmask,range_start,range_end,routers,"
        "ztp_service_ip,cumulus_profile,nvos_ztp\n"
        "management,192.0.2.0,255.255.255.0,192.0.2.50,192.0.2.99,"
        f"192.0.2.1,{service_ip},oob,no\n"
    )


def http_owner(
    name: str, ifindex: int, *, eligible: bool, reason: str | None = None,
) -> dict[str, object]:
    return {
        "ifname": name, "ifindex": ifindex,
        "eligible": eligible, "reason": reason,
    }


class ServiceEndpointConvergenceTests(unittest.TestCase):
    def test_shared_http_ownership_allows_eligible_duplicates_with_optional_ceiling(self):
        owners = (
            http_owner("eno2", 7, eligible=True),
            http_owner("eno3", 8, eligible=True),
        )
        validate = CONTRACT.validate_http_listener_ownership
        for ceiling in ((), ("eno2", "eno3")):
            with self.subTest(allowlist=ceiling):
                accepted = validate(
                    "198.51.100.5", owners, allowlist=ceiling,
                )
                self.assertEqual(
                    {"eno2", "eno3"},
                    {owner["ifname"] for owner in accepted},
                )
                self.assertEqual(
                    accepted,
                    validate(
                        "198.51.100.5", tuple(reversed(owners)),
                        allowlist=ceiling,
                    ),
                )

    def test_shared_http_ownership_enforces_active_allowlist_ceiling(self):
        owners = (
            http_owner("eno2", 7, eligible=True),
            http_owner("eno3", 8, eligible=True),
        )
        with self.assertRaises(ValueError) as caught:
            CONTRACT.validate_http_listener_ownership(
                "198.51.100.5", owners, allowlist=("eno2",),
            )
        self.assertIn("eno2", str(caught.exception))
        self.assertIn("eno3", str(caught.exception))

    def test_shared_http_ownership_records_ineligible_duplicates(self):
        owners = (
            http_owner("eno2", 7, eligible=True),
            http_owner("eno3", 8, eligible=False, reason="link is down"),
        )
        accepted = CONTRACT.validate_http_listener_ownership(
            "198.51.100.5", owners, allowlist=("eno2",),
        )
        self.assertEqual({"eno2", "eno3"}, {row["ifname"] for row in accepted})
        self.assertEqual(
            "link is down",
            next(row["reason"] for row in accepted if row["ifname"] == "eno3"),
        )

    def test_shared_http_ownership_rejects_no_eligible_owner(self):
        owners = (
            http_owner("eno2", 7, eligible=False, reason="link is down"),
            http_owner("dummy0", 8, eligible=False, reason="virtual link"),
        )
        with self.assertRaises(ValueError) as caught:
            CONTRACT.validate_http_listener_ownership(
                "198.51.100.5", owners, allowlist=("eno2",),
            )
        for name in ("eno2", "dummy0"):
            self.assertIn(name, str(caught.exception))

    def test_docker_http_owner_ceiling_precedes_runtime_writes(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        mgmt = document["common"]["mgmt"]
        mgmt["http"]["address"] = "198.51.100.5"
        mgmt["dhcp-server"]["status"] = "disabled"
        mgmt["ztp"]["status"] = "disabled"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / "http-owner"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                yaml.safe_dump(document), encoding="utf-8"
            )
            selected = SimpleNamespace(endpoint_ips=(), listener_names=())
            base_links = (
                {"ifindex": 7, "ifname": "eno2", "flags": [
                    "BROADCAST", "UP", "LOWER_UP"
                ], "operstate": "UP", "link_type": "ether"},
                {"ifindex": 8, "ifname": "eno3", "flags": [
                    "BROADCAST", "UP", "LOWER_UP"
                ], "operstate": "UP", "link_type": "ether"},
            )
            base_addresses = tuple({
                "ifindex": index, "ifname": name,
                "addr_info": [{"family": "inet", "local": "198.51.100.5",
                               "prefixlen": 24, "scope": "global"}],
            } for index, name in ((7, "eno2"), (8, "eno3")))
            cases = (
                ("allowed+allowed-no-ceiling", base_links, (), True),
                ("allowed+allowed", base_links, ("eno2", "eno3"), True),
                ("allowed+live-disallowed", base_links, ("eno2",), False),
                ("allowed+down-disallowed", (
                    base_links[0], {**base_links[1], "flags": ["BROADCAST"],
                                    "operstate": "DOWN"}
                ), ("eno2",), True),
                ("no-eligible", (
                    {**base_links[0], "flags": ["BROADCAST"],
                     "operstate": "DOWN"},
                    {**base_links[1], "flags": ["BROADCAST"],
                     "operstate": "DOWN"},
                ), ("eno2",), False),
            )
            expected_apache = None
            for label, links, allowlist, should_pass in cases:
                settings = ACTIVATE.Settings(
                    project_name="http-owner", scope="prod", http_root=root,
                    allowlist=allowlist,
                )
                with self.subTest(case=label), mock.patch.object(
                    ACTIVATE, "build_runtime_plan",
                    return_value=(selected, links, base_addresses, RUNTIME),
                ), mock.patch.object(
                    ACTIVATE, "runtime_plan_payload", return_value={},
                ):
                    if should_pass:
                        _selected, _runtime, _payload, apache = (
                            ACTIVATE.observe_runtime(settings)
                        )
                        self.assertEqual((), selected.endpoint_ips)
                        self.assertEqual(
                            ["Listen 198.51.100.5:80"],
                            [line for line in apache.splitlines()
                             if line.startswith("Listen ")],
                        )
                        if expected_apache is None:
                            expected_apache = apache
                        else:
                            self.assertEqual(expected_apache, apache)
                    else:
                        with mock.patch.object(
                            ACTIVATE, "ensure_runtime_directories"
                        ) as ensure, mock.patch.object(
                            ACTIVATE, "_atomic_write"
                        ) as write:
                            with self.assertRaises(ACTIVATE.ActivationError) as caught:
                                ACTIVATE.prepare_runtime(settings)
                            self.assertIn("eno2", str(caught.exception))
                            self.assertIn("eno3", str(caught.exception))
                            ensure.assert_not_called()
                            write.assert_not_called()
            settings = ACTIVATE.Settings(
                project_name="http-owner", scope="prod", http_root=root,
                allowlist=("eno2", "eno3"),
            )
            with mock.patch.object(
                ACTIVATE, "build_runtime_plan",
                return_value=(selected, tuple(reversed(base_links)),
                              tuple(reversed(base_addresses)), RUNTIME),
            ), mock.patch.object(ACTIVATE, "runtime_plan_payload", return_value={}):
                _selected, _runtime, _payload, reversed_apache = (
                    ACTIVATE.observe_runtime(settings)
                )
            self.assertEqual(expected_apache, reversed_apache)

    def test_shared_http_listener_merge_keeps_ztp_identity_independent(self):
        merge = CONTRACT.merge_http_listener_addresses
        self.assertEqual(
            ("192.0.2.10", "198.51.100.5"),
            merge(("192.0.2.10", "198.51.100.5"), None),
        )
        self.assertEqual(("198.51.100.5",), merge((), "198.51.100.5"))
        self.assertEqual(
            ("192.0.2.10",),
            merge(("192.0.2.10",), "192.0.2.10"),
        )
        self.assertEqual(
            ("192.0.2.10", "198.51.100.5"),
            merge(("192.0.2.10", "192.0.2.10"), "198.51.100.5"),
        )
        self.assertEqual(
            ("192.0.2.10", "198.51.100.5"),
            merge(("198.51.100.5", "192.0.2.10"), None),
        )
        for address in STRICT_INVALID_SERVICE_VALUES:
            with self.subTest(http_address=address):
                with self.assertRaisesRegex(ValueError, "common.mgmt.http.address"):
                    merge(("192.0.2.10",), address)
        with self.assertRaisesRegex(ValueError, "ZTP service IPv4"):
            merge(("0.0.0.0",), None)

    def test_declared_http_address_is_validated_by_both_global_readers(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        document["common"]["mgmt"]["http"]["port"] = 8080
        with tempfile.TemporaryDirectory() as directory:
            global_yaml = Path(directory) / "01-global.yaml"
            for address in (
                "not-ip", "", "0.0.0.0", "127.0.0.1", "169.254.23.8",
                "224.0.0.1", "255.255.255.255", "192.0.2.010",
                "2001:db8::10", ["198.51.100.5"], True, 3325256709,
            ):
                document["common"]["mgmt"]["http"]["address"] = address
                global_yaml.write_text(
                    yaml.safe_dump(document), encoding="utf-8"
                )
                with self.subTest(address=address, reader="setup"):
                    errors, _warnings = SETUP._validate_global_yaml(global_yaml)
                    self.assertTrue(
                        any("common.mgmt.http.address" in error for error in errors),
                        errors,
                    )
                with self.subTest(address=address, reader="load"):
                    with self.assertRaises(LOAD.LoadError):
                        LOAD.load_global(global_yaml)

            document["common"]["mgmt"]["http"]["address"] = "198.51.100.5"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            errors, _warnings = SETUP._validate_global_yaml(global_yaml)
            self.assertEqual([], errors)
            settings = LOAD.load_global(global_yaml)
            self.assertEqual(8080, settings.http_port)
            self.assertEqual((), settings.service_ips)

    def test_http_only_declared_address_is_checked_locally_without_ztp(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        mgmt = document["common"]["mgmt"]
        mgmt["http"]["address"] = "198.51.100.5"
        mgmt["dhcp-server"]["status"] = "disabled"
        mgmt["ztp"]["status"] = "disabled"
        with tempfile.TemporaryDirectory() as directory:
            global_yaml = Path(directory) / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            settings = replace(
                LOAD.load_global(global_yaml), http_root=LOAD.HTTP_ROOT
            )
            self.assertEqual((), settings.service_ips)
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"198.51.100.5"}
            ):
                self.assertTrue(LOAD.validate_management_host(settings))
            with mock.patch.object(
                LOAD, "local_ipv4_addresses", return_value={"192.0.2.10"}
            ):
                self.assertFalse(LOAD.validate_management_host(settings))

    def test_http_only_declared_address_renders_native_and_docker_without_ztp(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        mgmt = document["common"]["mgmt"]
        mgmt["http"]["address"] = "198.51.100.5"
        mgmt["http"]["port"] = 8080
        mgmt["dhcp-server"]["status"] = "disabled"
        mgmt["ztp"]["status"] = "disabled"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / "http-only"
            project.mkdir(parents=True)
            global_yaml = project / "01-global.yaml"
            global_yaml.write_text(yaml.safe_dump(document), encoding="utf-8")
            native_settings = LOAD.load_global(global_yaml)
            self.assertEqual((), native_settings.service_ips)
            with self.subTest(backend="native"):
                native = LOAD.render_native_apache_listener_config(
                    getattr(
                        native_settings, "http_listener_ips",
                        native_settings.service_ips,
                    ),
                    port=native_settings.http_port,
                )
                self.assertEqual(
                    ["Listen 198.51.100.5:8080"],
                    [line for line in native.splitlines() if line.startswith("Listen ")],
                )
                self.assertNotIn("0.0.0.0", native)

            docker_settings = ACTIVATE.Settings(
                project_name="http-only", scope="prod", http_root=root
            )
            selected = SimpleNamespace(endpoint_ips=(), listener_names=())
            links = ({
                "ifindex": 7, "ifname": "eno2", "flags": [
                    "BROADCAST", "UP", "LOWER_UP",
                ], "operstate": "UP", "link_type": "ether",
            },)
            addresses = ({
                "ifindex": 7, "ifname": "eno2", "addr_info": [{
                    "family": "inet", "local": "198.51.100.5",
                    "prefixlen": 24, "scope": "global",
                }],
            },)
            with mock.patch.object(
                ACTIVATE, "build_runtime_plan",
                return_value=(selected, links, addresses, RUNTIME),
            ), mock.patch.object(
                ACTIVATE, "runtime_plan_payload", return_value={}
            ):
                _selected, _runtime, _payload, docker = ACTIVATE.observe_runtime(
                    docker_settings
                )
            with self.subTest(backend="docker"):
                self.assertEqual(
                    ["Listen 198.51.100.5:8080"],
                    [line for line in docker.splitlines() if line.startswith("Listen ")],
                )
                self.assertNotIn("0.0.0.0", docker)
                self.assertEqual((), selected.endpoint_ips)
                self.assertFalse(
                    {"dhcpd", "ztp-monitor", "switch-collection", "manual-ztp"}
                    & set(ACTIVATE.expected_services(selected, dhcp_status="disabled"))
                )

    def test_declared_http_and_ztp_addresses_form_one_deduplicated_listener_set(self):
        document = yaml.safe_load(
            (ROOT / "DAY0-Prepare/template/01-global.yaml").read_text(
                encoding="utf-8"
            )
        )
        document["common"]["mgmt"]["http"]["port"] = 8080
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "DAY0-Prepare" / "address-union"
            project.mkdir(parents=True)
            global_yaml = project / "01-global.yaml"
            subnet_file = project / "02-dhcp-subnet_config.csv"
            subnet_file.write_text(subnet_csv("192.0.2.10"), encoding="utf-8")
            docker_settings = ACTIVATE.Settings(
                project_name="address-union", scope="prod", http_root=root
            )
            links = (
                {"ifindex": 7, "ifname": "eno2", "flags": [
                    "BROADCAST", "UP", "LOWER_UP",
                ], "operstate": "UP", "link_type": "ether"},
                {"ifindex": 8, "ifname": "eno3", "flags": [
                    "BROADCAST", "UP", "LOWER_UP",
                ], "operstate": "UP", "link_type": "ether"},
            )
            addresses = (
                {"ifindex": 7, "ifname": "eno2", "addr_info": [{
                    "family": "inet", "local": "192.0.2.10",
                    "prefixlen": 24, "scope": "global",
                }]},
                {"ifindex": 8, "ifname": "eno3", "addr_info": [{
                    "family": "inet", "local": "198.51.100.5",
                    "prefixlen": 24, "scope": "global",
                }]},
            )
            for address, expected in (
                ("192.0.2.10", {"Listen 192.0.2.10:8080"}),
                ("198.51.100.5", {
                    "Listen 192.0.2.10:8080", "Listen 198.51.100.5:8080"
                }),
            ):
                document["common"]["mgmt"]["http"]["address"] = address
                global_yaml.write_text(
                    yaml.safe_dump(document), encoding="utf-8"
                )
                settings = LOAD.apply_subnet_service_ips(
                    LOAD.load_global(global_yaml), subnet_file
                )
                self.assertEqual(("192.0.2.10",), settings.service_ips)
                with self.subTest(address=address, backend="native"):
                    native = LOAD.render_native_apache_listener_config(
                        getattr(settings, "http_listener_ips", settings.service_ips),
                        port=settings.http_port,
                    )
                    lines = [
                        line for line in native.splitlines()
                        if line.startswith("Listen ")
                    ]
                    self.assertEqual(expected, set(lines))
                    self.assertEqual(len(expected), len(lines))

                selected = SimpleNamespace(
                    endpoint_ips=("192.0.2.10",), listener_names=()
                )
                with mock.patch.object(
                    ACTIVATE, "build_runtime_plan",
                    return_value=(selected, links, addresses, RUNTIME),
                ), mock.patch.object(
                    ACTIVATE, "runtime_plan_payload", return_value={}
                ):
                    _selected, _runtime, _payload, docker = ACTIVATE.observe_runtime(
                        docker_settings
                    )
                with self.subTest(address=address, backend="docker"):
                    lines = [
                        line for line in docker.splitlines()
                        if line.startswith("Listen ")
                    ]
                    self.assertEqual(expected, set(lines))
                    self.assertEqual(len(expected), len(lines))
                    self.assertEqual(("192.0.2.10",), selected.endpoint_ips)

    def test_shared_endpoint_value_and_port_contract(self):
        endpoint = CONTRACT.validate_service_endpoint(
            "192.0.2.10", field="service endpoint"
        )
        self.assertIsInstance(endpoint, CONTRACT.ServiceEndpoint)
        self.assertEqual("192.0.2.10", endpoint.host)
        self.assertEqual(80, endpoint.port)
        self.assertEqual("Listen 192.0.2.10:80", endpoint.listen_directive)
        self.assertEqual("http://192.0.2.10", endpoint.origin)
        self.assertEqual(
            "http://192.0.2.10:8080",
            CONTRACT.validate_service_endpoint(
                "192.0.2.10", 8080, field="service endpoint"
            ).origin,
        )
        for value in (True, "80", 80.0, 0, 65536):
            with self.subTest(port=value):
                with self.assertRaises(ValueError):
                    CONTRACT.validate_service_endpoint(
                        "192.0.2.10", value, field="service endpoint"
                    )
        local_addresses = mock.Mock(
            return_value=("192.0.2.10", "192.0.2.10", "198.51.100.5")
        )
        self.assertEqual(
            endpoint,
            CONTRACT.validate_local_service_endpoint(
                "192.0.2.10",
                field="service endpoint",
                local_addresses=local_addresses,
            ),
        )
        local_addresses.assert_called_once_with()
        with self.assertRaisesRegex(ValueError, "assigned to this host"):
            CONTRACT.validate_local_service_endpoint(
                "192.0.2.11",
                field="service endpoint",
                local_addresses=lambda: ("192.0.2.10",),
            )
        unused_enumerator = mock.Mock(side_effect=AssertionError("must not run"))
        with self.assertRaises(ValueError):
            CONTRACT.validate_local_service_endpoint(
                "127.0.0.1",
                field="service endpoint",
                local_addresses=unused_enumerator,
            )
        unused_enumerator.assert_not_called()

    def test_shared_endpoint_rejects_every_strict_invalid_address_shape(self):
        for value in STRICT_INVALID_SERVICE_VALUES:
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    CONTRACT.validate_service_endpoint(
                        value, field="service endpoint"
                    )

    def test_native_listener_normalizer_returns_endpoint_carriers(self):
        endpoints = LOAD._canonical_apache_listener_addresses(("192.0.2.10",))
        self.assertEqual(1, len(endpoints))
        self.assertEqual("ServiceEndpoint", type(endpoints[0]).__name__)
        self.assertEqual("Listen 192.0.2.10:80", endpoints[0].listen_directive)

    def test_apache_listener_carriers_reject_every_non_service_address(self):
        for value in INVALID_SERVICE_ADDRESSES:
            with self.subTest(renderer="native", value=value):
                with self.assertRaises(LOAD.LoadError):
                    LOAD.render_native_apache_listener_config((value,))
            with self.subTest(renderer="container", value=value):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.render_apache_listener_config((value,))

    def test_subnet_service_ip_callers_share_the_rejection_boundary(self):
        for value in INVALID_SERVICE_ADDRESSES:
            row = {
                "ztp_service_ip": value,
                "cumulus_profile": "oob",
                "nvos_ztp": "no",
            }
            with self.subTest(caller="load", value=value):
                with self.assertRaises(LOAD.LoadError):
                    LOAD._parse_subnet_ztp_fields(row, 2)

            with tempfile.TemporaryDirectory() as temporary:
                csv_path = Path(temporary) / "02-dhcp-subnet_config.csv"
                csv_path.write_text(subnet_csv(value), encoding="utf-8")
                with self.subTest(caller="setup", value=value):
                    errors, _warnings = SETUP._validate_subnet_csv(csv_path)
                    self.assertTrue(
                        any("ztp_service_ip" in error for error in errors), errors
                    )
                with self.subTest(caller="dhcp", value=value):
                    with self.assertRaises(SystemExit):
                        DHCP.load_subnet_csv(csv_path, "/ztp")
                global_path = Path(temporary) / "01-global.yaml"
                global_path.write_text(
                    "common:\n  mgmt:\n    ztp:\n      ztp_url_prefix: /ztp\n",
                    encoding="utf-8",
                )
                with self.subTest(caller="manual", value=value):
                    with self.assertRaises(MANUAL.ManualZtpError):
                        MANUAL.provision_urls(csv_path, global_path)

    def test_subnet_service_ip_callers_preserve_valid_rendered_values(self):
        row = {
            "ztp_service_ip": "192.0.2.10",
            "cumulus_profile": "oob",
            "nvos_ztp": "no",
        }
        self.assertEqual(
            ("192.0.2.10", "oob", "no"),
            LOAD._parse_subnet_ztp_fields(row, 2),
        )
        with tempfile.TemporaryDirectory() as temporary:
            csv_path = Path(temporary) / "02-dhcp-subnet_config.csv"
            csv_path.write_text(subnet_csv("192.0.2.10"), encoding="utf-8")
            self.assertEqual(([], []), SETUP._validate_subnet_csv(csv_path))
            rows = DHCP.load_subnet_csv(csv_path, "/ztp")
            self.assertEqual(1, len(rows))
            self.assertEqual(
                {
                    "ztp_service_ip": "192.0.2.10",
                    "cumulus_profile": "oob",
                    "nvos_ztp": "no",
                    "cumulus_provision_url": (
                        "http://192.0.2.10/ztp/ztp-bootstrap_oob.sh"
                    ),
                    "bootfile_name": "",
                    "_network": ipaddress.IPv4Network("192.0.2.0/24"),
                },
                {
                    key: rows[0][key]
                    for key in (
                        "ztp_service_ip",
                        "cumulus_profile",
                        "nvos_ztp",
                        "cumulus_provision_url",
                        "bootfile_name",
                        "_network",
                    )
                },
            )
            global_path = Path(temporary) / "01-global.yaml"
            global_path.write_text(
                "common:\n  mgmt:\n    ztp:\n      ztp_url_prefix: /ztp\n",
                encoding="utf-8",
            )
            self.assertEqual(
                [(
                    ipaddress.IPv4Network("192.0.2.0/24"),
                    "http://192.0.2.10/ztp/ztp-bootstrap_oob.sh",
                )],
                MANUAL.provision_urls(csv_path, global_path),
            )

    def test_explicit_http_source_must_be_a_local_service_address(self):
        for value in INVALID_SERVICE_ADDRESSES:
            with self.subTest(value=value):
                with self.assertRaises(DEPLOY.DeployError):
                    DEPLOY.determine_http_source_ip([], explicit_ip=value)
        with mock.patch.object(
            DEPLOY, "_local_ipv4_addresses", return_value={"192.0.2.10"}
        ):
            self.assertEqual(
                "192.0.2.10",
                DEPLOY.determine_http_source_ip([], explicit_ip="192.0.2.10"),
            )
            with self.assertRaises(DEPLOY.DeployError):
                DEPLOY.determine_http_source_ip([], explicit_ip="192.0.2.11")

    def test_deploy_module_imports_shared_contract_from_arbitrary_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    (
                        "import runpy; "
                        f"runpy.run_path({str(ROOT / 'infra/deploy_infra.py')!r}, "
                        "run_name='service_endpoint_import_probe')"
                    ),
                ],
                cwd=temporary,
                text=True,
                capture_output=True,
            )
        self.assertEqual(0, result.returncode, result.stderr)

    def test_host_enumerators_apply_the_shared_service_boundary(self):
        result = SimpleNamespace(
            returncode=0,
            stdout=(
                "1: lo inet 127.0.0.1/8\n"
                "2: eth0 inet 169.254.23.8/16\n"
                "2: eth0 inet 192.0.2.10/24\n"
            ),
        )
        with mock.patch.object(LOAD.shutil, "which", side_effect=lambda name: name == "ip"):
            with mock.patch.object(LOAD, "_run_subprocess", return_value=result):
                self.assertEqual({"192.0.2.10"}, LOAD.local_ipv4_addresses())
        with mock.patch.object(DEPLOY.shutil, "which", return_value=True):
            with mock.patch.object(DEPLOY.subprocess, "run", return_value=result):
                self.assertEqual("192.0.2.10", DEPLOY._interface_ipv4("eth0"))

    def test_deploy_local_ipv4_enumerator_uses_ip_and_filters_other_families(self):
        result = SimpleNamespace(
            returncode=0,
            stdout=(
                "1: lo inet 127.0.0.1/8 scope host lo\n"
                "2: eth0 inet 169.254.23.8/16 scope link eth0\n"
                "2: eth0 inet 192.0.2.10/24 scope global eth0\n"
                "2: eth0 inet6 fe80::1%eth0/64 scope link\n"
            ),
        )
        with mock.patch.object(
            DEPLOY.shutil, "which", side_effect=lambda name: name == "ip"
        ):
            with mock.patch.object(
                DEPLOY.subprocess, "run", return_value=result
            ) as run:
                self.assertEqual(
                    {"192.0.2.10"}, DEPLOY._local_ipv4_addresses()
                )
        run.assert_called_once_with(
            ["ip", "-4", "-o", "addr", "show"],
            text=True,
            capture_output=True,
        )

    def test_deploy_local_ipv4_enumerator_falls_back_to_ifconfig(self):
        ip_failure = SimpleNamespace(returncode=1, stdout="")
        ifconfig_result = SimpleNamespace(
            returncode=0,
            stdout=(
                "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>\n"
                "\tinet 127.0.0.1 netmask 0xff000000\n"
                "en0: flags=8863<UP,BROADCAST,RUNNING,SIMPLEX,MULTICAST>\n"
                "\tinet6 fe80::1%en0 prefixlen 64 scopeid 0x4\n"
                "\tinet 198.51.100.10 netmask 0xffffff00 broadcast 198.51.100.255\n"
            ),
        )
        with mock.patch.object(DEPLOY.shutil, "which", return_value=True):
            with mock.patch.object(
                DEPLOY.subprocess,
                "run",
                side_effect=(ip_failure, ifconfig_result),
            ) as run:
                self.assertEqual(
                    {"198.51.100.10"}, DEPLOY._local_ipv4_addresses()
                )
        self.assertEqual(
            [
                mock.call(
                    ["ip", "-4", "-o", "addr", "show"],
                    text=True,
                    capture_output=True,
                ),
                mock.call(["ifconfig"], text=True, capture_output=True),
            ],
            run.call_args_list,
        )

    def test_deploy_local_ipv4_enumerator_returns_empty_on_no_usable_result(self):
        command_failure = SimpleNamespace(returncode=1, stdout="")
        invalid_only = SimpleNamespace(
            returncode=0,
            stdout=(
                "1: lo inet 127.0.0.1/8 scope host lo\n"
                "2: eth0 inet 169.254.23.8/16 scope link eth0\n"
                "2: eth0 inet6 fe80::1%eth0/64 scope link\n"
            ),
        )
        with self.subTest(result="commands fail"):
            with mock.patch.object(DEPLOY.shutil, "which", return_value=True):
                with mock.patch.object(
                    DEPLOY.subprocess,
                    "run",
                    side_effect=(command_failure, command_failure),
                ):
                    self.assertEqual(set(), DEPLOY._local_ipv4_addresses())
        with self.subTest(result="only unusable addresses"):
            with mock.patch.object(DEPLOY.shutil, "which", return_value=True):
                with mock.patch.object(
                    DEPLOY.subprocess,
                    "run",
                    side_effect=(invalid_only, invalid_only),
                ):
                    self.assertEqual(set(), DEPLOY._local_ipv4_addresses())
        with self.subTest(result="no enumerator installed"):
            with mock.patch.object(DEPLOY.shutil, "which", return_value=False):
                with mock.patch.object(DEPLOY.subprocess, "run") as run:
                    self.assertEqual(set(), DEPLOY._local_ipv4_addresses())
            run.assert_not_called()

    def test_accepted_rendering_bytes_remain_the_existing_contract(self):
        self.assertEqual(
            LOAD.render_native_apache_listener_config(("192.0.2.10",)),
            "# Generated by DAY0-Prepare/11-load.py; do not edit.\n"
            "# Exact service-IP listeners only; wildcard binds are forbidden.\n"
            "Listen 192.0.2.10:80\n\n"
            "<VirtualHost 192.0.2.10:80>\n"
            "    ServerName 192.0.2.10\n"
            "    DocumentRoot /var/www/html\n"
            "    ErrorLog /var/log/apache2/error.log\n"
            "    CustomLog /var/log/apache2/access.log combined\n"
            "</VirtualHost>\n",
        )
        self.assertEqual(
            ACTIVATE.render_apache_listener_config(("192.0.2.10",)),
            "# Generated by /opt/http-ztp/activate.py; do not edit.\n"
            "# Exact host-network listeners only; wildcard binds are forbidden.\n"
            "Listen 192.0.2.10:80\n\n"
            "<VirtualHost 192.0.2.10:80>\n"
            "    ServerName 192.0.2.10\n"
            "    DocumentRoot /var/www/html\n"
            "    ErrorLog /var/log/apache2/error.log\n"
            "    CustomLog /var/log/apache2/access.log combined\n"
            "</VirtualHost>\n",
        )


if __name__ == "__main__":
    unittest.main()
