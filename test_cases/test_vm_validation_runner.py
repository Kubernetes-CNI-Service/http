#!/usr/bin/env python3
"""Contracts for the read-only Ubuntu management-VM acceptance runner."""

from __future__ import annotations

import hashlib
import base64
import importlib.util
import ipaddress
import json
from datetime import datetime, timedelta
from pathlib import Path
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "test_cases/run_vm_validation.py"
SPEC = importlib.util.spec_from_file_location("vm_validation_runner", SCRIPT)
assert SPEC and SPEC.loader
VM = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VM
SPEC.loader.exec_module(VM)


def sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


class VmNetworkAcceptanceTests(unittest.TestCase):
    def test_one_nic_cannot_match_two_dhcp_shared_networks(self) -> None:
        subnets = (
            VM.DhcpSubnet(
                "direct-one", ipaddress.ip_network("192.0.2.0/25"),
                ipaddress.ip_address("192.0.2.100"),
            ),
            VM.DhcpSubnet(
                "relay-only", ipaddress.ip_network("198.51.100.0/25"),
                None,
            ),
            VM.DhcpSubnet(
                "direct-two", ipaddress.ip_network("203.0.113.0/25"),
                ipaddress.ip_address("203.0.113.100"),
            ),
        )
        collapsed = {
            "enp0s10": {
                ipaddress.ip_address("192.0.2.100"),
                ipaddress.ip_address("203.0.113.100"),
            },
        }
        self.assertEqual(
            {"enp0s10": ("direct-one", "direct-two")},
            VM.shared_network_conflicts(subnets, collapsed),
        )

        split = {
            "enp0s10": {ipaddress.ip_address("203.0.113.100")},
            "enp0s11": {ipaddress.ip_address("192.0.2.100")},
        }
        self.assertEqual({}, VM.shared_network_conflicts(subnets, split))
        self.assertEqual(
            {
                "192.0.2.100": ("enp0s11",),
                "203.0.113.100": ("enp0s10",),
            },
            VM.service_ip_assignments(subnets, split),
        )


class VmReleaseAcceptanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.project = self.root / "DAY0-Prepare/customer"
        self.project.mkdir(parents=True)
        self.payloads = {
            "global": ("01-global.yaml", b"schema_version: 2\n"),
            "devices": ("02-devices_config.csv", b"hostname,type\none,eth\n"),
            "subnet": (
                "02-dhcp-subnet_config.csv",
                b"shared_network,subnet,netmask,range_start,range_end,routers,"
                b"ztp_service_ip,cumulus_profile,nvos_ztp\n",
            ),
            "air_topology_policy": (
                "03-air-topology-policy.json", b'{"link_rewrites":[]}\n',
            ),
            "mini_air_devices": (
                "04-air-mini-devices.txt",
                b"[minimum-required]\nborder01\n[customer-provided]\n",
            ),
            "p2p": ("p2p.xlsx", b"synthetic-p2p"),
        }
        for _label, (name, payload) in self.payloads.items():
            (self.project / name).write_bytes(payload)
        self.parent = {
            "schema_version": 1,
            "release_id": "placeholder",
            "project": "customer",
            "validation": "passed",
            "inputs": {
                key: sha256(payload)
                for key, (_name, payload) in self.payloads.items()
            },
            "components": {},
            "inventory": [],
        }

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_parent_release_binds_every_current_project_input(self) -> None:
        self.assertEqual(
            [], VM.release_input_errors(self.project, self.parent),
        )
        (self.project / "02-devices_config.csv").write_bytes(b"changed\n")
        errors = VM.release_input_errors(self.project, self.parent)
        self.assertEqual(1, len(errors))
        self.assertIn("devices", errors[0])
        self.assertIn("SHA-256", errors[0])

    def test_release_id_is_recomputed_from_canonical_basis(self) -> None:
        basis = {
            key: self.parent[key]
            for key in ("project", "inputs", "components", "inventory")
        }
        expected = sha256(json.dumps(
            basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
        ).encode("utf-8"))[:20]
        self.parent["release_id"] = expected
        self.assertEqual([], VM.parent_release_errors(self.parent, "customer"))
        self.parent["release_id"] = "0" * 20
        self.assertIn(
            "canonical basis",
            "\n".join(VM.parent_release_errors(self.parent, "customer")),
        )

    def test_runtime_latest_pointers_match_parent_components(self) -> None:
        eth_release = self.project / "99-output-eth/release-eth"
        nvos_release = self.project / "99-output-ib_nvl/release-nvos"
        eth_release.mkdir(parents=True)
        nvos_release.mkdir(parents=True)
        (self.project / "99-output-eth/latest").symlink_to("release-eth")
        (self.project / "99-output-ib_nvl/latest").symlink_to("release-nvos")

        for relative, target in (
            ("ztp/config/cumulus/latest_yaml", eth_release),
            ("ztp/config/nvos/latest_yaml", nvos_release),
        ):
            pointer = self.root / relative
            pointer.parent.mkdir(parents=True)
            pointer.symlink_to(target)
        dhcp = self.project / "99-output-dhcp/dhcp-release-manifest.json"
        dhcp.parent.mkdir(parents=True)
        dhcp.write_text("{}\n", encoding="utf-8")
        dhcp_pointer = (
            self.root / "ztp/config/isc-dhcp-server/dhcp-release-manifest.json"
        )
        dhcp_pointer.parent.mkdir(parents=True)
        dhcp_pointer.symlink_to(dhcp)
        self.parent["components"] = {
            "cumulus": {"release_dir": "99-output-eth/release-eth"},
            "nvos": {"release_dir": "99-output-ib_nvl/release-nvos"},
            "dhcp": {},
        }

        self.assertEqual(
            [], VM.runtime_pointer_errors(self.root, self.project, self.parent),
        )
        (self.project / "99-output-eth/latest").unlink()
        (self.project / "99-output-eth/latest").symlink_to("../release-eth")
        self.assertIn(
            "cumulus project latest",
            "\n".join(
                VM.runtime_pointer_errors(self.root, self.project, self.parent)
            ),
        )


class VmDeviceCsvAcceptanceTests(unittest.TestCase):
    def test_repeated_schema_group_headers_are_valid_but_identity_is_unique(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "02-devices_config.csv"
            path.write_text(
                "hostname,type,eth0_ip,netmask,eth0_mac,eth1_ip,netmask,eth1_mac,"
                "vlan_id,svi_ip,netmask,vlan_ports,"
                "evpn_vrf,dhcp_relay,svi_ip,netmask,vlan_ports\n"
                "leaf01,eth,192.0.2.1,255.255.255.0,02:10:c0:00:02:01,,,,"
                "100,198.51.100.1,255.255.255.0,swp1,"
                "oob,bcm,203.0.113.1,255.255.255.0,bond1\n",
                encoding="utf-8",
            )
            errors, counts, fake_macs = VM.devices_csv_errors(path)
            self.assertEqual([], errors)
            self.assertEqual({"eth": 1}, counts)
            self.assertEqual(1, fake_macs)

            path.write_text(
                "hostname,type,hostname,eth0_mac,eth1_mac\n"
                "leaf01,eth,leaf01,02:10:c0:00:02:01,\n",
                encoding="utf-8",
            )
            errors, _counts, _fake_macs = VM.devices_csv_errors(path)
            self.assertIn("身份列必须且只能出现一次", "\n".join(errors))


class VmFullSystemdProfileTests(unittest.TestCase):
    def test_full_profile_enables_native_service_worker_and_active_http_checks(self) -> None:
        args = VM.parse_args([
            "customer", "--full-systemd", "--worker-scope", "prod",
            "--control-auth-user", "nvis",
        ])

        VM.apply_validation_profile(args)

        self.assertTrue(args.expect_services)
        self.assertTrue(args.expect_workers)
        self.assertTrue(args.check_http_content)
        self.assertTrue(args.check_source_syntax)
        self.assertEqual("prod", args.worker_scope)
        self.assertEqual("nvis", args.control_auth_user)

    def test_active_http_checks_require_an_explicit_control_user(self) -> None:
        args = VM.parse_args(["customer", "--check-http-content"])

        with self.assertRaisesRegex(ValueError, "--control-auth-user"):
            VM.apply_validation_profile(args)

    def test_legacy_air_flag_maps_to_scope_air(self) -> None:
        args = VM.parse_args(["customer", "--expect-workers", "--expect-air-workers"])

        VM.apply_validation_profile(args)

        self.assertEqual("air", args.worker_scope)

    def test_worker_commands_use_scope_pair_and_exact_project(self) -> None:
        root = Path("/var/www/html")
        project = root / "DAY0-Prepare/customer"
        commands = {
            "ztp-monitor": (
                "/usr/bin/python3 -u /var/www/html/DAY0-Prepare/12-ztp-monitor.py "
                "/var/www/html/DAY0-Prepare/customer --watch 30 --generate-html "
                "--collect-on-complete --known-hosts "
                "/var/www/html/ztp/status/ztp-known-hosts --scope prod"
            ),
            "switch-collection": (
                "/usr/bin/python3 -u /var/www/html/monitor/"
                "switch-collection-worker.py --scope prod"
            ),
            "manual-ztp": (
                "/usr/bin/python3 -u /var/www/html/monitor/"
                "manual-ztp-worker.py --scope prod"
            ),
        }
        for label, command in commands.items():
            with self.subTest(label=label):
                self.assertEqual(
                    [],
                    VM.worker_command_errors(
                        label, command, root=root, project=project,
                        expected_scope="prod",
                    ),
                )

        wrong_scope = commands["switch-collection"].replace(
            "--scope prod", "--scope air",
        )
        self.assertIn(
            "scope",
            "\n".join(VM.worker_command_errors(
                "switch-collection", wrong_scope, root=root, project=project,
                expected_scope="prod",
            )),
        )
        wrong_project = commands["ztp-monitor"].replace(
            "/DAY0-Prepare/customer", "/DAY0-Prepare/other",
        )
        self.assertIn(
            "project",
            "\n".join(VM.worker_command_errors(
                "ztp-monitor", wrong_project, root=root, project=project,
                expected_scope="prod",
            )),
        )

    def test_interfacesv4_parser_is_data_only_and_rejects_unsafe_names(self) -> None:
        self.assertEqual(
            ("enp0s10", "enp0s11"),
            VM.parse_interfacesv4(
                '# comment\nINTERFACESv4="enp0s10 enp0s11"\nINTERFACESv6=""\n'
            ),
        )
        self.assertEqual((), VM.parse_interfacesv4('INTERFACESv4=""\n'))
        with self.assertRaisesRegex(ValueError, "接口名"):
            VM.parse_interfacesv4('INTERFACESv4="enp0s10 --all"\n')
        with self.assertRaisesRegex(ValueError, "重复"):
            VM.parse_interfacesv4('INTERFACESv4="enp0s10 enp0s10"\n')

    def test_dhcp_runtime_accepts_automatic_or_validates_explicit_interfaces(self) -> None:
        assignments = {
            "192.0.2.100": ("enp0s10",),
            "198.51.100.100": ("enp0s11",),
        }
        self.assertEqual(
            [],
            VM.dhcp_runtime_interface_errors(
                (), assignments,
                "/usr/sbin/dhcpd -4 -f -cf /etc/dhcp/dhcpd.conf",
                {"enp0s10", "enp0s11", "enp0s8"},
            ),
        )
        command = (
            "/usr/sbin/dhcpd -4 -q -cf /etc/dhcp/dhcpd.conf "
            "enp0s10 enp0s11"
        )
        self.assertEqual(
            [],
            VM.dhcp_runtime_interface_errors(
                ("enp0s10", "enp0s11"), assignments, command,
                {"enp0s10", "enp0s11", "enp0s8"},
            ),
        )
        self.assertIn(
            "service_ip",
            "\n".join(VM.dhcp_runtime_interface_errors(
                ("enp0s10",), assignments, command, {"enp0s10", "enp0s11"},
            )),
        )
        self.assertIn(
            "cmdline",
            "\n".join(VM.dhcp_runtime_interface_errors(
                ("enp0s10", "enp0s11"), assignments,
                command.replace(" enp0s11", ""), {"enp0s10", "enp0s11"},
            )),
        )

    def test_ztp_prefix_is_read_from_schema_v2_without_importing_load(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "01-global.yaml"
            path.write_text(
                "schema_version: 2\n"
                "common:\n"
                "  mgmt:\n"
                "    ztp:\n"
                "      status: enabled\n"
                "      ztp_url_prefix: /factory/ztp\n",
                encoding="utf-8",
            )
            self.assertEqual("/factory/ztp", VM.read_ztp_prefix(path))
            path.write_text(
                "common:\n  mgmt:\n    ztp:\n"
                "      ztp_url_prefix: ../../escape\n",
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "ztp_url_prefix"):
                VM.read_ztp_prefix(path)

    def test_http_bootstrap_plan_preserves_relay_reference_to_direct_service(self) -> None:
        root = Path("/var/www/html")
        direct = ipaddress.ip_address("192.0.2.100")
        subnets = (
            VM.DhcpSubnet(
                "direct", ipaddress.ip_network("192.0.2.0/24"), direct,
                configured_service_ip=direct, cumulus_profile="oob",
                nvos_ztp=True,
            ),
            VM.DhcpSubnet(
                "relayed", ipaddress.ip_network("198.51.100.0/24"), None,
                configured_service_ip=direct, cumulus_profile="oob",
                nvos_ztp=True,
            ),
            VM.DhcpSubnet(
                "direct-two", ipaddress.ip_network("203.0.113.0/24"),
                ipaddress.ip_address("203.0.113.100"),
                configured_service_ip=ipaddress.ip_address("203.0.113.100"),
                cumulus_profile="oobofoob", nvos_ztp=False,
            ),
        )

        actual = VM.bootstrap_http_assets(root, subnets, "/ztp")

        self.assertEqual(
            {
                (
                    "192.0.2.100", "/ztp/ztp-bootstrap_oob.sh",
                    root / "ztp/ztp-bootstrap_oob.sh",
                ),
                ("192.0.2.100", "/ztp/ztp.json", root / "ztp/ztp.json"),
                (
                    "203.0.113.100", "/ztp/ztp-bootstrap_oobofoob.sh",
                    root / "ztp/ztp-bootstrap_oobofoob.sh",
                ),
            },
            {(item.address, item.url_path, item.source) for item in actual},
        )

    def test_release_http_samples_use_mac_entry_and_parent_bound_release(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "DAY0-Prepare/customer"
            release = project / "99-output-eth/release-1"
            release.mkdir(parents=True)
            config = release / "leaf01.yaml"
            config.write_text("hostname: leaf01\n", encoding="utf-8")
            link = release / "020000000001.yaml"
            link.symlink_to(config.name)
            manifest = {
                "devices": [{
                    "hostname": "leaf01", "config": config.name,
                    "macs": ["02:00:00:00:00:01"],
                }],
            }
            (release / "release-manifest.json").write_text(
                json.dumps(manifest) + "\n", encoding="utf-8",
            )
            parent = {
                "components": {
                    "cumulus": {"release_dir": "99-output-eth/release-1"},
                },
            }

            actual = VM.release_http_assets(
                root, project, parent, ("192.0.2.100",), "/ztp", samples=3,
            )

            self.assertEqual(1, len(actual))
            self.assertEqual("192.0.2.100", actual[0].address)
            self.assertEqual(
                "/ztp/config/cumulus/latest_yaml/020000000001.yaml",
                actual[0].url_path,
            )
            self.assertEqual(config.resolve(), actual[0].source)

    def test_http_asset_probe_compares_exact_body_without_proxy(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "ztp.json"
            source.write_bytes(b'{"url":"http://192.0.2.100/ztp"}\n')
            asset = VM.HttpAsset("192.0.2.100", "/ztp/ztp.json", source)
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Type", "application/json"),
            ]
            response.read.return_value = source.read_bytes()
            connection = mock.Mock()
            connection.getresponse.return_value = response

            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ) as constructor:
                detail = VM.verify_http_asset(asset, timeout=2.5)

            constructor.assert_called_once_with("192.0.2.100", 80, timeout=2.5)
            connection.request.assert_called_once_with(
                "GET", "/ztp/ztp.json",
                headers={
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Host": "192.0.2.100",
                    "User-Agent": "http-ztp-systemd-vm-validator/1",
                },
            )
            connection.close.assert_called_once_with()
            self.assertIn(f"bytes={source.stat().st_size}", detail)

            response.read.return_value = b"changed\n"
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                with self.assertRaisesRegex(ValueError, "内容 hash"):
                    VM.verify_http_asset(asset, timeout=2.5)

    def test_http_policy_probe_requires_exact_status(self) -> None:
        response = mock.Mock()
        response.status = 403
        response.getheaders.return_value = []
        response.read.return_value = b"Forbidden"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_http_status(
                "192.0.2.100", "/DAY0-Prepare/customer/01-global.yaml",
                expected=403, timeout=2.0,
            )
        self.assertIn("HTTP 403", detail)

        response.status = 404
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            with self.assertRaisesRegex(ValueError, "expected=403"):
                VM.verify_http_status(
                    "192.0.2.100", "/DAY0-Prepare/customer/01-global.yaml",
                    expected=403, timeout=2.0,
                )

    def test_http_head_probe_binds_content_length_without_reading_image(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            image = Path(temporary) / "switch.bin"
            image.write_bytes(b"firmware-bytes")
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Length", str(image.stat().st_size)),
            ]
            response.read.return_value = b""
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                detail = VM.verify_http_head(
                    "192.0.2.100", "/ztp/image/cumulus/switch.bin", image,
                    timeout=2.0,
                )
            self.assertIn(f"bytes={image.stat().st_size}", detail)
            connection.request.assert_called_once_with(
                "HEAD", "/ztp/image/cumulus/switch.bin",
                headers={
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "Host": "192.0.2.100",
                    "User-Agent": "http-ztp-systemd-vm-validator/1",
                },
            )

    def test_control_cgi_get_requires_live_worker_json(self) -> None:
        response = mock.Mock()
        response.status = 200
        response.getheaders.return_value = [
            ("Content-Type", "application/json; charset=utf-8"),
        ]
        response.read.return_value = json.dumps({
            "state": "idle", "process_alive": True,
        }).encode("utf-8")
        connection = mock.Mock()
        connection.getresponse.return_value = response
        authorization = "Basic " + base64.b64encode(
            b"nvis:operator-secret",
        ).decode("ascii")
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_control_cgi(
                "192.0.2.100", "ztp-monitor-control",
                url_path="/monitor/control/ztp-monitor",
                authorization=authorization, timeout=2.0,
            )
        self.assertIn("process_alive=true", detail)
        self.assertNotIn("operator-secret", detail)
        self.assertEqual(
            authorization,
            connection.request.call_args.kwargs["headers"]["Authorization"],
        )

        response.read.return_value = json.dumps({
            "state": "idle", "process_alive": False,
        }).encode("utf-8")
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            with self.assertRaisesRegex(ValueError, "process_alive"):
                VM.verify_control_cgi(
                    "192.0.2.100", "ztp-monitor-control",
                    url_path="/cgi-bin/ztp-monitor-control",
                    authorization=authorization, timeout=2.0,
                )

    def test_control_auth_prompts_once_and_challenges_before_credentials(self) -> None:
        password_reader = mock.Mock(return_value="one-use-secret")

        authorization = VM.read_control_authorization(
            "cumulus", password_reader=password_reader,
        )

        password_reader.assert_called_once_with(
            "Monitor control password for cumulus: ",
        )
        self.assertEqual(
            "Basic " + base64.b64encode(
                b"cumulus:one-use-secret",
            ).decode("ascii"),
            authorization,
        )
        self.assertNotIn("one-use-secret", repr(password_reader.call_args))

        response = mock.Mock()
        response.status = 401
        response.getheaders.return_value = [
            ("WWW-Authenticate", 'Basic realm="HTTP ZTP Monitor Control"'),
        ]
        response.read.return_value = b"Authorization Required"
        connection = mock.Mock()
        connection.getresponse.return_value = response
        with mock.patch.object(
            VM.http.client, "HTTPConnection", return_value=connection,
        ):
            detail = VM.verify_control_auth_challenge(
                "192.0.2.100", timeout=2.0,
            )

        self.assertIn("HTTP 401", detail)
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])

    def test_authenticated_monitor_and_both_control_routes_share_credentials(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            monitor = Path(temporary) / "monitor.html"
            monitor.write_bytes(b"<!doctype html><title>Monitor</title>\n")
            authorization = "Basic " + base64.b64encode(
                b"nvis:sentinel-password",
            ).decode("ascii")
            response = mock.Mock()
            response.status = 200
            response.getheaders.return_value = [
                ("Content-Type", "text/html; charset=utf-8"),
            ]
            response.read.return_value = monitor.read_bytes()
            connection = mock.Mock()
            connection.getresponse.return_value = response
            with mock.patch.object(
                VM.http.client, "HTTPConnection", return_value=connection,
            ):
                detail = VM.verify_http_asset(
                    VM.HttpAsset(
                        "192.0.2.100", "/monitor/monitor.html", monitor,
                    ),
                    timeout=2.0,
                    authorization=authorization,
                )
            self.assertNotIn("sentinel-password", detail)
            self.assertEqual(
                authorization,
                connection.request.call_args.kwargs["headers"]["Authorization"],
            )

        expected_routes = {
            "ztp-monitor-control": (
                "/monitor/control/ztp-monitor",
                "/cgi-bin/ztp-monitor-control",
            ),
            "switch-collection-control": (
                "/monitor/control/switch-collection",
                "/cgi-bin/switch-collection-control",
            ),
            "manual-ztp-control": (
                "/monitor/control/manual-ztp",
                "/cgi-bin/manual-ztp-control",
            ),
        }
        self.assertEqual(expected_routes, VM.CONTROL_CGI_ROUTES)

    def test_source_syntax_scan_is_read_only_and_reports_python_and_shell(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            good_python = tools / "good.py"
            good_python.write_text("value = 1\n", encoding="utf-8")
            empty_init = tools / "__init__.py"
            empty_init.write_bytes(b"")
            good_shell = tools / "good.sh"
            good_shell.write_text("#!/usr/bin/env bash\ntrue\n", encoding="utf-8")
            before = {
                path: (path.stat().st_mode, path.stat().st_mtime_ns, path.read_bytes())
                for path in (good_python, good_shell)
            }

            counts, errors = VM.source_syntax_errors(root)

            self.assertEqual({"python": 2, "shell": 1}, counts)
            self.assertEqual([], errors)
            for path, snapshot in before.items():
                self.assertEqual(snapshot, (
                    path.stat().st_mode, path.stat().st_mtime_ns,
                    path.read_bytes(),
                ))
            self.assertFalse(any(root.rglob("__pycache__")))

            (tools / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            (tools / "broken.sh").write_text("if then\n", encoding="utf-8")
            counts, errors = VM.source_syntax_errors(root)
            self.assertEqual({"python": 3, "shell": 2}, counts)
            self.assertIn("broken.py", "\n".join(errors))
            self.assertIn("broken.sh", "\n".join(errors))

    def test_apache_boundary_is_extracted_from_managed_heredoc(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary) / "infra-setup.sh"
            source.write_text(
                "before\n"
                "  cat <<'APACHE_PUBLIC_BOUNDARY_EOF'\n"
                "# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n"
                "<Directory \"/var/www/html\">\n"
                "    Options -Indexes\n"
                "</Directory>\n"
                "APACHE_PUBLIC_BOUNDARY_EOF\n"
                "after\n",
                encoding="utf-8",
            )

            payload = VM.expected_apache_boundary(source)

            self.assertEqual(
                b'# HTTP-ZTP-PUBLIC-BOUNDARY-V1\n'
                b'<Directory "/var/www/html">\n'
                b'    Options -Indexes\n'
                b'</Directory>\n',
                payload,
            )

    def test_installed_cgi_contract_requires_hash_and_executable_mode(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "root"
            cgi_root = Path(temporary) / "cgi-bin"
            source_dir = root / "monitor"
            source_dir.mkdir(parents=True)
            cgi_root.mkdir()
            for name in VM.CONTROL_CGI_NAMES:
                source = source_dir / f"{name}.cgi"
                destination = cgi_root / name
                source.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
                destination.write_bytes(source.read_bytes())
                destination.chmod(0o755)

            self.assertEqual([], VM.installed_cgi_errors(root, cgi_root))

            (cgi_root / VM.CONTROL_CGI_NAMES[0]).chmod(0o644)
            self.assertIn(
                "executable",
                "\n".join(VM.installed_cgi_errors(root, cgi_root)),
            )

    def test_monitor_report_must_be_current_project_scope_and_fresh(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "DAY0-Prepare/customer"
            project.mkdir(parents=True)
            snapshot = root / "ztp/status/20260906_120000"
            snapshot.mkdir(parents=True)
            latest = snapshot.parent / "latest"
            latest.symlink_to(snapshot.name)
            report = {
                "schema_version": 1,
                "project": "customer",
                "scope": "prod",
                "generated_at": datetime.now().astimezone().isoformat(
                    timespec="seconds"
                ),
                "devices": [{"hostname": "leaf01"}],
            }
            (snapshot / "report.json").write_text(
                json.dumps(report) + "\n", encoding="utf-8",
            )

            detail = VM.monitor_runtime_evidence(root, project, "prod")
            self.assertIn("devices=1", detail)

            report["generated_at"] = (
                datetime.now().astimezone() - timedelta(hours=2)
            ).isoformat(timespec="seconds")
            (snapshot / "report.json").write_text(
                json.dumps(report) + "\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "不新鲜"):
                VM.monitor_runtime_evidence(
                    root, project, "prod", max_age_seconds=1800,
                )

    def test_regular_source_scanner_does_not_follow_output_or_directory_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            tools = root / "tools"
            tools.mkdir()
            (tools / "ok.py").write_text("pass\n", encoding="utf-8")
            output = root / "DAY0-Prepare/customer/99-output-ztp"
            output.mkdir(parents=True)
            (output / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            outside = root / "outside"
            outside.mkdir()
            (outside / "broken.py").write_text("if True print('bad')\n", encoding="utf-8")
            (tools / "linked").symlink_to(outside, target_is_directory=True)

            counts, errors = VM.source_syntax_errors(root)

            self.assertEqual({"python": 1, "shell": 0}, counts)
            self.assertEqual([], errors)
            self.assertTrue(stat.S_ISLNK((tools / "linked").lstat().st_mode))


if __name__ == "__main__":
    unittest.main()
