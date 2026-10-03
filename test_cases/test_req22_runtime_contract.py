"""Independent REQ22 DHCP runtime input and mode expectations."""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = load_script("req22_runtime_contract", ROOT / "tools/ztp_service_runtime.py")
ACTIVATE = load_script("req22_activate_contract", ROOT / "infra/docker/activate.py")
LOAD = load_script("req22_load_contract", ROOT / "DAY0-Prepare/11-load.py")
DHCP = load_script(
    "req22_dhcp_generator_contract",
    ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py",
)
HEADER = (
    "shared_network,subnet,netmask,range_start,range_end,routers,"
    "ztp_service_ip,cumulus_profile,nvos_ztp\n"
)


class Req22RuntimeInputTests(unittest.TestCase):
    @staticmethod
    def _project(root: Path, *, dhcp: str, ztp: str) -> Path:
        project = root / "DAY0-Prepare" / "fixture"
        project.mkdir(parents=True)
        (project / "01-global.yaml").write_text(
            "common:\n  mgmt:\n"
            f"    dhcp-server:\n      status: {dhcp}\n"
            "    http:\n      status: enabled\n      address: 192.0.2.10\n"
            f"    ztp:\n      status: {ztp}\n",
            encoding="utf-8",
        )
        (project / "02-dhcp-subnet_config.csv").write_text(
            HEADER, encoding="utf-8",
        )
        return project

    def test_load_rejects_subnet_replacement_before_receipt_admission(self):
        for phase in ("after_validation", "during_source_hash"):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as directory:
                project = Path(directory)
                subnet = project / "02-dhcp-subnet_config.csv"
                subnet.write_text(HEADER, encoding="utf-8")
                replacement = project / "replacement.csv"
                replacement.write_text(
                    HEADER if phase == "during_source_hash"
                    else HEADER.replace("shared_network", "shared_networb"),
                    encoding="utf-8",
                )
                self.assertEqual(subnet.stat().st_size, replacement.stat().st_size)
                (project / "01-global.yaml").write_text("common: {}\n", encoding="utf-8")
                (project / "02-devices_config.csv").write_text("hostname,type\n", encoding="utf-8")
                p2p = project / "p2p.xlsx"
                p2p.write_bytes(b"read-only fixture\n")
                args = SimpleNamespace(
                    p2p_file=None, deployment_scope="all", switch_scope="all",
                    no_upgrade=True, mini=None, ssh_dir=None,
                )
                real_sha = LOAD._sha256_path
                swapped = False

                def swap():
                    nonlocal swapped
                    subnet.rename(project / "old.csv")
                    replacement.rename(subnet)
                    swapped = True

                def validate_then_swap(_path, _settings):
                    if phase == "after_validation":
                        swap()

                def hash_then_swap(path):
                    if phase == "during_source_hash" and Path(path) == subnet and not swapped:
                        swap()
                    return real_sha(path)

                with mock.patch.object(LOAD, "_load_global_document", return_value={}), \
                        mock.patch.object(
                            LOAD, "load_global", return_value=SimpleNamespace(schema_version="test"),
                        ), \
                        mock.patch.object(LOAD, "find_placeholder_password_sections", return_value=()), \
                        mock.patch.object(LOAD, "apply_subnet_service_ips", side_effect=lambda s, _: s), \
                        mock.patch.object(LOAD, "load_device_types", return_value=frozenset()), \
                        mock.patch.object(LOAD, "select_p2p", return_value=p2p), \
                        mock.patch.object(LOAD, "project_air_topology_policy", return_value=None), \
                        mock.patch.object(LOAD, "project_mini_air_devices", return_value=(None, None)), \
                        mock.patch.object(LOAD, "validate_subnet_file", side_effect=validate_then_swap), \
                        mock.patch.object(LOAD, "_sha256_path", side_effect=hash_then_swap), \
                        mock.patch.object(
                            LOAD, "validate_shared_artifact_receipts",
                            side_effect=AssertionError("receipt admission reached"),
                        ) as receipts:
                    with self.assertRaisesRegex(LOAD.LoadError, "subnet source changed"):
                        LOAD.validate_inputs(
                            project, args, allow_management_key_generation=False,
                            host_role="workstation",
                        )
                self.assertTrue(swapped)
                receipts.assert_not_called()

    def test_preserved_empty_host_count_rejects_rebound_leaf(self):
        for replacement_kind in ("symlink", "same-byte new inode"):
            with self.subTest(replacement=replacement_kind), \
                    tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                output = root / "dhcpd_ib.hosts"
                output.write_bytes(b"")
                detached = root / "detached.hosts"
                foreign = root / "foreign.hosts"
                foreign.write_bytes(b"")
                actual_lstat = os.lstat
                switched = False

                def rebind_after_checked_stat(path, *args, **kwargs):
                    nonlocal switched
                    metadata = actual_lstat(path, *args, **kwargs)
                    if os.fspath(path) == os.fspath(output) and not switched:
                        switched = True
                        output.rename(detached)
                        if replacement_kind == "symlink":
                            output.symlink_to(foreign)
                        else:
                            output.write_bytes(b"")
                    return metadata

                with mock.patch.object(
                    DHCP.os, "lstat", side_effect=rebind_after_checked_stat,
                ):
                    with self.assertRaises(OSError):
                        DHCP._count_preserved_host_declarations(output)
                self.assertTrue(switched)
                self.assertEqual(b"", detached.read_bytes())
                self.assertEqual(b"", foreign.read_bytes())

    def test_disabled_header_only_csv_produces_no_local_listeners(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            plan = RUNTIME.plan_dhcp_runtime(
                source, link_snapshot=[], address_snapshot=[],
                dhcp_enabled=False, ztp_enabled=False,
            )
            self.assertEqual((), plan.listener_names)
            self.assertEqual((), plan.endpoint_ips)

    def test_enabled_header_only_csv_is_not_a_runnable_dhcp_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER, encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "subnet row"):
                RUNTIME.plan_dhcp_runtime(
                    source, link_snapshot=[], address_snapshot=[],
                    dhcp_enabled=True, ztp_enabled=False,
                )

    def test_delimiter_only_record_is_not_a_blank_physical_line(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.write_text(HEADER + ",,,,,,,,\n", encoding="utf-8")
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "empty delimiter"):
                RUNTIME._read_dhcp_networks(source)

    def test_symlink_csv_cannot_supply_runtime_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.csv"
            target.write_text(HEADER, encoding="utf-8")
            source = Path(directory) / "02-dhcp-subnet_config.csv"
            source.symlink_to(target.name)
            with self.assertRaisesRegex(RUNTIME.RuntimeContractError, "non-symlink"):
                RUNTIME._read_dhcp_networks(source)

    def test_docker_reads_explicit_modes_from_current_global(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="disabled",
            )
            settings = SimpleNamespace(project_dir=project)
            self.assertEqual(
                (False, False), ACTIVATE.current_project_dhcp_ztp_modes(settings),
            )
            global_file = project / "01-global.yaml"
            global_file.write_text(
                global_file.read_text(encoding="utf-8").replace(
                    "ztp:\n      status: disabled", "ztp:\n      status: enabled",
                ), encoding="utf-8",
            )
            with self.assertRaisesRegex(ACTIVATE.ActivationError, "DHCP disabled.*ZTP enabled"):
                ACTIVATE.current_project_dhcp_ztp_modes(settings)

    def test_docker_and_runtime_share_disabled_header_only_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            project = self._project(
                Path(directory), dhcp="disabled", ztp="disabled",
            )
            settings = SimpleNamespace(
                project_dir=project,
                subnet_csv=project / "02-dhcp-subnet_config.csv",
                http_root=ROOT, allowlist=(), relay_ingress=(),
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=([], []),
                    ), mock.patch.object(
                        ACTIVATE, "_load_runtime_module", return_value=RUNTIME,
                    ), mock.patch.object(
                        RUNTIME, "plan_dhcp_runtime",
                        wraps=RUNTIME.plan_dhcp_runtime,
                    ) as planner:
                selected, _links, _addresses, runtime = ACTIVATE.build_runtime_plan(settings)
            self.assertIs(RUNTIME, runtime)
            self.assertEqual((), selected.listener_names)
            self.assertEqual((), selected.endpoint_ips)
            self.assertIs(False, planner.call_args.kwargs["dhcp_enabled"])
            self.assertIs(False, planner.call_args.kwargs["ztp_enabled"])

    def test_dhcp_exec_revalidation_carries_current_explicit_modes(self):
        tree = ast.parse(inspect.getsource(ACTIVATE.exec_managed_service))
        calls = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "revalidate_dhcp_runtime_plan"
        ]
        self.assertEqual(1, len(calls))
        keywords = {item.arg for item in calls[0].keywords}
        self.assertIn("dhcp_enabled", keywords)
        self.assertIn("ztp_enabled", keywords)

    def test_docker_observation_rejects_same_size_csv_replacement(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self._project(root, dhcp="disabled", ztp="disabled")
            source = project / "02-dhcp-subnet_config.csv"
            replacement = project / "replacement.csv"
            source.write_text(HEADER + " \n", encoding="utf-8")
            replacement.write_text(HEADER + "\t\n", encoding="utf-8")
            self.assertEqual(source.stat().st_size, replacement.stat().st_size)
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=root,
                state_root=root / "state", log_root=root / "log",
                apache_listeners=root / "apache.conf",
            )

            def replace_after_parse(*_args):
                source.rename(project / "old-subnet.csv")
                replacement.rename(source)
                selected = SimpleNamespace(endpoint_ips=())
                runtime = SimpleNamespace(
                    inspect_http_listener_owners=lambda *_args, **_kwargs: (
                        {"ifname": "eno7", "ifindex": 7,
                         "eligible": True, "reason": None},
                    ),
                )
                return selected, [], [], runtime

            with mock.patch.object(
                ACTIVATE, "build_runtime_plan", side_effect=replace_after_parse,
            ), mock.patch.object(
                ACTIVATE, "runtime_plan_payload", return_value={},
            ), mock.patch.object(ACTIVATE, "_atomic_write") as write:
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "subnet.*changed"):
                    ACTIVATE.observe_runtime(settings)
            write.assert_not_called()
            self.assertFalse(settings.state_root.exists())

    def test_parent_hash_accepts_only_receipt_proven_empty_host_file(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "dhcpd_ib.hosts"
            output.write_bytes(b"")
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.sha256_path(output)
            self.assertEqual(
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ACTIVATE.sha256_path(
                    output, allow_empty=True, expected_host_count=0,
                ),
            )
            output.write_text("host sw1 {\n}\n", encoding="utf-8")
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.sha256_path(
                    output, allow_empty=True, expected_host_count=0,
                )
            self.assertEqual(
                hashlib.sha256(b"host sw1 {\n}\n").hexdigest(),
                ACTIVATE.sha256_path(output, expected_host_count=1),
            )

    def test_docker_prepare_rejects_invalid_subnet_before_runtime_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self._project(root, dhcp="disabled", ztp="disabled")
            (project / "02-dhcp-subnet_config.csv").write_bytes(b"")
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", http_root=root,
                state_root=root / "state", log_root=root / "log",
                apache_listeners=root / "apache.conf",
            )
            with mock.patch.object(
                ACTIVATE, "ensure_runtime_directories",
            ) as mkdir, mock.patch.object(
                ACTIVATE, "_atomic_write",
            ) as write, mock.patch.object(
                ACTIVATE, "build_runtime_plan",
            ) as planner:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.prepare_runtime(settings)
            mkdir.assert_not_called()
            write.assert_not_called()
            planner.assert_not_called()

    def test_parent_release_accepts_only_counted_empty_unselected_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = self._project(root, dhcp="enabled", ztp="disabled")
            devices = project / "02-devices_config.csv"
            devices.write_text("hostname,type\nsw1,eth\n", encoding="utf-8")
            private = project / "99-output-dhcp"
            private.mkdir()
            public = root / "ztp/config/isc-dhcp-server"
            public.mkdir(parents=True)
            outputs = {}
            for name, body in (
                ("dhcpd.conf", b"subnet 192.0.2.0 netmask 255.255.255.0 {}\n"),
                ("dhcpd_eth.hosts", b"host sw1 {\n}\n"),
                ("dhcpd_ib.hosts", b""),
                ("dhcpd_nvl.hosts", b""),
            ):
                target = private / name
                target.write_bytes(body)
                (public / name).symlink_to(target)
                outputs[name] = {"sha256": hashlib.sha256(body).hexdigest()}
            child_path = private / "dhcp-release-manifest.json"
            child = {
                "release_id": "dhcp-child", "outputs": outputs,
                "counts": {"host_declarations_by_family": {
                    "eth": 1, "ib": 0, "nvl": 0,
                }},
            }
            child_path.write_text(json.dumps(child), encoding="utf-8")
            (public / child_path.name).symlink_to(os.path.relpath(child_path, public))
            parent_path = project / "99-output-ztp/current-release.json"
            parent_path.parent.mkdir()
            parent = {
                "schema_version": 2, "project": "fixture", "validation": "passed",
                "dhcp_status": "enabled", "deployment_scope": "prod",
                "switch_scope": "eth", "input_sources": {},
                "inventory": [{"hostname": "sw1", "type": "eth"}],
                "inputs": {
                    "global": hashlib.sha256(
                        (project / "01-global.yaml").read_bytes(),
                    ).hexdigest(),
                    "devices": hashlib.sha256(devices.read_bytes()).hexdigest(),
                    "subnet": hashlib.sha256(
                        (project / "02-dhcp-subnet_config.csv").read_bytes(),
                    ).hexdigest(),
                    "p2p": "0" * 64,
                },
                "components": {"dhcp": {
                    "release_id": "dhcp-child",
                    "manifest_sha256": hashlib.sha256(
                        child_path.read_bytes(),
                    ).hexdigest(),
                }},
            }

            def write_parent():
                keys = (
                    "project", "deployment_scope", "switch_scope", "inputs",
                    "input_sources", "components", "inventory", "dhcp_status",
                )
                basis = {key: parent[key] for key in keys}
                parent["release_id"] = hashlib.sha256(json.dumps(
                    basis, ensure_ascii=False, sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")).hexdigest()[:20]
                parent_path.write_text(json.dumps(parent), encoding="utf-8")

            write_parent()
            settings = ACTIVATE.Settings(
                project_name="fixture", scope="prod", switch_scope="eth",
                http_root=root,
            )
            with mock.patch.object(ACTIVATE, "validate_project_mount"), \
                    mock.patch.object(ACTIVATE, "_matching_p2p_input"):
                ACTIVATE.validate_parent_release(settings, parent_path)
                child["counts"]["host_declarations_by_family"]["eth"] = 0
                child_path.write_text(json.dumps(child), encoding="utf-8")
                parent["components"]["dhcp"]["manifest_sha256"] = (
                    hashlib.sha256(child_path.read_bytes()).hexdigest()
                )
                write_parent()
                with self.assertRaisesRegex(
                    ACTIVATE.ActivationError, "selected DHCP family",
                ):
                    ACTIVATE.validate_parent_release(settings, parent_path)

                for family in ("ib", "nvl"):
                    name = f"dhcpd_{family}.hosts"
                    body = f"host legacy-{family} {{\n}}\n".encode("ascii")
                    (private / name).write_bytes(body)
                    child["outputs"][name]["sha256"] = (
                        hashlib.sha256(body).hexdigest()
                    )
                child["counts"] = {"legacy_total": 3}
                child_path.write_text(json.dumps(child), encoding="utf-8")
                parent["components"]["dhcp"]["manifest_sha256"] = (
                    hashlib.sha256(child_path.read_bytes()).hexdigest()
                )
                write_parent()
                ACTIVATE.validate_parent_release(settings, parent_path)

    def test_native_dhcp_dry_run_accepts_receipt_proven_empty_hosts(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            bodies = {
                "dhcpd.conf": b'include "/etc/dhcp/dhcpd_eth.hosts";\n'
                b'include "/etc/dhcp/dhcpd_ib.hosts";\n'
                b'include "/etc/dhcp/dhcpd_nvl.hosts";\n',
                "dhcpd_eth.hosts": b"host sw1 {\n}\n",
                "dhcpd_ib.hosts": b"",
                "dhcpd_nvl.hosts": b"",
            }
            for name, body in bodies.items():
                (output / name).write_bytes(body)
            child = {
                "schema_version": 1, "release_id": "fixture-dhcp",
                "counts": {"host_declarations_by_family": {
                    "eth": 1, "ib": 0, "nvl": 0,
                }},
                "outputs": {
                    name: {"sha256": hashlib.sha256(body).hexdigest()}
                    for name, body in bodies.items()
                },
            }
            (output / "dhcp-release-manifest.json").write_text(
                json.dumps(child), encoding="utf-8",
            )
            mappings = {
                output / name: Path("/etc/dhcp") / name
                for name in bodies
            }
            with mock.patch.object(
                LOAD, "dhcp_file_mappings", return_value=mappings,
            ), mock.patch.object(LOAD, "run") as run:
                LOAD.mount_and_test_dhcp(dry_run=True)
            self.assertEqual(5, run.call_count)

    def test_parent_publication_checks_exact_host_counts(self):
        from test_cases import test_load_release_transaction as release_fixture

        fixture = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match",
        )
        fixture.setUp()
        try:
            output = fixture.ztp / "config/isc-dhcp-server"
            child_path = output / "dhcp-release-manifest.json"
            child = json.loads(child_path.read_text(encoding="utf-8"))
            for family, body in (
                ("eth", b"host leaf01 {\n}\n"),
                ("ib", b""),
                ("nvl", b""),
            ):
                name = f"dhcpd_{family}.hosts"
                (output / name).write_bytes(body)
                child["outputs"][name]["sha256"] = hashlib.sha256(body).hexdigest()
            child["counts"] = {"host_declarations_by_family": {
                "eth": 1, "ib": 0, "nvl": 0,
            }}
            child_path.write_text(json.dumps(child), encoding="utf-8")
            parent = release_fixture.LOAD.validate_and_publish_release(
                fixture.project, fixture.inputs,
            )
            self.assertEqual("passed", parent["validation"])
            current = fixture.project / "99-output-ztp/current-release.json"
            before = current.read_bytes()
            child["counts"]["host_declarations_by_family"]["ib"] = 1
            child_path.write_text(json.dumps(child), encoding="utf-8")
            with self.assertRaises(release_fixture.LOAD.LoadError):
                release_fixture.LOAD.validate_and_publish_release(
                    fixture.project, fixture.inputs,
                )
            self.assertEqual(before, current.read_bytes())
        finally:
            fixture.tearDown()

    def test_generator_candidate_option_targets_protected_sibling_before_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            public = root / "dhcpd.conf"
            public.write_bytes(b"accepted DHCP output\n")
            candidate = root / ".load-dhcp-contract"
            candidate.mkdir(mode=0o700)
            missing_subnet = root / "missing-subnet.csv"
            with mock.patch.object(sys, "argv", [
                "c1-generate_dhcp.py", "-y", "--candidate-output-dir",
                str(candidate),
            ]), mock.patch.object(DHCP, "OUTPUT_CONF", str(public)), \
                    mock.patch.object(DHCP, "SUBNET_CSV", str(missing_subnet)):
                with self.assertRaises(SystemExit) as caught:
                    DHCP.main()
                self.assertEqual(1, caught.exception.code)
                self.assertEqual(str(candidate / public.name), DHCP.OUTPUT_CONF)
            self.assertEqual(b"accepted DHCP output\n", public.read_bytes())
            self.assertEqual([], list(candidate.iterdir()))

    def test_deferred_dhcp_set_rolls_back_original_file_identities(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "DAY0-Prepare/fixture/99-output-dhcp"
            private.mkdir(parents=True)
            public = root / "ztp/config/isc-dhcp-server"
            public.mkdir(parents=True)
            names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
            )
            before = {}
            for name in names:
                target = private / name
                target.write_bytes(b"old:" + name.encode("ascii"))
                (public / name).symlink_to(target)
                before[name] = (target.stat().st_ino, target.read_bytes())
            candidate = LOAD.DeferredDHCPOutput.create(root / "ztp", "all")
            try:
                for name in names:
                    (candidate.stage / name).write_bytes(
                        b"new:" + name.encode("ascii"),
                    )
                candidate.publish()
                self.assertEqual(
                    b"new:dhcpd.conf", (private / "dhcpd.conf").read_bytes(),
                )
                candidate.rollback()
                self.assertEqual(
                    before,
                    {name: ((private / name).stat().st_ino,
                            (private / name).read_bytes()) for name in names},
                )
            finally:
                candidate.discard()
            self.assertFalse(candidate.stage.exists())

    def test_load_generator_keeps_c1_private_when_c2_rejects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            private = root / "DAY0-Prepare/fixture/99-output-dhcp"
            private.mkdir(parents=True)
            public = root / "ztp/config/isc-dhcp-server"
            public.mkdir(parents=True)
            names = (
                "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts",
                "dhcpd_nvl.hosts", "dhcp-release-manifest.json",
            )
            before = {}
            for name in names:
                target = private / name
                target.write_bytes(b"accepted:" + name.encode("ascii"))
                (public / name).symlink_to(target)
                before[name] = (target.stat().st_ino, target.read_bytes())
            reached = []

            def generator(command, **_kwargs):
                script = command[1]
                reached.append(script)
                if script == "c1-generate_dhcp.py":
                    self.assertIn("--candidate-output-dir", command)
                    candidate = Path(command[command.index("--candidate-output-dir") + 1])
                    for name in names:
                        (candidate / name).write_bytes(
                            b"candidate:" + name.encode("ascii"),
                        )
                if script == "90-c2-generate_configs.py":
                    raise LOAD.LoadError("controlled C2 rejection")

            with mock.patch.object(LOAD, "ZTP_DIR", root / "ztp"), \
                    mock.patch.object(LOAD, "run", side_effect=generator), \
                    mock.patch.object(
                        LOAD, "_device_types_after_dhcp",
                        return_value=frozenset({"eth"}),
                    ):
                with self.assertRaisesRegex(LOAD.LoadError, "controlled C2 rejection"):
                    LOAD.generate_configs(
                        frozenset({"eth"}), install_dhcp=False,
                        defer_dhcp_publication=True,
                    )
            self.assertEqual(
                ["b-xlsx_to_dot.py", "c1-generate_dhcp.py",
                 "90-c2-generate_configs.py"], reached,
            )
            self.assertEqual(
                before,
                {name: ((private / name).stat().st_ino,
                        (private / name).read_bytes()) for name in names},
            )
            self.assertEqual([], list(private.glob(".load-dhcp-*")))

    def test_load_main_defers_dhcp_until_parent_transaction(self):
        source = inspect.getsource(LOAD.main)
        prepare = source.index("_LOAD_DEFER_DHCP.set(")
        publish = source.index("deferred_dhcp_candidate.publish()")
        validate = source.index("parent_release = validate_and_publish_release(")
        rollback = source.index("deferred_dhcp_candidate.rollback()")
        accept = source.index("deferred_dhcp_candidate.accept_committed()")
        self.assertLess(prepare, publish)
        self.assertLess(publish, validate)
        self.assertLess(validate, rollback)
        self.assertLess(rollback, accept)


if __name__ == "__main__":
    unittest.main()
