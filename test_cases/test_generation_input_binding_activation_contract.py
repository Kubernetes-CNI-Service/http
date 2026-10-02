"""Direct contract for activation of a scoped DHCP child with empty families."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest import mock
import copy
from dataclasses import replace
from types import SimpleNamespace
import yaml

from test_cases.module_loader import load_script
from test_cases.test_manual_applied_config import dhcp_mode_release_fixture


ROOT = Path(__file__).resolve().parents[1]
ACTIVATE = load_script(
    "r22_empty_host_activation_contract", ROOT / "infra/docker/activate.py",
)
OUTPUTS = (
    "dhcpd.conf", "dhcpd_eth.hosts", "dhcpd_ib.hosts", "dhcpd_nvl.hosts",
)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _seal_parent(parent_path: Path, parent: dict, manifest: Path | None) -> None:
    """Keep the independent fixture's parent bound to its edited child."""
    if manifest is not None:
        parent["components"]["dhcp"]["manifest_sha256"] = _digest(manifest)
    basis_keys = (
        "project", "deployment_scope", "switch_scope", "inputs",
        "input_sources", "dhcp_status", "components", "inventory",
    )
    if "generated_inputs" in parent:
        basis_keys += ("generated_inputs",)
    basis = {name: parent[name] for name in basis_keys}
    parent["release_id"] = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]
    parent_path.write_text(json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8")


def _scoped_empty_fixture(root: Path, *, selected: str = "eth"):
    if selected not in {"eth", "ib", "nvl"}:
        raise ValueError(f"unsupported fixture scope: {selected}")
    project, parent_path, parent, public_manifest, dhcp_dir = (
        dhcp_mode_release_fixture(root, "enabled")
    )
    manifest_path = public_manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["switch_scope"] = selected
    manifest["counts"] = {
        "host_declarations_by_family": {
            family: int(family == selected) for family in ("eth", "ib", "nvl")
        },
    }
    for family in ("eth", "ib", "nvl"):
        if family != selected:
            (dhcp_dir / f"dhcpd_{family}.hosts").write_bytes(b"")
    if selected != "eth":
        parent["deployment_scope"] = "prod"
        parent["switch_scope"] = selected
        parent["inventory"][0]["type"] = selected
        original = project / "99-output-eth/release-a"
        nvos = project / "99-output-ib/release-a"
        nvos.parent.mkdir()
        shutil.copytree(original, nvos)
        component = parent["components"].pop("cumulus")
        component["release_dir"] = "99-output-ib/release-a"
        parent["components"]["nvos"] = component
        latest = root / "ztp/config/nvos/latest_yaml"
        latest.parent.mkdir(parents=True)
        latest.symlink_to(nvos)
    for name in OUTPUTS:
        manifest["outputs"][name]["sha256"] = _digest(dhcp_dir / name)
    manifest_path.write_text(json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8")
    _seal_parent(parent_path, parent, manifest_path)
    settings = ACTIVATE.Settings(
        http_root=root, project_name=project.name,
        scope="air" if selected == "eth" else "prod", switch_scope=selected,
    )
    return settings, parent_path, parent, manifest_path, manifest, dhcp_dir


def _redirect_empty_ib(directory: Path) -> None:
    unmanaged = directory.parent / "unmanaged-empty.hosts"
    unmanaged.write_bytes(b"")
    published = directory / "dhcpd_ib.hosts"
    published.unlink()
    published.symlink_to("../unmanaged-empty.hosts")


class ScopedEmptyHostActivationDirectTests(unittest.TestCase):
    def test_ib_and_nvl_selected_scopes_accept_only_other_empty_families(self):
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory(
                prefix=f"r22-empty-host-{selected}-",
            ) as name:
                settings, parent_path, _parent, _path, manifest, dhcp_dir = (
                    _scoped_empty_fixture(Path(name), selected=selected)
                )
                self.assertEqual(
                    {family: int(family == selected)
                     for family in ("eth", "ib", "nvl")},
                    manifest["counts"]["host_declarations_by_family"],
                )
                for family in ("eth", "ib", "nvl"):
                    size = (dhcp_dir / f"dhcpd_{family}.hosts").stat().st_size
                    self.assertEqual(family == selected, size > 0)
                identity = ACTIVATE.validate_parent_release(settings, parent_path)
                self.assertEqual(_digest(parent_path), identity["parent_release_sha256"])

    def test_ib_and_nvl_selected_empty_hosts_are_rejected_even_with_zero_count(self):
        for selected in ("ib", "nvl"):
            with self.subTest(selected=selected), tempfile.TemporaryDirectory(
                prefix=f"r22-selected-empty-{selected}-",
            ) as name:
                settings, parent_path, parent, manifest_path, manifest, dhcp_dir = (
                    _scoped_empty_fixture(Path(name), selected=selected)
                )
                selected_path = dhcp_dir / f"dhcpd_{selected}.hosts"
                selected_path.write_bytes(b"")
                manifest["counts"]["host_declarations_by_family"][selected] = 0
                manifest["outputs"][selected_path.name]["sha256"] = _digest(selected_path)
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8",
                )
                _seal_parent(parent_path, parent, manifest_path)
                with self.assertRaisesRegex(
                    ACTIVATE.ActivationError, "selected or declared family",
                ):
                    ACTIVATE.validate_parent_release(settings, parent_path)

    def test_empty_host_rejects_project_ancestor_rebinding_after_path_check(self):
        with tempfile.TemporaryDirectory(prefix="r22-empty-host-ancestor-") as name:
            root = Path(name)
            settings, parent_path, _parent, _manifest_path, _manifest, dhcp_dir = (
                _scoped_empty_fixture(root)
            )
            project = root / "DAY0-Prepare" / settings.project_name
            canonical = project / "99-output-dhcp/dhcpd_ib.hosts"
            canonical.write_bytes(b"")
            public = dhcp_dir / "dhcpd_ib.hosts"
            public.unlink()
            public.symlink_to(os.path.relpath(canonical, dhcp_dir))
            outside = root / "outside-project-copy"
            shutil.copytree(project, outside, symlinks=True)
            displaced = root / "displaced-original-project"
            original = ACTIVATE._canonical_regular_within
            canonical_checks = []

            def rebind_project_after_check(path, authority, label):
                result = original(path, authority, label)
                if path == canonical and label.endswith("dhcpd_ib.hosts"):
                    canonical_checks.append(True)
                    if len(canonical_checks) == 2:
                        project.rename(displaced)
                        project.symlink_to(outside, target_is_directory=True)
                return result

            with mock.patch.object(
                ACTIVATE, "_canonical_regular_within",
                side_effect=rebind_project_after_check,
            ):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_parent_release(settings, parent_path)
            self.assertEqual([True, True], canonical_checks)


def _versioned_fixture(
    root: Path, *, mode: str = "enabled", generated_authority: bool = False,
    runtime_endpoint: bool = False,
):
    """Independently seal two complete generations; never derive expected bytes from reader."""
    if mode == "enabled":
        settings, parent_path, parent, _manifest_path, manifest, dhcp_dir = (
            _scoped_empty_fixture(root)
        )
    else:
        project, parent_path, parent, public, dhcp_dir = (
            dhcp_mode_release_fixture(root, mode)
        )
        settings = ACTIVATE.Settings(
            http_root=root, project_name=project.name, scope="air", switch_scope="eth",
        )
        manifest = json.loads(public.resolve(strict=True).read_text(encoding="utf-8"))
        global_path = project / "01-global.yaml"
        global_data = yaml.safe_load(global_path.read_text(encoding="utf-8"))
        global_data["common"]["mgmt"]["ztp"]["status"] = "disabled"
        global_data["common"]["mgmt"]["http"]["address"] = "192.0.2.50"
        global_path.write_text(yaml.safe_dump(global_data, sort_keys=True), encoding="utf-8")
        subnet = project / "02-dhcp-subnet_config.csv"
        subnet.write_text(subnet.read_text(encoding="utf-8").splitlines()[0] + "\n",
                          encoding="utf-8")
        parent["inputs"]["global"] = _digest(global_path)
        parent["inputs"]["subnet"] = _digest(subnet)
    if runtime_endpoint:
        subnet = settings.project_dir / "02-dhcp-subnet_config.csv"
        original = subnet.read_text(encoding="utf-8")
        assert ",,none,no\n" in original
        subnet.write_text(
            original.replace(",,none,no\n", ",192.0.2.50,oob,no\n"),
            encoding="utf-8",
        )
        parent["inputs"]["subnet"] = _digest(subnet)
    if generated_authority:
        private = settings.project_dir / ".load-inventory-independent"
        private.mkdir(mode=0o700)
        derived = private / "02-devices_config.csv"
        derived.write_bytes(b"hostname,type\nleaf01,eth\n")
        derived.chmod(0o600)
        parent["generated_inputs"] = {"effective_devices": {
            "path": f"{private.name}/{derived.name}",
            "sha256": _digest(derived),
        }}
    output_root = settings.project_dir / "99-output-ztp"
    generations = output_root / "generations"
    generations.mkdir(parents=True)

    def make_generation(label: str, *, new_conf: bool):
        staging = generations / f".staging-{label}"
        staging.mkdir(mode=0o700)
        dhcp = staging / "dhcp"
        if mode == "enabled":
            dhcp.mkdir(mode=0o700)
        frozen_inputs = staging / "inputs"
        frozen_inputs.mkdir(mode=0o700)
        child_path = None
        if mode == "enabled":
            for name in OUTPUTS:
                shutil.copy2(dhcp_dir / name, dhcp / name)
            child = copy.deepcopy(manifest)
            if new_conf:
                (dhcp / "dhcpd.conf").write_bytes(b"independent-generation-B-config\n")
                child["outputs"]["dhcpd.conf"]["sha256"] = _digest(dhcp / "dhcpd.conf")
            child_path = dhcp / "dhcp-release-manifest.json"
            child_path.write_text(json.dumps(child, sort_keys=True) + "\n", encoding="utf-8")
        sealed = copy.deepcopy(parent)
        if new_conf:
            yaml_a = settings.project_dir / "99-output-eth/release-a"
            yaml_b = settings.project_dir / "99-output-eth/release-b"
            shutil.copytree(yaml_a, yaml_b)
            (yaml_b / "leaf01.yaml").write_bytes(b"hostname: leaf01\ngeneration: B\n")
            child_yaml = yaml_b / "release-manifest.json"
            yaml_receipt = json.loads(child_yaml.read_text(encoding="utf-8"))
            yaml_receipt["devices"][0]["config_sha256"] = _digest(
                yaml_b / "leaf01.yaml"
            )
            child_yaml.write_text(
                json.dumps(yaml_receipt, sort_keys=True) + "\n", encoding="utf-8",
            )
            sealed["components"]["cumulus"]["release_dir"] = (
                "99-output-eth/release-b"
            )
            sealed["components"]["cumulus"]["manifest_sha256"] = _digest(child_yaml)
        version_parent = staging / "current-release.json"
        _seal_parent(version_parent, sealed, child_path)
        source_paths = {
            "global": "01-global.yaml",
            "devices": "02-devices_config.csv",
            "subnet": "02-dhcp-subnet_config.csv",
            "p2p": sealed["input_sources"]["p2p"]["path"],
        }
        for key in sealed["inputs"]:
            (frozen_inputs / key).write_bytes(
                (settings.project_dir / source_paths[key]).read_bytes()
            )
        if "generated_inputs" in sealed:
            (frozen_inputs / "effective_devices").write_bytes(
                (settings.project_dir /
                 sealed["generated_inputs"]["effective_devices"]["path"]).read_bytes()
            )
        release_id = sealed["release_id"]
        staging.rename(generations / release_id)
        return release_id

    a = make_generation("a", new_conf=False)
    b = make_generation("b", new_conf=True) if mode == "enabled" else a
    if mode == "enabled" and a == b:
        raise AssertionError("independent A/B receipt fixtures must differ")
    selector = output_root / "current"
    selector.symlink_to(f"generations/{a}")
    return settings, selector, generations, a, b


def _select_generation(selector: Path, release_id: str) -> None:
    replacement = selector.with_name("current.next")
    replacement.symlink_to(f"generations/{release_id}")
    replacement.replace(selector)


class PinnedGenerationActivationDirectTests(unittest.TestCase):
    def _pinned_network_snapshot(self):
        links = [{
            "ifindex": 4, "ifname": "eth0",
            "flags": ["BROADCAST", "MULTICAST", "UP", "LOWER_UP"],
            "address": "02:00:00:00:00:04", "operstate": "UP",
            "link_type": "ether",
        }]
        addresses = [{
            "ifindex": 4, "ifname": "eth0",
            "addr_info": [{
                "family": "inet", "local": "192.0.2.50", "prefixlen": 24,
                "scope": "global", "flags": [],
                "valid_life_time": "forever", "preferred_life_time": "forever",
            }],
        }]
        return links, addresses

    def test_observe_pinned_runtime_plans_from_a_without_flat_b_or_state_writes(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-observe-a-") as name:
            root = Path(name)
            settings, selector, generations, a, _b = _versioned_fixture(
                root, runtime_endpoint=True,
            )
            settings = replace(
                settings, state_root=root / "state", apache_listeners=root / "listeners",
            )
            source = (generations / a / "inputs/subnet").read_bytes()
            (settings.project_dir / "02-dhcp-subnet_config.csv").write_bytes(b"B invalid subnet\n")
            flat_global = settings.project_dir / "01-global.yaml"
            changed = yaml.safe_load(flat_global.read_text(encoding="utf-8"))
            changed["common"]["mgmt"]["dhcp-server"]["status"] = "disabled"
            changed["common"]["mgmt"]["ztp"]["status"] = "disabled"
            flat_global.write_text(yaml.safe_dump(changed), encoding="utf-8")
            runtime = load_script(
                "r22_pinned_observe_runtime", ROOT / "tools/ztp_service_runtime.py",
            )
            real_plan = runtime.plan_dhcp_runtime
            observed_paths = []

            def capture_subnet(path, **options):
                temporary = Path(path)
                observed_paths.append(temporary)
                self.assertEqual(source, temporary.read_bytes())
                self.assertEqual(0o600, temporary.stat().st_mode & 0o777)
                self.assertEqual(0o700, temporary.parent.stat().st_mode & 0o777)
                self.assertEqual((True, True), (
                    options["dhcp_enabled"], options["ztp_enabled"],
                ))
                return real_plan(path, **options)

            with mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=runtime), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=self._pinned_network_snapshot(),
                    ), mock.patch.object(runtime, "plan_dhcp_runtime", side_effect=capture_subnet):
                selected, _runtime, payload, apache = ACTIVATE.observe_pinned_runtime(
                    settings, selector, expected_release_id=a,
                )
            self.assertEqual(1, len(observed_paths))
            self.assertFalse(observed_paths[0].exists())
            self.assertEqual(a, payload["selected_generation_release_id"])
            self.assertEqual(_digest(generations / a / "inputs/subnet"),
                             payload["subnet_sha256"])
            self.assertEqual(str(generations / a / "inputs/subnet"),
                             payload["subnet_csv"])
            self.assertEqual(tuple(selected.endpoint_ips), tuple(payload["endpoint_ips"]))
            self.assertIn("Listen", apache)
            self.assertFalse(settings.state_root.exists())
            self.assertFalse(settings.apache_listeners.exists())

    def test_observe_pinned_runtime_cleans_temporary_source_on_planner_failure(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-observe-fail-") as name:
            root = Path(name)
            settings, selector, _generations, a, _b = _versioned_fixture(root)
            settings = replace(settings, state_root=root / "state")
            observed_paths = []
            runtime = SimpleNamespace()

            def fail_plan(path, **_options):
                observed_paths.append(Path(path))
                raise ValueError("independent planner refusal")

            runtime.plan_dhcp_runtime = fail_plan
            with mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=runtime), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=self._pinned_network_snapshot(),
                    ):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.observe_pinned_runtime(
                        settings, selector, expected_release_id=a,
                    )
            self.assertEqual(1, len(observed_paths))
            self.assertFalse(observed_paths[0].exists())
            self.assertFalse(settings.state_root.exists())

    def test_frozen_policy_keeps_legacy_http_80_when_whole_section_is_absent(self):
        global_source = (
            b"common:\n  mgmt:\n    dhcp-server: {status: enabled}\n"
            b"    ztp: {status: enabled}\n"
        )
        policy = ACTIVATE._frozen_generation_policy(global_source)
        self.assertEqual((True, True), policy["service_modes"])
        self.assertEqual((80, None, True), policy["http"])
        with self.assertRaises(ACTIVATE.ActivationError):
            ACTIVATE._frozen_generation_policy(
                global_source + b"    http: {status: maybe}\n",
            )

    def test_pinned_source_view_keeps_a_policy_and_bytes_when_flat_inputs_become_b(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-source-a-") as name:
            settings, selector, generations, a, _b = _versioned_fixture(Path(name))
            original = (settings.project_dir / "01-global.yaml").read_bytes()
            flat_global = settings.project_dir / "01-global.yaml"
            changed = yaml.safe_load(original)
            changed["common"]["mgmt"]["dhcp-server"]["status"] = "disabled"
            changed["common"]["mgmt"]["ztp"]["status"] = "disabled"
            changed["common"]["mgmt"]["http"]["status"] = "disabled"
            flat_global.write_text(yaml.safe_dump(changed), encoding="utf-8")
            self.assertEqual((False, False), ACTIVATE._project_service_modes(settings))

            pinned = ACTIVATE.validate_pinned_generation(
                settings, selector, expected_release_id=a,
            )
            sources = pinned["frozen_source_bytes"]
            policy = pinned["frozen_policy"]
            self.assertEqual(a, pinned["release_id"])
            self.assertEqual(original, sources["global"])
            self.assertEqual(
                (generations / a / "inputs/subnet").read_bytes(), sources["subnet"],
            )
            self.assertEqual((True, True), policy["service_modes"])
            self.assertEqual((80, None, True), policy["http"])
            with self.assertRaises(TypeError):
                sources["global"] = flat_global.read_bytes()
            with self.assertRaises(TypeError):
                policy["service_modes"] = (False, False)

    def test_pinned_source_view_switch_during_read_remains_a_and_corruption_blocks(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-source-switch-") as name:
            settings, selector, generations, a, b = _versioned_fixture(Path(name))
            original = ACTIVATE._read_pinned_generation_file
            a_global = (generations / a / "inputs/global").read_bytes()
            switched = []

            def switch_after_parent(*args, **kwargs):
                payload = original(*args, **kwargs)
                if args[1] == "current-release.json" and not switched:
                    _select_generation(selector, b)
                    switched.append(True)
                return payload

            with mock.patch.object(
                ACTIVATE, "_read_pinned_generation_file", side_effect=switch_after_parent,
            ):
                pinned = ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=a,
                )
            self.assertEqual([True], switched)
            self.assertEqual(a_global, pinned["frozen_source_bytes"]["global"])
            self.assertEqual(b, ACTIVATE.validate_pinned_generation(
                settings, selector,
            )["release_id"])
            _select_generation(selector, a)
            (generations / a / "inputs/global").write_bytes(b"corrupt-old-a\n")
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=a,
                )

    def _marker_fixture(self, root: Path):
        settings, selector, generations, a, b = _versioned_fixture(root)
        settings = replace(
            settings,
            dhcp_config=settings.http_root / "ztp/config/isc-dhcp-server/dhcpd.conf",
        )
        selected = SimpleNamespace(
            endpoint_ips=("192.0.2.1",), listener_names=("eth0",),
        )
        return settings, selector, generations, a, b, selected

    def _marker_publication_patches(self, settings, a, *, after_runtime=None):
        parent = json.loads((settings.project_dir / "99-output-ztp/generations"
                             / a / "current-release.json").read_text(encoding="utf-8"))
        p2p = ACTIVATE.PUBLISHED_P2P_INPUT_LINK.as_posix()
        def runtime_identity(_settings):
            if after_runtime is not None:
                after_runtime()
            return {}
        return (
            mock.patch.object(ACTIVATE, "published_link_identity", return_value={
                p2p: {"sha256": parent["inputs"]["p2p"]},
            }),
            mock.patch.object(ACTIVATE, "published_runtime_identity",
                              side_effect=runtime_identity),
            mock.patch.object(ACTIVATE, "validate_image_source_contract",
                              return_value=[]),
        )

    def test_explicit_a_marker_rejects_b_flat_runtime_and_publication(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-mixed-") as name:
            settings, selector, generations, a, b, selected = self._marker_fixture(
                Path(name),
            )
            project = settings.project_dir
            flat_parent = project / "99-output-ztp/current-release.json"
            flat_parent.write_bytes((generations / b / "current-release.json").read_bytes())
            flat_dhcp = settings.dhcp_config.parent
            for output in (*OUTPUTS, "dhcp-release-manifest.json"):
                (flat_dhcp / output).write_bytes(
                    (generations / b / "dhcp" / output).read_bytes()
                )
            latest = settings.http_root / "ztp/config/cumulus/latest_yaml"
            latest.unlink()
            latest.symlink_to(project / "99-output-eth/release-b")
            self.assertEqual(a, ACTIVATE.validate_pinned_generation(
                settings, selector, expected_release_id=a,
            )["release_id"])
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        selector_path=selector, expected_release_id=a,
                    )

    def test_explicit_a_marker_accepts_only_matching_flat_a(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-a-") as name:
            settings, selector, _generations, a, _b, selected = (
                self._marker_fixture(Path(name))
            )
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                marker = ACTIVATE.build_activation_marker(
                    settings, selected,
                    selector_path=selector, expected_release_id=a,
                )
                valid, reason = ACTIVATE.validate_activation_marker(
                    marker, settings, selected,
                    selector_path=selector, expected_release_id=a,
                )
                self.assertTrue(valid, reason)
                legacy_valid, _reason = ACTIVATE.validate_activation_marker(
                    marker, settings, selected,
                )
                self.assertFalse(legacy_valid)
            self.assertEqual(a, marker["selected_generation_release_id"])
            self.assertEqual("pinned-flat-match", marker["generation_authority"])
            self.assertEqual(
                _digest(settings.project_dir / "99-output-ztp/generations"
                        / a / "current-release.json"),
                marker["parent_release_sha256"],
            )

    def test_default_marker_cannot_ignore_an_existing_generation_selector(self):
        with tempfile.TemporaryDirectory(prefix="r22-default-marker-selector-") as name:
            settings, _selector, _generations, a, _b, selected = (
                self._marker_fixture(Path(name))
            )
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaisesRegex(
                    ACTIVATE.ActivationError, "selector|generation",
                ):
                    ACTIVATE.build_activation_marker(settings, selected)

    def test_default_runtime_prepare_cannot_overwrite_a_with_flat_b_under_selector(self):
        with tempfile.TemporaryDirectory(prefix="r22-default-runtime-selector-") as name:
            settings, _selector, _generations, _a, _b, selected = (
                self._marker_fixture(Path(name))
            )
            with mock.patch.object(
                ACTIVATE, "project_http_policy", return_value=(80, None, True),
            ), mock.patch.object(
                ACTIVATE, "observe_runtime",
                return_value=(selected, object(), {}, "apache config\n"),
            ), mock.patch.object(
                ACTIVATE, "ensure_runtime_directories",
            ) as directories, mock.patch.object(
                ACTIVATE, "_atomic_write",
            ) as write:
                with self.assertRaisesRegex(
                    ACTIVATE.ActivationError, "selector|generation",
                ):
                    ACTIVATE.prepare_runtime(settings)
            directories.assert_not_called()
            write.assert_not_called()

    def test_explicit_a_marker_rejects_public_yaml_b_with_flat_a(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-yaml-") as name:
            settings, selector, _generations, a, _b, selected = (
                self._marker_fixture(Path(name))
            )
            latest = settings.http_root / "ztp/config/cumulus/latest_yaml"
            latest.unlink()
            latest.symlink_to(settings.project_dir / "99-output-eth/release-b")
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        selector_path=selector, expected_release_id=a,
                    )

    def test_explicit_a_marker_rejects_b_runtime_dhcp_even_with_flat_a(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-dhcp-") as name:
            settings, selector, generations, a, b, selected = (
                self._marker_fixture(Path(name))
            )
            installed = settings.project_dir / "installed-dhcp"
            shutil.copytree(settings.dhcp_config.parent, installed)
            (installed / "dhcpd.conf").write_bytes(
                (generations / b / "dhcp/dhcpd.conf").read_bytes()
            )
            settings = replace(settings, dhcp_config=installed / "dhcpd.conf")
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        selector_path=selector, expected_release_id=a,
                    )

    def test_explicit_a_marker_cannot_override_b_flat_parent_with_a_snapshot(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-override-") as name:
            settings, selector, generations, a, b, selected = (
                self._marker_fixture(Path(name))
            )
            settings.release_manifest.write_bytes(
                (generations / b / "current-release.json").read_bytes()
            )
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        release_manifest=generations / a / "current-release.json",
                        selector_path=selector, expected_release_id=a,
                    )

    def test_explicit_a_marker_rejects_selector_switch_during_build(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-switch-") as name:
            settings, selector, _generations, a, b, selected = (
                self._marker_fixture(Path(name))
            )
            patches = self._marker_publication_patches(
                settings, a, after_runtime=lambda: _select_generation(selector, b),
            )
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        selector_path=selector, expected_release_id=a,
                    )

    def test_explicit_a_marker_rejects_wrong_expected_release_and_later_switch(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-marker-expected-") as name:
            settings, selector, _generations, a, b, selected = (
                self._marker_fixture(Path(name))
            )
            patches = self._marker_publication_patches(settings, a)
            with patches[0], patches[1], patches[2]:
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.build_activation_marker(
                        settings, selected,
                        selector_path=selector, expected_release_id=b,
                    )
                marker = ACTIVATE.build_activation_marker(
                    settings, selected,
                    selector_path=selector, expected_release_id=a,
                )
                _select_generation(selector, b)
                valid, _reason = ACTIVATE.validate_activation_marker(
                    marker, settings, selected,
                    selector_path=selector, expected_release_id=a,
                )
                self.assertFalse(valid)

    def test_selected_generation_and_explicit_rollback_are_distinct_from_b_success(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-rollback-") as name:
            settings, selector, generations, a, b = _versioned_fixture(Path(name))
            selected_a = ACTIVATE.validate_pinned_generation(
                settings, selector, expected_release_id=a,
            )
            self.assertEqual(a, selected_a["release_id"])
            self.assertEqual(
                _digest(generations / a / "current-release.json"),
                selected_a["parent_release_sha256"],
            )
            parent_a = json.loads(
                (generations / a / "current-release.json").read_text(encoding="utf-8")
            )
            self.assertEqual(
                {
                    key: {
                        "release_id": value["release_id"],
                        "manifest_sha256": value["manifest_sha256"],
                    }
                    for key, value in parent_a["components"].items()
                },
                selected_a["parent_components"],
            )
            _select_generation(selector, b)
            selected_b = ACTIVATE.validate_pinned_generation(
                settings, selector, expected_release_id=b,
            )
            self.assertEqual(b, selected_b["release_id"])
            latest = settings.http_root / "ztp/config/cumulus/latest_yaml"
            latest.unlink()
            latest.symlink_to(settings.project_dir / "99-output-eth/release-b")
            _select_generation(selector, a)
            with self.assertRaises(ACTIVATE.ActivationError):
                ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=b,
                )
            self.assertEqual(
                a, ACTIVATE.validate_pinned_generation(
                    settings, selector, expected_release_id=a,
                )["release_id"],
            )

    def test_old_a_yaml_marker_and_manifest_must_still_be_usable(self):
        for leaf in ("release-manifest.json", ".published-complete", "leaf01.yaml"):
            with self.subTest(leaf=leaf), tempfile.TemporaryDirectory(
                prefix="r22-pinned-old-yaml-",
            ) as name:
                settings, selector, _generations, _a, b = _versioned_fixture(Path(name))
                latest = settings.http_root / "ztp/config/cumulus/latest_yaml"
                latest.unlink()
                latest.symlink_to(settings.project_dir / "99-output-eth/release-b")
                # B's public latest must not make A unreadable, but A's own
                # immutable child receipt is still an exact-hash dependency.
                ACTIVATE.validate_pinned_generation(settings, selector)
                (settings.project_dir / "99-output-eth/release-a" / leaf).write_bytes(
                    b"corrupt old A child\n"
                )
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_pinned_generation(settings, selector)

    def test_old_a_yaml_directory_rebind_during_read_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-yaml-rebind-") as name:
            settings, selector, _generations, _a, _b = _versioned_fixture(Path(name))
            yaml_a = settings.project_dir / "99-output-eth/release-a"
            original = ACTIVATE._read_pinned_generation_file
            swapped = []

            def rebind_after_manifest(*args, **kwargs):
                payload = original(*args, **kwargs)
                if args[1] == "release-manifest.json" and not swapped:
                    displaced = yaml_a.with_name("displaced-release-a")
                    yaml_a.rename(displaced)
                    shutil.copytree(displaced, yaml_a)
                    swapped.append(True)
                return payload

            with mock.patch.object(
                ACTIVATE, "_read_pinned_generation_file", side_effect=rebind_after_manifest,
            ):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_pinned_generation(settings, selector)
            self.assertEqual([True], swapped)

    def test_dhcp_subdirectory_rebind_during_read_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-dhcp-rebind-") as name:
            settings, selector, generations, a, _b = _versioned_fixture(Path(name))
            dhcp_a = generations / a / "dhcp"
            original = ACTIVATE._read_pinned_generation_file
            swapped = []

            def rebind_after_manifest(*args, **kwargs):
                payload = original(*args, **kwargs)
                if args[1].endswith("dhcp-release-manifest.json") and not swapped:
                    displaced = dhcp_a.with_name("displaced-dhcp")
                    dhcp_a.rename(displaced)
                    shutil.copytree(displaced, dhcp_a)
                    swapped.append(True)
                return payload

            with mock.patch.object(
                ACTIVATE, "_read_pinned_generation_file", side_effect=rebind_after_manifest,
            ):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_pinned_generation(settings, selector)
            self.assertEqual([True], swapped)

    def test_day0_ancestor_rebind_after_mount_check_fails_closed(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-ancestor-rebind-") as name:
            root = Path(name)
            settings, selector, _generations, _a, _b = _versioned_fixture(root)
            day0 = root / "DAY0-Prepare"
            outside = root / "outside-day0"
            shutil.copytree(day0, outside, symlinks=True)
            original = ACTIVATE.validate_project_mount
            swapped = []

            def rebind_after_mount(value):
                original(value)
                if not swapped:
                    day0.rename(root / "displaced-day0")
                    day0.symlink_to(outside, target_is_directory=True)
                    swapped.append(True)

            with mock.patch.object(
                ACTIVATE, "validate_project_mount", side_effect=rebind_after_mount,
            ):
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_pinned_generation(settings, selector)
            self.assertEqual([True], swapped)

    def test_selector_switch_after_pin_reads_only_a(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-switch-") as name:
            settings, selector, _generations, a, b = _versioned_fixture(Path(name))
            original = ACTIVATE._read_pinned_generation_file
            switched = []

            def switch_after_parent(*args, **kwargs):
                payload = original(*args, **kwargs)
                if args[1] == "current-release.json" and not switched:
                    _select_generation(selector, b)
                    switched.append(True)
                return payload

            with mock.patch.object(
                ACTIVATE, "_read_pinned_generation_file", side_effect=switch_after_parent,
            ):
                selected = ACTIVATE.validate_pinned_generation(settings, selector)
            self.assertEqual([True], switched)
            self.assertEqual(a, selected["release_id"])
            self.assertEqual(b, ACTIVATE.validate_pinned_generation(settings, selector)["release_id"])

    def test_selector_escapes_and_aliases_fail_closed(self):
        for target in ("/tmp/outside", "../elsewhere", "generations/../elsewhere"):
            with self.subTest(target=target), tempfile.TemporaryDirectory(
                prefix="r22-pinned-escape-",
            ) as name:
                settings, selector, _generations, _a, _b = _versioned_fixture(Path(name))
                selector.unlink()
                selector.symlink_to(target)
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_pinned_generation(settings, selector)

    def test_corrupt_snapshot_and_rebound_generation_inode_fail_closed(self):
        for mutation in ("corrupt", "rebind"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory(
                prefix="r22-pinned-corrupt-",
            ) as name:
                settings, selector, generations, a, _b = _versioned_fixture(Path(name))
                if mutation == "corrupt":
                    (generations / a / "dhcp/dhcpd.conf").write_bytes(b"tampered\n")
                    with self.assertRaises(ACTIVATE.ActivationError):
                        ACTIVATE.validate_pinned_generation(settings, selector)
                else:
                    original = ACTIVATE._read_pinned_generation_file
                    swapped = []

                    def rebind_after_parent(*args, **kwargs):
                        payload = original(*args, **kwargs)
                        if args[1] == "current-release.json" and not swapped:
                            original_dir = generations / a
                            original_dir.rename(generations / f"old-{a}")
                            shutil.copytree(generations / f"old-{a}", original_dir)
                            swapped.append(True)
                        return payload

                    with mock.patch.object(
                        ACTIVATE, "_read_pinned_generation_file", side_effect=rebind_after_parent,
                    ):
                        with self.assertRaises(ACTIVATE.ActivationError):
                            ACTIVATE.validate_pinned_generation(settings, selector)
                    self.assertEqual([True], swapped)

    def test_disabled_generation_has_no_dhcp_child_and_validates_frozen_http_only(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-disabled-") as name:
            settings, selector, generations, a, _b = _versioned_fixture(
                Path(name), mode="disabled",
            )
            self.assertFalse((generations / a / "dhcp").exists())
            pinned = ACTIVATE.validate_pinned_generation(
                settings, selector, expected_release_id=a,
            )
            self.assertEqual("disabled", pinned["parent_dhcp_status"])
            self.assertEqual({}, pinned["dhcp_output_sha256"])
            self.assertIsNone(pinned["dhcp_manifest_sha256"])
            self.assertEqual((False, False), pinned["frozen_policy"]["service_modes"])
            self.assertEqual((80, "192.0.2.50", True), pinned["frozen_policy"]["http"])

            (generations / a / "dhcp").mkdir()
            with self.assertRaisesRegex(ACTIVATE.ActivationError, "disabled.*DHCP"):
                ACTIVATE.validate_pinned_generation(settings, selector)

    def test_disabled_pinned_observation_uses_a_http_with_flat_b_and_no_dhcp(self):
        with tempfile.TemporaryDirectory(prefix="r22-disabled-observe-") as name:
            root = Path(name)
            settings, selector, generations, a, _b = _versioned_fixture(
                root, mode="disabled",
            )
            settings = replace(settings, state_root=root / "state")
            self.assertFalse((generations / a / "dhcp").exists())
            (settings.project_dir / "02-dhcp-subnet_config.csv").write_bytes(
                b"flat B invalid subnet\n",
            )
            flat_global = settings.project_dir / "01-global.yaml"
            changed = yaml.safe_load(flat_global.read_text(encoding="utf-8"))
            changed["common"]["mgmt"]["http"]["address"] = "198.51.100.77"
            changed["common"]["mgmt"]["dhcp-server"]["status"] = "enabled"
            flat_global.write_text(yaml.safe_dump(changed), encoding="utf-8")
            runtime = load_script(
                "r22_disabled_observe_runtime", ROOT / "tools/ztp_service_runtime.py",
            )
            with mock.patch.object(ACTIVATE, "_load_runtime_module", return_value=runtime), \
                    mock.patch.object(
                        ACTIVATE, "capture_stable_network_snapshot",
                        return_value=self._pinned_network_snapshot(),
                    ):
                selected, _runtime, payload, apache = ACTIVATE.observe_pinned_runtime(
                    settings, selector, expected_release_id=a,
                )
            self.assertEqual((), tuple(selected.listener_names))
            self.assertEqual((), tuple(selected.endpoint_ips))
            self.assertEqual(_digest(generations / a / "inputs/subnet"),
                             payload["subnet_sha256"])
            self.assertEqual(a, payload["selected_generation_release_id"])
            self.assertIn("Listen 192.0.2.50:80", apache)
            self.assertNotIn("198.51.100.77", apache)
            self.assertFalse(settings.state_root.exists())

    def test_disabled_parent_cannot_bind_enabled_policy_or_subnet_rows(self):
        for changed_input in ("global", "subnet"):
            with self.subTest(changed_input=changed_input), tempfile.TemporaryDirectory(
                prefix="r22-disabled-forged-source-",
            ) as name:
                settings, selector, generations, a, _b = _versioned_fixture(
                    Path(name), mode="disabled",
                )
                generation = generations / a
                source = generation / "inputs" / changed_input
                if changed_input == "global":
                    policy = yaml.safe_load(source.read_text(encoding="utf-8"))
                    policy["common"]["mgmt"]["ztp"]["status"] = "enabled"
                    source.write_text(yaml.safe_dump(policy), encoding="utf-8")
                    expected_error = "disabled pinned DHCP/ZTP"
                else:
                    source.write_text(
                        source.read_text(encoding="utf-8")
                        + "fabric,192.0.2.0,255.255.255.0,192.0.2.10,"
                        "192.0.2.20,192.0.2.1,,none,no\n",
                        encoding="utf-8",
                    )
                    expected_error = "header-only"
                parent_path = generation / "current-release.json"
                parent = json.loads(parent_path.read_text(encoding="utf-8"))
                parent["inputs"][changed_input] = _digest(source)
                _seal_parent(parent_path, parent, None)
                generation.rename(generations / parent["release_id"])
                _select_generation(selector, parent["release_id"])
                with self.assertRaisesRegex(ACTIVATE.ActivationError, expected_error):
                    ACTIVATE.validate_pinned_generation(
                        settings, selector, expected_release_id=parent["release_id"],
                    )

    def test_old_a_generated_inventory_uses_frozen_bytes_after_flat_source_changes(self):
        with tempfile.TemporaryDirectory(prefix="r22-pinned-derived-") as name:
            settings, selector, _generations, _a, _b = _versioned_fixture(
                Path(name), generated_authority=True,
            )
            ACTIVATE.validate_pinned_generation(settings, selector)
            derived = (
                settings.project_dir
                / ".load-inventory-independent/02-devices_config.csv"
            )
            derived.write_bytes(b"hostname,type\nforged,eth\n")
            ACTIVATE.validate_pinned_generation(settings, selector)
            frozen = (settings.project_dir / "99-output-ztp/generations"
                      / _a / "inputs/effective_devices")
            frozen.write_bytes(b"hostname,type\nforged,eth\n")
            with self.assertRaisesRegex(ACTIVATE.ActivationError, "pinned input"):
                ACTIVATE.validate_pinned_generation(settings, selector)

class ScopedEmptyHostActivationAdditionalDirectTests(unittest.TestCase):
    def test_empty_host_rejects_leaf_or_publication_link_rebinding_after_path_check(self):
        for kind in ("leaf", "publication_link"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory(
                prefix="r22-empty-host-race-",
            ) as name:
                settings, parent_path, _parent, _manifest_path, _manifest, dhcp_dir = (
                    _scoped_empty_fixture(Path(name))
                )
                project = settings.http_root / "DAY0-Prepare" / settings.project_name
                public = dhcp_dir / "dhcpd_ib.hosts"
                canonical = project / "99-output-dhcp" / public.name
                if kind == "publication_link":
                    canonical.write_bytes(b"")
                    public.unlink()
                    public.symlink_to(os.path.relpath(canonical, dhcp_dir))
                unmanaged = dhcp_dir.parent / "unmanaged-empty.hosts"
                unmanaged.write_bytes(b"")
                checked = canonical if kind == "publication_link" else public
                original = ACTIVATE._canonical_regular_within
                swapped = []

                def rebind_after_check(path, root, label):
                    result = original(path, root, label)
                    if (
                        not swapped and path == checked
                        and label.endswith("dhcpd_ib.hosts")
                    ):
                        public.unlink()
                        public.symlink_to(os.path.relpath(unmanaged, dhcp_dir))
                        swapped.append(True)
                    return result

                with mock.patch.object(
                    ACTIVATE, "_canonical_regular_within", side_effect=rebind_after_check,
                ):
                    with self.assertRaises(ACTIVATE.ActivationError):
                        ACTIVATE.validate_parent_release(settings, parent_path)
                self.assertEqual([True], swapped)

    def test_only_unselected_zero_count_hashed_hosts_may_be_empty(self):
        with tempfile.TemporaryDirectory(prefix="r22-empty-host-direct-") as name:
            root = Path(name)
            settings, parent_path, _parent, _path, _manifest, dhcp_dir = (
                _scoped_empty_fixture(root)
            )
            self.assertEqual(0, (dhcp_dir / "dhcpd_ib.hosts").stat().st_size)
            self.assertEqual(0, (dhcp_dir / "dhcpd_nvl.hosts").stat().st_size)
            identity = ACTIVATE.validate_parent_release(settings, parent_path)
            self.assertEqual(_digest(parent_path), identity["parent_release_sha256"])

    def test_empty_host_never_escapes_scope_count_or_hash_proof(self):
        mutations = (
            ("selected_ib", lambda manifest, directory: manifest.update(switch_scope="ib")),
            ("declared_ib", lambda manifest, directory: manifest["counts"][
                "host_declarations_by_family"].update(ib=1)),
            ("missing_counts", lambda manifest, directory: manifest.pop("counts")),
            ("extra_family_count", lambda manifest, directory: manifest["counts"][
                "host_declarations_by_family"].update(other=0)),
            ("missing_scope", lambda manifest, directory: manifest.pop("switch_scope")),
            ("invalid_boolean_count", lambda manifest, directory: manifest["counts"][
                "host_declarations_by_family"].update(ib=False)),
            ("invalid_string_count", lambda manifest, directory: manifest["counts"][
                "host_declarations_by_family"].update(ib="0")),
            ("wrong_hash", lambda manifest, directory: manifest["outputs"][
                "dhcpd_ib.hosts"].update(sha256="0" * 64)),
            ("unmanaged_zero_alias", lambda manifest, directory: _redirect_empty_ib(directory)),
            ("empty_selected_eth", lambda manifest, directory: (
                (directory / "dhcpd_eth.hosts").write_bytes(b""),
                manifest["counts"]["host_declarations_by_family"].update(eth=0),
                manifest["outputs"]["dhcpd_eth.hosts"].update(
                    sha256=hashlib.sha256(b"").hexdigest()),
            )),
            ("empty_conf", lambda manifest, directory: (
                (directory / "dhcpd.conf").write_bytes(b""),
                manifest["outputs"]["dhcpd.conf"].update(
                    sha256=hashlib.sha256(b"").hexdigest()),
            )),
        )
        for label, mutate in mutations:
            with self.subTest(case=label), tempfile.TemporaryDirectory(
                prefix="r22-empty-host-direct-",
            ) as name:
                settings, parent_path, parent, manifest_path, manifest, dhcp_dir = (
                    _scoped_empty_fixture(Path(name))
                )
                mutate(manifest, dhcp_dir)
                manifest_path.write_text(
                    json.dumps(manifest, sort_keys=True) + "\n", encoding="utf-8",
                )
                _seal_parent(parent_path, parent, manifest_path)
                with self.assertRaises(ACTIVATE.ActivationError):
                    ACTIVATE.validate_parent_release(settings, parent_path)

    def test_legacy_nonempty_parent_does_not_require_new_scope_counts(self):
        with tempfile.TemporaryDirectory(prefix="r22-legacy-host-direct-") as name:
            root = Path(name)
            project, parent_path, _parent, _public, _dhcp = (
                dhcp_mode_release_fixture(root, "enabled", legacy=True)
            )
            settings = ACTIVATE.Settings(
                http_root=root, project_name=project.name, scope="air",
                switch_scope="eth",
            )
            identity = ACTIVATE.validate_parent_release(settings, parent_path)
            self.assertEqual(_digest(parent_path), identity["parent_release_sha256"])


if __name__ == "__main__":
    unittest.main()
