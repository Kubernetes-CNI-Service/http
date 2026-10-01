"""Docker activation consumes the load-owned derived inventory authority."""

import hashlib
import importlib.util
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from test_cases.test_manual_applied_config import dhcp_mode_release_fixture


ROOT = Path(__file__).resolve().parents[1]


def load_activate():
    spec = importlib.util.spec_from_file_location(
        "docker_derived_parent_activate_under_test",
        ROOT / "infra/docker/activate.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


ACTIVATE = load_activate()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rebind_parent(parent: dict) -> None:
    keys = (
        "project", "deployment_scope", "switch_scope", "inputs",
        "input_sources", "dhcp_status", "components", "inventory",
    )
    if "generated_inputs" in parent:
        keys += ("generated_inputs",)
    basis = {key: parent[key] for key in keys}
    parent["release_id"] = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]


def attach_derived_inventory(project: Path, parent_path: Path, parent: dict) -> Path:
    directory = project / ".load-inventory-fixture"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    derived = directory / "02-devices_config.csv"
    derived.write_text(
        "hostname,type,eth0_ip\nleaf01,eth,192.0.2.10\n"
        "AIR-leaf01,air,192.0.2.10\n",
        encoding="utf-8",
    )
    derived.chmod(0o600)
    parent["generated_inputs"] = {
        "effective_devices": {
            "path": derived.relative_to(project).as_posix(),
            "sha256": sha256(derived),
        },
    }
    rebind_parent(parent)
    parent_path.write_text(json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8")
    return derived


class DockerDerivedParentDirectTests(unittest.TestCase):
    def fixture(self, temporary: str):
        root = Path(temporary) / "html"
        project, parent_path, parent, _public_dhcp, _dhcp_dir = (
            dhcp_mode_release_fixture(root, "disabled")
        )
        derived = attach_derived_inventory(project, parent_path, parent)
        settings = ACTIVATE.Settings(
            http_root=root, project_name="site-a", scope="air",
            switch_scope="eth",
        )
        return settings, project, parent_path, parent, derived

    def test_real_derived_parent_validates_with_generated_input_in_release_basis(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings, _project, parent_path, parent, derived = self.fixture(temporary)
            identity = ACTIVATE.validate_parent_release(settings, parent_path)
            self.assertEqual(
                sha256(parent_path), identity["parent_release_sha256"],
            )
            self.assertEqual(parent["inputs"]["devices"],
                             identity["parent_inputs"]["devices"])
            self.assertEqual(0o600, stat.S_IMODE(derived.stat().st_mode))

    def test_derived_inventory_byte_drift_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary:
            settings, _project, parent_path, _parent, derived = self.fixture(temporary)
            derived.write_bytes(derived.read_bytes() + b"tampered\n")
            with self.assertRaisesRegex(ACTIVATE.ActivationError, "derived inventory.*hash drift"):
                ACTIVATE.validate_parent_release(settings, parent_path)

    def test_derived_inventory_unsafe_paths_and_files_are_rejected(self):
        mutations = ("traversal", "symlink", "writable", "non_private_directory")
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                settings, project, parent_path, parent, derived = self.fixture(temporary)
                record = parent["generated_inputs"]["effective_devices"]
                if mutation == "traversal":
                    record["path"] = "../02-devices_config.csv"
                elif mutation == "symlink":
                    target = project / "derived-target.csv"
                    target.write_bytes(derived.read_bytes())
                    target.chmod(0o600)
                    derived.unlink()
                    derived.symlink_to(os.path.relpath(target, derived.parent))
                    record["sha256"] = sha256(target)
                elif mutation == "writable":
                    derived.chmod(0o620)
                else:
                    derived.parent.chmod(0o755)
                rebind_parent(parent)
                parent_path.write_text(
                    json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8",
                )
                with self.assertRaisesRegex(ACTIVATE.ActivationError, "derived inventory"):
                    ACTIVATE.validate_parent_release(settings, parent_path)


class DockerDerivedParentActivationWorkflowTests(unittest.TestCase):
    def test_derived_parent_reaches_real_activation_marker_builder(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "html"
            project, parent_path, parent, _public_dhcp, _dhcp_dir = (
                dhcp_mode_release_fixture(root, "disabled")
            )
            derived = attach_derived_inventory(project, parent_path, parent)
            settings = ACTIVATE.Settings(
                http_root=root, project_name="site-a", scope="air",
                switch_scope="eth",
            )
            selected = SimpleNamespace(endpoint_ips=("192.0.2.10",))
            public_p2p = ACTIVATE.PUBLISHED_P2P_INPUT_LINK.as_posix()
            with mock.patch.object(
                ACTIVATE, "published_link_identity", return_value={
                    public_p2p: {"sha256": parent["inputs"]["p2p"]},
                },
            ), mock.patch.object(
                ACTIVATE, "published_runtime_identity", return_value={},
            ), mock.patch.object(
                ACTIVATE, "validate_image_source_contract", return_value={},
            ), mock.patch.object(
                ACTIVATE, "project_http_listener_ips", return_value=("192.0.2.10",),
            ), mock.patch.object(
                ACTIVATE, "expected_services", return_value=("apache2",),
            ):
                marker = ACTIVATE.build_activation_marker(
                    settings, selected, release_manifest=parent_path,
                )
            self.assertEqual(
                sha256(parent_path), marker["parent_release_sha256"],
            )
            self.assertEqual(parent["inputs"]["devices"],
                             marker["parent_inputs"]["devices"])
            self.assertEqual(sha256(derived),
                             parent["generated_inputs"]["effective_devices"]["sha256"])


if __name__ == "__main__":
    unittest.main()
