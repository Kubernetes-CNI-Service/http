"""ZTP monitor consumes load's private derived inventory release authority."""

import hashlib
import importlib.util
import json
import os
import copy
import sys
import tempfile
import unittest
from pathlib import Path

from test_cases import test_load_release_transaction as release_fixture


ROOT = Path(__file__).resolve().parents[1]


def load_monitor():
    spec = importlib.util.spec_from_file_location(
        "monitor_derived_parent_under_test",
        ROOT / "DAY0-Prepare/12-ztp-monitor.py",
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


MONITOR = load_monitor()
LOAD = release_fixture.LOAD


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def rebind_parent(parent: dict) -> None:
    keys = (
        "project", "deployment_scope", "switch_scope", "inputs",
        "input_sources", "dhcp_status", "components", "inventory",
    )
    if "generated_inputs" in parent:
        keys += ("generated_inputs",)
    parent["release_id"] = hashlib.sha256(json.dumps(
        {key: parent[key] for key in keys}, ensure_ascii=False,
        sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]


class DerivedParentFixture(unittest.TestCase):
    def setUp(self):
        self.release = release_fixture.ReleaseTransactionTests(
            "test_writes_parent_release_after_all_components_match"
        )
        self.release.setUp()
        self.project = self.release.project
        self.private = Path(tempfile.mkdtemp(
            prefix=".load-inventory-", dir=self.project,
        ))
        self.private.chmod(0o700)
        self.derived = self.private / "02-devices_config.csv"
        self.derived.write_bytes(self.release.devices_file.read_bytes() + b"\n")
        self.derived.chmod(0o600)
        self.inputs = LOAD.replace(
            self.release.inputs,
            effective_devices_file=self.derived,
            effective_devices_sha256=sha256(self.derived),
        )

    def tearDown(self):
        self.release.tearDown()

    def publish(self):
        return LOAD.validate_and_publish_release(
            self.project, self.inputs, publish=True,
        )

    @property
    def parent_path(self):
        return self.project / "99-output-ztp/current-release.json"


class MonitorDerivedParentDirectTests(DerivedParentFixture):
    def test_derived_inventory_byte_drift_is_rejected(self):
        self.publish()
        self.derived.write_bytes(self.derived.read_bytes() + b"tampered\n")
        with self.assertRaisesRegex(ValueError, "派生 inventory.*SHA-256"):
            MONITOR.load_release_identity(self.project)

    def test_unsafe_derived_inventory_path_and_authority_are_rejected(self):
        mutations = ("traversal", "symlink", "writable", "public_directory")
        published = self.publish()
        original = self.derived.read_bytes()
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                if self.derived.is_symlink():
                    self.derived.unlink()
                self.derived.write_bytes(original)
                self.derived.chmod(0o600)
                self.private.chmod(0o700)
                parent = copy.deepcopy(published)
                record = parent["generated_inputs"]["effective_devices"]
                if mutation == "traversal":
                    record["path"] = "../02-devices_config.csv"
                elif mutation == "symlink":
                    target = self.project / "derived-target.csv"
                    target.write_bytes(self.derived.read_bytes())
                    target.chmod(0o600)
                    self.derived.unlink()
                    self.derived.symlink_to(os.path.relpath(target, self.private))
                    record["sha256"] = sha256(target)
                elif mutation == "writable":
                    self.derived.chmod(0o620)
                else:
                    self.private.chmod(0o755)
                rebind_parent(parent)
                self.parent_path.write_text(
                    json.dumps(parent, sort_keys=True) + "\n", encoding="utf-8",
                )
                with self.assertRaisesRegex(ValueError, "派生 inventory"):
                    MONITOR.load_release_identity(self.project)


class LoadToMonitorDerivedParentWorkflowTests(DerivedParentFixture):
    def test_real_load_parent_is_accepted_by_monitor_with_derived_inventory(self):
        parent = self.publish()
        self.assertEqual(
            {"path": self.derived.relative_to(self.project).as_posix(),
             "sha256": sha256(self.derived)},
            parent["generated_inputs"]["effective_devices"],
        )
        identity = MONITOR.load_release_identity(self.project)
        self.assertEqual(parent["release_id"], identity["release_id"])


if __name__ == "__main__":
    unittest.main()
