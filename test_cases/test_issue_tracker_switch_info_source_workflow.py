"""Real v2 emitter info_archive role -> bounded Switch preview, not qualification."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from monitor.issue_tracker_switch_info_source import (
    SwitchInfoHoldError,
    map_switch_source_rows,
    read_switch_info_preview,
)
from test_cases.test_collection_v2_emitter_contract import EMITTER, identity
from test_cases.test_issue_tracker_switch_info_source import _info


class SwitchInfoSourceWorkflowTests(unittest.TestCase):
    def _published_role(self, root: Path):
        chosen = identity()
        slot = "ethernet/prod"
        leaf = (root / "monitor/status/collection-cycles" / chosen["project_key"]
                / "prod/switch_collection/artifacts/00000000000000000007")
        sidecar = leaf / "ethernet-prod"
        inventory = leaf / "inputs/ethernet-prod.csv"
        inventory.parent.mkdir(parents=True)
        frozen = b"hostname,type,eth0_ip\nleaf-a,eth,192.0.2.10\n"
        inventory.write_bytes(frozen)
        context = {
            "identity": chosen, "source_slot": slot,
            "artifacts": {
                "evidence": str(sidecar / "evidence-manifest.json"),
                "envelope": str(sidecar / "identity-envelope.json"),
                "input_inventory": str(inventory),
            },
            "input_inventory_sha256": hashlib.sha256(frozen).hexdigest(),
        }
        context_path = root / "context.json"
        context_path.write_bytes(EMITTER.canonical(context))
        planned = root / "planned.txt"
        planned.write_text("leaf-a\n", encoding="utf-8")
        legacy = root / "legacy.txt"
        legacy.write_text(EMITTER.PREFIX + json.dumps({
            "schema_version": 1, "task": "switch_collection", "state": "success",
            "planned": 1, "succeeded": 1, "failed_count": 0, "failed_devices": [],
        }, separators=(",", ":")) + "\n", encoding="utf-8")
        archive = root / "ethernet/monitor/eth-info/20260925-0315-prod.tar.gz"
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, "w:gz") as bundle:
            stamp = "20260925-0315-prod"
            folder = tarfile.TarInfo(stamp + "/")
            folder.type = tarfile.DIRTYPE
            bundle.addfile(folder)
            body = _info("leaf-a", fan_state="fail", asic_current="82")
            member = tarfile.TarInfo(stamp + "/leaf-a.info")
            member.size = len(body)
            bundle.addfile(member, io.BytesIO(body))
            metadata = json.dumps({
                "schema_version": 1, "environment": "prod",
                "collector": "cron.sh", "collected_at": "2026-09-25T03:15:00+08:00",
                "device_count": 1,
            }, separators=(",", ":")).encode()
            meta = tarfile.TarInfo(stamp + "/collection.json")
            meta.size = len(metadata)
            bundle.addfile(meta, io.BytesIO(metadata))
        args = argparse.Namespace(
            context_file=context_path, legacy_result_file=legacy,
            planned_file=planned, info=archive, link=None, csv=None,
        )
        with mock.patch.object(EMITTER, "ROOT", root):
            child, evidence, envelope, sidecar_dir = EMITTER.build_result(args)
            EMITTER.publish(sidecar_dir, evidence, envelope)
        return archive, child, sidecar_dir

    def test_published_info_role_yields_only_preview_and_rewrite_holds(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, child, sidecar = self._published_role(root)
            roles = json.loads((sidecar / "evidence-manifest.json").read_bytes())["roles"]
            self.assertEqual("info_archive", roles[0]["role"])
            self.assertEqual("present", roles[0]["state"])
            self.assertEqual(2, child["schema_version"])
            self.assertEqual(hashlib.sha256(archive.read_bytes()).hexdigest(),
                             roles[0]["sha256"])
            preview = read_switch_info_preview(
                archive, expected_sha256=roles[0]["sha256"],
                expected_size_bytes=roles[0]["size_bytes"],
                source_slot="ethernet/prod", selected_hosts=("leaf-a",),
            )
            self.assertEqual({
                ("leaf-a", "fan", "PSU1/FAN1"),
                ("leaf-a", "asic_temp", "Asic-Temp-Sensor"),
            }, set(preview.abnormal_keys))
            self.assertFalse(preview.qualified)
            values = {(value.hostname, value.category, value.component_or_sensor): value
                      for value in preview.abnormal_values}
            self.assertEqual(set(preview.abnormal_keys), set(values))
            self.assertEqual(("fail", None, None, None),
                             (values[("leaf-a", "fan", "PSU1/FAN1")].state,
                              values[("leaf-a", "fan", "PSU1/FAN1")].current_c,
                              values[("leaf-a", "fan", "PSU1/FAN1")].maximum_c,
                              values[("leaf-a", "fan", "PSU1/FAN1")].critical_c))
            self.assertEqual(("ok", 82.0, 70.0, 80.0),
                             (values[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].state,
                              values[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].current_c,
                              values[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].maximum_c,
                              values[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].critical_c))
            self.assertEqual(tuple(preview.abnormal_values),
                             tuple(row.value for row in map_switch_source_rows(preview)))
            original = archive.read_bytes()
            archive.write_bytes(original + b"x")
            with self.assertRaises(SwitchInfoHoldError):
                read_switch_info_preview(
                    archive, expected_sha256=roles[0]["sha256"],
                    expected_size_bytes=roles[0]["size_bytes"],
                    source_slot="ethernet/prod", selected_hosts=("leaf-a",),
                )


if __name__ == "__main__":
    unittest.main()
