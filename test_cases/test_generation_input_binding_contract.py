#!/usr/bin/env python3
"""Direct regression for generator input authority across a second read."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script
from test_cases.test_v2_generation_flow import (
    V2MlagSetupPreflightTests,
    run_v2_mlag_setup_preflight,
)


ROOT = Path(__file__).resolve().parents[1]
C2_PATH = ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
C1_PATH = ROOT / "ztp/config/isc-dhcp-server/c1-generate_dhcp.py"
D_PATH = ROOT / "ztp/config/cumulus/d-hostname2mac.py"


class GenerationInputBindingDirectTests(unittest.TestCase):
    """A generator must not replace same-named output across input versions."""

    def test_c2_description_single_pointer_keeps_legacy_and_binds_immutable_version(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-pointer-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project / source.name).read_bytes())
                generation = private / "generation"
                generation.mkdir()
                (generation / "candidate.txt").write_bytes(b"candidate B")
                legacy = private / "generation_with_desc"
                legacy.mkdir()
                (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
                pointer = private / "generation_with_desc_current"
                c2 = load_script("r22_c2_pointer_direct", C2_PATH)

                def patch_candidate(_dot, stage, _display, _authority):
                    (Path(stage) / "patched-marker.txt").write_bytes(b"complete patch B")

                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_patch_descriptions_in_directory", side_effect=patch_candidate), \
                        redirect_stdout(io.StringIO()):
                    c2._run_patch_descriptions(str(private / "topology.dot"), str(generation))

                self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
                self.assertFalse((legacy / "patched-marker.txt").exists())
                self.assertTrue(pointer.is_symlink())
                target_name = os.readlink(pointer)
                self.assertRegex(target_name, r"^\.generation_with_desc\.version\.[0-9a-f]+$")
                version = private / target_name
                self.assertTrue(version.is_dir())
                self.assertFalse(version.is_symlink())
                self.assertEqual(b"complete patch B", (version / "patched-marker.txt").read_bytes())
                self.assertEqual(str(pointer), c2._selected_description_output(str(generation)))
                pinned = c2._pin_selected_description_output(str(generation))
                self.assertEqual(str(pointer), pinned["display_path"])
                self.assertEqual(str(version), pinned["read_path"])
                self.assertEqual(b"complete patch B", (Path(pinned["read_path"]) / "patched-marker.txt").read_bytes())
                c2._verify_pinned_description_output(str(generation), pinned)
                manifest = json.loads((version / ".description-version.json").read_text())
                self.assertEqual(1, manifest["schema_version"])
                self.assertEqual("generation", manifest["timestamp"])
                self.assertEqual(
                    hashlib.sha256(b"complete patch B").hexdigest(),
                    manifest["files"]["patched-marker.txt"],
                )
                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_patch_descriptions_in_directory", side_effect=patch_candidate), \
                        redirect_stdout(io.StringIO()):
                    c2._run_patch_descriptions(str(private / "topology.dot"), str(generation))
                self.assertNotEqual(target_name, os.readlink(pointer))
                self.assertEqual(b"complete patch B", (pointer / "patched-marker.txt").read_bytes())
                self.assertEqual(b"complete patch B", (version / "patched-marker.txt").read_bytes())
                with self.assertRaisesRegex(ValueError, "changed|pointer"):
                    c2._verify_pinned_description_output(str(generation), pinned)
                inventory = c2._inspect_description_output_recovery(str(legacy))
                self.assertEqual("clean", inventory["state"])
                self.assertEqual([str(version)], inventory["unreferenced_versions"])
                self.assertEqual("historical-or-orphan", inventory["unreferenced_classification"])
        finally:
            fixture.cleanup()

    def test_c2_abrupt_commit_never_removes_legacy_directory(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            for crash_after in (1, 2):
                with self.subTest(crash_after=crash_after), \
                        tempfile.TemporaryDirectory(prefix="r22-c2-abrupt-") as name:
                    private = Path(name)
                    source = private / "02-devices_config.csv"
                    source.write_bytes((project / source.name).read_bytes())
                    generation = private / "generation"
                    generation.mkdir()
                    (generation / "candidate.txt").write_bytes(b"candidate B")
                    legacy = private / "generation_with_desc"
                    legacy.mkdir()
                    (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
                    pointer = private / "generation_with_desc_current"
                    c2 = load_script("r22_c2_abrupt_direct", C2_PATH)
                    real_replace = c2.os.replace
                    observed = {"replaces": 0}

                    def abrupt_after_replace(src, dst, *args, **kwargs):
                        result = real_replace(src, dst, *args, **kwargs)
                        observed["replaces"] += 1
                        if observed["replaces"] == crash_after:
                            raise BaseException("simulated abrupt process exit")
                        return result

                    with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                            mock.patch.object(c2, "_patch_descriptions_in_directory", return_value=None), \
                            mock.patch.object(c2.os, "replace", side_effect=abrupt_after_replace), \
                            redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(BaseException, "simulated abrupt"):
                            c2._run_patch_descriptions(str(private / "topology.dot"), str(generation))

                    self.assertGreaterEqual(observed["replaces"], crash_after)
                    self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
                    self.assertFalse((legacy / "candidate.txt").exists())
                    if pointer.is_symlink():
                        self.assertTrue(pointer.resolve(strict=True).is_dir())
                        self.assertEqual(b"candidate B", (pointer / "candidate.txt").read_bytes())

        finally:
            fixture.cleanup()

    def test_d_current_pointer_is_verified_and_never_falls_back_on_tampering(self):
        with tempfile.TemporaryDirectory(prefix="r22-d-current-") as name:
            output_root = Path(name) / "99-output"
            output_root.mkdir()
            timestamp = "20261002_010203"
            base = output_root / timestamp
            base.mkdir()
            legacy = output_root / f"{timestamp}_with_desc"
            legacy.mkdir()
            (legacy / "legacy.txt").write_bytes(b"accepted legacy A")
            version = output_root / f".{timestamp}_with_desc.version.abcdef12abcdef12abcdef12abcdef12"
            version.mkdir()
            (version / "spine.yaml").write_bytes(b"complete patched B")
            manifest = {
                "schema_version": 1,
                "timestamp": timestamp,
                "files": {"spine.yaml": hashlib.sha256(b"complete patched B").hexdigest()},
            }
            (version / ".description-version.json").write_text(
                json.dumps(manifest), encoding="utf-8",
            )
            pointer = output_root / f"{timestamp}_with_desc_current"
            pointer.symlink_to(version.name, target_is_directory=True)
            d = load_script("r22_d_current_direct", D_PATH)
            context = d._cumulus_dir_context(str(base))

            selected = d._preferred_cumulus_contexts([context])
            self.assertEqual([str(pointer)], [item["path"] for item in selected])
            self.assertEqual(str(version), selected[0]["read_path"])
            self.assertIsNone(d._archive_combined_sources(selected))
            self.assertTrue(pointer.is_symlink())
            self.assertEqual(b"complete patched B", (version / "spine.yaml").read_bytes())
            old_residue = output_root / f".{timestamp}_with_desc.tmp.interrupted.old"
            old_residue.mkdir()
            with self.assertRaisesRegex(ValueError, "unresolved|backup|description"):
                d._preferred_cumulus_contexts([context])
            old_residue.rmdir()
            manifest_path = version / ".description-version.json"
            manifest_path.write_text(
                '{"schema_version":2,"schema_version":1,'
                f'"timestamp":"{timestamp}","files":'
                f'{{"spine.yaml":"{manifest["files"]["spine.yaml"]}"}}}}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ValueError, "manifest|duplicate|description"):
                d._preferred_cumulus_contexts([context])
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            (version / "spine.yaml").write_bytes(b"tampered patched C")
            with self.assertRaisesRegex(ValueError, "pointer|version|manifest|hash|description"):
                d._preferred_cumulus_contexts([context])
            (version / "spine.yaml").write_bytes(b"complete patched B")
            other = output_root / f".{timestamp}_with_desc.version.12345678123456781234567812345678"
            other.mkdir()
            (other / "spine.yaml").write_bytes(b"other complete patch C")
            (other / ".description-version.json").write_text(json.dumps({
                "schema_version": 1,
                "timestamp": timestamp,
                "files": {"spine.yaml": hashlib.sha256(b"other complete patch C").hexdigest()},
            }), encoding="utf-8")
            pointer.unlink()
            pointer.symlink_to(other.name, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "pointer|changed|description"):
                d._cumulus_source_path(selected[0])
            pointer.unlink()
            pointer.symlink_to(version.name, target_is_directory=True)
            self.assertEqual(str(version), d._preferred_cumulus_contexts([context])[0]["read_path"])
            pointer.unlink()
            pointer.symlink_to("../outside", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "pointer|version|manifest|description"):
                d._preferred_cumulus_contexts([context])
            pointer.unlink()
            pointer.symlink_to(f".{timestamp}_with_desc.version.abcdef12", target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "pointer|version|manifest|description"):
                d._preferred_cumulus_contexts([context])
            self.assertEqual(b"accepted legacy A", (legacy / "legacy.txt").read_bytes())

    def test_c2_rechecks_version_after_fsync_before_pointer_commit(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-post-fsync-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project / source.name).read_bytes())
                generation = private / "generation"
                generation.mkdir()
                (generation / "candidate.txt").write_bytes(b"candidate B")
                legacy = private / "generation_with_desc"
                legacy.mkdir()
                (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
                c2 = load_script("r22_c2_post_fsync_direct", C2_PATH)
                real_fsync = c2._fsync_description_version

                def tamper_after_fsync(directory):
                    real_fsync(directory)
                    (Path(directory) / "candidate.txt").write_bytes(b"tampered after fsync")

                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_patch_descriptions_in_directory", return_value=None), \
                        mock.patch.object(c2, "_fsync_description_version", side_effect=tamper_after_fsync), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "description|version|hash|changed"):
                        c2._run_patch_descriptions(str(private / "topology.dot"), str(generation))
                self.assertFalse((private / "generation_with_desc_current").exists())
                self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
        finally:
            fixture.cleanup()

    def test_c2_final_yaml_validation_never_deletes_frozen_legacy_source(self):
        with tempfile.TemporaryDirectory(prefix="r22-c2-legacy-validation-") as name:
            legacy = Path(name) / "20261002_010203_with_desc"
            legacy.mkdir()
            invalid = legacy / "spine.yaml"
            invalid.write_bytes(b"set: [not valid YAML")
            c2 = load_script("r22_c2_legacy_validation_direct", C2_PATH)
            with redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "YAML|校验|语法"):
                    c2._validate_final_yaml_outputs(str(legacy))
            self.assertEqual(b"set: [not valid YAML", invalid.read_bytes())

    def test_d_default_input_discovers_current_pointer_without_base_or_legacy(self):
        with tempfile.TemporaryDirectory(prefix="r22-d-current-default-") as name:
            service = Path(name) / "cumulus"
            output_root = service / "template/99-output"
            output_root.mkdir(parents=True)
            timestamp = "20261002_010203"
            version = output_root / f".{timestamp}_with_desc.version.abcdef12abcdef12abcdef12abcdef12"
            version.mkdir()
            (version / "spine.yaml").write_bytes(b"complete patched B")
            (version / ".description-version.json").write_text(json.dumps({
                "schema_version": 1,
                "timestamp": timestamp,
                "files": {"spine.yaml": hashlib.sha256(b"complete patched B").hexdigest()},
            }), encoding="utf-8")
            pointer = output_root / f"{timestamp}_with_desc_current"
            pointer.symlink_to(version.name, target_is_directory=True)
            d = load_script("r22_d_current_default_direct", D_PATH)
            with mock.patch.object(d.os, "getcwd", return_value=str(service)), \
                    redirect_stdout(io.StringIO()):
                self.assertEqual(str(pointer), d._resolve_yaml_dir())

    def test_d_invalid_current_pointer_stops_main_before_publish_or_source_cleanup(self):
        with tempfile.TemporaryDirectory(prefix="r22-d-invalid-current-") as name:
            private = Path(name)
            output_root = private / "99-output"
            output_root.mkdir()
            timestamp = "20261002_010203"
            base = output_root / timestamp
            base.mkdir()
            legacy = output_root / f"{timestamp}_with_desc"
            legacy.mkdir()
            (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
            pointer = output_root / f"{timestamp}_with_desc_current"
            pointer.symlink_to("../outside", target_is_directory=True)
            csv_file = private / "02-devices_config.csv"
            csv_file.write_bytes(b"fixture only; load_csv is stubbed")
            d = load_script("r22_d_invalid_current_main_direct", D_PATH)
            devices = {"spine": {"hostname": "spine", "dev_type": "eth"}}
            with mock.patch.object(d.sys, "argv", [
                    "d-hostname2mac.py", "--csv", str(csv_file),
                    "--deployment-scope", "prod", "--switch", "eth", str(base),
                ]), mock.patch.object(d, "load_csv", return_value=devices), \
                    mock.patch.object(d, "_publish_production_cumulus") as publish, \
                    mock.patch.object(d, "_set_latest_yaml") as set_latest, \
                    mock.patch.object(d, "_archive_combined_sources") as archive, \
                    mock.patch.object(d, "_remove_superseded_cumulus_base") as remove_base, \
                    redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "pointer|version|manifest|description"):
                    d.main()
                publish.assert_not_called()
                set_latest.assert_not_called()
                archive.assert_not_called()
                remove_base.assert_not_called()
            self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
            self.assertEqual("../outside", os.readlink(pointer))

    def test_d_legacy_description_path_must_be_a_real_directory(self):
        for legacy_kind in ("symlink", "regular-file"):
            with self.subTest(legacy_kind=legacy_kind), \
                    tempfile.TemporaryDirectory(prefix="r22-d-legacy-type-") as name:
                output_root = Path(name) / "99-output"
                output_root.mkdir()
                timestamp = "20261002_010203"
                base = output_root / timestamp
                base.mkdir()
                legacy = output_root / f"{timestamp}_with_desc"
                if legacy_kind == "symlink":
                    legacy.symlink_to(base.name, target_is_directory=True)
                else:
                    legacy.write_bytes(b"not a directory")
                d = load_script("r22_d_legacy_type_direct", D_PATH)
                with self.assertRaisesRegex(ValueError, "legacy|description|directory"):
                    d._preferred_cumulus_contexts([d._cumulus_dir_context(str(base))])
                self.assertTrue(base.is_dir())
                self.assertTrue(os.path.lexists(legacy))

    def test_d_successful_publish_cleanup_retains_legacy_description_source(self):
        with tempfile.TemporaryDirectory(prefix="r22-d-retain-legacy-") as name:
            output_root = Path(name) / "99-output"
            output_root.mkdir()
            timestamp = "20261002_010203"
            base = output_root / timestamp
            base.mkdir()
            legacy = output_root / f"{timestamp}_with_desc"
            legacy.mkdir()
            (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
            d = load_script("r22_d_retain_legacy_direct", D_PATH)
            selected = d._preferred_cumulus_contexts([d._cumulus_dir_context(str(base))])
            self.assertEqual(str(legacy), selected[0]["path"])
            self.assertIsNone(d._archive_combined_sources(selected))
            self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
            self.assertFalse((output_root / f"{timestamp}_combine_sources.tar.gz").exists())

    def test_c2_and_d_cold_inventory_blocks_new_stage_or_unpointed_version(self):
        for residue_kind in ("stage", "version"):
            with self.subTest(residue_kind=residue_kind), \
                    tempfile.TemporaryDirectory(prefix="r22-description-orphan-") as name:
                output_root = Path(name) / "99-output"
                output_root.mkdir()
                timestamp = "20261002_010203"
                base = output_root / timestamp
                base.mkdir()
                legacy = output_root / f"{timestamp}_with_desc"
                legacy.mkdir()
                (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
                residue = output_root / f".{timestamp}_with_desc.{residue_kind}.abcdef12abcdef12abcdef12abcdef12"
                residue.mkdir()
                (residue / "marker.txt").write_bytes(b"inert uncertain B")
                c2 = load_script("r22_c2_new_orphan_direct", C2_PATH)
                d = load_script("r22_d_new_orphan_direct", D_PATH)

                observed = c2._inspect_description_output_recovery(str(legacy))
                self.assertIn(residue_kind, observed["state"])
                self.assertEqual(b"inert uncertain B", (residue / "marker.txt").read_bytes())
                with self.assertRaisesRegex(ValueError, "unresolved|stage|version|description"):
                    c2._require_clean_description_output(str(legacy))
                with self.assertRaisesRegex(ValueError, "unresolved|stage|version|description"):
                    d._preferred_cumulus_contexts([d._cumulus_dir_context(str(base))])
                self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())
                self.assertEqual(b"inert uncertain B", (residue / "marker.txt").read_bytes())

    def test_c2_and_d_reject_orphaned_temporary_current_pointer(self):
        with tempfile.TemporaryDirectory(prefix="r22-description-pointer-temp-") as name:
            output_root = Path(name) / "99-output"
            output_root.mkdir()
            timestamp = "20261002_010203"
            base = output_root / timestamp
            base.mkdir()
            legacy = output_root / f"{timestamp}_with_desc"
            legacy.mkdir()
            (legacy / "old-marker.txt").write_bytes(b"accepted legacy A")
            pending = output_root / f".{timestamp}_with_desc.current.tmp.abcdef12abcdef12abcdef12abcdef12"
            pending.symlink_to(f".{timestamp}_with_desc.version.abcdef12abcdef12abcdef12abcdef12")
            c2 = load_script("r22_c2_pointer_temp_direct", C2_PATH)
            d = load_script("r22_d_pointer_temp_direct", D_PATH)
            inventory = c2._inspect_description_output_recovery(str(legacy))
            self.assertIn("current", inventory["state"])
            with self.assertRaisesRegex(ValueError, "unresolved|pointer|description"):
                c2._require_clean_description_output(str(legacy))
            with self.assertRaisesRegex(ValueError, "unresolved|pointer|description"):
                d._preferred_cumulus_contexts([d._cumulus_dir_context(str(base))])
            self.assertTrue(pending.is_symlink())
            self.assertEqual(b"accepted legacy A", (legacy / "old-marker.txt").read_bytes())

    def test_d_description_rename_residue_rejects_base_fallback(self):
        """An interrupted patch must not make unpatched production the winner."""
        for patched_visible in (False, True):
            with self.subTest(patched_visible=patched_visible), \
                    tempfile.TemporaryDirectory(prefix="r22-d-patch-residue-") as name:
                output_root = Path(name) / "99-output"
                output_root.mkdir()
                timestamp = "20261002_010203"
                base = output_root / timestamp
                base.mkdir()
                (base / "base-marker.txt").write_bytes(b"unpatched base B")
                patched = output_root / f"{timestamp}_with_desc"
                staged = output_root / f".{timestamp}_with_desc.tmp.interrupted"
                backup = output_root / f".{timestamp}_with_desc.tmp.interrupted.old"
                backup.mkdir()
                (backup / "old-marker.txt").write_bytes(b"complete patched A")
                candidate = patched if patched_visible else staged
                candidate.mkdir()
                (candidate / "new-marker.txt").write_bytes(b"candidate patched B")
                d = load_script("r22_d_patch_residue_selector_direct", D_PATH)
                context = d._cumulus_dir_context(str(base))
                self.assertIsNotNone(context)

                with self.assertRaisesRegex(ValueError, "unresolved|description|backup|staging"):
                    d._preferred_cumulus_contexts([context])

                self.assertEqual(b"unpatched base B", (base / "base-marker.txt").read_bytes())
                self.assertEqual(b"complete patched A", (backup / "old-marker.txt").read_bytes())
                self.assertEqual(b"candidate patched B", (candidate / "new-marker.txt").read_bytes())
                self.assertEqual(patched_visible, patched.exists())

    def test_d_description_rename_residue_blocks_publish_without_side_effects(self):
        with tempfile.TemporaryDirectory(prefix="r22-d-patch-publish-") as name:
            private = Path(name)
            output_root = private / "99-output"
            output_root.mkdir()
            timestamp = "20261002_010203"
            base = output_root / timestamp
            base.mkdir()
            (base / "base-marker.txt").write_bytes(b"unpatched base B")
            staged = output_root / f".{timestamp}_with_desc.tmp.interrupted"
            staged.mkdir()
            (staged / "new-marker.txt").write_bytes(b"candidate patched B")
            backup = output_root / f".{timestamp}_with_desc.tmp.interrupted.old"
            backup.mkdir()
            (backup / "old-marker.txt").write_bytes(b"complete patched A")
            old_release = output_root / "20261001_010203_combine"
            old_release.mkdir()
            latest = private / "latest_yaml"
            latest.symlink_to(old_release, target_is_directory=True)
            csv_file = private / "02-devices_config.csv"
            csv_file.write_bytes(b"fixture only; load_csv is stubbed")
            d = load_script("r22_d_patch_residue_publish_direct", D_PATH)
            devices = {"spine": {"hostname": "spine", "dev_type": "eth"}}

            with mock.patch.object(d.sys, "argv", [
                    "d-hostname2mac.py", "--csv", str(csv_file),
                    "--deployment-scope", "prod", "--switch", "eth", str(base),
                ]), mock.patch.object(d, "load_csv", return_value=devices), \
                    mock.patch.object(d, "_publish_production_cumulus") as publish, \
                    mock.patch.object(d, "_publish_combined_cumulus") as combined, \
                    mock.patch.object(d, "_set_latest_yaml") as set_latest, \
                    mock.patch.object(d, "_archive_combined_sources") as archive, \
                    mock.patch.object(d, "_remove_superseded_cumulus_base") as remove_base, \
                    mock.patch.object(d.shutil, "rmtree") as remove_tree, \
                    redirect_stdout(io.StringIO()):
                with self.assertRaisesRegex(ValueError, "unresolved|description|backup|staging"):
                    d.main()
                publish.assert_not_called()
                combined.assert_not_called()
                set_latest.assert_not_called()
                archive.assert_not_called()
                remove_base.assert_not_called()
                remove_tree.assert_not_called()

            self.assertEqual(str(old_release), os.readlink(latest))
            self.assertEqual(b"unpatched base B", (base / "base-marker.txt").read_bytes())
            self.assertEqual(b"candidate patched B", (staged / "new-marker.txt").read_bytes())
            self.assertEqual(b"complete patched A", (backup / "old-marker.txt").read_bytes())

    def test_c2_orphaned_description_backup_blocks_new_publication(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-crash-residue-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project / source.name).read_bytes())
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"new B candidate")
                backup = private / ".generation_with_desc.tmp.interrupted.old"
                backup.mkdir()
                (backup / "old-marker.txt").write_bytes(b"committed A")
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                c2 = load_script("r22_c2_crash_residue_direct", C2_PATH)
                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_load_description_intent", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_lines", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_devices", return_value=[]), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "unresolved|orphan|backup"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                self.assertEqual(b"committed A", (backup / "old-marker.txt").read_bytes())
                self.assertFalse((private / "generation_with_desc").exists())
        finally:
            fixture.cleanup()

    def test_c2_cold_inventory_classifies_both_crash_windows_without_mutating_or_publishing(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            for after_new_rename in (False, True):
                with self.subTest(after_new_rename=after_new_rename), \
                        tempfile.TemporaryDirectory(prefix="r22-c2-cold-inventory-") as name:
                    private = Path(name)
                    source = private / "02-devices_config.csv"
                    source.write_bytes((project / source.name).read_bytes())
                    generation = private / "generation"
                    generation.mkdir()
                    (generation / "new-marker.txt").write_bytes(b"new input B")
                    final = private / "generation_with_desc"
                    staging = private / ".generation_with_desc.tmp.interrupted"
                    backup = private / ".generation_with_desc.tmp.interrupted.old"
                    backup.mkdir()
                    (backup / "old-marker.txt").write_bytes(b"complete old A")
                    candidate = final if after_new_rename else staging
                    candidate.mkdir()
                    (candidate / "new-marker.txt").write_bytes(b"candidate B")
                    latest = private / "latest"
                    latest.symlink_to(final.name, target_is_directory=True)
                    dot = private / "topology.dot"
                    dot.write_text("", encoding="utf-8")
                    c2 = load_script("r22_c2_cold_inventory_direct", C2_PATH)

                    expected_state = (
                        "new-visible-before-cleanup" if after_new_rename
                        else "gap-after-old-rename"
                    )
                    observed = c2._inspect_description_output_recovery(str(final))
                    self.assertEqual(expected_state, observed["state"])
                    self.assertEqual(str(backup), observed["old_candidate"])
                    self.assertEqual(
                        None if after_new_rename else str(staging),
                        observed["staging_candidate"],
                    )
                    self.assertEqual(b"complete old A", (backup / "old-marker.txt").read_bytes())
                    self.assertEqual(b"candidate B", (candidate / "new-marker.txt").read_bytes())
                    self.assertEqual(final.name, os.readlink(latest))
                    with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                            mock.patch.object(c2, "_load_description_intent", side_effect=AssertionError("must not patch")), \
                            redirect_stdout(io.StringIO()), \
                            self.assertRaisesRegex(ValueError, "unresolved|cold|backup"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                    self.assertEqual(expected_state, c2._inspect_description_output_recovery(str(final))["state"])
                    self.assertEqual(b"complete old A", (backup / "old-marker.txt").read_bytes())
                    self.assertEqual(b"candidate B", (candidate / "new-marker.txt").read_bytes())
                    self.assertEqual(final.name, os.readlink(latest))
        finally:
            fixture.cleanup()

    def test_c2_cold_inventory_treats_symlinked_or_multiple_residue_as_ambiguous(self):
        with tempfile.TemporaryDirectory(prefix="r22-c2-ambiguous-residue-") as name:
            private = Path(name)
            final = private / "generation_with_desc"
            final.mkdir()
            (final / "old-marker.txt").write_bytes(b"stable A")
            residue = private / ".generation_with_desc.tmp.untrusted.old"
            residue.symlink_to(final, target_is_directory=True)
            c2 = load_script("r22_c2_ambiguous_residue_direct", C2_PATH)
            observed = c2._inspect_description_output_recovery(str(final))
            self.assertEqual("ambiguous", observed["state"])
            self.assertIsNone(observed["old_candidate"])
            self.assertTrue(residue.is_symlink())
            self.assertEqual(b"stable A", (final / "old-marker.txt").read_bytes())
            residue.unlink()
            first = private / ".generation_with_desc.tmp.first.old"
            second = private / ".generation_with_desc.tmp.second.old"
            first.mkdir()
            second.mkdir()
            observed = c2._inspect_description_output_recovery(str(final))
            self.assertEqual("ambiguous", observed["state"])
            self.assertIsNone(observed["old_candidate"])
            self.assertEqual(b"stable A", (final / "old-marker.txt").read_bytes())

    def test_c1_global_reader_rejects_valid_b_when_load_pinned_a(self):
        """DHCP generation must share LOAD's exact global input authority."""
        with tempfile.TemporaryDirectory(prefix="r22-c1-global-authority-") as name:
            source = Path(name) / "01-global.yaml"
            source_a = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_bytes()
            source_b = source_a.replace(b"192.0.2.53", b"192.0.2.54")
            self.assertNotEqual(source_a, source_b)
            source.write_bytes(source_b)
            c1 = load_script("r22_c1_global_authority_direct", C1_PATH)
            with mock.patch.dict(os.environ, {
                "HTTP_EXPECTED_GLOBAL_SHA256": hashlib.sha256(source_b).hexdigest(),
            }):
                c1.load_project_global(str(source))
            authority = hashlib.sha256(source_a).hexdigest()
            with mock.patch.dict(os.environ, {
                "HTTP_EXPECTED_GLOBAL_SHA256": authority,
            }), self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                c1.load_project_global(str(source))

    def test_c2_global_reader_rejects_valid_b_when_load_pinned_a(self):
        """A child must reject a different legal global document before parsing it."""
        with tempfile.TemporaryDirectory(prefix="r22-c2-global-authority-") as name:
            source = Path(name) / "01-global.yaml"
            source_a = (ROOT / "DAY0-Prepare/template/01-global.yaml").read_bytes()
            source_b = source_a.replace(b"192.0.2.53", b"192.0.2.54")
            self.assertNotEqual(source_a, source_b)
            source.write_bytes(source_b)
            c2 = load_script("r22_c2_global_authority_direct", C2_PATH)
            with mock.patch.object(c2, "_GLOBAL_FILE", str(source)), \
                    mock.patch.dict(os.environ, {
                        "HTTP_EXPECTED_GLOBAL_SHA256": hashlib.sha256(source_b).hexdigest(),
                    }):
                c2._load_global_document()
            authority = hashlib.sha256(source_a).hexdigest()
            with mock.patch.object(c2, "_GLOBAL_FILE", str(source)), \
                    mock.patch.dict(os.environ, {
                        "HTTP_EXPECTED_GLOBAL_SHA256": authority,
                    }), self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                c2._load_global_document()

    def test_c2_description_rejects_ancestor_symlink_aba_during_csv_read(self):
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0], rows_b[1][0] = "Border03", "Border04"
        fixture_a, project_a, errors_a, _ = run_v2_mlag_setup_preflight(rows_a)
        fixture_b, project_b, errors_b, _ = run_v2_mlag_setup_preflight(rows_b)
        try:
            self.assertEqual([], errors_a)
            self.assertEqual([], errors_b)
            with tempfile.TemporaryDirectory(prefix="r22-c2-ancestor-aba-") as name:
                private = Path(name)
                source_a, source_b = private / "A", private / "B"
                source_a.mkdir()
                source_b.mkdir()
                filename = "02-devices_config.csv"
                (source_a / filename).write_bytes((project_a / filename).read_bytes())
                (source_b / filename).write_bytes((project_b / filename).read_bytes())
                current = private / "current"
                current.symlink_to(source_a, target_is_directory=True)
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"candidate")
                existing = private / "generation_with_desc"
                existing.mkdir()
                (existing / "old-marker.txt").write_bytes(b"accepted-old")
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                c2 = load_script("r22_c2_ancestor_aba_direct", C2_PATH)
                real_read = c2._load_csv_hostnames
                observed = {}

                def read_b_then_restore_a():
                    current.unlink()
                    current.symlink_to(source_b, target_is_directory=True)
                    try:
                        hosts = real_read()
                        observed["hosts"] = hosts
                        return hosts
                    finally:
                        current.unlink()
                        current.symlink_to(source_a, target_is_directory=True)

                with mock.patch.object(c2, "_CSV_FILE", str(current / filename)), \
                        mock.patch.object(c2, "_load_csv_hostnames", side_effect=read_b_then_restore_a), \
                        mock.patch.object(c2, "_load_description_intent", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_lines", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_devices", return_value=[]), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                self.assertEqual({"border03", "border04"}, observed.get("hosts"))
                self.assertEqual(b"accepted-old", (existing / "old-marker.txt").read_bytes())
                self.assertFalse((existing / "new-marker.txt").exists())
                self.assertFalse(any(private.glob(".generation_with_desc.tmp.*")))
        finally:
            fixture_b.cleanup()
            fixture_a.cleanup()

    def test_c2_description_rejects_transient_missing_csv_during_second_read(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _ = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-missing-aba-") as name:
                private = Path(name)
                source_a = private / "A"
                source_a.mkdir()
                filename = "02-devices_config.csv"
                (source_a / filename).write_bytes((project / filename).read_bytes())
                current = private / "current"
                current.symlink_to(source_a, target_is_directory=True)
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"candidate")
                existing = private / "generation_with_desc"
                existing.mkdir()
                (existing / "old-marker.txt").write_bytes(b"accepted-old")
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                c2 = load_script("r22_c2_missing_aba_direct", C2_PATH)
                real_read = c2._load_csv_hostnames
                observed = {}

                def read_missing_then_restore_a():
                    current.unlink()
                    current.symlink_to(private / "missing", target_is_directory=True)
                    try:
                        hosts = real_read()
                        observed["hosts"] = hosts
                        return hosts
                    finally:
                        current.unlink()
                        current.symlink_to(source_a, target_is_directory=True)

                with mock.patch.object(c2, "_CSV_FILE", str(current / filename)), \
                        mock.patch.object(c2, "_load_csv_hostnames", side_effect=read_missing_then_restore_a), \
                        mock.patch.object(c2, "_load_description_intent", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_lines", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_devices", return_value=[]), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                self.assertEqual(set(), observed.get("hosts"))
                self.assertEqual(b"accepted-old", (existing / "old-marker.txt").read_bytes())
                self.assertFalse((existing / "new-marker.txt").exists())
                self.assertFalse(any(private.glob(".generation_with_desc.tmp.*")))
        finally:
            fixture.cleanup()

    def test_c2_declined_description_prompt_rechecks_csv_before_followup(self):
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0], rows_b[1][0] = "Border03", "Border04"
        fixture_a, project_a, errors_a, _ = run_v2_mlag_setup_preflight(rows_a)
        fixture_b, project_b, errors_b, _ = run_v2_mlag_setup_preflight(rows_b)
        try:
            self.assertEqual([], errors_a)
            self.assertEqual([], errors_b)
            with tempfile.TemporaryDirectory(prefix="r22-c2-decline-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project_a / source.name).read_bytes())
                replacement = (project_b / source.name).read_bytes()
                c2 = load_script("r22_c2_decline_direct", C2_PATH)
                with mock.patch.object(c2, "_CSV_FILE", str(source)):
                    baseline = c2._csv_input_authority()

                    def decline_after_edit(*_args, **_kwargs):
                        source.write_bytes(replacement)
                        return "n"

                    with mock.patch.object(c2, "_timed_input", side_effect=decline_after_edit), \
                            redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                            c2.prompt_patch_descriptions(
                                str(private / "generation"),
                                expected_csv_authority=baseline,
                            )
                self.assertEqual(replacement, source.read_bytes())
                self.assertFalse((private / "generation_with_desc").exists())
        finally:
            fixture_b.cleanup()
            fixture_a.cleanup()

    def test_c2_missing_dot_prompt_rechecks_csv_before_followup(self):
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0], rows_b[1][0] = "Border03", "Border04"
        fixture_a, project_a, errors_a, _ = run_v2_mlag_setup_preflight(rows_a)
        fixture_b, project_b, errors_b, _ = run_v2_mlag_setup_preflight(rows_b)
        try:
            self.assertEqual([], errors_a)
            self.assertEqual([], errors_b)
            with tempfile.TemporaryDirectory(prefix="r22-c2-no-dot-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project_a / source.name).read_bytes())
                replacement = (project_b / source.name).read_bytes()
                c2 = load_script("r22_c2_no_dot_direct", C2_PATH)
                with mock.patch.object(c2, "_CSV_FILE", str(source)):
                    baseline = c2._csv_input_authority()

                    def no_dot_after_edit(_suffix):
                        source.write_bytes(replacement)
                        return []

                    with mock.patch.object(c2, "_timed_input", return_value="y"), \
                            mock.patch.object(c2, "_topology_dot_files", side_effect=no_dot_after_edit), \
                            redirect_stdout(io.StringIO()):
                        with self.assertRaisesRegex(ValueError, "input|source|authority|drift|chang"):
                            c2.prompt_patch_descriptions(
                                str(private / "generation"),
                                expected_csv_authority=baseline,
                            )
                self.assertEqual(replacement, source.read_bytes())
                self.assertFalse((private / "generation_with_desc").exists())
        finally:
            fixture_b.cleanup()
            fixture_a.cleanup()

    def test_c2_description_staging_commits_unchanged_input_and_keeps_old_on_patch_error(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-stage-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project / source.name).read_bytes())
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"new-generation")
                existing = private / "generation_with_desc"
                existing.mkdir()
                old_artifact = existing / "old-marker.txt"
                old_artifact.write_bytes(b"previous-generation")
                c2 = load_script("r22_c2_staging_direct", C2_PATH)
                patches = (
                    mock.patch.object(c2, "_CSV_FILE", str(source)),
                    mock.patch.object(c2, "_load_description_intent", return_value=[]),
                    mock.patch.object(c2, "_load_dot_lines", return_value=[]),
                    mock.patch.object(c2, "_load_dot_devices", return_value=[]),
                )
                with patches[0], patches[1], patches[2], patches[3], \
                        redirect_stdout(io.StringIO()):
                    c2._run_patch_descriptions(str(dot), str(generation))
                pointer = private / "generation_with_desc_current"
                self.assertEqual(b"new-generation", (pointer / "new-marker.txt").read_bytes())
                self.assertEqual(b"previous-generation", old_artifact.read_bytes())
                self.assertEqual(source.read_bytes(), (project / source.name).read_bytes())

                old_artifact.write_bytes(b"stable-before-error")
                selected_before_error = os.readlink(pointer)
                with patches[0], patches[1], patches[2], patches[3], \
                        mock.patch.object(c2, "_load_csv_hostnames", side_effect=ValueError("patch failed")), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "patch failed"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                self.assertEqual(b"stable-before-error", old_artifact.read_bytes())
                self.assertEqual(selected_before_error, os.readlink(pointer))
                self.assertEqual(b"new-generation", (pointer / "new-marker.txt").read_bytes())
                self.assertFalse(any(private.glob(".generation_with_desc.tmp.*")))
        finally:
            fixture.cleanup()

    def test_c2_description_interrupted_after_pointer_replace_keeps_both_complete_versions(self):
        rows = V2MlagSetupPreflightTests().pair()
        fixture, project, errors, _warnings = run_v2_mlag_setup_preflight(rows)
        try:
            self.assertEqual([], errors)
            with tempfile.TemporaryDirectory(prefix="r22-c2-second-rename-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes((project / source.name).read_bytes())
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"new-generation")
                existing = private / "generation_with_desc"
                existing.mkdir()
                (existing / "old-marker.txt").write_bytes(b"accepted-old")
                latest = private / "latest"
                latest.symlink_to(existing.name, target_is_directory=True)
                c2 = load_script("r22_c2_second_rename_direct", C2_PATH)
                real_replace = c2.os.replace
                observed = {"pointer_replace": False}

                def interrupt_after_pointer_replace(src, dst, *args, **kwargs):
                    result = real_replace(src, dst, *args, **kwargs)
                    if dst == str(private / "generation_with_desc_current"):
                        observed["pointer_replace"] = True
                        raise RuntimeError("interrupted after pointer replace")
                    return result

                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_load_description_intent", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_lines", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_devices", return_value=[]), \
                        mock.patch.object(c2.os, "replace", side_effect=interrupt_after_pointer_replace), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "interrupted after pointer replace"):
                        c2._run_patch_descriptions(str(dot), str(generation))

                self.assertTrue(observed["pointer_replace"])
                self.assertEqual(b"accepted-old", (existing / "old-marker.txt").read_bytes())
                self.assertFalse((existing / "new-marker.txt").exists())
                self.assertEqual(b"accepted-old", (latest / "old-marker.txt").read_bytes())
                pointer = private / "generation_with_desc_current"
                self.assertTrue(pointer.is_symlink())
                self.assertEqual(b"new-generation", (pointer / "new-marker.txt").read_bytes())
                self.assertFalse(any(private.glob(".generation_with_desc.tmp.*")))
        finally:
            fixture.cleanup()

    def test_c2_description_second_read_rejects_same_inode_drift_before_replacing_existing_same_name_output(self):
        # These are two independently legal project inputs, not malformed CSV
        # used to provoke an unrelated parser failure.
        rows_a = V2MlagSetupPreflightTests().pair()
        rows_b = copy.deepcopy(rows_a)
        rows_b[0][0] = "Border03"
        rows_b[1][0] = "Border04"
        fixture_a, project_a, errors_a, _warnings_a = run_v2_mlag_setup_preflight(rows_a)
        fixture_b, project_b, errors_b, _warnings_b = run_v2_mlag_setup_preflight(rows_b)
        try:
            self.assertEqual([], errors_a)
            self.assertEqual([], errors_b)
            bytes_a = (project_a / "02-devices_config.csv").read_bytes()
            bytes_b = (project_b / "02-devices_config.csv").read_bytes()
            self.assertNotEqual(bytes_a, bytes_b)
            self.assertEqual(len(bytes_a), len(bytes_b))

            with tempfile.TemporaryDirectory(prefix="r22-c2-second-read-") as name:
                private = Path(name)
                source = private / "02-devices_config.csv"
                source.write_bytes(bytes_a)
                initial = source.stat()
                dot = private / "topology.dot"
                dot.write_text("", encoding="utf-8")
                generation = private / "generation"
                generation.mkdir()
                (generation / "new-marker.txt").write_bytes(b"new-generation")
                existing = private / "generation_with_desc"
                existing.mkdir()
                old_artifact = existing / "old-marker.txt"
                old_artifact.write_bytes(b"existing-same-name-before-drift")

                c2 = load_script("r22_c2_second_read_direct", C2_PATH)
                real_copytree = c2.shutil.copytree
                real_read = c2._load_csv_hostnames
                observations = {}

                def mutate_after_first_output_copy(src, dst, *args, **kwargs):
                    result = real_copytree(src, dst, *args, **kwargs)
                    source.write_bytes(bytes_b)
                    os.utime(source, ns=(initial.st_atime_ns, initial.st_mtime_ns))
                    changed = source.stat()
                    observations["same_inode"] = changed.st_ino == initial.st_ino
                    observations["same_size"] = changed.st_size == initial.st_size
                    observations["same_mtime"] = changed.st_mtime_ns == initial.st_mtime_ns
                    return result

                def observe_real_conditional_read():
                    hosts = real_read()
                    observations["second_read_hosts"] = hosts
                    return hosts

                failure = None
                with (
                    mock.patch.object(c2, "_CSV_FILE", str(source)),
                    mock.patch.object(c2.shutil, "copytree", side_effect=mutate_after_first_output_copy),
                    mock.patch.object(c2, "_load_csv_hostnames", side_effect=observe_real_conditional_read),
                    mock.patch.object(c2, "_load_description_intent", return_value=[]),
                    mock.patch.object(c2, "_load_dot_lines", return_value=[]),
                    mock.patch.object(c2, "_load_dot_devices", return_value=[]),
                    redirect_stdout(io.StringIO()),
                ):
                    try:
                        c2._run_patch_descriptions(str(dot), str(generation))
                    except Exception as error:  # The contract requires an explicit refusal.
                        failure = error

                self.assertTrue(observations.get("same_inode"), observations)
                self.assertTrue(observations.get("same_size"), observations)
                self.assertTrue(observations.get("same_mtime"), observations)
                self.assertEqual(
                    {"border03", "border04"},
                    observations.get("second_read_hosts"),
                    observations,
                )
                self.assertIsNotNone(
                    failure,
                    "c2 accepted a second read of legal B after generating from legal A",
                )
                self.assertRegex(str(failure).lower(), r"input|source|authority|drift|chang")
                self.assertEqual(b"existing-same-name-before-drift", old_artifact.read_bytes())
                self.assertFalse((existing / "new-marker.txt").exists())
        finally:
            fixture_b.cleanup()
            fixture_a.cleanup()


if __name__ == "__main__":
    unittest.main()
