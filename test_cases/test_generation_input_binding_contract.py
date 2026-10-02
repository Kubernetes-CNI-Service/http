#!/usr/bin/env python3
"""Direct regression for generator input authority across a second read."""

from __future__ import annotations

import copy
from contextlib import redirect_stdout
import hashlib
import io
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


class GenerationInputBindingDirectTests(unittest.TestCase):
    """A generator must not replace same-named output across input versions."""

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
                self.assertEqual(b"new-generation", (existing / "new-marker.txt").read_bytes())
                self.assertFalse(old_artifact.exists())
                self.assertEqual(source.read_bytes(), (project / source.name).read_bytes())

                old_artifact.write_bytes(b"stable-before-error")
                with patches[0], patches[1], patches[2], patches[3], \
                        mock.patch.object(c2, "_load_csv_hostnames", side_effect=ValueError("patch failed")), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(ValueError, "patch failed"):
                        c2._run_patch_descriptions(str(dot), str(generation))
                self.assertEqual(b"stable-before-error", old_artifact.read_bytes())
                self.assertEqual(b"new-generation", (existing / "new-marker.txt").read_bytes())
                self.assertFalse(any(private.glob(".generation_with_desc.tmp.*")))
        finally:
            fixture.cleanup()

    def test_c2_description_interrupted_after_second_rename_restores_old_directory(self):
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
                observed = {"second_rename": False}

                def interrupt_after_second_rename(src, dst, *args, **kwargs):
                    result = real_replace(src, dst, *args, **kwargs)
                    if dst == str(existing) and str(src).startswith(
                        str(private / ".generation_with_desc.tmp.")
                    ):
                        observed["second_rename"] = True
                        raise RuntimeError("interrupted after second rename")
                    return result

                with mock.patch.object(c2, "_CSV_FILE", str(source)), \
                        mock.patch.object(c2, "_load_description_intent", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_lines", return_value=[]), \
                        mock.patch.object(c2, "_load_dot_devices", return_value=[]), \
                        mock.patch.object(c2.os, "replace", side_effect=interrupt_after_second_rename), \
                        redirect_stdout(io.StringIO()):
                    with self.assertRaisesRegex(RuntimeError, "interrupted after second rename"):
                        c2._run_patch_descriptions(str(dot), str(generation))

                self.assertTrue(observed["second_rename"])
                self.assertEqual(b"accepted-old", (existing / "old-marker.txt").read_bytes())
                self.assertFalse((existing / "new-marker.txt").exists())
                self.assertEqual(b"accepted-old", (latest / "old-marker.txt").read_bytes())
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
