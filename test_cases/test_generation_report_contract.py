#!/usr/bin/env python3
"""REQ-16 R16-9 direct contract for the first governed generation report.

The expected wire-blob fingerprints and schema are fixed independently of the
future producer.  All projects and published links in this module are private
temporary fixtures; no host key, deployment root, or service is touched.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.test_ssh_key_preparation_contract import public_line


ROOT = Path(__file__).resolve().parents[1]
REPORT_HELPER = ROOT / "tools/generation_report.py"
LAPTOP_FINGERPRINT = "SHA256:MiTPEMIPDeIyBsV88xw/beaNZDfLZ3+t8BcYvmzNQqk"
MANAGEMENT_FINGERPRINT = "SHA256:I+cLpWGbiZDeDs5PZ1FV1vPBwzgMEST7Wjs4BUYKywU"
REPORT_KEYS = frozenset({
    "schema_version", "record_type", "project", "release_id",
    "generated_at", "public_keys",
})


def report_helper():
    if not REPORT_HELPER.is_file():
        raise AssertionError("R16-9 governed producer tools/generation_report.py is absent")
    spec = importlib.util.spec_from_file_location("r16_generation_report_contract", REPORT_HELPER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def parent_release(project: Path) -> dict[str, object]:
    """Independent schema-2 parent fixture with its real basis digest shape."""
    basis: dict[str, object] = {
        "project": project.name,
        "deployment_scope": "all",
        "switch_scope": "all",
        "dhcp_status": "disabled",
        "inputs": {},
        "input_sources": {},
        "components": {},
        "inventory": [],
    }
    release_id = hashlib.sha256(json.dumps(
        basis, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()[:20]
    return {
        "schema_version": 2,
        "release_id": release_id,
        "generated_at": "2026-09-24T12:00:00+08:00",
        "validation": "passed",
        **basis,
    }


class GenerationReportContract(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="r16-report-direct-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.project = self.root / "DAY0-Prepare/demo"
        self.project.mkdir(parents=True, mode=0o700)
        self.published = self.root / "ztp/config/publickey"
        self.published.mkdir(parents=True, mode=0o700)
        self.laptop = public_line("ssh-ed25519", 31, "laptop")
        self.management = public_line("ssh-ed25519", 47, "management")
        for name, content in (
            ("laptop.pub", self.laptop),
            ("mgmt-server.pub", self.management),
        ):
            leaf = self.project / name
            leaf.write_bytes(content)
            leaf.chmod(0o644)
            (self.published / name).symlink_to(leaf)
        self.parent = parent_release(self.project)
        self.output = self.project / "99-output-ztp"
        self.output.mkdir(mode=0o700)
        (self.output / "current-release.json").write_text(
            json.dumps(self.parent, sort_keys=True) + "\n", encoding="utf-8",
        )

    def build(self):
        return report_helper().build_report(
            self.project, self.parent, published_dir=self.published,
        )

    def publish(self):
        helper = report_helper()
        report = helper.build_report(
            self.project, self.parent, published_dir=self.published,
        )
        candidate = helper.prepare_generation_report(self.project, report)
        self.assertFalse((self.output / "generation-report.json").exists())
        helper.commit_prepared_generation_report(candidate)
        return helper, report

    def test_schema3_uses_pinned_ssh_wire_fingerprints_not_public_lines(self):
        # Independent OpenSSH oracle: these two literals were measured with
        # /usr/bin/ssh-keygen -lf on the fixed public_line fixtures.
        for line, expected in (
            (self.laptop, LAPTOP_FINGERPRINT),
            (self.management, MANAGEMENT_FINGERPRINT),
        ):
            result = subprocess.run(
                ["/usr/bin/ssh-keygen", "-lf", "-"], input=line,
                capture_output=True, check=True,
            )
            self.assertIn(expected.encode(), result.stdout)
        report = self.build()
        self.assertEqual(REPORT_KEYS, set(report))
        self.assertEqual(3, report["schema_version"])
        self.assertEqual("http-v3-public-key-generation-report", report["record_type"])
        self.assertEqual("demo", report["project"])
        self.assertEqual(self.parent["release_id"], report["release_id"])
        self.assertEqual(self.parent["generated_at"], report["generated_at"])
        self.assertEqual([
            {
                "role": "laptop", "name": "laptop.pub",
                "algorithm": "ssh-ed25519", "fingerprint": LAPTOP_FINGERPRINT,
            },
            {
                "role": "management", "name": "mgmt-server.pub",
                "algorithm": "ssh-ed25519", "fingerprint": MANAGEMENT_FINGERPRINT,
            },
        ], report["public_keys"])
        self.assertNotIn("report_format_version", report)
        serialized = json.dumps(report, sort_keys=True)
        self.assertNotIn("ssh-ed25519 AAAA", serialized)
        self.assertNotIn("PRIVATE KEY", serialized)

        # R16-3 ignores comments; whole-line SHA or HOME-path inference fails.
        (self.project / "laptop.pub").write_bytes(
            self.laptop.replace(b" laptop\n", b" different-comment\n"),
        )
        self.assertEqual(LAPTOP_FINGERPRINT, self.build()["public_keys"][0]["fingerprint"])

    def test_published_link_must_bind_this_projects_same_name_regular_leaf(self):
        helper = report_helper()
        other = self.root / "DAY0-Prepare/other"
        other.mkdir(mode=0o700)
        (other / "laptop.pub").write_bytes(self.laptop)
        published = self.published / "laptop.pub"
        published.unlink()
        published.symlink_to(other / "laptop.pub")
        with self.assertRaises(Exception):
            helper.build_report(self.project, self.parent, published_dir=self.published)
        published.unlink()
        published.symlink_to(self.project / "mgmt-server.pub")
        with self.assertRaises(Exception):
            helper.build_report(self.project, self.parent, published_dir=self.published)
        published.unlink()
        published.write_bytes(self.laptop)  # A copied regular leaf is not the published link.
        with self.assertRaises(Exception):
            helper.build_report(self.project, self.parent, published_dir=self.published)

    def test_missing_empty_duplicate_and_changed_published_keys_fail_closed(self):
        helper = report_helper()
        management = self.project / "mgmt-server.pub"
        management.write_bytes(b"")
        with self.assertRaises(Exception):
            helper.build_report(self.project, self.parent, published_dir=self.published)
        management.write_bytes(self.laptop)
        with self.assertRaises(Exception):
            helper.build_report(self.project, self.parent, published_dir=self.published)
        management.write_bytes(self.management)
        self.publish()
        management.write_bytes(public_line("ssh-ed25519", 48, "rotated"))
        with self.assertRaises(Exception):
            helper.inspect_generation_report(self.project, published_dir=self.published)

    def test_inspector_binds_parent_release_and_does_not_read_ad_hoc_root_file(self):
        helper, report = self.publish()
        ad_hoc = self.project / "generation-report.json"
        ad_hoc_bytes = b'{"schema_version":2,"report_format_version":1,"untrusted":"ad-hoc"}\n'
        ad_hoc.write_bytes(ad_hoc_bytes)
        self.assertEqual(
            report,
            helper.inspect_generation_report(self.project, published_dir=self.published),
        )
        self.assertEqual(ad_hoc_bytes, ad_hoc.read_bytes())
        changed = dict(self.parent, release_id="a" * 20)
        (self.output / "current-release.json").write_text(
            json.dumps(changed) + "\n", encoding="utf-8",
        )
        with self.assertRaises(Exception):
            helper.inspect_generation_report(self.project, published_dir=self.published)
        self.assertEqual(ad_hoc_bytes, ad_hoc.read_bytes())

    def test_prepare_does_not_publish_and_failed_commit_preserves_old_record(self):
        helper, old = self.publish()
        path = self.output / "generation-report.json"
        old_bytes = path.read_bytes()
        candidate = helper.prepare_generation_report(self.project, old)
        self.assertEqual(old_bytes, path.read_bytes())
        with mock.patch.object(helper.os, "replace", side_effect=OSError("injected rename failure")):
            with self.assertRaises(Exception):
                helper.commit_prepared_generation_report(candidate)
        self.assertEqual(old_bytes, path.read_bytes())
        self.assertEqual(old, json.loads(path.read_text(encoding="utf-8")))

    def test_existing_symlink_hardlink_fifo_and_unknown_version_are_not_overwritten(self):
        helper = report_helper()
        report = self.build()
        destination = self.output / "generation-report.json"
        sentinel = self.root / "external-sentinel.json"
        sentinel.write_bytes(b"outside\n")
        for shape in ("symlink", "hardlink", "fifo", "unknown-version"):
            with self.subTest(shape=shape):
                destination.unlink(missing_ok=True)
                if shape == "symlink":
                    destination.symlink_to(sentinel)
                elif shape == "hardlink":
                    os.link(sentinel, destination)
                elif shape == "fifo":
                    os.mkfifo(destination)
                else:
                    destination.write_text('{"schema_version":999}\n', encoding="utf-8")
                with self.assertRaises(Exception):
                    candidate = helper.prepare_generation_report(self.project, report)
                    helper.commit_prepared_generation_report(candidate)
                self.assertEqual(b"outside\n", sentinel.read_bytes())
                if shape == "unknown-version":
                    self.assertEqual(b'{"schema_version":999}\n', destination.read_bytes())
                destination.unlink()

    def test_existing_schema3_malformed_or_duplicate_identity_blocks_replacement(self):
        helper = report_helper()
        replacement = self.build()
        destination = self.output / "generation-report.json"
        for defect in (
            "malformed-release-id", "naive-timestamp", "malformed-algorithm",
            "duplicate-public-identity",
        ):
            with self.subTest(defect=defect):
                old = json.loads(json.dumps(replacement))
                if defect == "malformed-release-id":
                    old["release_id"] = "g" * 20  # Not hexadecimal.
                elif defect == "naive-timestamp":
                    old["generated_at"] = "2026-09-24T12:00:00"  # No timezone.
                elif defect == "malformed-algorithm":
                    old["public_keys"][0]["algorithm"] = "ssh-ed25519\ncorrupt"
                else:
                    old["public_keys"][1]["algorithm"] = old["public_keys"][0]["algorithm"]
                    old["public_keys"][1]["fingerprint"] = old["public_keys"][0]["fingerprint"]
                old_bytes = (json.dumps(old, sort_keys=True) + "\n").encode("utf-8")
                destination.write_bytes(old_bytes)
                with self.assertRaises(helper.GenerationReportError):
                    helper.prepare_generation_report(self.project, replacement)
                self.assertEqual(old_bytes, destination.read_bytes())
                self.assertEqual([], list(self.output.glob(".generation-report.*.tmp")))

    def test_directory_fsync_failure_after_replace_exposes_new_record_but_no_success(self):
        helper, old = self.publish()
        destination = self.output / "generation-report.json"
        old_bytes = destination.read_bytes()
        (self.project / "mgmt-server.pub").write_bytes(
            public_line("ssh-ed25519", 48, "rotated"),
        )
        replacement = helper.build_report(
            self.project, self.parent, published_dir=self.published,
        )
        self.assertNotEqual(old, replacement)
        candidate = helper.prepare_generation_report(self.project, replacement)
        with mock.patch.object(
            helper.os, "fsync", side_effect=OSError("injected directory fsync failure"),
        ) as fsync:
            with self.assertRaisesRegex(OSError, "injected directory fsync failure"):
                helper.commit_prepared_generation_report(candidate)
        fsync.assert_called_once()
        self.assertNotEqual(old_bytes, destination.read_bytes())
        self.assertEqual(replacement, json.loads(destination.read_text(encoding="utf-8")))
        self.assertFalse(candidate.temporary.exists())
        self.assertFalse(helper.discard_prepared_generation_report(candidate))

    def test_commit_rejects_postcheck_parent_swap_without_outside_write(self):
        """The final check must bind the parent of the actual rename, not its path."""
        helper, report = self.publish()  # No-injection commit control.
        candidate = helper.prepare_generation_report(self.project, report)
        outside = self.root / "outside-commit"
        outside.mkdir(mode=0o700)
        sentinel = outside / "generation-report.json"
        sentinel_bytes = b"outside commit sentinel must not change\n"
        sentinel.write_bytes(sentinel_bytes)
        (outside / candidate.temporary.name).write_bytes(b"attacker same-name source\n")
        held_original = self.project / "99-output-ztp.held-commit"
        real_replace = os.replace
        injected = []

        def swap_then_replace(source, destination, *args, **kwargs):
            if (Path(source).name == candidate.temporary.name
                    and Path(destination).name == candidate.destination.name
                    and not injected):
                self.output.rename(held_original)
                self.output.symlink_to(outside, target_is_directory=True)
                injected.append((Path(source).name, Path(destination).name))
            return real_replace(source, destination, *args, **kwargs)

        try:
            with mock.patch.object(helper.os, "replace", side_effect=swap_then_replace):
                with self.assertRaises(Exception):
                    helper.commit_prepared_generation_report(candidate)
        finally:
            if self.output.is_symlink():
                self.output.unlink()
            if held_original.exists():
                held_original.rename(self.output)
        self.assertEqual([(candidate.temporary.name, candidate.destination.name)], injected)
        self.assertEqual(sentinel_bytes, sentinel.read_bytes())

    def test_discard_postcheck_parent_swap_cannot_unlink_outside_name(self):
        """The staged inode must be unlinked only relative to its held parent."""
        helper = report_helper()
        report = self.build()
        control = helper.prepare_generation_report(self.project, report)
        self.assertTrue(helper.discard_prepared_generation_report(control))
        self.assertFalse(control.temporary.exists())
        candidate = helper.prepare_generation_report(self.project, report)
        outside = self.root / "outside-discard"
        outside.mkdir(mode=0o700)
        sentinel = outside / candidate.temporary.name
        sentinel_bytes = b"outside staged-name sentinel must not change\n"
        sentinel.write_bytes(sentinel_bytes)
        held_original = self.project / "99-output-ztp.held-discard"
        real_unlink = os.unlink
        real_path_unlink = Path.unlink
        injected = []

        def inject_before_unlink(path):
            if Path(path).name == candidate.temporary.name and not injected:
                self.output.rename(held_original)
                self.output.symlink_to(outside, target_is_directory=True)
                injected.append(Path(path).name)

        def swap_then_unlink(path, *args, **kwargs):
            inject_before_unlink(path)
            return real_unlink(path, *args, **kwargs)

        def swap_then_path_unlink(path, *args, **kwargs):
            # CPython pathlib can retain the original os.unlink on its
            # accessor; intercept both the current Path API and a future
            # descriptor-relative os.unlink implementation.
            inject_before_unlink(path)
            return real_path_unlink(path, *args, **kwargs)

        try:
            with mock.patch.object(helper.os, "unlink", side_effect=swap_then_unlink), \
                    mock.patch.object(helper.Path, "unlink", new=swap_then_path_unlink):
                try:
                    discarded = helper.discard_prepared_generation_report(candidate)
                except Exception:
                    discarded = False
        finally:
            if self.output.is_symlink():
                self.output.unlink()
            if held_original.exists():
                held_original.rename(self.output)
        self.assertEqual([candidate.temporary.name], injected)
        self.assertTrue(sentinel.is_file(),
                        "outside same-name sentinel was deleted by discard")
        self.assertEqual(sentinel_bytes, sentinel.read_bytes())
        if discarded:
            self.assertFalse(candidate.temporary.exists(),
                             "successful discard must remove the original staged inode")

    def test_prepare_parent_swap_at_create_never_writes_outside_directory(self):
        helper = report_helper()
        report = self.build()
        control = helper.prepare_generation_report(self.project, report)
        self.assertTrue(control.temporary.is_file())
        self.assertTrue(helper.discard_prepared_generation_report(control))

        outside = self.root / "outside-prepare-create"
        outside.mkdir(mode=0o700)
        held_original = self.project / "99-output-ztp.held-prepare-create"
        real_open = os.open
        real_fsync = os.fsync
        injected: list[str] = []
        outside_creates: list[bool] = []
        outside_writes: list[tuple[str, bytes]] = []

        def swap_at_staged_create(path, flags, *args, **kwargs):
            if (flags & os.O_CREAT and ".generation-report." in Path(path).name
                    and not injected):
                self.output.rename(held_original)
                self.output.symlink_to(outside, target_is_directory=True)
                injected.append(Path(path).name)
            try:
                return real_open(path, flags, *args, **kwargs)
            finally:
                if injected and Path(path).name == injected[0]:
                    outside_creates.append((outside / injected[0]).exists())

        def observe_staged_fsync(descriptor):
            if injected:
                for path in outside.glob(".generation-report.*.tmp"):
                    outside_writes.append((path.name, path.read_bytes()))
            return real_fsync(descriptor)

        candidate = None
        failure = None
        try:
            with mock.patch.object(helper.os, "open", side_effect=swap_at_staged_create), \
                    mock.patch.object(helper.os, "fsync", side_effect=observe_staged_fsync):
                try:
                    candidate = helper.prepare_generation_report(self.project, report)
                except Exception as exc:
                    failure = exc
        finally:
            if self.output.is_symlink():
                self.output.unlink()
            if held_original.exists():
                held_original.rename(self.output)
        self.assertEqual(1, len(injected), "the real staged-create primitive must be reached")
        self.assertIsNotNone(failure, "rebound visible output must fail closed")
        self.assertIsNone(candidate)
        self.assertEqual([], outside_writes, "prepare wrote staged report bytes outside its held output")
        self.assertEqual([False], outside_creates, "prepare created an outside staged file")

    def test_prepare_fsync_failure_cleanup_cannot_delete_outside_same_name(self):
        helper = report_helper()
        report = self.build()
        control = helper.prepare_generation_report(self.project, report)
        self.assertTrue(helper.discard_prepared_generation_report(control))

        outside = self.root / "outside-prepare-cleanup"
        outside.mkdir(mode=0o700)
        held_original = self.project / "99-output-ztp.held-prepare-cleanup"
        sentinel_bytes = b"outside staged-name sentinel must survive cleanup\n"
        injected: list[Path] = []

        def swap_then_fail_stage_fsync(_descriptor):
            staged = list(self.output.glob(".generation-report.*.tmp"))
            self.assertEqual(1, len(staged))
            self.output.rename(held_original)
            self.output.symlink_to(outside, target_is_directory=True)
            sentinel = outside / staged[0].name
            sentinel.write_bytes(sentinel_bytes)
            injected.append(sentinel)
            raise OSError("injected staged-file fsync failure")

        failure = None
        try:
            with mock.patch.object(helper.os, "fsync", side_effect=swap_then_fail_stage_fsync):
                try:
                    helper.prepare_generation_report(self.project, report)
                except Exception as exc:
                    failure = exc
        finally:
            if self.output.is_symlink():
                self.output.unlink()
            if held_original.exists():
                held_original.rename(self.output)
        self.assertEqual(1, len(injected), "the real staged-file fsync must be reached")
        self.assertIsNotNone(failure)
        self.assertTrue(injected[0].is_file(), "prepare cleanup deleted outside same-name sentinel")
        self.assertEqual(sentinel_bytes, injected[0].read_bytes())

    def test_inspector_parent_open_swap_rejects_rebound_output_ancestry(self):
        helper, report = self.publish()
        self.assertEqual(
            report,
            helper.inspect_generation_report(self.project, published_dir=self.published),
        )
        held_original = self.project / "99-output-ztp.held-inspect"
        real_open = os.open
        injected: list[str] = []

        def swap_at_parent_record_open(path, flags, *args, **kwargs):
            if Path(path).name == "current-release.json" and not injected:
                self.output.rename(held_original)
                self.output.symlink_to(held_original, target_is_directory=True)
                injected.append(Path(path).name)
            return real_open(path, flags, *args, **kwargs)

        observed = None
        failure = None
        try:
            with mock.patch.object(helper.os, "open", side_effect=swap_at_parent_record_open):
                try:
                    observed = helper.inspect_generation_report(
                        self.project, published_dir=self.published,
                    )
                except Exception as exc:
                    failure = exc
        finally:
            if self.output.is_symlink():
                self.output.unlink()
            if held_original.exists():
                held_original.rename(self.output)
        self.assertEqual(["current-release.json"], injected)
        self.assertIsNone(observed)
        self.assertIsNotNone(failure, "inspector accepted records through rebound output symlink")


if __name__ == "__main__":
    unittest.main()
