#!/usr/bin/env python3
"""Archive project selection and local import-target consistency contracts."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/import-from-download.py"
SPEC = importlib.util.spec_from_file_location("import_target_contract", SCRIPT)
assert SPEC and SPEC.loader
IMPORTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = IMPORTER
SPEC.loader.exec_module(IMPORTER)

DOWNLOAD_SPEC = importlib.util.spec_from_file_location(
    "download_global_authority_contract", ROOT / "tools/tar-for-download.py",
)
assert DOWNLOAD_SPEC and DOWNLOAD_SPEC.loader
DOWNLOAD = importlib.util.module_from_spec(DOWNLOAD_SPEC)
sys.modules[DOWNLOAD_SPEC.name] = DOWNLOAD
DOWNLOAD_SPEC.loader.exec_module(DOWNLOAD)


def project_archive(
    path: Path,
    projects: list[str],
    *,
    global_payloads: dict[str, bytes] | None = None,
    sync_baselines: dict[str, str] | None = None,
) -> None:
    global_payloads = global_payloads or {}
    sync_baselines = sync_baselines or {}
    with tarfile.open(path, "w:gz") as archive:
        for project in projects:
            directory = tarfile.TarInfo(f"DAY0-Prepare/{project}")
            directory.type = tarfile.DIRTYPE
            directory.mode = 0o755
            archive.addfile(directory)
            payload = b"hostname,type\n"
            devices = tarfile.TarInfo(
                f"DAY0-Prepare/{project}/02-devices_config.csv"
            )
            devices.mode = 0o644
            devices.size = len(payload)
            archive.addfile(devices, io.BytesIO(payload))
            if project in global_payloads:
                global_payload = global_payloads[project]
                global_file = tarfile.TarInfo(
                    f"DAY0-Prepare/{project}/01-global.yaml"
                )
                global_file.mode = 0o600
                global_file.size = len(global_payload)
                archive.addfile(global_file, io.BytesIO(global_payload))
            if project in sync_baselines:
                baseline_payload = (
                    sync_baselines[project] + "\n"
                ).encode("ascii")
                baseline_file = tarfile.TarInfo(
                    f"DAY0-Prepare/{project}/99-output-ztp/"
                    ".sync-code-global.sha256"
                )
                baseline_file.mode = 0o600
                baseline_file.size = len(baseline_payload)
                archive.addfile(baseline_file, io.BytesIO(baseline_payload))


class ArchiveProjectSelectionTests(unittest.TestCase):
    def test_help_separates_local_download_import_from_remote_upload_deploy(self):
        guidance = IMPORTER.HELP_EPILOG
        self.assertIn("只用于把管理服务器的 download 项目数据带回本地", guidance)
        self.assertIn("tools/tar-for-upload.py", guidance)
        self.assertIn("--deploy", guidance)
        self.assertIn("deployment_prewrite_guard.py", guidance)
        self.assertNotIn("直接把归档解压到 HTTP 根目录", guidance)
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            IMPORTER.parse_args(["project-download.tar.gz", "--deploy"])

    def test_unique_project_is_automatic_but_multiple_projects_fail_closed(self):
        self.assertEqual(["one"], IMPORTER.select_projects(["one"]))
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "只包含一个"):
            IMPORTER.select_projects(["one", "two"])

    def test_project_option_is_the_local_target_folder(self):
        args = IMPORTER.parse_args(["download.tar.gz", "-p", "customer"])
        self.assertEqual(Path("customer"), args.project)

    def test_project_names_reject_unsafe_archive_identity(self):
        member = tarfile.TarInfo("DAY0-Prepare/bad name/02-devices_config.csv")
        member.size = 1
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "项目名不安全"):
            IMPORTER.project_names([member])


class LocalTargetConsistencyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.day0 = self.root / "DAY0-Prepare"
        self.day0.mkdir()
        self.patches = (
            mock.patch.object(IMPORTER, "ROOT", self.root),
            mock.patch.object(IMPORTER, "DAY0", self.day0),
        )
        for patcher in self.patches:
            patcher.start()

    def tearDown(self):
        for patcher in reversed(self.patches):
            patcher.stop()
        self.temporary.cleanup()

    def valid_target(self, name: str = "customer") -> Path:
        target = self.day0 / name
        target.mkdir()
        (target / "02-devices_config.csv").write_text(
            "hostname,type\n", encoding="utf-8",
        )
        return target

    def test_default_and_explicit_target_resolve_to_same_project(self):
        expected = self.day0.resolve() / "customer"
        self.assertEqual(
            expected, IMPORTER.resolve_target_project("customer", None)
        )
        self.assertEqual(
            expected,
            IMPORTER.resolve_target_project(
                "customer", Path("DAY0-Prepare/customer"),
            ),
        )

    def test_target_may_have_different_name_but_must_be_direct_child(self):
        self.assertEqual(
            self.day0.resolve() / "target",
            IMPORTER.resolve_target_project("source", Path("target")),
        )
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "直接子目录"):
            IMPORTER.resolve_target_project(
                "source", self.day0 / "nested/source",
            )

    def test_existing_target_must_be_real_complete_project(self):
        target = self.day0 / "customer"
        target.mkdir()
        (target / "unrelated").write_text("x", encoding="utf-8")
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "缺少普通"):
            IMPORTER.resolve_target_project("customer", target)

        for child in target.iterdir():
            child.unlink()
        outside = self.root / "outside"
        outside.mkdir()
        target.rmdir()
        target.symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "直接子目录|实际目录"):
            IMPORTER.resolve_target_project("customer", target)

    def test_existing_release_identity_must_match_source(self):
        target = self.valid_target()
        release = target / "99-output-ztp/current-release.json"
        release.parent.mkdir()
        release.write_text(
            json.dumps({"project": "another"}), encoding="utf-8",
        )
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "release 身份.*不一致"):
            IMPORTER.resolve_target_project("customer", target)
        release.write_text(
            json.dumps({"project": "customer"}), encoding="utf-8",
        )
        self.assertEqual(
            target.resolve(), IMPORTER.resolve_target_project("customer", target)
        )
        alias = self.valid_target("local-customer")
        alias_release = alias / "99-output-ztp/current-release.json"
        alias_release.parent.mkdir()
        alias_release.write_text(
            json.dumps({"project": "local-customer"}), encoding="utf-8",
        )
        self.assertEqual(
            alias.resolve(),
            IMPORTER.resolve_target_project("archive-customer", alias),
        )

    def test_name_mismatch_requires_explicit_confirmation(self):
        targets = {"archive-name": self.day0.resolve() / "local-name"}
        mismatches = IMPORTER.target_name_mismatches(targets)
        self.assertEqual("archive-name", mismatches[0]["source_project"])
        self.assertTrue(
            IMPORTER.confirm_mismatched_targets(mismatches, assume_yes=True)
        )
        self.assertTrue(
            IMPORTER.confirm_mismatched_targets(
                mismatches, interactive=True, input_func=lambda _prompt: "IMPORT",
            )
        )
        self.assertFalse(
            IMPORTER.confirm_mismatched_targets(
                mismatches, interactive=True, input_func=lambda _prompt: "no",
            )
        )
        with self.assertRaisesRegex(IMPORTER.ImportErrorSafe, "--yes"):
            IMPORTER.confirm_mismatched_targets(
                mismatches, interactive=False,
            )

    def test_explicit_target_is_recorded_for_single_project_review(self):
        archive = self.root / "one.tar.gz"
        project_archive(archive, ["two"])
        review_root = self.root / "reviews"
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = IMPORTER.main([
                str(archive), "--review-only",
                "--review-root", str(review_root),
                "--project", "DAY0-Prepare/local-two",
            ])
        self.assertEqual(0, result, output.getvalue())
        report_path = next(review_root.glob("*/import-report.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual(["two"], list(report["projects"]))
        self.assertEqual(
            str(self.day0.resolve() / "local-two"),
            report["project_targets"]["two"],
        )
        self.assertEqual(1, len(report["target_name_mismatches"]))
        self.assertFalse((self.day0 / "local-two").exists())

    def test_yes_allows_merge_into_confirmed_different_name(self):
        archive = self.root / "source.tar.gz"
        project_archive(archive, ["source-name"])
        review_root = self.root / "reviews"
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = IMPORTER.main([
                str(archive), "--review-root", str(review_root),
                "--project", "local-name", "--yes",
            ])
        self.assertEqual(0, result, output.getvalue())
        imported = self.day0 / "local-name/02-devices_config.csv"
        self.assertTrue(imported.is_file())
        self.assertEqual(0o644, stat.S_IMODE(imported.stat().st_mode))
        review_file = next(
            review_root.glob(
                "*/DAY0-Prepare/source-name/02-devices_config.csv"
            )
        )
        self.assertEqual(0o600, stat.S_IMODE(review_file.stat().st_mode))
        console = output.getvalue()
        self.assertIn("新文件：1 个，已经导入。", console)
        self.assertIn("相同文件：0 个，跳过。", console)
        self.assertIn(
            "冲突文件：0 个，保留本地版本，没有覆盖。", console,
        )
        report_path = next(review_root.glob("*/import-report.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        self.assertEqual("merge-new-only", report["mode"])

    def test_remote_global_divergence_is_hash_reported_without_overwriting_mac(
        self,
    ) -> None:
        local_payload = b"schema_version: 2\nsource: mac\n"
        remote_payload = b"schema_version: 2\nsource: vm\n"
        baseline = hashlib.sha256(local_payload).hexdigest()
        archive = self.root / "customer.tar.gz"
        project_archive(
            archive,
            ["customer"],
            global_payloads={"customer": remote_payload},
            sync_baselines={"customer": baseline},
        )
        target = self.valid_target()
        local_global = target / "01-global.yaml"
        local_global.write_bytes(local_payload)
        review_root = self.root / "reviews"
        output = io.StringIO()

        with redirect_stdout(output), redirect_stderr(output):
            result = IMPORTER.main([
                str(archive), "--review-root", str(review_root),
            ])

        self.assertEqual(0, result, output.getvalue())
        self.assertEqual(local_payload, local_global.read_bytes())
        report_path = next(review_root.glob("*/import-report.json"))
        report = json.loads(report_path.read_text(encoding="utf-8"))
        comparison = report["projects"]["customer"]["global_sync"]
        self.assertEqual("remote-only", comparison["classification"])
        self.assertEqual(baseline, comparison["local_sha256"])
        self.assertEqual(
            hashlib.sha256(remote_payload).hexdigest(),
            comparison["archive_sha256"],
        )
        self.assertEqual(baseline, comparison["sync_baseline_sha256"])
        self.assertIn("01-global.yaml", report["projects"]["customer"]["conflicts"])
        console = output.getvalue()
        self.assertIn("VM/归档端单边修改", console)
        self.assertIn("Mac 本地版本保持不变", console)
        report_markdown = report_path.with_name("import-report.md").read_text(
            encoding="utf-8",
        )
        self.assertIn("01-global.yaml comparison", report_markdown)
        self.assertIn("forensics only", report_markdown)
        self.assertIn(baseline, report_markdown)

    def test_real_download_archive_carries_common_global_baseline_to_import(self):
        local_payload = b"schema_version: 2\nsource: mac\n"
        remote_payload = b"schema_version: 2\nsource: vm\n"
        baseline = hashlib.sha256(local_payload).hexdigest()

        remote_root = self.root / "remote"
        remote_day0 = remote_root / "DAY0-Prepare"
        remote_project = remote_day0 / "customer"
        remote_project.mkdir(parents=True)
        (remote_project / "01-global.yaml").write_bytes(remote_payload)
        (remote_project / "02-devices_config.csv").write_text(
            "hostname,type\n", encoding="utf-8",
        )
        state = remote_project / "99-output-ztp/.sync-code-global.sha256"
        state.parent.mkdir()
        state.write_text(baseline + "\n", encoding="ascii")
        archive = self.root / "customer-download.tar.gz"
        args = SimpleNamespace(
            all_day0=False,
            project=str(remote_project),
            output=archive,
            force=False,
        )
        with (
            mock.patch.object(DOWNLOAD.package_core, "ROOT", remote_root),
            mock.patch.object(DOWNLOAD.package_core, "DAY0", remote_day0),
            mock.patch.object(
                DOWNLOAD.package_core, "MANIFEST", remote_root / "missing-manifest",
            ),
            redirect_stdout(io.StringIO()),
        ):
            packaged_archive = DOWNLOAD.create_day0_archive(args)
            self.assertEqual(archive.resolve(), packaged_archive.resolve())

        with tarfile.open(packaged_archive, "r:gz") as packaged:
            self.assertIn(
                "DAY0-Prepare/customer/99-output-ztp/"
                ".sync-code-global.sha256",
                packaged.getnames(),
            )

        target = self.valid_target()
        (target / "01-global.yaml").write_bytes(local_payload)
        review_root = self.root / "reviews"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(0, IMPORTER.main([
                str(packaged_archive), "--review-only",
                "--review-root", str(review_root),
            ]))
        report_path = next(review_root.glob("*/import-report.json"))
        comparison = json.loads(report_path.read_text(encoding="utf-8"))[
            "projects"
        ]["customer"]["global_sync"]
        self.assertEqual("remote-only", comparison["classification"])
        self.assertEqual(baseline, comparison["sync_baseline_sha256"])
        self.assertEqual(local_payload, (target / "01-global.yaml").read_bytes())

    def test_archive_permissions_are_sanitized_for_new_entries_only(self):
        self.assertEqual(0o644, IMPORTER.sanitized_import_mode(0o644))
        self.assertEqual(0o600, IMPORTER.sanitized_import_mode(0o600))
        self.assertEqual(0o644, IMPORTER.sanitized_import_mode(0o666))
        self.assertEqual(0o755, IMPORTER.sanitized_import_mode(0o4755))
        self.assertEqual(
            0o755,
            IMPORTER.sanitized_import_mode(0o777, directory=True),
        )

    def test_identical_and_conflicting_files_keep_local_permissions(self):
        review = self.root / "review.yaml"
        destination = self.root / "local.yaml"
        review.write_text("same\n", encoding="utf-8")
        review.chmod(0o600)
        destination.write_text("same\n", encoding="utf-8")
        destination.chmod(0o640)
        report = IMPORTER.new_project_report()
        modes = {"DAY0-Prepare/source/local.yaml": 0o644}

        IMPORTER.merge_entry(
            review, destination, "local.yaml", report, modes,
            "DAY0-Prepare/source/local.yaml",
        )
        self.assertEqual(["local.yaml"], report["identical"])
        self.assertEqual(0o640, stat.S_IMODE(destination.stat().st_mode))

        review.write_text("different\n", encoding="utf-8")
        IMPORTER.merge_entry(
            review, destination, "local.yaml", report, modes,
            "DAY0-Prepare/source/local.yaml",
        )
        self.assertEqual(["local.yaml"], report["conflicts"])
        self.assertEqual(0o640, stat.S_IMODE(destination.stat().st_mode))

    def test_multi_project_archive_is_rejected_even_with_target_option(self):
        archive = self.root / "all.tar.gz"
        project_archive(archive, ["one", "two"])
        review_root = self.root / "reviews"
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(output):
            result = IMPORTER.main([
                str(archive), "--review-only",
                "--review-root", str(review_root),
                "--project", "DAY0-Prepare/two",
            ])
        self.assertEqual(1, result)
        self.assertIn("只包含一个", output.getvalue())


if __name__ == "__main__":
    unittest.main()
