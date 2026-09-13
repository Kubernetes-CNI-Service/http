#!/usr/bin/env python3
"""Contracts for the generated root README module catalog."""

from __future__ import annotations

import importlib.util
import html
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/update-root-readme.py"
USER_MANUAL_SCRIPT = ROOT / "tools/update-user-manual.py"


def load_script():
    spec = importlib.util.spec_from_file_location("update_root_readme", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def load_path(name: str, path: Path):
    """Load one repository script without depending on its filename syntax."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get(name)
    sys.modules[name] = module
    parent = str(path.parent)
    inserted = parent not in sys.path
    if inserted:
        sys.path.insert(0, parent)
    try:
        spec.loader.exec_module(module)
    finally:
        if inserted:
            sys.path.remove(parent)
        if previous is None:
            sys.modules.pop(name, None)
        else:
            sys.modules[name] = previous
    return module


def bash_commands(text: str) -> list[str]:
    """Return logical, non-comment commands from fenced shell examples."""
    commands = []
    for block in re.findall(r"```(?:bash|sh)\n(.*?)```", text, re.DOTALL):
        logical = re.sub(r"\\\n[ \t]*", " ", block)
        for line in logical.splitlines():
            command = line.split("#", 1)[0].strip()
            if command:
                commands.append(command)
    return commands


class DocumentationCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.catalog = load_script()

    def test_discovery_excludes_outputs_history_details_and_deduplicates_aliases(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            included = (
                root / "tools/README.md",
                root / "infra/policy/README.md",
                root / "docs/README.md",
                root / "ztp/optimize/issue-tracker/README.md",
            )
            excluded = (
                root / "README.md",
                root / ".hidden/README.md",
                root / "DAY0-Prepare/project/README.md",
                root / "module/99-output-run/README.md",
                root / "outputs/review-evidence/README.md",
                root / "ztp/optimize/issue-tracker/OPT-001-example/README.md",
            )
            for path in included + excluded:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"# {path.parent.name}\n", encoding="utf-8")
            canonical = root / "ethernet/monitor/README.md"
            canonical.parent.mkdir(parents=True)
            canonical.write_text("# Shared monitor\n", encoding="utf-8")
            alias = root / "infiniband/monitor/README.md"
            alias.parent.mkdir(parents=True)
            alias.symlink_to("../../ethernet/monitor/README.md")
            self.assertEqual(
                sorted(path.relative_to(root) for path in included + (canonical,)),
                [path.relative_to(root) for path in self.catalog.source_readmes(root)],
            )
            entries = {
                entry.path.relative_to(root): entry
                for entry in self.catalog.catalog_entries(root)
            }
            self.assertEqual(
                (Path("infiniband/monitor/README.md"),),
                tuple(
                    path.relative_to(root)
                    for path in entries[canonical.relative_to(root)].aliases
                ),
            )

    def test_generated_catalog_is_a_parseable_link_index_not_embedded_source(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "module/README.md"
            source.parent.mkdir(parents=True)
            source.write_text(
                "# Module title\n\nUNIQUE_BODY_THAT_MUST_NOT_BE_EMBEDDED\n",
                encoding="utf-8",
            )
            catalog = self.catalog.generated_catalog(root)
            self.assertIn("[Module title](module/README.md)", catalog)
            self.assertNotIn("UNIQUE_BODY_THAT_MUST_NOT_BE_EMBEDDED", catalog)
            self.assertEqual(1, catalog.count("module/README.md"))
            rows = [line for line in catalog.splitlines() if line.startswith("| `")]
            self.assertEqual(1, len(rows), catalog)

    def test_render_replaces_only_the_generated_catalog(self):
        current = (
            "# Root\n\nintro\n"
            f"{self.catalog.BEGIN}\n\nold\n{self.catalog.END}\nfooter\n"
        )
        rendered = self.catalog.render_root_readme(
            current, "### `module/README.md`\n\n# Module",
        )
        self.assertEqual(
            "# Root\n\nintro\n"
            f"{self.catalog.BEGIN}\n\n"
            "### `module/README.md`\n\n# Module\n"
            f"{self.catalog.END}\nfooter\n",
            rendered,
        )

    def test_user_manual_generator_replaces_only_its_owned_blocks(self):
        updater = load_path("update_user_manual_direct", USER_MANUAL_SCRIPT)
        current = (
            "prefix\n"
            f"{updater.FILE_BEGIN}\nold file catalog\n{updater.FILE_END}\n"
            "middle\n"
            f"{updater.SCRIPT_BEGIN}\nold script catalog\n{updater.SCRIPT_END}\n"
            "suffix\n"
        )
        rendered = updater.replace_block(
            current, updater.FILE_BEGIN, updater.FILE_END, "new catalog",
        )
        self.assertEqual(
            "prefix\n"
            f"{updater.FILE_BEGIN}\nnew catalog\n{updater.FILE_END}\n"
            "middle\n"
            f"{updater.SCRIPT_BEGIN}\nold script catalog\n{updater.SCRIPT_END}\n"
            "suffix\n",
            rendered,
        )
        with self.assertRaisesRegex(RuntimeError, "exactly one marker pair"):
            updater.replace_block("no markers", updater.FILE_BEGIN, updater.FILE_END, "x")
        with self.assertRaisesRegex(RuntimeError, "exactly one marker pair"):
            updater.replace_block(
                f"{updater.FILE_BEGIN}\na\n{updater.FILE_END}\n{updater.FILE_END}",
                updater.FILE_BEGIN,
                updater.FILE_END,
                "x",
            )

    def test_user_manual_atomic_writer_rejects_symlink_and_hardlink_targets(self):
        updater = load_path("update_user_manual_writer", USER_MANUAL_SCRIPT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "manual.html"
            target.write_text("original\n", encoding="utf-8")
            hardlink = root / "manual-hardlink.html"
            os.link(target, hardlink)
            with self.assertRaisesRegex(RuntimeError, "unsafe manual target"):
                updater.atomic_write(target, "replacement\n")
            self.assertEqual("original\n", target.read_text(encoding="utf-8"))
            hardlink.unlink()
            link = root / "manual-link.html"
            link.symlink_to(target.name)
            with self.assertRaisesRegex(RuntimeError, "unsafe manual target"):
                updater.atomic_write(link, "replacement\n")
            self.assertEqual("original\n", target.read_text(encoding="utf-8"))

    def test_user_manual_exhaustively_describes_maintained_files_and_scripts(self):
        inventory = subprocess.run(
            ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
            cwd=ROOT,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=True,
        ).stdout.decode("utf-8").split("\0")
        maintained = {path for path in inventory if path}
        scripts = {
            path for path in maintained
            if Path(path).suffix.lower() in {".py", ".sh", ".cgi"}
        }
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        file_rows = {
            match.group(1): match.group(2)
            for match in re.finditer(
                r'<tr data-file-path="([^"]+)">(.*?)</tr>',
                manual,
                flags=re.DOTALL,
            )
        }
        script_entries = {
            match.group(1): match.group(2)
            for match in re.finditer(
                r'<details[^>]*data-script-reference="([^"]+)"[^>]*>(.*?)</details>',
                manual,
                flags=re.DOTALL,
            )
        }
        self.assertEqual(maintained, set(file_rows))
        self.assertEqual(scripts, set(script_entries))

        for path, row in file_rows.items():
            plain = " ".join(re.sub(r"<[^>]+>", " ", row).split())
            with self.subTest(file=path):
                self.assertIn("类别：", plain)
                self.assertIn("作用：", plain)
                self.assertIn("维护/生成责任：", plain)
                self.assertGreaterEqual(len(plain), 55)

        required_fields = (
            "作用：", "是否直接运行：", "运行环境：", "使用场景：",
            "前置条件：", "语法/调用方式：", "主要参数：", "输入：",
            "输出/状态：", "成功判据：", "失败恢复：", "示例：",
        )
        for path, entry in script_entries.items():
            plain = " ".join(re.sub(r"<[^>]+>", " ", entry).split())
            with self.subTest(script=path):
                for field in required_fields:
                    self.assertIn(field, plain)
                self.assertGreaterEqual(len(plain), 240)

        required_runtime_patterns = {
            "DAY0-Prepare/<project>/", "DAY0-Prepare/dumps/*", "image/*",
            "apps/ubuntu-24.04/<arch>/", "outputs/*", "download/*",
            "package-imports/*", "firmware/*", "monitor/status/*",
            "Finished-projects/*",
        }
        self.assertEqual(
            required_runtime_patterns,
            {
                html.unescape(value)
                for value in re.findall(r'data-path-pattern="([^"]+)"', manual)
            },
        )

    def test_user_manual_validation_entrypoints_use_their_real_cli(self):
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")

        def script_entry(relative: str) -> str:
            match = re.search(
                rf'<details[^>]*data-script-reference="{re.escape(relative)}"[^>]*>'
                r'(.*?)</details>',
                manual,
                flags=re.DOTALL,
            )
            self.assertIsNotNone(match, relative)
            return html.unescape(
                " ".join(re.sub(r"<[^>]+>", " ", match.group(1)).split())
            )

        runner = script_entry("test_cases/run_related_tests.py")
        self.assertIn(
            "语法/调用方式： python3 -B test_cases/run_related_tests.py [options]",
            runner,
        )
        self.assertIn("--all", runner)
        self.assertIn("--check", runner)
        self.assertIn("--require-full", runner)
        self.assertNotIn("-m unittest -v test_cases.run_related_tests", runner)

        validator = script_entry("test_cases/run_vm_validation.py")
        self.assertIn(
            "语法/调用方式： sudo python3 -B test_cases/run_vm_validation.py "
            "<project> [options]",
            validator,
        )
        self.assertIn("--full-systemd", validator)
        self.assertIn("只读验收", validator)
        self.assertNotIn("-m unittest -v test_cases.run_vm_validation", validator)

    def test_offline_repository_and_test_gate_documentation_are_fail_closed(self):
        apps = (ROOT / "apps/README.md").read_text(encoding="utf-8")
        self.assertIn("repository.meta", apps)
        self.assertNotIn("当前 Ubuntu 24.04 的 amd64/arm64 仓库已分开生成", apps)

        test_readme = (ROOT / "test_cases/README.md").read_text(encoding="utf-8")
        all_position = test_readme.index("run_related_tests.py --all -v")
        check_position = test_readme.index("run_related_tests.py --check")
        self.assertLess(all_position, check_position)
        self.assertNotRegex(test_readme, r"\*\*\d+ 个受管脚本路径\*\*")

    def test_documentation_tree_and_manifest_path_governance(self):
        deferred_q01 = (
            "docs/README.md",
            "docs/architecture/README.md",
            "docs/deployment/BUNDLE_WORKFLOWS.md",
            "docs/deployment/README.md",
            "docs/operations/README.md",
            "docs/reference/README.md",
            "docs/validation/README.md",
            "infra/docker/README.md",
        )
        for relative in deferred_q01:
            with self.subTest(relative=relative):
                self.assertFalse(os.path.lexists(ROOT / relative), relative)

        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        patterns = {
            pattern
            for rule in manifest["path_rules"]
            for pattern in rule["paths"]
        }
        self.assertNotIn("docs/**/*.md", patterns)
        self.assertTrue(set(deferred_q01).isdisjoint(manifest["tracked_support"]))

    def test_public_docs_do_not_link_to_ignored_internal_documents(self):
        pattern = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
        for source in sorted((ROOT / "docs").rglob("*.md")):
            for raw in pattern.findall(source.read_text(encoding="utf-8")):
                destination = raw.strip().split()[0].strip("<>")
                if not destination or destination.startswith(
                    ("#", "http://", "https://", "mailto:")
                ):
                    continue
                target = (source.parent / destination.split("#", 1)[0]).resolve()
                with self.subTest(source=source.relative_to(ROOT), target=target):
                    self.assertTrue(target.exists())
                    relative = target.relative_to(ROOT).as_posix()
                    ignored = subprocess.run(
                        ["git", "-C", str(ROOT), "check-ignore", "--quiet", relative],
                        check=False,
                    )
                    self.assertNotEqual(0, ignored.returncode, relative)

if __name__ == "__main__":
    unittest.main()
