#!/usr/bin/env python3
"""Contracts for the generated root README module catalog."""

from __future__ import annotations

import importlib.util
import copy
import contextlib
import fnmatch
import html
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import stat
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/update-root-readme.py"
USER_MANUAL_SCRIPT = ROOT / "tools/update-user-manual.py"
USER_MANUAL_CONTRACT = ROOT / "test_cases/user_manual_contract.json"


class _ManualNode:
    """Small HTML tree used to keep the manual contract tests dependency-free."""

    def __init__(self, tag="root", attrs=(), parent=None):
        self.tag = tag
        self.attrs = dict(attrs)
        self.parent = parent
        self.children = []
        self.fragments = []

    def walk(self):
        yield self
        for child in self.children:
            yield from child.walk()

    def text(self):
        pieces = list(self.fragments)
        for child in self.children:
            pieces.append(child.text())
        return " ".join(" ".join(pieces).split())

    def ancestor(self, tag=None, attr=None):
        node = self.parent
        while node is not None:
            if (tag is None or node.tag == tag) and (
                attr is None or attr[0] in node.attrs
            ):
                return node
            node = node.parent
        return None


class _ManualParser(HTMLParser):
    _VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.root = _ManualNode()
        self.stack = [self.root]

    def handle_starttag(self, tag, attrs):
        node = _ManualNode(tag, attrs, self.stack[-1])
        self.stack[-1].children.append(node)
        if tag not in self._VOID:
            self.stack.append(node)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in self._VOID:
            self.stack.pop()

    def handle_endtag(self, tag):
        for index in range(len(self.stack) - 1, 0, -1):
            if self.stack[index].tag == tag:
                del self.stack[index:]
                return

    def handle_data(self, data):
        if data.strip():
            self.stack[-1].fragments.append(data)


def _strict_json(path: Path):
    def reject_duplicates(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)


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
                root / "monitor/cabletracker-main/README.md",
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

    def test_user_manual_full_render_preserves_registered_sentinels(self):
        updater = load_path("update_user_manual_sentinel", USER_MANUAL_SCRIPT)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manual = root / "user-manual.html"
            original = (
                '<article data-manual-version="v2" data-visible-in="v2 v3-dev">\n'
                '<section id="permanent-chapter" data-chapter>sentinel</section>\n'
                f"{updater.FILE_BEGIN}\nold files\n{updater.FILE_END}\n"
                '<div id="permanent-feature"><span id="permanent-feature-steps"></span></div>\n'
                f"{updater.SCRIPT_BEGIN}\nold scripts\n{updater.SCRIPT_END}\n"
                "</article>\n"
            )
            manual.write_text(original, encoding="utf-8")
            with mock.patch.object(updater, "repository_inventory", return_value=[]):
                with mock.patch.object(updater, "render_file_catalog", return_value="new files"):
                    with mock.patch.object(updater, "render_script_reference", return_value="new scripts"):
                        rendered = updater.render_manual(root)
            self.assertEqual(1, rendered.count("permanent-chapter"))
            self.assertEqual(1, rendered.count("permanent-feature-steps"))
            self.assertEqual(
                original.replace("old files", "new files").replace("old scripts", "new scripts"),
                rendered,
            )

    def _assert_user_manual_registry(self, contract, manual, *, use_subtests=True):
        self.assertEqual(1, contract["schema_version"])
        self.assertEqual("user-manual.html", contract["manual"])

        parser = _ManualParser()
        parser.feed(manual)
        nodes = list(parser.root.walk())
        ids = [node.attrs["id"] for node in nodes if node.attrs.get("id")]
        self.assertEqual(len(ids), len(set(ids)), "manual ids must be globally unique")
        by_id = {node.attrs["id"]: node for node in nodes if node.attrs.get("id")}

        articles = {
            node.attrs["data-manual-version"]: node
            for node in nodes
            if node.tag == "article" and node.attrs.get("data-manual-version")
        }
        article_rows = {row["id"]: row for row in contract["articles"]}
        self.assertEqual(3, len(article_rows))
        self.assertEqual(set(article_rows), set(articles))

        chapter_rows = {row["id"]: row for row in contract["chapters"]}
        self.assertEqual(33, len(chapter_rows))
        actual_chapters = {
            node.attrs["id"]: node
            for node in nodes
            if node.tag == "section" and "data-chapter" in node.attrs
        }
        self.assertEqual(set(chapter_rows), set(actual_chapters))
        for chapter_id, row in chapter_rows.items():
            context = (
                self.subTest(chapter=chapter_id)
                if use_subtests else contextlib.nullcontext()
            )
            with context:
                self.assertEqual("active", row["status"])
                self.assertIn(row["introduced_in"], article_rows)
                node = actual_chapters[chapter_id]
                article = node.ancestor("article", ("data-manual-version", None))
                self.assertIsNotNone(article)
                self.assertEqual(row["article"], article.attrs["data-manual-version"])
                heading = next(child for child in node.children if child.tag == "h2")
                self.assertEqual(row["title"], heading.text())

        feature_rows = {row["id"]: row for row in contract["features"]}
        self.assertEqual(28, len(feature_rows))
        actual_features = {
            node.attrs["id"]: node
            for node in nodes
            if node.attrs.get("id")
            and ({"runbook", "scenario"} & set(node.attrs.get("class", "").split()))
        }
        self.assertEqual(set(feature_rows), set(actual_features))
        for feature_id, row in feature_rows.items():
            context = (
                self.subTest(feature=feature_id)
                if use_subtests else contextlib.nullcontext()
            )
            with context:
                node = actual_features[feature_id]
                article = node.ancestor("article", ("data-manual-version", None))
                self.assertIsNotNone(article)
                self.assertEqual(row["article"], article.attrs["data-manual-version"])
                self.assertEqual(row["title"], node.attrs["data-nav-title"])
                self.assertIn(row["introduced_in"], article_rows)
                self.assertIn(row["status"], {"active", "deprecated"})
                anchors = row["anchors"]
                self.assertEqual({"steps", "risk", "rollback"}, set(anchors))
                self.assertEqual(3, len(set(anchors.values())))
                descendants = {
                    descendant.attrs.get("id") for descendant in node.walk()
                }
                self.assertLessEqual(set(anchors.values()), descendants)
                for role, anchor_id in anchors.items():
                    self.assertIn(anchor_id, by_id, role)
                    self.assertEqual(role, by_id[anchor_id].attrs.get("data-manual-role"))
                    self.assertTrue(by_id[anchor_id].attrs.get("aria-label"))
                if row["status"] == "deprecated":
                    replacement = row.get("replacement")
                    self.assertIn(replacement, feature_rows)
                    self.assertEqual("active", feature_rows[replacement]["status"])
                    self.assertIn(row["deprecation_notice"], node.text())

    def test_user_manual_registry_is_strict_complete_and_bidirectional(self):
        contract = _strict_json(USER_MANUAL_CONTRACT)
        manual = (ROOT / contract["manual"]).read_text(encoding="utf-8")
        self._assert_user_manual_registry(contract, manual)

    def test_user_manual_deprecation_contract_accepts_and_rejects_synthetic_states(self):
        contract = _strict_json(USER_MANUAL_CONTRACT)
        manual = (ROOT / contract["manual"]).read_text(encoding="utf-8")
        deprecated = contract["features"][0]
        replacement = contract["features"][1]
        notice = "此功能已弃用，请改用替代功能。"
        deprecated["status"] = "deprecated"
        deprecated["replacement"] = replacement["id"]
        deprecated["deprecation_notice"] = notice
        pattern = rf'(<[^>]+\bid="{re.escape(deprecated["id"])}"[^>]*>)'
        rendered, count = re.subn(pattern, rf"\1<span>{notice}</span>", manual, count=1)
        self.assertEqual(1, count)
        self._assert_user_manual_registry(contract, rendered, use_subtests=False)

        missing_replacement = copy.deepcopy(contract)
        missing_replacement["features"][0].pop("replacement")
        with self.assertRaises(AssertionError):
            self._assert_user_manual_registry(
                missing_replacement, rendered, use_subtests=False,
            )

        deprecated_replacement = copy.deepcopy(contract)
        second = deprecated_replacement["features"][1]
        third = deprecated_replacement["features"][2]
        second_notice = "此替代功能也已弃用，请改用第三项功能。"
        second["status"] = "deprecated"
        second["replacement"] = third["id"]
        second["deprecation_notice"] = second_notice
        second_pattern = rf'(<[^>]+\bid="{re.escape(second["id"])}"[^>]*>)'
        deprecated_rendered, count = re.subn(
            second_pattern, rf"\1<span>{second_notice}</span>", rendered, count=1,
        )
        self.assertEqual(1, count)
        with self.assertRaises(AssertionError):
            self._assert_user_manual_registry(
                deprecated_replacement, deprecated_rendered, use_subtests=False,
            )

        with self.assertRaises(AssertionError):
            self._assert_user_manual_registry(contract, manual, use_subtests=False)

    def test_user_manual_profiles_compose_articles_and_complete_navigation(self):
        contract = _strict_json(USER_MANUAL_CONTRACT)
        parser = _ManualParser()
        parser.feed((ROOT / contract["manual"]).read_text(encoding="utf-8"))
        nodes = list(parser.root.walk())
        profiles = {row["id"]: row["articles"] for row in contract["profiles"]}
        self.assertEqual(
            {"v1": ["v1"], "v2": ["v2"], "v3-dev": ["v2", "v3-dev"]},
            profiles,
        )
        articles = {
            node.attrs["data-manual-version"]: node
            for node in nodes
            if node.tag == "article" and node.attrs.get("data-manual-version")
        }
        for article_id, article in articles.items():
            expected = {
                profile_id
                for profile_id, members in profiles.items()
                if article_id in members
            }
            self.assertEqual(
                expected,
                set(article.attrs.get("data-visible-in", "").split()),
                article_id,
            )

        chapters = contract["chapters"]
        trees = {
            node.attrs["data-version-nav"]: node
            for node in nodes
            if node.attrs.get("data-version-nav")
        }
        for profile_id, article_ids in profiles.items():
            expected = [
                row["id"] for article_id in article_ids
                for row in chapters if row["article"] == article_id
            ]
            actual = [
                descendant.attrs["href"].removeprefix("#")
                for descendant in trees[profile_id].walk()
                if descendant.tag == "a" and descendant.attrs.get("href", "").startswith("#")
            ]
            self.assertEqual(expected, actual, profile_id)

        article_profiles = {
            article_id: {
                profile_id for profile_id, members in profiles.items()
                if article_id in members
            }
            for article_id in articles
        }
        by_id = {node.attrs["id"]: node for node in nodes if node.attrs.get("id")}
        for link in (node for node in nodes if node.tag == "a"):
            href = link.attrs.get("href", "")
            if not href.startswith("#"):
                continue
            target = by_id.get(href[1:])
            self.assertIsNotNone(target, href)
            source_article = link.ancestor("article", ("data-manual-version", None))
            target_article = target.ancestor("article", ("data-manual-version", None))
            if source_article is not None and target_article is not None:
                self.assertLessEqual(
                    article_profiles[source_article.attrs["data-manual-version"]],
                    article_profiles[target_article.attrs["data-manual-version"]],
                    href,
                )

    def test_user_manual_javascript_uses_profile_composition_everywhere(self):
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        script = re.search(r"<script>\s*(.*?)\s*</script>", manual, re.DOTALL)
        self.assertIsNotNone(script)
        source = script.group(1)
        self.assertIn("function currentArticles()", source)
        self.assertIn("article.dataset.visibleIn.split", source)
        self.assertIn("currentArticles().flatMap", source)
        self.assertIn("currentArticles().forEach", source)
        self.assertIn("const first = visibleSections()[0]", source)
        self.assertNotIn("function currentArticle()", source)
        self.assertNotIn("article.dataset.manualVersion !== version", source)

    def test_user_manual_cites_no_git_ignored_document_as_authority(self):
        from test_cases import test_public_publication_contract as publication

        known_ignored = publication._canonical_git(
            ROOT, "check-ignore", "--no-index", "--quiet", "--", "USER_MANUAL.md",
        )
        self.assertEqual(
            0, known_ignored.returncode,
            "git check-ignore must be available and recognize a known ignored path",
        )
        parser = _ManualParser()
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        parser.feed(manual)
        authority_words = ("权威", "依据", "约束")
        for node in parser.root.walk():
            text = node.text()
            if node.tag not in {"p", "td", "dd", "div", "summary"}:
                continue
            if not any(word in text for word in authority_words):
                continue
            for code in (item for item in node.walk() if item.tag == "code"):
                candidate = code.text().strip()
                if not candidate or any(mark in candidate for mark in "<>*[] "):
                    continue
                if not candidate.lower().endswith(
                    (".md", ".markdown", ".txt", ".rst", "readme")
                ):
                    continue
                ignored = publication._canonical_git(
                    ROOT, "check-ignore", "--no-index", "--quiet", "--", candidate,
                )
                self.assertIn(
                    ignored.returncode, {0, 1},
                    f"git check-ignore failed for {candidate!r}",
                )
                self.assertNotEqual(
                    0, ignored.returncode,
                    f"manual cites git-ignored authority {candidate!r}: {text}",
                )
        self.assertNotIn("由该目录的 README", manual)

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
        from test_cases import test_public_publication_contract as publication

        inventory_result = publication._canonical_git(
            ROOT, "ls-files", "--cached", "--others", "--exclude-standard", "-z",
        )
        self.assertEqual(0, inventory_result.returncode, inventory_result.stderr)
        inventory = inventory_result.stdout.decode("utf-8").split("\0")
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

    def test_user_manual_does_not_truncate_options_or_hide_load_type_alias(self):
        updater = load_path("manual_complete_options", USER_MANUAL_SCRIPT)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "synthetic.py"
            expected = tuple(f"--option-{i}" for i in range(24))
            path.write_text("\n".join(f"parser.add_argument({option!r})" for option in expected))
            self.assertEqual(expected, updater.script_options(path))
        for option in ("--p2p-legacy-columns", "--ztp-monitor-scope", "--type"):
            self.assertIn(option, updater.script_options(ROOT / "DAY0-Prepare/11-load.py"))
        manual = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        entry = re.search(r'<details[^>]*data-script-reference="DAY0-Prepare/11-load.py"[^>]*>(.*?)</details>', manual, re.DOTALL)
        self.assertIsNotNone(entry)
        self.assertIn("--type", html.unescape(entry.group(1)))

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

    def test_v3_generated_load_guidance_declares_the_real_host_role(self):
        updater = load_path("manual_v3_host_role", USER_MANUAL_SCRIPT)
        load = load_path("manual_v3_load_parser", ROOT / "DAY0-Prepare/11-load.py")

        def assert_role(command: str, expected: str) -> None:
            tokens = shlex.split(command)
            script_index = tokens.index("DAY0-Prepare/11-load.py")
            args = load.parse_args(tokens[script_index + 1:])
            self.assertEqual(expected, load.resolve_host_role(args.host_role, "Linux"))

        project_computer = updater.script_profile(ROOT, "DAY0-Prepare/11-load.py")
        self.assertIn("项目电脑", project_computer["environment"])
        assert_role(project_computer["example"], "workstation")

        native_worker = updater.script_profile(ROOT, "monitor/manual-ztp-worker.py")
        self.assertIn("上层生命周期", native_worker["scenario"])
        assert_role(native_worker["example"], "management-server")

        # Removing the role must be caught even when argparse accepts the command.
        missing_role = project_computer["example"].replace(
            "--host-role=workstation", "",
        )
        with self.assertRaisesRegex(load.LoadError, "explicit --host-role"):
            assert_role(missing_role, "workstation")

    def test_v3_current_guides_bind_copyable_load_commands_to_host_role(self):
        load = load_path("manual_v3_guide_parser", ROOT / "DAY0-Prepare/11-load.py")
        guides = (
            ("docs/deployment/BUNDLE_WORKFLOWS.md", "management-server"),
            ("ztp/templates/README.md", "workstation"),
        )
        for relative, expected in guides:
            text = (ROOT / relative).read_text(encoding="utf-8")
            commands = [
                command for command in bash_commands(text)
                if "DAY0-Prepare/11-load.py" in command
            ]
            self.assertTrue(commands, relative)
            for command in commands:
                with self.subTest(guide=relative, command=command):
                    tokens = shlex.split(command)
                    index = tokens.index("DAY0-Prepare/11-load.py")
                    args = load.parse_args(tokens[index + 1:])
                    self.assertEqual(
                        expected, load.resolve_host_role(args.host_role, "Linux"),
                    )

    def test_v3_generated_manual_workflow_keeps_role_bound_examples(self):
        updater = load_path("manual_v3_render_role", USER_MANUAL_SCRIPT)
        rendered = updater.render_manual(ROOT)
        current = (ROOT / "user-manual.html").read_text(encoding="utf-8")
        self.assertEqual(current, rendered, "generated manual must be current")
        generated = rendered.split(updater.SCRIPT_BEGIN, 1)[1].split(
            updater.SCRIPT_END, 1,
        )[0]
        examples = re.findall(
            r"<pre><code>([^<]*DAY0-Prepare/11-load\.py[^<]*)</code></pre>",
            generated,
        )
        self.assertTrue(examples)
        for example in examples:
            with self.subTest(example=example):
                self.assertRegex(html.unescape(example), r"--host-role=(?:workstation|management-server)")

    def test_offline_repository_and_test_gate_documentation_are_fail_closed(self):
        apps = (ROOT / "apps/README.md").read_text(encoding="utf-8")
        self.assertIn("repository.meta", apps)
        self.assertNotIn("当前 Ubuntu 24.04 的 amd64/arm64 仓库已分开生成", apps)

        test_readme = (ROOT / "test_cases/README.md").read_text(encoding="utf-8")
        all_position = test_readme.index("run_related_tests.py --all -v")
        check_position = test_readme.index("run_related_tests.py --check")
        self.assertLess(all_position, check_position)
        self.assertNotRegex(test_readme, r"\*\*\d+ 个受管脚本路径\*\*")

    def test_template_guide_names_distinct_laptop_and_management_key_origins(self):
        guide = (ROOT / "DAY0-Prepare/template/README.txt").read_text(
            encoding="utf-8",
        )
        self.assertIn("setup 不从模板复制 laptop.pub", guide)
        self.assertIn("本机 ~/.ssh", guide)
        self.assertIn("server-delegated", guide)
        self.assertIn("管理服务器端准备并校验", guide)
        self.assertNotIn("把这里的全部缺失文件复制到真实项目", guide)
        self.assertNotIn("setup 会复制到真实项目", guide)
        self.assertNotIn("创建项目后必须先替换地址、MAC、凭据、公钥", guide)
        self.assertNotIn("当前执行用户的 `~/.ssh/id_ed25519.pub`", guide)

    def test_documentation_tree_and_manifest_path_governance(self):
        from test_cases import test_public_publication_contract as publication

        published_q01 = (
            "docs/README.md",
            "docs/architecture/README.md",
            "docs/deployment/BUNDLE_WORKFLOWS.md",
            "docs/deployment/README.md",
            "docs/operations/README.md",
            "docs/reference/README.md",
            "docs/validation/README.md",
            "infra/docker/README.md",
        )
        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(
                encoding="utf-8"
            )
        )
        patterns = tuple(
            pattern
            for rule in manifest["path_rules"]
            for pattern in rule["paths"]
        )
        tracked_support = set(manifest["tracked_support"])
        for relative in published_q01:
            with self.subTest(relative=relative):
                result = publication._canonical_git(
                    ROOT, "ls-files", "--error-unmatch", "-z", "--", relative,
                )
                self.assertEqual(relative.encode("utf-8") + b"\0", result.stdout)
                self.assertEqual(0, result.returncode, result.stderr)
                metadata = (ROOT / relative).lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode), relative)
                self.assertEqual(0o644, stat.S_IMODE(metadata.st_mode), relative)
                ignored = publication._canonical_git(
                    ROOT, "check-ignore", "--no-index", "--quiet", "--", relative,
                )
                self.assertEqual(1, ignored.returncode, relative)
                self.assertIn(relative, tracked_support)
                self.assertTrue(
                    any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns),
                    f"published document lacks a path rule: {relative}",
                )

    def test_public_docs_do_not_link_to_ignored_internal_documents(self):
        from test_cases import test_public_publication_contract as publication

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
                    ignored = publication._canonical_git(
                        ROOT, "check-ignore", "--quiet", relative,
                    )
                    self.assertNotEqual(0, ignored.returncode, relative)

if __name__ == "__main__":
    unittest.main()
