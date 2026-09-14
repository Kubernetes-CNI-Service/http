"""Contract tests for the fail-closed public Git repository audit."""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "test_cases/audit_public_tree.py"
TOPLEVEL_REQUIREMENTS = (
    ("Jinja2", "3.1.6"),
    ("PyYAML", "6.0.3"),
    ("pandas", "2.3.3"),
    ("openpyxl", "3.1.5"),
    ("XlsxWriter", "3.2.9"),
)
TOPLEVEL_LOCK = ROOT / "requirements-container-top-level.lock"
TOPLEVEL_WHEELS = (
    (
        "Jinja2",
        "3.1.6",
        (
            (
                "jinja2-3.1.6-py3-none-any.whl",
                "85ece4451f492d0c13c5dd7c13a64681a86afae63a5f347908daf103ce6d2f67",
            ),
        ),
    ),
    (
        "PyYAML",
        "6.0.3",
        (
            (
                "pyyaml-6.0.3-cp312-cp312-manylinux2014_aarch64."
                "manylinux_2_17_aarch64.manylinux_2_28_aarch64.whl",
                "9149cad251584d5fb4981be1ecde53a1ca46c891a79788c0df828d2f166bda28",
            ),
            (
                "pyyaml-6.0.3-cp312-cp312-manylinux2014_x86_64."
                "manylinux_2_17_x86_64.manylinux_2_28_x86_64.whl",
                "ba1cc08a7ccde2d2ec775841541641e4548226580ab850948cbfda66a1befcdc",
            ),
        ),
    ),
    (
        "pandas",
        "2.3.3",
        (
            (
                "pandas-2.3.3-cp312-cp312-manylinux_2_24_x86_64."
                "manylinux_2_28_x86_64.whl",
                "b3d11d2fda7eb164ef27ffc14b4fcab16a80e1ce67e9f57e19ec0afaf715ba89",
            ),
            (
                "pandas-2.3.3-cp312-cp312-manylinux_2_24_aarch64."
                "manylinux_2_28_aarch64.whl",
                "ecaf1e12bdc03c86ad4a7ea848d66c685cb6851d807a26aa245ca3d2017a1908",
            ),
        ),
    ),
    (
        "openpyxl",
        "3.1.5",
        (
            (
                "openpyxl-3.1.5-py2.py3-none-any.whl",
                "5282c12b107bffeef825f4617dc029afaf41d0ea60823bbb665ef3079dc79de2",
            ),
        ),
    ),
    (
        "XlsxWriter",
        "3.2.9",
        (
            (
                "xlsxwriter-3.2.9-py3-none-any.whl",
                "9a5db42bc5dff014806c58a20b9eae7322a134abb6fce3c92c181bfb275ec5b3",
            ),
        ),
    ),
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


PUBLIC_AUDIT = load_module("public_audit_under_contract_test", AUDIT)


class PublicRepositoryAuditContractTest(unittest.TestCase):
    maxDiff = None

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        subprocess.run(
            ["git", "init", "-q", str(self.root)],
            check=True,
            text=True,
            capture_output=True,
        )
        self.write(".gitignore", "ignored/\n__pycache__/\n")

    def write(self, relative: str, content: str | bytes = "safe\n") -> Path:
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            target.write_bytes(content)
        else:
            target.write_text(content, encoding="utf-8")
        return target

    def git(self, *args: str) -> None:
        subprocess.run(
            ["git", "-C", str(self.root), *args],
            check=True,
            text=True,
            capture_output=True,
        )

    def audit(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-B", str(AUDIT), "--root", str(self.root)],
            text=True,
            capture_output=True,
            check=False,
        )

    def assert_rejected(self, result: subprocess.CompletedProcess[str], kind: str):
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn(f"[{kind}]", result.stderr)

    @staticmethod
    def factory_source_lines() -> list[bytes]:
        return (ROOT / "tools/control-auth.py").read_bytes().splitlines(
            keepends=True
        )

    def install_exact_factory_block(self) -> list[bytes]:
        lines = self.factory_source_lines()
        expected_line_digests = {
            37: "a413f1a3384e97dec91a9e4922d249208698c44286f8f9261e9000d40765dfff",
            38: "503d66d2392e60e24306ed201cf57f9ce8117a0dbcdd05a361de712002199ee6",
        }
        for line_number, expected_digest in expected_line_digests.items():
            self.assertEqual(
                expected_digest,
                hashlib.sha256(lines[line_number - 1]).hexdigest(),
            )
        self.assertEqual(
            "e3be7cb0122e5b189744e1133a955a40be4a8c2254a37bffa942298f9a15032a",
            hashlib.sha256(b"".join(lines[35:39])).hexdigest(),
        )
        self.write(
            "tools/control-auth.py",
            b"# exact line padding\n" * 35 + b"".join(lines[35:39]),
        )
        return lines

    def assert_no_verifier_value_in_output(
        self, result: subprocess.CompletedProcess[str], lines: list[bytes]
    ) -> None:
        output = result.stdout + result.stderr
        for line_number in (37, 38):
            record = lines[line_number - 1].split(b'"', 2)[1]
            verifier = record.split(b":", 1)[1].split(b"\\n", 1)[0]
            self.assertNotIn(verifier.decode("ascii"), output)

    def test_exact_public_factory_verifiers_are_narrow_and_fail_closed(self):
        lines = self.install_exact_factory_block()
        result = self.audit()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

        canonical = self.root / "tools/control-auth.py"
        exact = canonical.read_bytes()
        self.write("src/copied-helper.py", exact)
        result = self.audit()
        self.assert_rejected(result, "password-hash")
        self.assertIn("unknown reusable password hash", result.stderr)
        self.assert_no_verifier_value_in_output(result, lines)
        (self.root / "src/copied-helper.py").unlink()

        original_lines = exact.splitlines(keepends=True)
        mutations = []
        changed_hash_line = bytearray(original_lines[36])
        end = changed_hash_line.index(b"\\n\"")
        changed_hash_line[end - 1] = ord("A") if changed_hash_line[end - 1] != ord("A") else ord("B")
        mutations.append((36, bytes(changed_hash_line)))
        mutations.append((36, original_lines[36].replace(b"nvis:", b"root:")))
        mutations.append((36, original_lines[36].replace(b"$12$", b"$11$")))
        mutations.append((36, b'    b"nvis:removed\\n"\n'))
        mutations.append((35, b"FACTORY_RECORDS = tuple((\n"))
        for index, (line_index, replacement) in enumerate(mutations):
            with self.subTest(mutation=index):
                candidate = list(original_lines)
                candidate[line_index] = replacement
                canonical.write_bytes(b"".join(candidate))
                result = self.audit()
                self.assert_rejected(result, "password-hash")
                self.assertIn("known factory record line changed", result.stderr)
                self.assertIn("update the allowlist digest", result.stderr)
                self.assertIn("re-run the semantic factory tests", result.stderr)
                self.assert_no_verifier_value_in_output(result, lines)

        canonical.write_bytes(exact)
        alphabetic_body = "A" * 53
        third = (
            "    b\"other:$2y$12$" + alphabetic_body + "\\n\"\n"
        ).encode("ascii")
        canonical.write_bytes(exact + third)
        result = self.audit()
        self.assert_rejected(result, "password-hash")
        self.assert_no_verifier_value_in_output(result, lines)

        canonical.write_bytes(exact)
        unrelated = "$" + "2y$12$" + "Z" * 53
        self.write("src/unrelated-verifier.txt", unrelated + "\n")
        result = self.audit()
        self.assert_rejected(result, "password-hash")
        self.assertIn("unknown reusable password hash", result.stderr)
        self.assertNotIn(unrelated, result.stdout + result.stderr)

    def test_factory_authority_requires_exactly_two_line_digests(self):
        lines = self.factory_source_lines()
        authorities = PUBLIC_AUDIT.PUBLIC_FACTORY_VERIFIER_LINE_AUTHORITIES
        self.assertEqual(2, len(authorities))
        third = (39, hashlib.sha256(b"third\n").hexdigest())
        with mock.patch.object(
            PUBLIC_AUDIT,
            "PUBLIC_FACTORY_VERIFIER_LINE_AUTHORITIES",
            authorities + (third,),
        ):
            with self.assertRaisesRegex(
                PUBLIC_AUDIT.AuditError, "exactly two"
            ):
                PUBLIC_AUDIT.scan_content(
                    "tools/control-auth.py", b"".join(lines)
                )

    def test_first_commit_scans_untracked_candidates_but_not_ignored_files(self):
        self.write("src/tool.py", "print('safe')\n")
        self.write("ignored/operator.pub", self.valid_public_key())
        result = self.audit()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("2 Git candidate", result.stdout)

        secret = "gh" + "p_" + "A" * 36
        self.write("src/credentials.txt", secret + "\n")
        result = self.audit()
        self.assert_rejected(result, "token")
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_staged_blob_is_scanned_even_when_worktree_copy_is_clean(self):
        secret = "gh" + "p_" + "S" * 36
        self.write("src/staged.txt", secret + "\n")
        self.git("add", "src/staged.txt")
        self.write("src/staged.txt", "safe worktree copy\n")

        result = self.audit()
        self.assert_rejected(result, "token")
        self.assertNotIn(secret, result.stdout + result.stderr)

    def test_tracked_field_project_is_rejected_even_when_ignore_is_bypassed(self):
        field_path = "DAY0-Prepare/2099-customer/02-devices_config.csv"
        private_ip = ".".join(("10", "0", "0", "1"))
        self.write(field_path, f"hostname,eth0_ip\nfield-leaf,{private_ip}\n")
        self.git("add", "-f", field_path)
        result = self.audit()
        self.assert_rejected(result, "field-path")
        self.assertIn("2099-customer", result.stderr)

    def test_force_added_internal_documentation_is_rejected(self):
        self.write("README.md", "field-only operating notes\n")
        self.git("add", "-f", "README.md")
        self.assert_rejected(self.audit(), "field-path")

        (self.root / "README.md").unlink()
        self.git("rm", "--cached", "README.md")
        internal = "ztp/optimize/issue-tracker/OPT-999/README.md"
        self.write(internal, "field incident evidence\n")
        self.git("add", "-f", internal)
        self.assert_rejected(self.audit(), "field-path")

    def test_private_ipv4_and_non_synthetic_mac_are_rejected_without_value_leak(self):
        private_ip = ".".join(("10", "43", "241", "9"))
        field_mac = ":".join(("04", "c5", "cd", "5c", "ad", "c0"))
        source = self.write(
            "src/config.py",
            "endpoint = " + repr(private_ip) + "\nmac = " + repr(field_mac) + "\n",
        )
        result = self.audit()
        self.assert_rejected(result, "private-ipv4")
        self.assert_rejected(result, "non-synthetic-mac")
        self.assertNotIn(private_ip, result.stdout + result.stderr)
        self.assertNotIn(field_mac, result.stdout + result.stderr)

        source.unlink()
        compact_field_mac = "".join(("04", "c5", "cd", "5c", "ad", "c0"))
        compact_source = self.write(
            "src/compact_identity.py",
            "mac_plain = " + repr(compact_field_mac) + "\n",
        )
        result = self.audit()
        self.assert_rejected(result, "non-synthetic-mac")
        self.assertNotIn(compact_field_mac, result.stdout + result.stderr)
        compact_source.unlink()

        private_template = "10." + "43.1.{host}"
        self.write("src/render.py", "endpoint = f" + repr(private_template) + "\n")
        result = self.audit()
        self.assert_rejected(result, "private-ipv4")
        self.assertNotIn(private_template, result.stdout + result.stderr)
        (self.root / "src/render.py").unlink()

        self.write(
            "src/examples.py",
            "hosts = ['192.0.2.10', '198.51.100.8', '203.0.113.7', "
            "'127.0.0.1', '02:00:00:00:00:01', "
            "'00:00:00:00:00:00']\n",
        )
        self.assertEqual(0, self.audit().returncode)

    def test_vrr_protocol_mac_is_allowed_only_with_explicit_vrr_semantics(self):
        vrr_base = ":".join(("00", "00", "5e", "00", "00", "00"))
        vrr_vlan = ":".join(("00", "00", "5e", "00", "00", "64"))
        source = self.write(
            "src/vrr.yaml",
            f"base_mac: {vrr_base}\nvrr_mac: {vrr_vlan}\n",
        )
        result = self.audit()
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

        source.write_text(f"device_mac: {vrr_vlan}\n", encoding="utf-8")
        result = self.audit()
        self.assert_rejected(result, "non-synthetic-mac")
        self.assertNotIn(vrr_vlan, result.stdout + result.stderr)

    def test_sensitive_path_components_are_rejected_without_value_leak(self):
        private_ip = ".".join(("172", "20", "1", "5"))
        self.write(f"src/{private_ip}/tool.py")
        result = self.audit()
        self.assert_rejected(result, "sensitive-path")
        self.assertNotIn(private_ip, result.stdout + result.stderr)

        (self.root / f"src/{private_ip}/tool.py").unlink()
        credential = "path-" + "only-secret-value"
        sensitive_path = "src/pass" + "word=" + credential + "/tool.py"
        self.write(sensitive_path)
        result = self.audit()
        self.assert_rejected(result, "sensitive-path")
        self.assertNotIn(credential, result.stdout + result.stderr)

        (self.root / sensitive_path).unlink()
        self.write("config/.env.production", "MODE=example\n")
        self.assert_rejected(self.audit(), "sensitive-path")

    def test_cleartext_credential_and_rounds_password_hash_are_rejected(self):
        credential = "correct-" + "horse-battery-staple"
        assignment = "pass" + "word = " + repr(credential) + "\n"
        path = self.write("src/settings.py", assignment)
        result = self.audit()
        self.assert_rejected(result, "cleartext-credential")
        self.assertNotIn(credential, result.stdout + result.stderr)
        path.unlink()

        unquoted = "another-" + "unsafe-value"
        unquoted_assignment = "pass" + "word: " + unquoted + "\n"
        path = self.write("src/settings.yaml", unquoted_assignment)
        result = self.audit()
        self.assert_rejected(result, "cleartext-credential")
        self.assertNotIn(unquoted, result.stdout + result.stderr)
        path.unlink()

        password_hash = "$" + "6$rounds=5000$salt$" + "A" * 86
        self.write("src/hash.txt", password_hash + "\n")
        result = self.audit()
        self.assert_rejected(result, "password-hash")
        self.assertNotIn(password_hash, result.stdout + result.stderr)

    def test_images_and_unknown_binary_content_fail_closed(self):
        self.write("src/screenshot.png", b"\x89PNG\r\n\x1a\nsynthetic")
        self.assert_rejected(self.audit(), "binary-artifact")
        (self.root / "src/screenshot.png").unlink()

        self.write("src/payload.dat", b"safe-prefix\x00binary-tail")
        self.assert_rejected(self.audit(), "binary-content")

    def test_blob_larger_than_five_mib_is_rejected(self):
        target = self.write("src/large.dat", b"")
        with target.open("wb") as handle:
            handle.truncate(5 * 1024 * 1024 + 1)
        self.assert_rejected(self.audit(), "large-blob")

    def test_symlink_must_be_relative_internal_present_and_publishable(self):
        self.write("src/target.txt")
        os.symlink("target.txt", self.root / "src/good-link")
        self.assertEqual(0, self.audit().returncode)

        (self.root / "src/good-link").unlink()
        os.symlink("/etc/passwd", self.root / "src/absolute-link")
        self.assert_rejected(self.audit(), "absolute-symlink")

        (self.root / "src/absolute-link").unlink()
        os.symlink("../../outside", self.root / "src/escape-link")
        self.assert_rejected(self.audit(), "escaping-symlink")

        (self.root / "src/escape-link").unlink()
        os.symlink("missing.txt", self.root / "src/broken-link")
        self.assert_rejected(self.audit(), "broken-symlink")

        (self.root / "src/broken-link").unlink()
        ignored = self.write("ignored/local-only.txt")
        os.symlink(os.path.relpath(ignored, self.root / "src"), self.root / "src/private-link")
        self.assert_rejected(self.audit(), "unpublished-symlink")

    def test_private_key_password_hash_token_and_public_key_are_rejected(self):
        cases = {
            "private-key": (
                "src/private.txt",
                "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key\n",
            ),
            "password-hash": (
                "src/password.txt",
                "$" + "6$abcdefghijklmnop$" + "A" * 86 + "\n",
            ),
            "token": (
                "src/token.txt",
                "github_" + "pat_" + "A" * 22 + "_" + "B" * 59 + "\n",
            ),
            "ssh-public-key": ("src/operator.txt", self.valid_public_key()),
        }
        for expected_kind, (relative, content) in cases.items():
            with self.subTest(kind=expected_kind):
                path = self.write(relative, content)
                result = self.audit()
                self.assert_rejected(result, expected_kind)
                self.assertNotIn(content.strip(), result.stdout + result.stderr)
                path.unlink()

    def test_nonempty_public_key_file_is_rejected_even_if_payload_is_malformed(self):
        self.write("examples/operator.pub", "placeholder-not-a-key\n")
        self.assert_rejected(self.audit(), "credential-file")

    def test_force_added_mixed_case_ssh_private_sentinel_is_never_public(self):
        sentinel = "DOCKER_MGMT_PUBLIC_SECRET_26fbed634a134d35"
        private = self.write(
            ".SSH/id_ed25519",
            "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n"
            + sentinel
            + "\n-----END " + "OPENSSH PRIVATE KEY-----\n",
        )
        self.git("add", "-f", os.fspath(private.relative_to(self.root)))
        result = self.audit()
        self.assert_rejected(result, "private-key")
        self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_exact_synthetic_fixture_exception_cannot_move_or_change(self):
        marker = "    -----BEGIN " + "PRIVATE KEY-----\n"
        end_marker = "    -----END " + "PRIVATE KEY-----\n"
        expected = "test_cases/test_diagnostic_bundle.py"
        lines = ["# padding\n"] * 76 + [marker, "    {sentinel}\n", end_marker]
        self.write(expected, "".join(lines))
        self.assertEqual(0, self.audit().returncode)

        source = self.root / expected
        source.write_text(
            source.read_text(encoding="utf-8").replace("    {sentinel}\n", "    changed\n"),
            encoding="utf-8",
        )
        self.assert_rejected(self.audit(), "private-key")

        source.write_text("".join(lines), encoding="utf-8")
        source.write_text("# inserted\n" + source.read_text(encoding="utf-8"), encoding="utf-8")
        self.assert_rejected(self.audit(), "private-key")

        source.unlink()
        self.write("test_cases/copied_fixture.py", "".join(lines))
        self.assert_rejected(self.audit(), "private-key")

    def test_zero_byte_canonical_placeholders_are_exactly_scoped(self):
        allowed = "DAY0-Prepare/template/mgmt-server.pub"
        self.write(allowed, b"")
        self.assertEqual(0, self.audit().returncode)

        self.write(allowed, "ssh placeholder\n")
        self.assert_rejected(self.audit(), "credential-file")

        (self.root / allowed).unlink()
        self.write("examples/mgmt-server.pub", b"")
        self.assert_rejected(self.audit(), "credential-file")

    def test_output_directory_sentinel_content_is_exact(self):
        path = "DAY0-Prepare/template/99-output-eth/.gitkeep"
        marker = "# Retain this empty runtime-output skeleton in source checkouts.\n"
        self.write(path, marker)
        self.assertEqual(0, self.audit().returncode)

        self.write(path, marker + "field output\n")
        self.assert_rejected(self.audit(), "placeholder-content")

    @staticmethod
    def valid_public_key() -> str:
        algorithm = b"ssh-ed25519"
        blob = (
            struct.pack(">I", len(algorithm))
            + algorithm
            + struct.pack(">I", 32)
            + b"A" * 32
        )
        return "ssh-ed25519 " + base64.b64encode(blob).decode("ascii") + " synthetic\n"


class PublicRepositoryWorkflowContractTest(unittest.TestCase):
    def test_ci_is_read_only_and_orders_approval_check_before_full_suite(self):
        workflow = (ROOT / ".github/workflows/tests.yml").read_text(encoding="utf-8")
        check = "test_cases/run_related_tests.py --check"
        suite = "python3 -B -m unittest discover"
        self.assertIn("python-version: '3.12'", workflow)
        self.assertIn("contents: read", workflow)
        self.assertNotIn("run_related_tests.py --all", workflow)
        self.assertIn(check, workflow)
        self.assertIn(suite, workflow)
        self.assertLess(workflow.index(check), workflow.index(suite))
        self.assertIn("test_cases/audit_public_tree.py", workflow)
        install = "pip install"
        audit = "test_cases/audit_public_tree.py"
        self.assertIn("persist-credentials: false", workflow)
        self.assertLess(workflow.index(audit), workflow.index(install))
        self.assertLess(workflow.index(check), workflow.index(install))
        self.assertIn(
            "actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4",
            workflow,
        )
        self.assertIn(
            "actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5",
            workflow,
        )

    def test_development_requirements_are_minimal_and_bounded(self):
        lines = [
            line.strip()
            for line in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
        self.assertEqual(
            [f"{name}=={version}" for name, version in TOPLEVEL_REQUIREMENTS],
            lines,
        )
        for line in lines:
            self.assertRegex(line, r"^[A-Za-z][A-Za-z0-9]*==\d+(?:\.\d+)*$")

    def test_container_toplevel_lock_is_canonical_hash_only_and_matches_dev(self):
        self.assertTrue(
            TOPLEVEL_LOCK.is_file(),
            "missing canonical TOPLEVEL-5 container dependency lock",
        )
        metadata = TOPLEVEL_LOCK.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(1, metadata.st_nlink)
        self.assertLessEqual(metadata.st_size, 64 * 1024)
        raw = TOPLEVEL_LOCK.read_text(encoding="ascii")
        lines = raw.splitlines()
        self.assertTrue(lines)
        self.assertEqual(
            "# TOPLEVEL-5 only. Install with pip --no-deps. Transitive closure, "
            "base APT, and full image reproducibility are deferred.",
            lines[0],
        )
        self.assertTrue(raw.endswith("\n"))
        expected_lines = [lines[0]]
        for name, version, wheels in TOPLEVEL_WHEELS:
            for filename, digest in wheels:
                expected_lines.append(f"# wheel: {filename} sha256:{digest}")
            expected_lines.append(f"{name}=={version} \\")
            for index, (_filename, digest) in enumerate(wheels):
                suffix = " \\" if index < len(wheels) - 1 else ""
                expected_lines.append(f"    --hash=sha256:{digest}{suffix}")
        self.assertEqual(
            "\n".join(expected_lines) + "\n",
            raw,
            "lock must be the independent official PyPI CPython 3.12 Ubuntu "
            "amd64/arm64 wheel allowlist (no sdists or foreign platform tags)",
        )
        self.assertEqual(
            TOPLEVEL_REQUIREMENTS,
            tuple((name, version) for name, version, _wheels in TOPLEVEL_WHEELS),
        )
        lowered = raw.casefold()
        for forbidden in (
            "://", "file:", "git+", "hg+", "svn+", "bzr+", " @ ", ";",
            "--index-url", "--extra-index-url", "--find-links", "--editable", "-e ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, lowered)

        logical = []
        pending = []
        for raw_line in lines[1:]:
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            continuation = stripped.endswith("\\")
            pending.append(stripped[:-1].rstrip() if continuation else stripped)
            if not continuation:
                logical.append(" ".join(pending))
                pending = []
        self.assertEqual([], pending, "unterminated requirement continuation")

        observed = []
        all_hashes = set()
        for record in logical:
            tokens = shlex.split(record)
            self.assertGreaterEqual(len(tokens), 2, record)
            name, version = tokens[0].split("==", 1)
            self.assertRegex(name, r"^[A-Za-z][A-Za-z0-9]*$")
            self.assertRegex(version, r"^\d+(?:\.\d+)*$")
            hashes = [token.removeprefix("--hash=sha256:") for token in tokens[1:]]
            self.assertTrue(hashes, f"no wheel hash for {name}")
            self.assertTrue(
                all(token.startswith("--hash=sha256:") for token in tokens[1:]),
                f"non-hash option in {name}",
            )
            self.assertEqual(sorted(hashes), hashes, f"non-canonical hash order for {name}")
            self.assertEqual(len(hashes), len(set(hashes)), f"duplicate wheel hash for {name}")
            for digest in hashes:
                self.assertRegex(digest, r"^[0-9a-f]{64}$")
                self.assertNotIn(digest, all_hashes, "duplicate hash across top-level records")
                all_hashes.add(digest)
            observed.append((name, version))

        self.assertEqual(list(TOPLEVEL_REQUIREMENTS), observed)
        self.assertEqual(len(observed), len({name.casefold() for name, _ in observed}))

    def test_production_dependency_version_literals_match_development_pins(self):
        pins = {}
        for line in (ROOT / "requirements-dev.txt").read_text(
            encoding="utf-8",
        ).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            name, version = line.split("==", 1)
            pins[name] = version

        manifest = json.loads(
            (ROOT / "test_cases/script_test_manifest.json").read_text(
                encoding="utf-8",
            )
        )
        text_suffixes = {
            ".py", ".cgi", ".sh", ".conf", ".yaml", ".yml", ".j2",
            ".txt", ".example",
        }
        candidates = set(manifest["scripts"]) | set(manifest["tracked_support"])
        pattern = re.compile(r"(?<![A-Za-z0-9_-])(Jinja2|PyYAML)==(\d+(?:\.\d+)*)")
        occurrences = []
        for relative in sorted(candidates):
            if relative == "requirements-dev.txt":
                continue
            path = ROOT / relative
            if path.name != "Dockerfile" and path.suffix not in text_suffixes:
                continue
            source = path.read_text(encoding="utf-8", errors="replace")
            occurrences.extend(
                (relative, match.group(1), match.group(2))
                for match in pattern.finditer(source)
            )

        self.assertTrue(
            any(name == "Jinja2" for _path, name, _version in occurrences),
            "dependency-literal scan must exercise at least one production pin",
        )
        for relative, name, version in occurrences:
            with self.subTest(path=relative, dependency=name):
                self.assertIn(name, pins)
                self.assertEqual(pins[name], version)

    def test_repository_candidate_tree_passes_the_public_audit(self):
        result = subprocess.run(
            [sys.executable, "-B", str(AUDIT), "--root", str(ROOT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_public_n3_residual_is_bound_only_to_real_environment_runbook(self):
        authorities = (
            ROOT / "test_cases/REAL_ENVIRONMENT.md",
            ROOT / "docs/operations/README.md",
            ROOT / "infra/docker/README.md",
        )
        fragments = (
            "N=3 is not proof of an attacker",
            "same-identity breaker N=1→2→3",
            "automatic repair loops are forbidden",
            "sudo ./infra/infra-setup.sh --recover-monitor-authority",
            "sudo ./infra/docker/deploy.sh recover-monitor-authority",
            "never manually unlink/chmod/rewrite",
            "exactly one fixed warning",
            "re-wedging remains possible",
        )
        for authority in authorities:
            with self.subTest(authority=authority):
                metadata = authority.lstat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(0o644, stat.S_IMODE(metadata.st_mode))
                content = authority.read_text(encoding="utf-8")
                for fragment in fragments:
                    self.assertIn(fragment, content)


if __name__ == "__main__":
    unittest.main()
