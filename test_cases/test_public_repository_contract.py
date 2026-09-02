"""Contract tests for the fail-closed public Git repository audit."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
AUDIT = ROOT / "test_cases/audit_public_tree.py"


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
            "'127.0.0.1', '02:00:00:00:00:01']\n",
        )
        self.assertEqual(0, self.audit().returncode)

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
        lines = {
            line.strip()
            for line in (ROOT / "requirements-dev.txt").read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }
        expected_names = {"PyYAML", "pandas", "openpyxl", "XlsxWriter"}
        self.assertEqual(expected_names, {line.split("==", 1)[0] for line in lines})
        for line in lines:
            self.assertRegex(line, r"^[A-Za-z]+==\d+(?:\.\d+)*$")

    def test_repository_candidate_tree_passes_the_public_audit(self):
        result = subprocess.run(
            [sys.executable, "-B", str(AUDIT), "--root", str(ROOT)],
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
