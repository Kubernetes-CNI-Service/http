"""H1-H4: independent synthetic image membership and live/image separation.

No Python glob emulates Docker's ignore engine. Static checks pin ordered
rules; the opt-in synthetic BuildKit test measures COPY membership itself.
An unexecuted Docker test is REAL_ENV debt, never a context-validation PASS.
"""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script as load_source
from test_cases.test_ztp_container_runtime import ROOT, DOCKER_ROOT, load_script


IGNORE_FILES = (ROOT / ".dockerignore", DOCKER_ROOT / ".dockerignore",
                DOCKER_ROOT / "Dockerfile.dockerignore")
# These literal expected members are independent of both the ignore patterns
# and activate.py's selectors. Payloads are harmless markers, not credentials.
ALLOWED = (
    "DAY0-Prepare/11-load.py", "DAY0-Prepare/template/01-global.yaml",
    "DAY0-Prepare/template/p2p/mapping.log", "monitor/deployment.json",
    "tools/service-account.json", "tools/team.service-account.json.example",
    "infra/docker/container.env.example", "ztp/fixture.py",
    "ethernet/fixture.py", "infiniband/fixture.py", "nvlink/fixture.py",
    "requirements-container-top-level.lock",
)
DENIED = (
    "DAY0-Prepare/site-a/01-global.yaml", "DAY0-Prepare/site-a/notes.txt",
    "DAY0-Prepare/site-a/subdir/fixture.py", "Finished-projects/site-a/data.json",
    "cre.json", "operator.service-account.json", "monitor/cre.json",
    "tools/sub/team.service-account.json", "infra/sub/deep/cre.json",
    "DAY0-Prepare/template/cre.json", "DAY0-Prepare/template/p2p/cre.json",
    "DAY0-Prepare/template/operator.service-account.json",
    "DAY0-Prepare/template/private/deep/operator.service-account.json",
    "DAY0-Prepare/template/private/key.pem", "DAY0-Prepare/template/.env",
    "DAY0-Prepare/template/private/.env.dev", "monitor/secret.key",
    "infra/.SSH/id_ed25519", "tools/.ssh/config",
    "monitor/.control-users.candidate.synthetic",
    "DAY0-Prepare/template/.control-users.recovery.synthetic",
    "infra/docker/control-users.htpasswd", "monitor/control-users.htpasswd.copy",
    "ztp/config/cumulus/template/01-global.yaml", "ztp/image/fixture.bin",
)
FINAL_DENIES = (
    "**/cre.json", "**/*.service-account.json", "**/*.key", "**/*.pem",
    "**/.env", "**/.env.*", "**/.[Ss][Ss][Hh]/**",
    "**/.control-users.*", "**/*.htpasswd*",
)


def synthetic_tree(root):
    for name in ALLOWED:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic public marker\n")


class ImageContextSafetyDirectTests(unittest.TestCase):
    def test_three_ignore_files_pin_final_depth_independent_secret_denials(self):
        for path in IGNORE_FILES:
            with self.subTest(path=path):
                self.assertEqual(IGNORE_FILES[0].read_bytes(), path.read_bytes())
                rules = [line.strip() for line in path.read_text().splitlines()
                         if line.strip() and not line.startswith("#")]
                self.assertEqual("**", rules[0])
                self.assertNotIn("!DAY0-Prepare/", rules)
                self.assertIn("!DAY0-Prepare/*.py", rules)
                self.assertIn("!DAY0-Prepare/template/**", rules)
                last_include = max(i for i, line in enumerate(rules) if line.startswith("!"))
                for denied in FINAL_DENIES:
                    self.assertIn(denied, rules)
                    self.assertGreater(rules.index(denied), last_include)

    def test_physical_image_guard_rejects_unmanifested_project_and_secret_names(self):
        activate = load_script("activate.py")
        for name in DENIED:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                manifest = root / "infra/docker/deployment-source-manifest.json"
                activate.write_image_source_manifest(root, manifest)
                forbidden = root / name
                forbidden.parent.mkdir(parents=True, exist_ok=True)
                forbidden.write_bytes(b"synthetic denied marker\n")
                before = manifest.read_bytes()
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)
                self.assertEqual(before, manifest.read_bytes())

    def test_physical_guard_preserves_nonsecret_templates_and_manifest(self):
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            synthetic_tree(root)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            activate.write_image_source_manifest(root, manifest)
            activate.verify_image_source_tree(root)
            activate.verify_image_source_manifest(root, manifest)

    def test_even_empty_project_or_credential_directories_are_rejected(self):
        activate = load_script("activate.py")
        for name in ("DAY0-Prepare/site-a", "DAY0-Prepare/template/.sSh", "Finished-projects"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                (root / name).mkdir(parents=True)
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)


class ImageContextSafetyWorkflowTests(unittest.TestCase):
    def test_dockerfile_uses_image_only_gate_and_live_gate_allows_project_data(self):
        package = load_source("image_context_package_common", ROOT / "tools/_package_common.py")
        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text()
        self.assertIn("activate.py verify-image-source-manifest", dockerfile)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            synthetic_tree(root)
            manifest = root / "infra/docker/deployment-source-manifest.json"
            # Exercise the real package helper -> activate builder -> image/live
            # CLI chain. Only filesystem roots change; no subprocess is mocked.
            with mock.patch.object(package, "ROOT", root), mock.patch.object(
                package, "DEPLOYMENT_SOURCE_MANIFEST_BUILDER", DOCKER_ROOT / "activate.py"
            ):
                self.assertEqual(manifest, package.write_deployment_source_manifest(manifest))
            base = [sys.executable, "-B", str(DOCKER_ROOT / "activate.py")]
            options = ["--source-root", str(root), "--manifest", str(manifest)]
            clean_image = subprocess.run(
                base + ["verify-image-source-manifest", *options], capture_output=True, text=True
            )
            self.assertEqual(0, clean_image.returncode, clean_image.stderr)
            project = root / "DAY0-Prepare/site-a/01-global.yaml"
            project.parent.mkdir()
            project.write_bytes(b"synthetic legitimate live project\n")
            manifest_before = manifest.read_bytes()
            live = subprocess.run(base + ["verify-source-manifest", *options], capture_output=True, text=True)
            image = subprocess.run(base + ["verify-image-source-manifest", *options], capture_output=True, text=True)
            self.assertEqual(0, live.returncode, live.stderr)
            self.assertEqual(2, image.returncode, image.stderr)
            self.assertIn("forbidden image source member", image.stderr)
            self.assertEqual(manifest_before, manifest.read_bytes())
            self.assertEqual(b"synthetic legitimate live project\n", project.read_bytes())

    def test_preloaded_gate_checks_embedded_tree_not_mounted_live_tree(self):
        activate = load_script("activate.py")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "image"
            live = root / "live"
            synthetic_tree(image)
            synthetic_tree(live)
            # A real image-scoped gate must run before live compatibility.
            secret = image / "DAY0-Prepare/template/cre.json"
            secret.write_bytes(b"synthetic denied marker\n")
            os_release = root / "os-release"
            os_release.write_text('ID=ubuntu\nVERSION_ID="24.04"\n')
            with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                activate.verify_deployment_image(live, root / "absent-manifest",
                                                 os_release=os_release, image_source_root=image)


@unittest.skipUnless(os.environ.get("HTTP_TEST_SYNTHETIC_DOCKER") == "1",
                     "NOT RUN: opt-in synthetic BuildKit membership; TC-REAL-IMAGE-CONTEXT-001")
class SyntheticDockerMembershipTests(unittest.TestCase):
    def test_copy_membership_with_each_independent_ignore_entrypoint(self):
        self.assertIsNotNone(shutil.which("docker"), "explicit Docker test requested but CLI unavailable")
        environment = {key: value for key, value in os.environ.items()
                       if key not in {"DOCKER_HOST", "DOCKER_CONTEXT", "BUILDX_BUILDER"}}
        context_name = subprocess.check_output(["docker", "context", "show"], env=environment, text=True).strip()
        description = json.loads(subprocess.check_output(
            ["docker", "context", "inspect", context_name], env=environment, text=True))[0]
        self.assertTrue(description["Endpoints"]["docker"]["Host"].startswith("unix://"),
                        "synthetic validation requires a local Docker socket")
        builder = subprocess.check_output([
            "docker", "--context", context_name, "buildx", "inspect", context_name,
        ], env=environment, text=True)
        self.assertEqual(["docker"], re.findall(r"(?m)^Driver:\s+(\S+)\s*$", builder),
                         "use only the local daemon's built-in builder")
        self.assertEqual([context_name], re.findall(r"(?m)^Endpoint:\s+(\S+)\s*$", builder))
        for ignore in IGNORE_FILES:
            with self.subTest(ignore=ignore), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                context, result = base / "context", base / "result"
                synthetic_tree(context)
                for name in DENIED:
                    path = context / name
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"synthetic denied marker\n")
                # Never use the repository as Docker's context, nor copy any
                # repository content other than this one ignore-rules file.
                (context / ".dockerignore").write_bytes(ignore.read_bytes())
                dockerfile = base / "Dockerfile"
                dockerfile.write_text("FROM scratch\nCOPY . /\n")
                if ignore.name == "Dockerfile.dockerignore":
                    (base / "Dockerfile.dockerignore").write_bytes(ignore.read_bytes())
                    (context / ".dockerignore").write_text("**\n")
                completed = subprocess.run([
                    "docker", "--context", context_name, "buildx", "build", "--builder", context_name,
                    "--network=none", "--progress=plain",
                    "--file", str(dockerfile), "--output", f"type=local,dest={result}", str(context),
                ], capture_output=True, text=True, timeout=120, env=environment)
                self.assertEqual(0, completed.returncode, completed.stderr)
                observed = {path.relative_to(result).as_posix() for path in result.rglob("*") if path.is_file()}
                self.assertEqual(set(ALLOWED), observed)
                self.assertFalse((result / "DAY0-Prepare/site-a").exists())


if __name__ == "__main__":
    unittest.main()
