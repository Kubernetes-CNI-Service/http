"""H1-H4: independent synthetic image membership and live/image separation.

No Python glob emulates Docker's ignore engine. Static checks pin ordered
rules; the opt-in synthetic BuildKit test measures COPY membership itself.
An unexecuted Docker test is REAL_ENV debt, never a context-validation PASS.
"""
import hashlib
from itertools import product
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
    "DAY0-Prepare/template/laptop.pub",
)
# Independently transcribed live bindings from R-0132, not gate-derived values.
RUNTIME_MEMBERS = (
    "infra/01-global.yaml", "infra/02-devices_config.csv",
    "monitor/01-global.yaml", "monitor/02-devices_config.csv", "monitor/generate-monitor.log",
    "ethernet/eth.csv", "ethernet/p2p.xlsx", "ethernet/monitor/eth.csv",
    "ethernet/monitor/cronjob.log", "infiniband/ib.csv", "infiniband/p2p.xlsx",
    "infiniband/monitor/ib.csv", "infiniband/monitor/cronjob.log",
    "nvlink/nvsw.csv", "nvlink/p2p.xlsx", "nvlink/monitor/nvsw.csv",
    "nvlink/monitor/cronjob.log",
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
    "DAY0-Prepare/template/99-output/91-devices.yaml",
    "DAY0-Prepare/template/99-output-backup/notes.txt",
    "DAY0-Prepare/template/p2p/foo.lock",
    "DAY0-Prepare/template/finished-history/x.txt",
    "DAY0-Prepare/template/mixed/exact/CRE.JSON", "DAY0-Prepare/template/cre.json.bak",
    "DAY0-Prepare/template/mixed/CrE.JsOn.BAK",
    "DAY0-Prepare/template/mixed/service/OPERATOR.SERVICE-ACCOUNT.JSON",
    "DAY0-Prepare/template/private/uppercase/KEY.PEM", "monitor/mixed/SECRET.KEY",
    "DAY0-Prepare/template/private/key.P12", "tools/key.PFX",
    "DAY0-Prepare/template/private/key.JkS", "infra/key.KEYSTORE",
    "DAY0-Prepare/template/id_ed25519", "DAY0-Prepare/template/id_rsa.backup",
    "DAY0-Prepare/template/ID_ECDSA.old", "DAY0-Prepare/template/.ENV.dev",
    "DAY0-Prepare/template/.CONTROL-USERS.backup", "monitor/a.HTPASSWD.copy",
) + RUNTIME_MEMBERS
FINAL_RUNTIME_DENIES = (
    "**/99-output*", "**/99-output*/**", "**/*.lock",
    "**/finished-history", "**/finished-history/**",
)
MANIFEST_MEMBER = "infra/docker/deployment-source-manifest.json"
DAY0_INCLUDES = {"!DAY0-Prepare/*.py", "!DAY0-Prepare/template/", "!DAY0-Prepare/template/**"}
SECRET_BASENAMES = (
    "cre.json", "CrE.JsOn.BAK", "operator.SERVICE-ACCOUNT.JSON", "key.KEY", "key.PEM",
    "key.P12", "key.PFX", "key.JKS", "key.KEYSTORE", "ID_RSA.backup", "id_ed25519",
    "id_ecdsa.old", ".sSh", ".ENV", ".ENV.dev", ".CONTROL-USERS.backup", "a.HTPASSWD.copy",
)
PUBLIC_BASENAMES = (
    "laptop.pub", "service-account.json", "team.service-account.json.example",
    "container.env.example", "mapping.log", "cream.json", "key.pem.example",
)


def synthetic_tree(root):
    for name in ALLOWED:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"synthetic public marker\n")


def live_shaped_tree(root, runtime_symlinks=False):
    synthetic_tree(root)
    for name in DENIED:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if runtime_symlinks and name in RUNTIME_MEMBERS:
            path.symlink_to("synthetic-missing-runtime-target")
        else:
            path.write_bytes(b"synthetic denied marker\n")
    (root / "DAY0-Prepare/template/empty/.sSh").mkdir(parents=True)
    observed = {path.relative_to(root).as_posix() for path in root.rglob("*")
                if path.is_file() or path.is_symlink()}
    expected = set(ALLOWED) | set(DENIED)
    if observed != expected:
        raise AssertionError(f"live fixture lost literal members: {sorted(expected - observed)}")


def build_live_manifest(root):
    package = load_source("image_context_package_common", ROOT / "tools/_package_common.py")
    manifest = root / MANIFEST_MEMBER
    with mock.patch.object(package, "ROOT", root), mock.patch.object(
        package, "DEPLOYMENT_SOURCE_MANIFEST_BUILDER", DOCKER_ROOT / "activate.py"
    ):
        if package.write_deployment_source_manifest(manifest) != manifest:
            raise AssertionError("real package helper returned a different manifest")
    return manifest


def verify_cli(command, root, manifest):
    return subprocess.run([sys.executable, "-B", str(DOCKER_ROOT / "activate.py"), command,
                           "--source-root", str(root), "--manifest", str(manifest)],
                          capture_output=True, text=True)


class ImageContextSafetyDirectTests(unittest.TestCase):
    def test_live_fixture_preserves_every_literal_name_on_the_host_filesystem(self):
        expected = set(ALLOWED) | set(DENIED)
        # Case variants need different parent directories on default macOS;
        # overwriting an earlier marker is not mixed-case COPY coverage.
        self.assertEqual(len(expected), len({name.casefold() for name in expected}))
        for symlinks in (False, True):
            with self.subTest(symlinks=symlinks), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                live_shaped_tree(root, symlinks)
                observed = {p.relative_to(root).as_posix() for p in root.rglob("*")
                            if p.is_file() or p.is_symlink()}
                self.assertEqual(expected, observed)

    def test_three_ignore_files_pin_final_depth_independent_secret_denials(self):
        for path in IGNORE_FILES:
            with self.subTest(path=path):
                self.assertEqual(IGNORE_FILES[0].read_bytes(), path.read_bytes())
                rules = [line.strip() for line in path.read_text().splitlines()
                         if line.strip() and not line.startswith("#")]
                self.assertEqual("**", rules[0])
                self.assertEqual(DAY0_INCLUDES, {r for r in rules if r.startswith("!DAY0-Prepare/")})
                last_include = max(i for i, line in enumerate(rules) if line.startswith("!"))
                contract = load_source("image_context_contract", ROOT / "tools/project_contract.py")
                for denied in contract.image_credential_docker_patterns():
                    self.assertIn(denied, rules)
                    self.assertGreater(rules.index(denied), last_include)
                broad_include = max(i for i, r in enumerate(rules)
                                    if r.startswith("!") and r != "!requirements-container-top-level.lock")
                for denied in FINAL_RUNTIME_DENIES:
                    self.assertIn(denied, rules)
                    self.assertGreater(rules.index(denied), broad_include)
                self.assertGreater(rules.index("!requirements-container-top-level.lock"), rules.index("**/*.lock"))

    def test_shared_credential_vocabulary_has_independent_positive_and_negative_cases(self):
        contract = load_source("image_context_contract", ROOT / "tools/project_contract.py")
        for name in SECRET_BASENAMES:
            with self.subTest(name=name):
                self.assertTrue(contract.is_image_credential_name(name))
        for name in PUBLIC_BASENAMES:
            with self.subTest(name=name):
                self.assertFalse(contract.is_image_credential_name(name))

    def test_final_ignore_denials_cover_every_physical_gate_exclusion(self):
        activate = load_script("activate.py")
        forbidden = (set(activate.IMAGE_SOURCE_EXCLUDED_PATHS) - {MANIFEST_MEMBER}) | {
            prefix + "**" for prefix in activate.IMAGE_SOURCE_EXCLUDED_PREFIXES
        }
        for path in IGNORE_FILES:
            rules = [line.strip() for line in path.read_text().splitlines()
                     if line.strip() and not line.startswith("#")]
            last_include = max(i for i, line in enumerate(rules) if line.startswith("!"))
            for name in sorted(forbidden):
                with self.subTest(ignore=path, name=name):
                    self.assertIn(name, rules)
                    self.assertGreater(rules.index(name), last_include)

    def test_live_manifest_excludes_all_forbidden_names_without_following_runtime_links(self):
        activate = load_script("activate.py")
        for symlinks in (False, True):
            with self.subTest(symlinks=symlinks), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                live_shaped_tree(root, symlinks)
                manifest = root / MANIFEST_MEMBER
                payload = activate.write_image_source_manifest(root, manifest)
                self.assertEqual(set(ALLOWED), {record["path"] for record in payload["files"]})
                activate.verify_image_source_manifest(root, manifest)
                for name in RUNTIME_MEMBERS:
                    self.assertEqual(symlinks, (root / name).is_symlink())
                    self.assertTrue(os.path.lexists(root / name))

    def test_runtime_member_symlinks_are_physically_rejected(self):
        activate = load_script("activate.py")
        for name in RUNTIME_MEMBERS:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.symlink_to("synthetic-missing-runtime-target")
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)

    def test_changed_context_support_files_select_the_membership_tests(self):
        runner = load_source("image_context_runner", ROOT / "test_cases/run_related_tests.py")
        manifest = runner.load_and_validate_manifest(ROOT, ROOT / "test_cases/script_test_manifest.json")
        for relative in (".dockerignore", "infra/docker/.dockerignore", "infra/docker/Dockerfile.dockerignore",
                         "infra/docker/Dockerfile"):
            with self.subTest(path=relative):
                selected = runner.select_tests(ROOT, manifest, [relative], runner.PendingChanges())
                self.assertFalse(selected.full_suite, selected.reasons)
                self.assertIn("test_cases.test_image_context_safety", selected.tests)
                self.assertIn("test_cases.test_ztp_container_runtime", selected.tests)

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
        for name in ("DAY0-Prepare/site-a", "DAY0-Prepare/template/.sSh", "Finished-projects",
                     "DAY0-Prepare/template/finished-history", "DAY0-Prepare/template/99-output",
                     "DAY0-Prepare/template/foo.lock"):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                (root / name).mkdir(parents=True)
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)


class ImageContextSafetyWorkflowTests(unittest.TestCase):
    def test_dockerfile_uses_image_only_gate_and_live_gate_allows_project_data(self):
        dockerfile = (DOCKER_ROOT / "Dockerfile").read_text()
        logical = re.sub(r"\\\n\s*", " ", dockerfile)
        copies = re.findall(r"(?m)^COPY \. (\S+)/$", logical)
        self.assertEqual(["/opt/http-ztp/source-tree"], copies)
        gate_runs = [line for line in logical.splitlines()
                     if line.startswith("RUN ") and " verify-image-source-manifest " in line]
        self.assertEqual(1, len(gate_runs))
        self.assertNotRegex(gate_runs[0], r"\|\||;|(?<!&)&(?!&)")
        clauses = [" ".join(clause.split()) for clause in gate_runs[0].split("&&")]
        self.assertIn("/opt/http-ztp/activate.py verify-image-source-manifest "
                      "--source-root " + copies[0] + " --manifest /opt/http-ztp/image-source.sha256", clauses)
        for symlinks in (False, True):
            with self.subTest(symlinks=symlinks), tempfile.TemporaryDirectory() as directory:
                root, exported = Path(directory) / "live", Path(directory) / "image"
                live_shaped_tree(root, symlinks)
                # Exercise the real package helper -> activate builder -> image/live
                # CLI chain. Only filesystem roots change; no subprocess is mocked.
                manifest = build_live_manifest(root)
                manifest_before = manifest.read_bytes()
                self.assertEqual(set(ALLOWED), {r["path"] for r in json.loads(manifest_before)["files"]})
                live = verify_cli("verify-source-manifest", root, manifest)
                image = verify_cli("verify-image-source-manifest", root, manifest)
                self.assertEqual(0, live.returncode, live.stderr)
                self.assertEqual(2, image.returncode, image.stderr)
                self.assertIn("forbidden image source member", image.stderr)
                # Independently constructed allowed tree, not a Python simulation
                # of Docker filtering. The opt-in test below measures actual COPY.
                synthetic_tree(exported)
                image_manifest = exported / MANIFEST_MEMBER
                image_manifest.write_bytes(manifest_before)
                clean_image = verify_cli("verify-image-source-manifest", exported, image_manifest)
                self.assertEqual(0, clean_image.returncode, clean_image.stderr)
                self.assertEqual(manifest_before, manifest.read_bytes())
                self.assertEqual(b"synthetic denied marker\n", (root / "DAY0-Prepare/site-a/01-global.yaml").read_bytes())
                for name in RUNTIME_MEMBERS:
                    self.assertEqual(symlinks, (root / name).is_symlink())

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
        self.assertNotRegex(builder, r"(?m)^Error:", builder)
        self.assertEqual(["docker"], re.findall(r"(?m)^Driver:\s+(\S+)\s*$", builder),
                         "use only the local daemon's built-in builder")
        self.assertEqual([context_name], re.findall(r"(?m)^Endpoint:\s+(\S+)\s*$", builder))
        for ignore, symlinks in product(IGNORE_FILES, (False, True)):
            with self.subTest(ignore=ignore, symlinks=symlinks), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                context, result = base / "context", base / "result"
                live_shaped_tree(context, symlinks)
                manifest = build_live_manifest(context)
                manifest_before = manifest.read_bytes()
                self.assertEqual(set(ALLOWED), {r["path"] for r in json.loads(manifest_before)["files"]})
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
                observed = {path.relative_to(result).as_posix() for path in result.rglob("*")
                            if path.is_file() or path.is_symlink()}
                self.assertEqual(set(ALLOWED) | {MANIFEST_MEMBER}, observed)
                self.assertFalse((result / "DAY0-Prepare/site-a").exists())
                self.assertFalse((result / "DAY0-Prepare/template/empty/.sSh").exists())
                self.assertFalse((result / "DAY0-Prepare/template/finished-history").exists())
                verified = verify_cli("verify-image-source-manifest", result, result / MANIFEST_MEMBER)
                self.assertEqual(0, verified.returncode, verified.stderr)
                self.assertEqual(manifest_before, (result / MANIFEST_MEMBER).read_bytes())
                self.assertEqual(manifest_before, manifest.read_bytes())
                print(json.dumps({
                    "ignore": ignore.relative_to(ROOT).as_posix(),
                    "ignore_sha256": hashlib.sha256(ignore.read_bytes()).hexdigest(),
                    "runtime_form": "dangling-symlinks" if symlinks else "regular-files",
                    "runtime_members": len(RUNTIME_MEMBERS), "observed": sorted(observed),
                    "literal_input_members": len(set(ALLOWED) | set(DENIED)),
                    "manifest_sha256": hashlib.sha256(manifest_before).hexdigest(),
                    "copy_returncode": completed.returncode, "image_gate_returncode": verified.returncode,
                }, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
