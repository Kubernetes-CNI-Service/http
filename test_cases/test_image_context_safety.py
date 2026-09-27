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
# Fixture membership/target strings come from producer authority, never from
# the image deny predicate. The permitted controls above remain independent.
PRODUCER_CONTRACT = load_source("image_context_producers", ROOT / "tools/project_contract.py")
RUNTIME_TARGETS = dict(PRODUCER_CONTRACT.runtime_link_specs())
RUNTIME_MEMBERS = tuple(RUNTIME_TARGETS)
RUNTIME_FORMS = ("regular", "resolving", "dangling")
EMPTY_DENIED_DIRS = (
    "DAY0-Prepare/template/empty/.sSh", "ztp/optimize/site-a-sample",
    "monitor/status",
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
    "infra/docker/container.env", "infra/docker/desired-state.json",
    "infra/docker/runtime-state.json", "ztp/.setup_manifest",
    "ztp/config/isc-dhcp-server/dhcpd_synthetic.hosts",
    "monitor/status/collection-cycles/air/ethernet/0001.json",
    "monitor/generate-monitor.log", "monitor/monitor.html",
    "monitor/cabletracker-main/fixture.js", "monitor/cabletracker-main.zip",
    "DAY0-Prepare/template/id_ed25519", "DAY0-Prepare/template/id_rsa.backup",
    "DAY0-Prepare/template/ID_ECDSA.old", "DAY0-Prepare/template/.ENV.dev",
    "DAY0-Prepare/template/.CONTROL-USERS.backup", "monitor/a.HTPASSWD.copy",
) + RUNTIME_MEMBERS
CONTEXT_ONLY_DENIED = ("01-global-dev.yaml",)
SYNTHETIC_DENIED = DENIED + CONTEXT_ONLY_DENIED
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
    "id_rsa.pub", "id_ed25519.pub", "id_ecdsa.pub",
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


def live_shaped_tree(root, runtime_form="regular"):
    if runtime_form not in RUNTIME_FORMS:
        raise AssertionError("unknown runtime fixture form")
    synthetic_tree(root)
    expected = set(ALLOWED) | set(SYNTHETIC_DENIED)
    for name in sorted(set(SYNTHETIC_DENIED)):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if runtime_form != "regular" and name in RUNTIME_TARGETS:
            project = "site-a" if runtime_form == "resolving" else "missing-site"
            path.symlink_to(RUNTIME_TARGETS[name].format(project=project))
        else:
            path.write_bytes(b"synthetic denied marker\n")
    if runtime_form == "resolving":
        project_root = (root / "DAY0-Prepare/site-a").resolve()
        for name in RUNTIME_MEMBERS:
            target = (root / name).resolve(strict=False)
            target.relative_to(project_root)  # fail before writes if the fixture escapes
            if target.suffix:
                target.parent.mkdir(parents=True, exist_ok=True)
                if not target.exists():
                    target.write_bytes(b"synthetic project marker\n")
                expected.add(target.relative_to(root.resolve()).as_posix())
            else:
                target.mkdir(parents=True, exist_ok=True)
        if not all((root / name).exists() for name in RUNTIME_MEMBERS):
            raise AssertionError("resolving fixture contains a dangling producer binding")
    if runtime_form == "dangling" and any((root / name).exists() for name in RUNTIME_MEMBERS):
        raise AssertionError("dangling fixture contains a resolving producer binding")
    for name in EMPTY_DENIED_DIRS:
        (root / name).mkdir(parents=True, exist_ok=True)
    observed = {path.relative_to(root).as_posix() for path in root.rglob("*")
                if path.is_file() or path.is_symlink()}
    if observed != expected:
        raise AssertionError(f"live fixture terminal mismatch: {sorted(expected ^ observed)}")
    return expected


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
    def test_every_declared_producer_binding_is_denied_independently_of_suffix(self):
        activate = load_script("activate.py")
        setup = load_source("image_context_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
        names = {path.as_posix() for path, _target, _project in activate.PUBLISHED_RUNTIME_LINKS}
        names.update("ztp/" + name for name, _target, _kind in setup.MAPPINGS)
        names.update(name for name, _target, _kind in setup.WORKSPACE_INPUT_MAPPINGS)
        for mappings in (setup.BRINGUP_OUTPUT_MAPPINGS, setup.ANALYZER_INPUT_MAPPINGS,
                         setup.ANALYZER_OUTPUT_MAPPINGS, setup._NET_CSV_LINKS):
            names.update(Path(path).relative_to(ROOT).as_posix() for path, _target in mappings)
        names.update(Path(path).relative_to(ROOT).as_posix()
                     for path in setup.P2P_INPUT_LINKS + setup.P2P_OUTPUT_LINKS)
        names.add(Path(setup.P2P_AIR_JSON_LINK).relative_to(ROOT).as_posix())
        for pairs in (setup._monitor_inventory_link_pairs(), setup._monitor_link_paths(str(ROOT / "DAY0-Prepare/site-a"))):
            names.update(Path(path).relative_to(ROOT).as_posix() for path, _target in pairs)
        # Independent acceptance cases for the publication-pointer family.
        names.update(("ztp/config/cumulus/latest_yaml", "ztp/config/nvos/latest_yaml"))
        self.assertTrue(names.issubset(RUNTIME_MEMBERS), sorted(names - set(RUNTIME_MEMBERS)))
        for name, form in product(sorted(names), ("file", "directory", "dangling")):
            with self.subTest(name=name, form=form), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                member = root / name
                member.parent.mkdir(parents=True, exist_ok=True)
                if form == "directory":
                    member.mkdir()
                elif form == "dangling":
                    member.symlink_to("synthetic-missing-project-target")
                else:
                    member.write_bytes(b"synthetic runtime marker\n")
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)

    def test_host_state_generated_reference_and_excluded_subtree_entries_are_denied(self):
        activate = load_script("activate.py")
        names = (
            "Finished-projects", "infra/docker/container.env", "infra/docker/desired-state.json",
            "infra/docker/runtime-state.json", "ztp/status", "ztp/.setup_manifest",
            "ztp/config/isc-dhcp-server/dhcpd_synthetic.hosts", "ztp/optimize/site-a-sample",
            "monitor/monitor.html", "monitor/cabletracker-main", "monitor/cabletracker-main.zip",
            "infra/logs", "infiniband/bringup", "monitor/status", "ztp/backup",
            "infra/.logs.lock", "infra/.logs-migration.json",
            "infra/.logs-migration.ABC123",
            "ztp/config/cumulus/template/.claude", "ztp/config/publickey", "ztp/image",
            "tools/ib-tool-Jie", "tools/ibdiagnet-analyze-tool",
        )
        for name, form in product(names, ("file", "directory", "dangling", "descendant")):
            with self.subTest(name=name, form=form), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                synthetic_tree(root)
                member = root / name
                member.parent.mkdir(parents=True, exist_ok=True)
                if form == "directory":
                    member.mkdir()
                elif form == "descendant":
                    member.mkdir()
                    (member / "unmanifested.opaque").write_bytes(b"synthetic nested marker\n")
                elif form == "dangling":
                    member.symlink_to("synthetic-missing-project-target")
                else:
                    member.write_bytes(b"synthetic host state\n")
                with self.assertRaisesRegex(activate.ActivationError, "forbidden image source member"):
                    activate.verify_image_source_tree(root)

    def test_host_state_family_matching_preserves_neutral_prefix_neighbors(self):
        for name in ("infra/logs-extra/source.py", "monitor/status-code.py",
                     "infra/.logs-migrationx", "infra/.logs-migration-not-a-receipt",
                     "monitor/cabletracker-mainland/source.py", "ztp/optimize/site-sample-extra/source.py",
                     "ztp/optimize/neutral/site-sample/source.py", "infra/docker/container.env.example"):
            with self.subTest(name=name):
                self.assertFalse(PRODUCER_CONTRACT.is_image_host_state_path(name))

    def test_shared_producer_contract_retains_independent_target_examples(self):
        expected = {
            "monitor/ethernet": "../DAY0-Prepare/{project}/99-output-monitor/ethernet",
            "monitor/ztp-status": "../ztp/status",
            "ethernet/monitor/eth.csv": "../eth.csv",
            "ethernet/monitor/eth-info": "../../DAY0-Prepare/{project}/99-output-monitor/ethernet/eth-info",
            "ztp/config/cumulus/latest_yaml": "template/99-output/latest",
            "ztp/config/nvos/latest_yaml": "template/99-output-ib_nvl/latest",
            "ztp/config/cumulus/template/P2P/output-p2p": "../../../../../DAY0-Prepare/{project}/99-output-p2p",
            "ztp/config/nvos/template/P2P/ib-info": "../../../../../DAY0-Prepare/{project}/99-output-monitor/infiniband/ib-info",
        }
        for name, target in expected.items():
            with self.subTest(name=name):
                self.assertEqual(target, RUNTIME_TARGETS[name])

    def test_image_host_state_ignore_block_is_generated_from_shared_vocabulary(self):
        contract = load_source("image_context_contract", ROOT / "tools/project_contract.py")
        self.assertTrue(hasattr(contract, "image_host_state_docker_patterns"))
        expected = list(contract.image_host_state_docker_patterns())
        for path in IGNORE_FILES:
            lines = path.read_text().splitlines()
            self.assertIn("# BEGIN generated image host-state denials", lines)
            self.assertIn("# END generated image host-state denials", lines)
            start = lines.index("# BEGIN generated image host-state denials")
            end = lines.index("# END generated image host-state denials")
            self.assertEqual(expected, lines[start + 1:end])
            self.assertGreater(start, max(i for i, line in enumerate(lines) if line.startswith("!")))

    def test_live_fixture_preserves_every_literal_name_on_the_host_filesystem(self):
        expected = set(ALLOWED) | set(SYNTHETIC_DENIED)
        # Case variants need different parent directories on default macOS;
        # overwriting an earlier marker is not mixed-case COPY coverage.
        self.assertEqual(len(expected), len({name.casefold() for name in expected}))
        for runtime_form in RUNTIME_FORMS:
            with self.subTest(runtime_form=runtime_form), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                expected = live_shaped_tree(root, runtime_form)
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
                self.assertIn("!requirements-container-top-level.lock", rules)
                self.assertGreater(rules.index("!requirements-container-top-level.lock"), rules.index("**/*.lock"))

    def test_ignore_change_rule_includes_management_key_pins(self):
        manifest = json.loads((ROOT / "test_cases/script_test_manifest.json").read_text())
        paths = {".dockerignore", "infra/docker/.dockerignore",
                 "infra/docker/Dockerfile.dockerignore", "infra/docker/Dockerfile"}
        matching = [rule for rule in manifest["path_rules"] if set(rule["paths"]) == paths]
        self.assertEqual(1, len(matching))
        self.assertTrue({
            "test_cases.test_image_context_safety", "test_cases.test_ztp_container_runtime",
            "test_cases.test_docker_management_ssh_key",
        }.issubset(matching[0]["tests"]))

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
        for runtime_form in RUNTIME_FORMS:
            with self.subTest(runtime_form=runtime_form), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                live_shaped_tree(root, runtime_form)
                manifest = root / MANIFEST_MEMBER
                payload = activate.write_image_source_manifest(root, manifest)
                self.assertEqual(set(ALLOWED), {record["path"] for record in payload["files"]})
                activate.verify_image_source_manifest(root, manifest)
                for name in RUNTIME_MEMBERS:
                    self.assertEqual(runtime_form != "regular", (root / name).is_symlink())
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
    def test_setup_real_monitor_and_latest_producers_consume_the_shared_contract(self):
        setup = load_source("image_context_setup", ROOT / "DAY0-Prepare/01-a-setup.py")
        project = ROOT / "DAY0-Prepare/site-a"
        for name, target in setup._monitor_link_paths(str(project)) + setup._monitor_inventory_link_pairs():
            relative = Path(name).relative_to(ROOT).as_posix()
            self.assertIn(relative, RUNTIME_TARGETS)
            self.assertEqual(RUNTIME_TARGETS[relative].format(project="site-a"),
                             os.path.relpath(target, os.path.dirname(name)))
        with mock.patch.object(setup, "_latest_cumulus_publish_dir", return_value="synthetic-cumulus-release"), \
                mock.patch.object(setup, "_latest_nvos_publish_dir", return_value="synthetic-nvos-release"), \
                mock.patch.object(setup, "_make_exact_link") as link:
            setup._process_latest_yaml(str(project))
        self.assertEqual(4, link.call_count)
        outer = {Path(call.args[0]).relative_to(ROOT).as_posix():
                 os.path.relpath(call.args[1], os.path.dirname(call.args[0]))
                 for call in link.call_args_list if Path(call.args[0]).name == "latest_yaml"}
        self.assertEqual({"ztp/config/cumulus/latest_yaml": "template/99-output/latest",
                          "ztp/config/nvos/latest_yaml": "template/99-output-ib_nvl/latest"}, outer)
        self.assertTrue(set(outer).issubset(RUNTIME_MEMBERS))

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
        for runtime_form in RUNTIME_FORMS:
            with self.subTest(runtime_form=runtime_form), tempfile.TemporaryDirectory() as directory:
                root, exported = Path(directory) / "live", Path(directory) / "image"
                live_shaped_tree(root, runtime_form)
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
                    self.assertEqual(runtime_form != "regular", (root / name).is_symlink())

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
        for ignore, runtime_form in product(IGNORE_FILES, RUNTIME_FORMS):
            with self.subTest(ignore=ignore, runtime_form=runtime_form), tempfile.TemporaryDirectory() as directory:
                base = Path(directory)
                context, result = base / "context", base / "result"
                input_members = live_shaped_tree(context, runtime_form)
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
                self.assertEqual({r["path"] for r in json.loads(manifest_before)["files"]},
                                 observed - {MANIFEST_MEMBER})
                self.assertFalse((result / "DAY0-Prepare/site-a").exists())
                self.assertFalse((result / "DAY0-Prepare/template/empty/.sSh").exists())
                self.assertFalse((result / "DAY0-Prepare/template/finished-history").exists())
                for name in EMPTY_DENIED_DIRS:
                    self.assertFalse(os.path.lexists(result / name), name)
                verified = verify_cli("verify-image-source-manifest", result, result / MANIFEST_MEMBER)
                self.assertEqual(0, verified.returncode, verified.stderr)
                self.assertEqual(manifest_before, (result / MANIFEST_MEMBER).read_bytes())
                self.assertEqual(manifest_before, manifest.read_bytes())
                print(json.dumps({
                    "ignore": ignore.relative_to(ROOT).as_posix(),
                    "ignore_sha256": hashlib.sha256(ignore.read_bytes()).hexdigest(),
                    "runtime_form": runtime_form,
                    "runtime_members": len(RUNTIME_MEMBERS), "observed": sorted(observed),
                    "input_terminal_members": len(input_members),
                    "manifest_sha256": hashlib.sha256(manifest_before).hexdigest(),
                    "copy_returncode": completed.returncode, "image_gate_returncode": verified.returncode,
                }, sort_keys=True), flush=True)


if __name__ == "__main__":
    unittest.main()
