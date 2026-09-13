#!/usr/bin/env python3
"""Direct and generator-workflow contracts for project password rotation."""

from __future__ import annotations

from contextlib import redirect_stderr, redirect_stdout
import ctypes
import importlib.util
import io
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

import yaml


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "tools/password-update.py"
GENERATOR_SCRIPT = (
    ROOT / "ztp/config/cumulus/template/90-c2-generate_configs.py"
)
LOAD_SCRIPT = ROOT / "DAY0-Prepare/11-load.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot import {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    sys.path.insert(0, str(path.parent))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.pop(0)
    return module


PASSWORD_UPDATE = load_module("password_update_under_test", SCRIPT)
GENERATOR = load_module("password_update_generator", GENERATOR_SCRIPT)
LOAD = load_module("password_update_load", LOAD_SCRIPT)

CUMULUS_HASH = "$6$testsalt$cumulus-checksum"
IB_HASH = "$y$j9T$ib-testsalt$ib-checksum"
NVL_HASH = "$y$j9T$nvl-testsalt$nvl-checksum"
HASHES = {
    "eth": CUMULUS_HASH,
    "ib": IB_HASH,
    "nvl": NVL_HASH,
}


class _FakeCFunction:
    """Small ctypes-function double that still accepts signature metadata."""

    def __init__(self, callback):
        self._callback = callback
        self.argtypes = None
        self.restype = None

    def __call__(self, *args):
        return self._callback(*args)


class _FakeLibxcrypt:
    """Deterministic crypt_gensalt_rn/crypt_rn double for backend contracts."""

    def __init__(self, *, verification_mismatch=False):
        self.verification_mismatch = verification_mismatch
        self.settings = []
        self.passwords = []
        self.crypt_gensalt_rn = _FakeCFunction(self._gensalt)
        self.crypt_rn = _FakeCFunction(self._crypt)

    @staticmethod
    def _bytes(value):
        if isinstance(value, bytes):
            return value
        if isinstance(value, bytearray):
            return bytes(value)
        return ctypes.string_at(value)

    def _gensalt(
        self, prefix, _count, _entropy, entropy_size, _output, _output_size,
    ):
        prefix_bytes = self._bytes(prefix)
        if entropy_size < 16:
            return None
        if prefix_bytes == b"$6$":
            return b"$6$testsalt$"
        if prefix_bytes == b"$y$":
            return b"$y$j9T$testsalt$"
        return None

    def _crypt(self, password, setting, _workspace, _workspace_size):
        password_bytes = self._bytes(password)
        setting_bytes = self._bytes(setting)
        self.passwords.append(password_bytes)
        self.settings.append(setting_bytes)
        if setting_bytes.startswith(b"$6$"):
            value = CUMULUS_HASH.encode("ascii")
        elif setting_bytes.startswith(b"$y$"):
            value = IB_HASH.encode("ascii")
        else:
            return None
        if self.verification_mismatch and setting_bytes == value:
            return value + b"-mismatch"
        return value

GLOBAL_TEXT = """schema_version: 2
# this comment and all unrelated formatting must remain byte-for-byte stable
switches:
  - eth:
      version: 5.18.1
      system:
        aaa:
          user:
            cumulus:
              full-name: cumulus,,,
              hashed-password: "'*'" # cumulus credential
  - ib:
      version: 25-03-1010
      system:
        aaa:
          user:
            admin:
              password: '*' # IB credential
        security:
          password-hardening:
            state: disabled
  - nvl:
      version: 25.02.4282
      system:
        aaa:
          user:
            admin:
              password: '*' # NVLink credential
        security:
          password-hardening:
            state: disabled
custom-extension: {keep: exactly}
"""

EXPECTED_TEXT = """schema_version: 2
# this comment and all unrelated formatting must remain byte-for-byte stable
switches:
  - eth:
      version: 5.18.1
      system:
        aaa:
          user:
            cumulus:
              full-name: cumulus,,,
              hashed-password: "$6$testsalt$cumulus-checksum" # cumulus credential
  - ib:
      version: 25-03-1010
      system:
        aaa:
          user:
            admin:
              password: "$y$j9T$ib-testsalt$ib-checksum" # IB credential
        security:
          password-hardening:
            state: disabled
  - nvl:
      version: 25.02.4282
      system:
        aaa:
          user:
            admin:
              password: "$y$j9T$nvl-testsalt$nvl-checksum" # NVLink credential
        security:
          password-hardening:
            state: disabled
custom-extension: {keep: exactly}
"""


class PasswordUpdateDirectTests(unittest.TestCase):
    def test_extract_password_hashes_returns_only_validated_platform_values(self):
        rendered = PASSWORD_UPDATE.rewrite_global_passwords(
            GLOBAL_TEXT, HASHES, sections=("eth", "ib", "nvl"),
        )

        self.assertEqual(
            HASHES,
            PASSWORD_UPDATE.extract_password_hashes(
                rendered, sections=("eth", "ib", "nvl"),
            ),
        )
        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError, "eth.*合法",
        ):
            PASSWORD_UPDATE.extract_password_hashes(
                GLOBAL_TEXT, sections=("eth",),
            )

    def test_rewrite_changes_only_password_scalars_and_preserves_crlf(self):
        source = GLOBAL_TEXT.replace("\n", "\r\n")
        expected = EXPECTED_TEXT.replace("\n", "\r\n")

        rendered = PASSWORD_UPDATE.rewrite_global_passwords(
            source, HASHES, sections=("eth", "ib", "nvl"),
        )

        self.assertEqual(expected, rendered)
        parsed = yaml.safe_load(rendered)
        switches = {
            next(iter(item)): next(iter(item.values()))
            for item in parsed["switches"]
        }
        self.assertEqual(
            CUMULUS_HASH,
            switches["eth"]["system"]["aaa"]["user"]["cumulus"][
                "hashed-password"
            ],
        )
        self.assertEqual(
            IB_HASH,
            switches["ib"]["system"]["aaa"]["user"]["admin"]["password"],
        )
        self.assertEqual(
            NVL_HASH,
            switches["nvl"]["system"]["aaa"]["user"]["admin"]["password"],
        )

    def test_nvos_requires_disabled_hardening_and_one_supported_field(self):
        enabled = GLOBAL_TEXT.replace(
            "state: disabled", "state: enabled", 1,
        )
        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError,
            "ib.*password-hardening.*disabled",
        ):
            PASSWORD_UPDATE.rewrite_global_passwords(
                enabled, {"ib": IB_HASH}, sections=("ib",),
            )

        duplicate = GLOBAL_TEXT.replace(
            "              password: '*' # IB credential",
            "              password: '*' # IB credential\n"
            "              hashed-password: '*'",
        )
        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError,
            "ib.*password.*hashed-password",
        ):
            PASSWORD_UPDATE.rewrite_global_passwords(
                duplicate, {"ib": IB_HASH}, sections=("ib",),
            )

    def test_project_contract_is_validated_before_requesting_a_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                GLOBAL_TEXT.replace("state: disabled", "state: enabled", 1),
                encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError,
                "password-hardening.*disabled",
            ):
                PASSWORD_UPDATE.rotate_project_passwords(
                    project,
                    platform="ib",
                    dry_run=True,
                    root=root,
                    day0=day0,
                    reader=lambda _prompt: self.fail(
                        "invalid global must fail before password input"
                    ),
                )

    def test_missing_hash_backend_fails_before_requesting_a_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                GLOBAL_TEXT, encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )

            with mock.patch.object(
                PASSWORD_UPDATE.shutil, "which", return_value=None,
            ), mock.patch.object(
                PASSWORD_UPDATE, "_homebrew_libxcrypt_path", return_value=None,
            ), self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "mkpasswd.*libxcrypt|libxcrypt.*mkpasswd",
            ):
                PASSWORD_UPDATE.rotate_project_passwords(
                    project,
                    platform="all",
                    dry_run=True,
                    root=root,
                    day0=day0,
                    reader=lambda _prompt: self.fail(
                        "missing hash backend must fail before password input"
                    ),
                )

    def test_incompatible_hash_backend_fails_before_requesting_a_password(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            (project / "01-global.yaml").write_text(
                GLOBAL_TEXT, encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )

            def incompatible_backend(command, **kwargs):
                method = command[1]
                if method == "--method=sha-512":
                    return subprocess.CompletedProcess(
                        command, 0, CUMULUS_HASH + "\n", "",
                    )
                return subprocess.CompletedProcess(
                    command, 1, "", "Invalid method 'yescrypt'\n",
                )

            with mock.patch.object(
                PASSWORD_UPDATE.shutil, "which", return_value="/opt/local/bin/mkpasswd",
            ), mock.patch.object(
                PASSWORD_UPDATE.subprocess, "run", side_effect=incompatible_backend,
            ) as runner, self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "yescrypt|Yescrypt",
            ):
                PASSWORD_UPDATE.rotate_project_passwords(
                    project,
                    platform="all",
                    dry_run=True,
                    root=root,
                    day0=day0,
                    reader=lambda _prompt: self.fail(
                        "incompatible backend must fail before password input"
                    ),
                )

            self.assertEqual(2, runner.call_count)
            self.assertTrue(all(
                call.kwargs["input"] == "http-mkpasswd-capability-probe\n"
                for call in runner.call_args_list
            ))

    def test_macos_libxcrypt_generates_and_verifies_both_required_hashes(self):
        secret = "placeholder"
        library = _FakeLibxcrypt()
        library_path = Path(
            "/opt/homebrew/Cellar/libxcrypt/4.5.2/lib/libcrypt.2.dylib"
        )
        with mock.patch.object(
            PASSWORD_UPDATE.shutil, "which", return_value=None,
        ), mock.patch.object(
            PASSWORD_UPDATE.platform, "system", return_value="Darwin",
        ), mock.patch.object(
            PASSWORD_UPDATE, "_homebrew_libxcrypt_path",
            return_value=library_path,
        ), mock.patch.object(
            PASSWORD_UPDATE, "_load_libxcrypt", return_value=library,
        ), mock.patch.object(
            PASSWORD_UPDATE.subprocess, "run",
        ) as runner:
            backend = PASSWORD_UPDATE.validate_hash_backend(("eth", "ib", "nvl"))
            sha512 = PASSWORD_UPDATE.hash_password(secret, "sha-512")
            yescrypt = PASSWORD_UPDATE.hash_password(secret, "yescrypt")

        self.assertEqual(str(library_path), backend)
        self.assertEqual(CUMULUS_HASH, sha512)
        self.assertEqual(IB_HASH, yescrypt)
        self.assertTrue(all(value == secret.encode("ascii") or value == b"http-mkpasswd-capability-probe" for value in library.passwords))
        self.assertIn(CUMULUS_HASH.encode("ascii"), library.settings)
        self.assertIn(IB_HASH.encode("ascii"), library.settings)
        runner.assert_not_called()

    def test_mkpasswd_remains_preferred_when_libxcrypt_is_installed(self):
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=CUMULUS_HASH + "\n", stderr="",
        )
        with mock.patch.object(
            PASSWORD_UPDATE.shutil, "which", return_value="/usr/bin/mkpasswd",
        ), mock.patch.object(
            PASSWORD_UPDATE, "_homebrew_libxcrypt_path",
        ) as libxcrypt, mock.patch.object(
            PASSWORD_UPDATE.subprocess, "run", return_value=completed,
        ):
            self.assertEqual(
                CUMULUS_HASH,
                PASSWORD_UPDATE.hash_password("placeholder", "sha-512"),
            )

        libxcrypt.assert_not_called()

    def test_libxcrypt_verification_failure_never_exposes_plaintext(self):
        secret = "placeholder"
        library = _FakeLibxcrypt(verification_mismatch=True)
        with mock.patch.object(
            PASSWORD_UPDATE.shutil, "which", return_value=None,
        ), mock.patch.object(
            PASSWORD_UPDATE.platform, "system", return_value="Darwin",
        ), mock.patch.object(
            PASSWORD_UPDATE, "_homebrew_libxcrypt_path",
            return_value=Path("/trusted/libcrypt.2.dylib"),
        ), mock.patch.object(
            PASSWORD_UPDATE, "_load_libxcrypt", return_value=library,
        ):
            with self.assertRaises(PASSWORD_UPDATE.PasswordUpdateError) as caught:
                PASSWORD_UPDATE.hash_password(secret, "yescrypt")

        self.assertNotIn(secret, str(caught.exception))

    def test_homebrew_libxcrypt_candidate_must_be_trusted_regular_file(self):
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory) / "homebrew"
            cellar = prefix / "Cellar/libxcrypt"
            library = cellar / "4.5.2/lib/libcrypt.2.dylib"
            library.parent.mkdir(parents=True)
            library.write_bytes(b"safe-library-fixture")
            library.chmod(0o444)

            self.assertEqual(
                library.resolve(),
                PASSWORD_UPDATE._validate_libxcrypt_candidate(library, cellar),
            )

            symlink = cellar / "4.5.2/lib/libcrypt-link.dylib"
            symlink.symlink_to(library.name)
            with self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "regular file|symlink",
            ):
                PASSWORD_UPDATE._validate_libxcrypt_candidate(symlink, cellar)

            library.chmod(0o664)
            with self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "writable|权限",
            ):
                PASSWORD_UPDATE._validate_libxcrypt_candidate(library, cellar)

    def test_platform_selection_does_not_touch_other_credentials(self):
        rendered = PASSWORD_UPDATE.rewrite_global_passwords(
            GLOBAL_TEXT, {"eth": CUMULUS_HASH}, sections=("eth",),
        )

        self.assertIn(f'hashed-password: "{CUMULUS_HASH}"', rendered)
        self.assertEqual(2, rendered.count("password: '*'"))

    def test_password_yaml_alias_is_rejected_instead_of_rewriting_anchor(self):
        aliased = GLOBAL_TEXT.replace(
            "schema_version: 2\n",
            "schema_version: 2\nshared-secret: &shared-secret \"'*'\"\n",
        ).replace(
            "hashed-password: \"'*'\" # cumulus credential",
            "hashed-password: *shared-secret # cumulus credential",
        )
        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError, "anchor/alias",
        ):
            PASSWORD_UPDATE.rewrite_global_passwords(
                aliased, {"eth": CUMULUS_HASH}, sections=("eth",),
            )

    def test_password_policy_requires_strong_printable_secret(self):
        PASSWORD_UPDATE.validate_plaintext_password(
            "Aa1!bcde", account_names=("cumulus",),
        )
        PASSWORD_UPDATE.validate_plaintext_password(
            "Correct-Horse9!Battery", account_names=("cumulus",),
        )
        rejected = (
            "Short1!",
            "all-lowercase-password9!",
            "ALL-UPPERCASE-PASSWORD9!",
            "NoDigits-In-ThisPassword!",
            "NoSpecialCharacterPassword9",
            "Strong-Admin-Password9!",
            "Correct-Horse9!Batter\u00ff",
        )
        for password in rejected:
            with self.subTest(password=password):
                with self.assertRaises(PASSWORD_UPDATE.PasswordUpdateError):
                    PASSWORD_UPDATE.validate_plaintext_password(
                        password, account_names=("admin",),
                    )

    def test_system_type_selects_sha512_for_cumulus_and_yescrypt_for_nvos(self):
        plaintexts = {
            "eth": "placeholder",
            "ib": "placeholder",
            "nvl": "placeholder",
        }
        with mock.patch.object(
            PASSWORD_UPDATE, "hash_password",
            side_effect=(CUMULUS_HASH, IB_HASH, NVL_HASH),
        ) as hasher:
            hashes = PASSWORD_UPDATE._hashes_for_sections(
                ("eth", "ib", "nvl"), plaintexts,
            )

        self.assertEqual(HASHES, hashes)
        self.assertEqual(
            [
                mock.call("placeholder", "sha-512"),
                mock.call("placeholder", "yescrypt"),
                mock.call("placeholder", "yescrypt"),
            ],
            hasher.call_args_list,
        )

    def test_platform_selection_exposes_three_independent_system_types(self):
        self.assertEqual(("eth", "ib", "nvl"), PASSWORD_UPDATE._sections_from_platform("all"))
        self.assertEqual(("eth",), PASSWORD_UPDATE._sections_from_platform("cumulus"))
        self.assertEqual(("ib",), PASSWORD_UPDATE._sections_from_platform("ib"))
        self.assertEqual(("nvl",), PASSWORD_UPDATE._sections_from_platform("nvl"))
        self.assertEqual(("ib", "nvl"), PASSWORD_UPDATE._sections_from_platform("nvos"))
        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError, "未知平台",
        ):
            PASSWORD_UPDATE._sections_from_platform("unexpected")

    def test_default_prompts_for_three_passwords_and_same_mode_prompts_once(self):
        distinct_answers = iter((
            "Aa1!ethx", "Aa1!ethx",
            "Bb2@ibxx", "Bb2@ibxx",
            "Cc3#nvlx", "Cc3#nvlx",
        ))
        distinct_prompts = []

        def distinct_reader(prompt):
            distinct_prompts.append(prompt)
            return next(distinct_answers)

        values = PASSWORD_UPDATE._passwords_for_sections(
            ("eth", "ib", "nvl"),
            same_password=False,
            reader=distinct_reader,
        )
        self.assertEqual(
            {"eth": "Aa1!ethx", "ib": "Bb2@ibxx", "nvl": "Cc3#nvlx"},
            values,
        )
        self.assertEqual(6, len(distinct_prompts))
        self.assertIn("Cumulus", distinct_prompts[0])
        self.assertIn("NVOS IB", distinct_prompts[2])
        self.assertIn("NVOS NVLink", distinct_prompts[4])

        shared_answers = iter(("Dd4$allx", "Dd4$allx"))
        shared_prompts = []

        def shared_reader(prompt):
            shared_prompts.append(prompt)
            return next(shared_answers)

        shared = PASSWORD_UPDATE._passwords_for_sections(
            ("eth", "ib", "nvl"),
            same_password=True,
            reader=shared_reader,
        )
        self.assertEqual(
            {"eth": "Dd4$allx", "ib": "Dd4$allx", "nvl": "Dd4$allx"},
            shared,
        )
        self.assertEqual(2, len(shared_prompts))

    def test_nvos_pair_can_share_one_password_but_single_platform_cannot(self):
        answers = iter(("Ee5%pair", "Ee5%pair"))
        shared = PASSWORD_UPDATE._passwords_for_sections(
            ("ib", "nvl"), same_password=True, reader=lambda _prompt: next(answers),
        )
        self.assertEqual({"ib": "Ee5%pair", "nvl": "Ee5%pair"}, shared)

        with self.assertRaisesRegex(
            PASSWORD_UPDATE.PasswordUpdateError, "多个系统",
        ):
            PASSWORD_UPDATE._passwords_for_sections(
                ("eth",), same_password=True,
                reader=lambda _prompt: self.fail("不应提示密码"),
            )

    def test_mkpasswd_receives_secret_only_over_stdin(self):
        secret = "placeholder"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0, stdout=CUMULUS_HASH + "\n", stderr="",
        )
        with mock.patch.object(
            PASSWORD_UPDATE.shutil, "which", return_value="/usr/bin/mkpasswd",
        ), mock.patch.object(
            PASSWORD_UPDATE.subprocess, "run", return_value=completed,
        ) as runner:
            result = PASSWORD_UPDATE.hash_password(secret, "sha-512")

        self.assertEqual(CUMULUS_HASH, result)
        command = runner.call_args.args[0]
        self.assertEqual(
            [
                "/usr/bin/mkpasswd",
                "--method=sha-512",
                "--password-fd=0",
            ],
            command,
        )
        self.assertNotIn(secret, command)
        self.assertEqual(secret + "\n", runner.call_args.kwargs["input"])
        self.assertFalse(runner.call_args.kwargs.get("shell", False))
        self.assertNotIn(
            "MKPASSWD_OPTIONS", runner.call_args.kwargs["env"],
        )

    def test_hash_backend_rejects_wrong_algorithm_without_leaking_secret(self):
        secret = "placeholder"
        completed = subprocess.CompletedProcess(
            args=[], returncode=0,
            stdout="$5$wrong$algorithm\n", stderr=secret,
        )
        with mock.patch.object(
            PASSWORD_UPDATE.shutil, "which", return_value="/usr/bin/mkpasswd",
        ), mock.patch.object(
            PASSWORD_UPDATE.subprocess, "run", return_value=completed,
        ):
            with self.assertRaises(PASSWORD_UPDATE.PasswordUpdateError) as caught:
                PASSWORD_UPDATE.hash_password(secret, "yescrypt")
        self.assertNotIn(secret, str(caught.exception))

    def test_file_update_is_atomic_mode_preserving_and_dry_run_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "01-global.yaml"
            path.write_bytes(GLOBAL_TEXT.encode("utf-8"))
            path.chmod(0o640)

            preview = PASSWORD_UPDATE.update_global_file(
                path, HASHES, sections=("eth", "ib", "nvl"), dry_run=True,
            )
            self.assertEqual(GLOBAL_TEXT, path.read_text(encoding="utf-8"))
            self.assertNotEqual(preview.before_sha256, preview.after_sha256)

            result = PASSWORD_UPDATE.update_global_file(
                path, HASHES, sections=("eth", "ib", "nvl"), dry_run=False,
            )
            self.assertEqual(EXPECTED_TEXT, path.read_text(encoding="utf-8"))
            self.assertEqual(0o640, stat.S_IMODE(path.stat().st_mode))
            self.assertEqual(preview.before_sha256, result.before_sha256)
            self.assertEqual(preview.after_sha256, result.after_sha256)
            self.assertEqual([], list(path.parent.glob(".01-global.yaml.*")))

    def test_global_symlink_and_project_outside_day0_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            real = project / "real-global.yaml"
            real.write_text(GLOBAL_TEXT, encoding="utf-8")
            (project / "01-global.yaml").symlink_to(real.name)
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )

            with self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "regular file|symlink",
            ):
                PASSWORD_UPDATE.resolve_global_file(
                    "demo", root=root, day0=day0,
                )

            outside = root / "outside"
            outside.mkdir()
            (outside / "01-global.yaml").write_text(GLOBAL_TEXT, encoding="utf-8")
            (outside / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            with self.assertRaisesRegex(
                PASSWORD_UPDATE.PasswordUpdateError, "DAY0-Prepare",
            ):
                PASSWORD_UPDATE.resolve_global_file(
                    str(outside), root=root, day0=day0,
                )

    def test_main_output_never_contains_plaintext_or_generated_hashes(self):
        secret = "placeholder"
        result = PASSWORD_UPDATE.UpdateResult(
            path=Path("/safe/01-global.yaml"),
            sections=("eth", "ib", "nvl"),
            before_sha256="a" * 64,
            after_sha256="b" * 64,
            changed=True,
            dry_run=False,
        )
        stdout = io.StringIO()
        stderr = io.StringIO()
        with mock.patch.object(
            PASSWORD_UPDATE, "rotate_project_passwords", return_value=result,
        ), redirect_stdout(stdout), redirect_stderr(stderr):
            status = PASSWORD_UPDATE.main(["demo"])

        output = stdout.getvalue() + stderr.getvalue()
        self.assertEqual(0, status)
        self.assertNotIn(secret, output)
        for value in HASHES.values():
            self.assertNotIn(value, output)

    def test_main_handoff_is_runtime_neutral_and_forbids_docker_load_after_sync(self):
        result = PASSWORD_UPDATE.UpdateResult(
            path=Path("/safe/01-global.yaml"),
            sections=("eth", "ib", "nvl"),
            before_sha256="a" * 64,
            after_sha256="b" * 64,
            changed=True,
            dry_run=False,
        )
        stdout = io.StringIO()
        with mock.patch.object(
            PASSWORD_UPDATE, "rotate_project_passwords", return_value=result,
        ), redirect_stdout(stdout):
            status = PASSWORD_UPDATE.main(["demo"])

        output = stdout.getvalue()
        self.assertEqual(0, status)
        self.assertIn("同步时必须显式选择 runtime", output)
        self.assertIn("Native/systemd", output)
        self.assertIn("--runtime native", output)
        self.assertIn("DAY0-Prepare/11-load.py", output)
        self.assertIn("Docker/Supervisor", output)
        self.assertIn("--runtime docker", output)
        self.assertIn("infra/docker/deploy.sh deploy", output)
        self.assertIn("deploy-preloaded <IMAGE_ID>", output)
        self.assertIn("source write 后不得执行 load", output)
        self.assertNotIn("同步到管理服务器后必须重新运行 11-load.py", output)


class PasswordUpdateGeneratorWorkflowTests(unittest.TestCase):
    def test_load_cli_enables_interactive_selection_and_rejects_dry_run_mutation(self):
        args = LOAD.parse_args(["demo", "--update-passwords"])
        self.assertIs(args.update_passwords, True)
        LOAD.validate_password_update_options(args)

        dry_run = LOAD.parse_args([
            "demo", "--dry-run", "--update-passwords",
        ])
        with self.assertRaisesRegex(LOAD.LoadError, "dry-run"):
            LOAD.validate_password_update_options(dry_run)

    def test_load_password_menu_lists_five_choices_and_maps_each_system(self):
        expected = {
            "1": ("cumulus", False),
            "2": ("ib", False),
            "3": ("nvl", False),
        }
        for choice, result in expected.items():
            with self.subTest(choice=choice):
                output = []
                self.assertEqual(
                    result,
                    LOAD.prompt_password_update_selection(
                        reader=lambda _prompt, value=choice: value,
                        printer=output.append,
                    ),
                )
                menu = "\n".join(output)
                for label in (
                    "Cumulus Ethernet", "NVOS IB", "NVOS NVLink",
                    "NVOS IB/NVLink", "ALL",
                ):
                    self.assertIn(label, menu)

    def test_load_password_menu_asks_multi_systems_whether_to_share_password(self):
        answers = iter(("4", "y"))
        self.assertEqual(
            ("nvos", True),
            LOAD.prompt_password_update_selection(
                reader=lambda _prompt: next(answers), printer=lambda _line: None,
            ),
        )

        answers = iter(("5", ""))
        self.assertEqual(
            ("all", False),
            LOAD.prompt_password_update_selection(
                reader=lambda _prompt: next(answers), printer=lambda _line: None,
            ),
        )

    def test_load_preflights_both_hash_methods_before_project_mutation(self):
        with mock.patch.object(
            LOAD, "_load_password_update_module", return_value=PASSWORD_UPDATE,
        ), mock.patch.object(
            PASSWORD_UPDATE, "_mkpasswd_executable",
            return_value="/usr/bin/mkpasswd",
        ), mock.patch.object(
            PASSWORD_UPDATE, "hash_password",
        ) as hasher:
            self.assertEqual(
                "/usr/bin/mkpasswd", LOAD.preflight_password_update_backend(),
            )
        self.assertEqual([
            mock.call("http-mkpasswd-capability-probe", "sha-512"),
            mock.call("http-mkpasswd-capability-probe", "yescrypt"),
        ], hasher.call_args_list)

    def test_load_runs_password_rotation_under_lock_before_input_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "demo"
            project.mkdir()
            (project / "01-global.yaml").write_text(
                GLOBAL_TEXT, encoding="utf-8",
            )
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            events = []

            def initialize(*_args, **_kwargs):
                events.append("initialize")

            def select(*_args, **_kwargs):
                events.append("select")
                return "all", True

            def rotate(*_args, **_kwargs):
                events.append("password")

            def reject_after_rotation(*_args, **_kwargs):
                events.append("validate")
                raise LOAD.LoadError("stop after order check")

            def preflight_backend():
                events.append("backend")

            with mock.patch.object(
                LOAD, "preflight_password_update_backend",
                side_effect=preflight_backend,
            ), mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=73,
            ) as acquire, mock.patch.object(
                LOAD, "release_deployment_lock",
            ) as release, mock.patch.object(
                LOAD, "runtime_os", return_value="Darwin",
            ), mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ), mock.patch.object(
                LOAD, "resolve_project", return_value=project,
            ), mock.patch.object(
                LOAD, "sync_marker_present", return_value=False,
            ), mock.patch.object(
                LOAD, "initialize_from_template", side_effect=initialize,
            ), mock.patch.object(
                LOAD, "prompt_password_update_selection", side_effect=select,
            ), mock.patch.object(
                LOAD, "update_passwords_before_load", side_effect=rotate,
            ) as password_step, mock.patch.object(
                LOAD, "validate_inputs", side_effect=reject_after_rotation,
            ):
                status = LOAD.main([
                    str(project), "--update-passwords",
                ])

            self.assertEqual(1, status)
            self.assertEqual(
                ["backend", "initialize", "select", "password", "validate"], events,
            )
            acquire.assert_called_once_with(exclusive=True)
            release.assert_called_once_with(73)
            password_step.assert_called_once_with(
                project, platform="all", same_password=True,
            )

    def test_macos_missing_backend_blocks_combined_password_and_mini_before_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "demo"
            project.mkdir()
            (project / "01-global.yaml").write_text(
                GLOBAL_TEXT, encoding="utf-8",
            )
            customer = project / "customer-devices.txt"
            customer.write_text("tan-spine02\n", encoding="utf-8")

            with mock.patch.object(
                LOAD, "preflight_password_update_backend",
                side_effect=LOAD.LoadError("未找到 whois 包提供的 mkpasswd"),
            ) as backend, mock.patch.object(
                LOAD, "acquire_deployment_lock",
            ) as acquire, mock.patch.object(
                LOAD, "initialize_from_template",
            ) as initialize, mock.patch.object(
                LOAD, "prompt_password_update_selection",
            ) as prompt, mock.patch.object(
                LOAD, "generate_configs",
            ) as generate:
                status = LOAD.main([
                    str(project), "--no-upgrade", "--update-passwords",
                    "--air", "--mini", customer.name,
                ])

            self.assertEqual(1, status)
            backend.assert_called_once_with()
            acquire.assert_not_called()
            initialize.assert_not_called()
            prompt.assert_not_called()
            generate.assert_not_called()
            self.assertTrue(customer.is_file())
            self.assertFalse(customer.is_symlink())
            self.assertFalse((project / "04-air-mini-devices.txt").exists())

    def test_macos_combined_password_and_mini_reaches_generation_in_order(self):
        with tempfile.TemporaryDirectory() as directory:
            project = Path(directory) / "demo"
            project.mkdir()
            customer = project / "customer-devices.txt"
            customer.write_text("tan-spine02\n", encoding="utf-8")
            settings = mock.Mock(
                schema_version=2,
                versions={"eth": "5.18"},
                ztp_prefix="/ztp",
            )
            inputs = mock.Mock(
                settings=settings,
                device_types=frozenset({"eth"}),
                pubkeys=(),
                p2p_file=project / "p2p.xlsx",
                air_topology_policy=None,
            )
            events = []
            generated_mini_paths = []

            def event(name, result=None):
                def callback(*_args, **_kwargs):
                    events.append(name)
                    return result
                return callback

            def stop_after_generation(*_args, **kwargs):
                events.append("generate")
                generated_mini_paths.append(kwargs["mini_devices_file"])
                raise LOAD.LoadError("stop after combined option check")

            with mock.patch.object(
                LOAD, "preflight_password_update_backend",
                side_effect=event("backend"),
            ), mock.patch.object(
                LOAD, "acquire_deployment_lock", return_value=73,
            ), mock.patch.object(
                LOAD, "release_deployment_lock",
            ), mock.patch.object(
                LOAD, "runtime_os", return_value="Darwin",
            ), mock.patch.object(
                LOAD, "supports_local_ztp_services", return_value=False,
            ), mock.patch.object(
                LOAD, "resolve_project", return_value=project,
            ), mock.patch.object(
                LOAD, "sync_marker_present", return_value=False,
            ), mock.patch.object(
                LOAD, "initialize_from_template", side_effect=event("initialize"),
            ), mock.patch.object(
                LOAD, "prompt_password_update_selection",
                side_effect=event("select", ("all", True)),
            ), mock.patch.object(
                LOAD, "update_passwords_before_load", side_effect=event("password"),
            ), mock.patch.object(
                LOAD, "validate_inputs", side_effect=event("validate", (inputs, {})),
            ), mock.patch.object(
                LOAD, "activate_project", side_effect=event("activate"),
            ), mock.patch.object(
                LOAD, "render_ztp_runtime", side_effect=event("runtime"),
            ), mock.patch.object(
                LOAD, "snapshot_release_links", return_value={},
            ), mock.patch.object(
                LOAD, "generate_configs", side_effect=stop_after_generation,
            ):
                status = LOAD.main([
                    str(project), "--no-upgrade", "--update-passwords",
                    "--air", "--mini", customer.name,
                ])

            self.assertEqual(1, status)
            self.assertEqual([
                "backend", "initialize", "select", "password", "validate",
                "activate", "runtime", "generate",
            ], events)
            self.assertEqual([customer.resolve()], generated_mini_paths)

    def test_load_password_step_updates_global_before_real_generators_consume_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            global_file = project / "01-global.yaml"
            global_file.write_bytes(GLOBAL_TEXT.encode("utf-8"))
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            binary_dir = root / "bin"
            binary_dir.mkdir()
            mkpasswd = binary_dir / "mkpasswd"
            mkpasswd.write_text(
                "#!/bin/sh\n"
                "IFS= read -r ignored\n"
                "case \"$1\" in\n"
                "  --method=sha-512) printf '%s\\n' '$6$testsalt$cumulus-checksum' ;;\n"
                "  --method=yescrypt) printf '%s\\n' '$y$j9T$testsalt$nvos-checksum' ;;\n"
                "  *) exit 2 ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            mkpasswd.chmod(0o755)
            answers = iter(("Ff6&allx", "Ff6&allx"))

            with mock.patch.dict(os.environ, {"PATH": str(binary_dir)}):
                result = LOAD.update_passwords_before_load(
                    project,
                    platform="all",
                    same_password=True,
                    root=root,
                    day0=day0,
                    reader=lambda _prompt: next(answers),
                )

            self.assertTrue(result.changed)
            with mock.patch.object(GENERATOR, "_GLOBAL_FILE", str(global_file)):
                eth = GENERATOR.load_global("eth")
                ib = GENERATOR.load_global("ib")
                nvl = GENERATOR.load_global("nvl")
            self.assertTrue(
                eth["system"]["aaa"]["user"]["cumulus"][
                    "hashed-password"
                ].startswith("$6$")
            )
            self.assertTrue(
                ib["system"]["aaa"]["user"]["admin"]["password"].startswith("$y$")
            )
            self.assertTrue(
                nvl["system"]["aaa"]["user"]["admin"]["password"].startswith("$y$")
            )

    def test_macos_load_uses_libxcrypt_before_real_generators_consume_hashes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "http"
            day0 = root / "DAY0-Prepare"
            project = day0 / "demo"
            project.mkdir(parents=True)
            global_file = project / "01-global.yaml"
            global_file.write_bytes(GLOBAL_TEXT.encode("utf-8"))
            (project / "02-devices_config.csv").write_text(
                "hostname,type\n", encoding="utf-8",
            )
            library = _FakeLibxcrypt()
            answers = iter(("Gg7*allx", "Gg7*allx"))

            with mock.patch.object(
                LOAD, "_load_password_update_module", return_value=PASSWORD_UPDATE,
            ), mock.patch.object(
                PASSWORD_UPDATE.shutil, "which", return_value=None,
            ), mock.patch.object(
                PASSWORD_UPDATE.platform, "system", return_value="Darwin",
            ), mock.patch.object(
                PASSWORD_UPDATE, "_homebrew_libxcrypt_path",
                return_value=Path(
                    "/opt/homebrew/Cellar/libxcrypt/4.5.2/lib/libcrypt.2.dylib"
                ),
            ), mock.patch.object(
                PASSWORD_UPDATE, "_load_libxcrypt", return_value=library,
            ):
                self.assertIn(
                    "libcrypt.2.dylib", LOAD.preflight_password_update_backend(),
                )
                result = LOAD.update_passwords_before_load(
                    project,
                    platform="all",
                    same_password=True,
                    root=root,
                    day0=day0,
                    reader=lambda _prompt: next(answers),
                )

            self.assertTrue(result.changed)
            with mock.patch.object(GENERATOR, "_GLOBAL_FILE", str(global_file)):
                eth = GENERATOR.load_global("eth")
                ib = GENERATOR.load_global("ib")
                nvl = GENERATOR.load_global("nvl")
            self.assertEqual(
                CUMULUS_HASH,
                eth["system"]["aaa"]["user"]["cumulus"]["hashed-password"],
            )
            self.assertEqual(
                IB_HASH,
                ib["system"]["aaa"]["user"]["admin"]["password"],
            )
            self.assertEqual(
                IB_HASH,
                nvl["system"]["aaa"]["user"]["admin"]["password"],
            )

    def test_rotated_hashes_reach_real_cumulus_and_nvos_generation_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            global_file = Path(directory) / "01-global.yaml"
            global_file.write_bytes(GLOBAL_TEXT.encode("utf-8"))
            PASSWORD_UPDATE.update_global_file(
                global_file, HASHES,
                sections=("eth", "ib", "nvl"), dry_run=False,
            )

            with mock.patch.object(GENERATOR, "_GLOBAL_FILE", str(global_file)):
                eth = GENERATOR.load_global("eth")
                ib = GENERATOR.load_global("ib")
                nvl = GENERATOR.load_global("nvl")

            source = (
                ROOT
                / "ztp/config/cumulus/template/03-templates-j2/oob-leaf.yaml.j2"
            ).read_text(encoding="utf-8")
            password_line = next(
                line.strip()
                for line in source.splitlines()
                if "g.system.aaa.user.cumulus['hashed-password']" in line
            )
            rendered = GENERATOR.build_env().from_string(
                password_line + "\n"
            ).render(g=eth)

            self.assertEqual(
                CUMULUS_HASH,
                yaml.safe_load(rendered)["hashed-password"],
            )
            self.assertEqual(
                IB_HASH,
                GENERATOR._build_system_ib("ib-switch01", ib)["aaa"]["user"]
                ["admin"]["password"],
            )
            self.assertEqual(
                NVL_HASH,
                GENERATOR._build_system_ib("nvl-switch01", nvl)["aaa"]["user"]
                ["admin"]["password"],
            )


if __name__ == "__main__":
    unittest.main()
