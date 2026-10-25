#!/usr/bin/env python3
"""Required external KAT; independent target credential policy tests-first.
O-only prospective v4 text: no author execution, no crypt hash copied into repo.
"""
from __future__ import annotations
import ast
import hashlib
import hmac
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from test_cases.module_loader import load_script

ROOT = Path(__file__).resolve().parents[1]
APP = load_script("initial_target_policy_draft",
    ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py")
KAT_SHA256 = "646c817d8028af7385cd61bce7a2d5ed34eb522798a498f6cb0df1b75a8e1cbf"

def required_external_kat():
    configured = os.environ.get("HTTP_TEST_INITIAL_SETUP_KAT_INPUT")
    if not configured or not Path(configured).is_absolute():
        raise RuntimeError("FIXTURE HOLD: explicit absolute HTTP_TEST_INITIAL_SETUP_KAT_INPUT required")
    path = Path(configured)
    # O_NONBLOCK must be set before fstat: a substituted FIFO cannot block open.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        first = os.fstat(fd)
        if not stat.S_ISREG(first.st_mode) or first.st_nlink != 1 or first.st_size != 135693:
            raise RuntimeError("FIXTURE HOLD: required KAT file type/link/size changed")
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        nine = tuple(getattr(first, name) for name in fields)
        readings = []
        for _ in range(2):
            if nine != tuple(getattr(os.fstat(fd), name) for name in fields):
                raise RuntimeError("FIXTURE HOLD: KAT FD changed before a pass")
            if nine != tuple(getattr(path.lstat(), name) for name in fields):
                raise RuntimeError("FIXTURE HOLD: KAT named identity changed before a pass")
            os.lseek(fd, 0, os.SEEK_SET)
            chunks = []
            total = 0
            eof = False
            # At most fixed source size plus one byte per pass; no unbounded
            # read after cap. An exact source still needs a real EOF observation.
            while total < 135694:
                part = os.read(fd, min(65536, 135694 - total))
                if not part:
                    eof = True
                    break
                total += len(part)
                chunks.append(part)
            if not eof or total != 135693:
                raise RuntimeError("FIXTURE HOLD: KAT is truncated/growing or lacks bounded EOF")
            if nine != tuple(getattr(os.fstat(fd), name) for name in fields):
                raise RuntimeError("FIXTURE HOLD: KAT FD changed during a pass")
            if nine != tuple(getattr(path.lstat(), name) for name in fields):
                raise RuntimeError("FIXTURE HOLD: KAT named identity changed during a pass")
            readings.append(b"".join(chunks))
        if readings[0] != readings[1]:
            raise RuntimeError("FIXTURE HOLD: KAT changed between complete passes")
        raw = readings[0]
    finally:
        os.close(fd)
    if hashlib.sha256(raw).hexdigest() != KAT_SHA256:
        raise RuntimeError("FIXTURE HOLD: KAT source SHA differs from reviewed input")
    selected = {}
    for node in ast.parse(raw).body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            name = node.targets[0].id
            if name in {"PASSWORD", "SHA512", "YESCRYPT"}:
                if name in selected or not isinstance(node.value, ast.Constant) or type(node.value.value) is not str:
                    raise RuntimeError("FIXTURE HOLD: KAT literal missing/ambiguous/not an exact string")
                selected[name] = node.value.value
    if set(selected) != {"PASSWORD", "SHA512", "YESCRYPT"}:
        raise RuntimeError("FIXTURE HOLD: required three KAT literals missing")
    if not selected["SHA512"].startswith("$6$") or not selected["YESCRYPT"].startswith("$y$"):
        raise RuntimeError("FIXTURE HOLD: reviewed KAT algorithms changed")
    return selected

def project_global(setting):
    # Literal project shape, not derived from APP's parser or generator.
    return (
        "schema_version: 2\ncommon:\n  switch:\n    system:\n"
        "      config:\n        auto-save:\n          state: enabled\n"
        "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
        '          admin:\n            password: "' + setting + '"\n'
    )

class IndependentTargetCredentialPolicyDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kat = required_external_kat()

    def test_original_external_sha512_and_yescrypt_pairs_use_real_backend(self):
        for algorithm in ("SHA512", "YESCRYPT"):
            with self.subTest(algorithm=algorithm):
                self.assertTrue(APP.verify_password_hash(self.kat["PASSWORD"], self.kat[algorithm]))
                self.assertFalse(APP.verify_password_hash("Incorrect123!", self.kat[algorithm]))

    def test_worker_uses_stdin_only_and_backend_timeout_is_fail_closed(self):
        reply = subprocess.CompletedProcess([], 0, '{"status":"match"}', "")
        # Sole transport MODEL. This does not replace the real external KAT
        # method above or qualify a native crypt library.
        with patch.dict(os.environ, {
                "NVOS_TARGET_PASSWORD": "PUBLIC-AMBIENT-TARGET",
                "ZTP_ETH_PASSWORD": "PUBLIC-AMBIENT-OOB",
                "PYTHONPATH": "/PUBLIC-AMBIENT-PYTHONPATH",
                "LD_PRELOAD": "/PUBLIC-AMBIENT-LIBRARY",
                "HTTP_TEST_INITIAL_SETUP_KAT_INPUT": "/PUBLIC-AMBIENT-KAT",
        }), patch.object(APP.subprocess, "run", return_value=reply) as run:
            self.assertTrue(APP.verify_password_hash(self.kat["PASSWORD"], self.kat["SHA512"]))
        args, kwargs = run.call_args
        expected_argv = [
            sys.executable, "-I", "-S", "-B",
            str((ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py").resolve()),
            "--_verify-password",
        ]
        self.assertEqual(1, run.call_count, "one verification may spawn only one fixed worker")
        self.assertTrue(args == (expected_argv,), "worker argv must use the sole canonical same-interpreter entry")
        self.assertTrue(set(kwargs) == {"input", "text", "capture_output", "timeout", "check", "env"},
                        "worker kwargs must be a closed transport protocol")
        self.assertTrue(kwargs["text"] is True and kwargs["capture_output"] is True and
                        kwargs["check"] is False, "worker capture options must be exact booleans")
        self.assertTrue(type(kwargs["timeout"]) is int and kwargs["timeout"] == 8,
                        "worker deadline must be the reviewed eight seconds")
        self.assertTrue(kwargs["env"] == {
            "PATH": os.defpath, "LC_ALL": "C", "LANG": "C", "PYTHONDONTWRITEBYTECODE": "1",
        }, "worker must receive only the independent fixed environment")
        request = json.loads(kwargs["input"])
        self.assertTrue(type(request) is dict and set(request) == {"password", "hash"},
                        "worker stdin must contain exactly the two reviewed fields")
        self.assertTrue(type(request["password"]) is str and type(request["hash"]) is str and
                        hmac.compare_digest(request["password"], self.kat["PASSWORD"]) and
                        hmac.compare_digest(request["hash"], self.kat["SHA512"]),
                        "only stdin may carry this exact password and project crypt setting")
        self.assertLessEqual(len(kwargs["input"].encode("utf-8")), 8192,
                             "worker JSON request must fit the fixed input budget")
        self.assertFalse(self.kat["SHA512"] in repr(args), "crypt setting must not enter argv")
        self.assertFalse(self.kat["PASSWORD"] in repr(args), "KAT password must not enter argv")
        self.assertTrue(self.kat["PASSWORD"] in kwargs["input"], "worker must receive secret on stdin")
        self.assertLessEqual(kwargs["timeout"], 10)
        with patch.object(APP.subprocess, "run", side_effect=subprocess.TimeoutExpired(["worker"], 8)):
            with self.assertRaises(APP.SetupError) as caught:
                APP.verify_password_hash(self.kat["PASSWORD"], self.kat["YESCRYPT"])
        self.assertFalse(self.kat["PASSWORD"] in str(caught.exception),
                         "diagnostic must not disclose the KAT password")
        self.assertFalse(self.kat["YESCRYPT"] in str(caught.exception),
                         "diagnostic must not disclose the KAT setting")

    def test_interactive_target_matches_project_and_changed_global_invalidates_cached_secret(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            original = project_global(self.kat["YESCRYPT"])
            path.write_text(original, encoding="utf-8")
            policy = APP.ProjectPasswordPolicy(path, "admin")
            with patch.object(APP.getpass, "getpass",
                              side_effect=[self.kat["PASSWORD"], self.kat["PASSWORD"]]) as prompts:
                value = policy.password()
            self.assertTrue(hmac.compare_digest(value, self.kat["PASSWORD"]))
            self.assertEqual(2, prompts.call_count)
            self.assertTrue(policy.matches(self.kat["PASSWORD"]))
            self.assertFalse(policy.matches("PUBLIC-UNRELATED-OOB-ONLY"))
            self.assertTrue(original == path.read_text(encoding="utf-8"),
                            "policy must not rewrite the project global")
            path.write_text(original + "# PUBLIC independent content change\n", encoding="utf-8")
            with self.assertRaises(APP.SetupError):
                policy.assert_unchanged()
            # Check the actual cached-secret consumers, not only the guard API.
            with patch.object(APP.getpass, "getpass",
                              side_effect=AssertionError("changed project must not prompt")) as changed_prompts:
                with self.assertRaises(APP.SetupError):
                    policy.password()
                with self.assertRaises(APP.SetupError):
                    policy.matches(self.kat["PASSWORD"])
            changed_prompts.assert_not_called()

    def test_explicit_auto_target_is_real_verified_and_never_prompts_or_uses_oob(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            path.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
            with patch.object(APP.getpass, "getpass", side_effect=AssertionError("auto prompt forbidden")) as prompts:
                with self.subTest(source="correct explicit target"):
                    policy = APP.ProjectPasswordPolicy(path, "admin",
                        target_password=self.kat["PASSWORD"], interactive=False)
                    self.assertTrue(hmac.compare_digest(policy.password(), self.kat["PASSWORD"]))
                for supplied in (None, "PUBLIC-UNRELATED-OOB-ONLY"):
                    with self.subTest(source="missing" if supplied is None else "mismatch"):
                        with self.assertRaises(APP.SetupError):
                            policy = APP.ProjectPasswordPolicy(path, "admin",
                                target_password=supplied, interactive=False)
                            policy.password()
            prompts.assert_not_called()

    def test_owned_auto_env_supports_explicit_target_without_relaxing_legacy_data_grammar(self):
        initial = "PUBLIC-INITIAL-ONLY"
        oob = "PUBLIC-OOB-ONLY"
        base = "NVOS_INITIAL_PASSWORD=" + initial + "\nZTP_ETH_PASSWORD=" + oob + "\n"
        target_line = "NVOS_TARGET_PASSWORD=" + self.kat["PASSWORD"] + "\n"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "auto.env"
            with self.subTest(format="extended"):
                path.write_text(base + target_line, encoding="utf-8")
                path.chmod(0o600)
                values = APP.read_auto_credentials(path)
                self.assertEqual({"NVOS_INITIAL_PASSWORD", "NVOS_TARGET_PASSWORD", "ZTP_ETH_PASSWORD"}, set(values))
                self.assertEqual(initial, values["NVOS_INITIAL_PASSWORD"])
                self.assertEqual(oob, values["ZTP_ETH_PASSWORD"])
                self.assertTrue(hmac.compare_digest(self.kat["PASSWORD"], values["NVOS_TARGET_PASSWORD"]))
            # Legacy format may still be read as data; actual AUTO write admission
            # must separately reject its missing target. No silent OOB migration.
            with self.subTest(format="legacy data only"):
                path.write_text(base, encoding="utf-8")
                path.chmod(0o600)
                values = APP.read_auto_credentials(path)
                self.assertEqual({"NVOS_INITIAL_PASSWORD", "ZTP_ETH_PASSWORD"}, set(values))
                self.assertNotIn("NVOS_TARGET_PASSWORD", values)
            for label, payload in (
                ("duplicate target", base + target_line + target_line),
                ("empty target", base + "NVOS_TARGET_PASSWORD=\n"),
                ("unknown key", base + target_line + "NVOS_TARGET_PASSWORD_EXTRA=PUBLIC\n"),
            ):
                with self.subTest(format=label):
                    path.write_text(payload, encoding="utf-8")
                    path.chmod(0o600)
                    with self.assertRaises(APP.SetupError):
                        APP.read_auto_credentials(path)
            with self.subTest(format="unsafe mode"):
                path.write_text(base + target_line, encoding="utf-8")
                path.chmod(0o644)
                with self.assertRaises(APP.SetupError):
                    APP.read_auto_credentials(path)


    def test_supplied_target_rejects_non_string_length_and_non_printable_ascii_before_backend(self):
        samples = (
            ("missing", None), ("boolean", True), ("integer", 7),
            ("list", []), ("mapping", {}),
            ("empty", ""), ("seven", "A" * 7), ("one hundred twenty nine", "A" * 129),
            ("non ASCII", "PUBLIC-\u00e9-8"), ("DEL", "PUBLIC-\x7f-8"),
            ("NUL", "PUBLIC-\x00-8"), ("newline", "PUBLIC-\n-8"),
            ("carriage return", "PUBLIC-\r-8"), ("tab", "PUBLIC-\t-8"),
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            path.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
            for label, supplied in samples:
                attempts = []
                def forbidden_backend(*args, **kwargs):
                    attempts.append("backend called")
                    raise AssertionError("invalid target must not enter the hash backend")
                with self.subTest(shape=label), patch.object(APP, "verify_password_hash",
                        side_effect=forbidden_backend), patch.object(
                        APP.getpass, "getpass", side_effect=AssertionError("auto prompt forbidden")) as prompts:
                    with self.assertRaises(APP.SetupError):
                        policy = APP.ProjectPasswordPolicy(path, "admin",
                            target_password=supplied, interactive=False)
                        policy.password()
                    self.assertEqual([], attempts)
                    prompts.assert_not_called()

    def test_supplied_target_accepts_inclusive_ascii_shape_before_modeled_match(self):
        # This is only syntax admission through a clearly MODELED hash boundary.
        # The original external 12-character SHA512/yescrypt real pairs remain
        # independently required above. No new KAT is generated here.
        samples = (("eight", "A" * 8), ("one hundred twenty eight", "~" * 128),
                   ("printable space", " " * 8))
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            path.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
            for label, supplied in samples:
                observed = []
                def modeled_match(password, setting):
                    observed.append((password, setting))
                    return True
                with self.subTest(shape=label), patch.object(APP, "verify_password_hash",
                        side_effect=modeled_match), patch.object(
                        APP.getpass, "getpass", side_effect=AssertionError("auto prompt forbidden")) as prompts:
                    policy = APP.ProjectPasswordPolicy(path, "admin",
                        target_password=supplied, interactive=False)
                    self.assertTrue(hmac.compare_digest(supplied, policy.password()))
                    self.assertTrue(bool(observed), "syntax-admitted target must still enter verification")
                    self.assertTrue(all(hmac.compare_digest(password, supplied) and
                        hmac.compare_digest(setting, self.kat["YESCRYPT"])
                        for password, setting in observed),
                        "verification must use the supplied target and this project's exact setting")
                    prompts.assert_not_called()

class ProjectPasswordGlobalParserDraftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.kat = required_external_kat()

    def test_account_ib_override_and_prior_alias_have_independent_literal_authorities(self):
        # Common admin and IB operator intentionally share one real setting;
        # IB admin overrides it with the other. Matching cleartext alone cannot
        # distinguish these roles, so compare the selected setting explicitly.
        source = (
            "common:\n  switch:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: &common_target " +
            json.dumps(self.kat["SHA512"]) + "\n"
            "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
            "          admin:\n            password: "
                + json.dumps(self.kat["YESCRYPT"])
                + "\n"
            "          operator:\n            password: *common_target\n"
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            path.write_text(source, encoding="utf-8")
            before = path.read_bytes()
            admin = APP.ProjectPasswordPolicy(path, "admin",
                target_password=self.kat["PASSWORD"], interactive=False)
            operator = APP.ProjectPasswordPolicy(path, "operator",
                target_password=self.kat["PASSWORD"], interactive=False)
            self.assertTrue(hmac.compare_digest(admin.target_hash, self.kat["YESCRYPT"]),
                            "the exact IB account override must win, not the first password")
            self.assertTrue(hmac.compare_digest(operator.target_hash, self.kat["SHA512"]),
                            "only the explicit account may resolve the prior common alias")
            self.assertTrue(hmac.compare_digest(admin.password(), self.kat["PASSWORD"]))
            self.assertTrue(hmac.compare_digest(operator.password(), self.kat["PASSWORD"]))
            self.assertFalse(admin.matches("Incorrect123!"))
            self.assertTrue(before == path.read_bytes(), "policy/parser must not modify the actual global")

    def test_ambiguous_or_unsupported_global_is_rejected_before_hash_or_prompt(self):
        sha = json.dumps(self.kat["SHA512"])
        yescrypt = json.dumps(self.kat["YESCRYPT"])
        valid = project_global(self.kat["YESCRYPT"])
        target = (
            "            password: "
            + yescrypt
            + "\n"
        )
        cases = (
            ("duplicate selected mapping key", valid.replace(target, target + target)),
            ("two IB profiles even with same value", valid +
                "- ib:\n    system:\n      aaa:\n        user:\n"
                "          admin:\n            password: "
                    + yescrypt
                    + "\n"),
            ("switches not a list", "switches:\n  ib:\n    system: null\n"),
            ("IB section not a mapping", "switches:\n- ib: []\n"),
            ("selected system not a mapping", "switches:\n- ib:\n    system: PUBLIC\n"),
            ("selected user not a mapping", "switches:\n- ib:\n    system:\n      aaa:\n        user: []\n"),
            ("account absent", valid.replace("          admin:", "          another:")),
            ("non string setting", valid.replace(target, "            password: false\n")),
            ("malformed crypt setting", valid.replace(target, "            password: PUBLIC-NOT-CRYPT\n")),
            ("unknown alias", valid.replace(target, "            password: *unavailable\n")),
            ("forward alias", valid.replace(target, "            password: *later\n") +
                "- nvl:\n    note: &later " + yescrypt + "\n"),
            ("duplicate anchor with otherwise valid authority",
                "common:\n  switch:\n    system:\n      aaa:\n        user:\n"
                "          admin:\n            password: &duplicate " + sha + "\n"
                "switches:\n- ib:\n    system:\n      aaa:\n        user:\n"
                "          admin:\n            password: &duplicate " + yescrypt + "\n"),
            ("recursive alias", "common:\n  switch: &recursive\n    note: *recursive\n" +
                valid[valid.index("switches:"):]),
            ("tagged selected setting", valid.replace(target, "            password: !!str " + yescrypt + "\n")),
            ("unsupported unquoted tag in common", valid.replace(
                "  switch:\n", "  switch:\n    note: !unsupported PUBLIC\n", 1)),
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            for label, source in cases:
                attempts = []
                def forbidden_backend(*args, **kwargs):
                    attempts.append("backend called")
                    raise AssertionError("bad project authority must not invoke the hash backend")
                path.write_text(source, encoding="utf-8")
                before = path.read_bytes()
                with self.subTest(case=label), patch.object(APP, "verify_password_hash",
                        side_effect=forbidden_backend), patch.object(
                        APP.getpass, "getpass", side_effect=AssertionError("invalid global must not prompt")) as prompts:
                    with self.assertRaises(APP.SetupError):
                        policy = APP.ProjectPasswordPolicy(path, "admin",
                            target_password=self.kat["PASSWORD"], interactive=False)
                        policy.password()
                    self.assertEqual([], attempts)
                    prompts.assert_not_called()
                    self.assertTrue(before == path.read_bytes(), "rejected global must remain byte-identical")

    def test_same_bytes_alias_rebinding_invalidates_all_policy_consumers_before_backend(self):
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            original = root / "project-one-global.yaml"
            other = root / "project-two-global.yaml"
            canary = root / "PUBLIC-CANARY"
            original.write_text(project_global(self.kat["YESCRYPT"]), encoding="utf-8")
            other.write_bytes(original.read_bytes())
            canary.write_bytes(b"PUBLIC-FOREIGN-CONTROL\n")
            alias = root / "01-global.yaml"
            alias.symlink_to(original)
            policy = APP.ProjectPasswordPolicy(alias, "admin",
                target_password=self.kat["PASSWORD"], interactive=False)
            protected = {path: (tuple(getattr(path.lstat(), field) for field in fields), path.read_bytes())
                         for path in (original, other, canary)}
            alias.unlink()
            alias.symlink_to(other)
            attempts = []
            def forbidden_backend(*args, **kwargs):
                attempts.append("backend called")
                raise AssertionError("rebound project must not invoke the backend")
            with patch.object(APP, "verify_password_hash", side_effect=forbidden_backend), patch.object(
                    APP.getpass, "getpass", side_effect=AssertionError("rebound project must not prompt")) as prompts:
                with self.assertRaises(APP.SetupError):
                    policy.assert_unchanged()
                with self.assertRaises(APP.SetupError):
                    policy.password()
                with self.assertRaises(APP.SetupError):
                    policy.matches(self.kat["PASSWORD"])
                self.assertEqual([], attempts)
                prompts.assert_not_called()
            self.assertTrue(all(before == (tuple(getattr(path.lstat(), field) for field in fields),
                path.read_bytes()) for path, before in protected.items()),
                "policy invalidation must preserve both project globals and the foreign control")

    def test_adjacent_and_triple_double_quoted_settings_are_not_single_yaml_authority(self):
        setting = self.kat["YESCRYPT"]
        valid = project_global(setting)
        original_line = (
            "            password: "
            + json.dumps(setting)
            + "\n"
        )
        split = 7
        values = (
            ("two adjacent double quoted tokens",
             json.dumps(setting[:split]) + " " + json.dumps(setting[split:])),
            ("triple double quoted token", '"""' + setting + '"""'),
            ("Python octal escape is not a JSON/YAML authority",
             json.dumps(setting).replace("$", "\\044", 1)),
            ("Python named escape is not a JSON/YAML authority",
             json.dumps(setting).replace("$", "\\N{DOLLAR SIGN}", 1)),
        )
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "01-global.yaml"
            for label, raw_scalar in values:
                source = valid.replace(original_line, "            password: "
                    + raw_scalar
                    + "\n")
                attempts = []
                def forbidden_backend(*args, **kwargs):
                    attempts.append("backend called")
                    raise AssertionError("non-single YAML scalar must not invoke backend")
                path.write_text(source, encoding="utf-8")
                before = path.read_bytes()
                with self.subTest(case=label), patch.object(APP, "verify_password_hash",
                        side_effect=forbidden_backend), patch.object(
                        APP.getpass, "getpass", side_effect=AssertionError("invalid global must not prompt")) as prompts:
                    with self.assertRaises(APP.SetupError):
                        policy = APP.ProjectPasswordPolicy(path, "admin",
                            target_password=self.kat["PASSWORD"], interactive=False)
                        policy.password()
                    self.assertEqual([], attempts)
                    prompts.assert_not_called()
                    self.assertTrue(before == path.read_bytes(),
                                    "rejected quoted authority must remain byte-identical")


class WorkerMalformedProtocolTests(unittest.TestCase):
    def test_parent_deep_json_reply_is_a_sanitized_domain_failure(self):
        kat = required_external_kat()
        # Independent bounded PUBLIC malformed reply. It must not become a
        # raw RecursionError or an accepted native password result.
        deep = "[" * 3000 + "0" + "]" * 3000
        self.assertLessEqual(len(deep.encode("ascii")), 8192)
        reply = subprocess.CompletedProcess([], 0, deep, "")
        with patch.object(APP.subprocess, "run", return_value=reply) as run:
            with self.assertRaises(APP.SetupError) as caught:
                APP.verify_password_hash(kat["PASSWORD"], kat["SHA512"])
        self.assertEqual(1, run.call_count, "exactly one bounded worker request is permitted")
        message = str(caught.exception)
        self.assertTrue(message == "project password verification backend failed or is unavailable",
                        "malformed worker replies require the fixed safe diagnostic")
        self.assertTrue(kat["PASSWORD"] not in message and kat["SHA512"] not in message,
                        "a protocol diagnostic must not expose credentials or settings")
        self.assertIsNone(caught.exception.__cause__)
        self.assertTrue(caught.exception.__suppress_context__)

    def test_actual_private_worker_deep_stdin_has_exact_error_protocol(self):
        # No valid password/hash request: the actual isolated private CLI must
        # reject this before reaching native crypt or ordinary project main.
        deep = "[" * 3000 + "0" + "]" * 3000
        self.assertLessEqual(len(deep.encode("ascii")), 8192)
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            canary = home / "01-global.yaml"
            canary.write_bytes(b"PUBLIC-NOT-A-PASSWORD-PROJECT\n")
            before = canary.read_bytes()
            result = subprocess.run(
                [sys.executable, "-I", "-S", "-B",
                 str((ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py").resolve()),
                 "--_verify-password"],
                input=deep, text=True, capture_output=True, timeout=8, check=False,
                cwd=home, env={"PATH": os.defpath, "LC_ALL": "C", "LANG": "C",
                               "PYTHONDONTWRITEBYTECODE": "1"},
            )
            self.assertEqual(2, result.returncode)
            self.assertEqual('{"status":"error"}\n', result.stdout)
            self.assertEqual("", result.stderr)
            self.assertEqual(before, canary.read_bytes())
            self.assertEqual(["01-global.yaml"], sorted(path.name for path in home.iterdir()))


class AutoEnvTargetShapeTests(unittest.TestCase):
    def test_reader_admits_only_valid_explicit_target_and_never_verifies_or_prompts(self):
        base = "NVOS_INITIAL_PASSWORD=PUBLIC-INITIAL\nZTP_ETH_PASSWORD=PUBLIC-OOB\n"
        valid = ("A" * 8, "B" * 128, " " * 8, "PUBLIC-TARGET-ONLY")
        invalid = ("A" * 7, "B" * 129, "PUBLIC-\u00e9-TARGET", "PUBLIC-\x7f-TARGET", "PUBLIC-\x00-TARGET")
        fields = ("st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
                  "st_size", "st_mtime_ns", "st_ctime_ns")
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "auto.env"
            with patch.object(APP, "verify_password_hash",
                    side_effect=AssertionError("credential data reader must not verify project hashes")) as verify, \
                 patch.object(APP.getpass, "getpass",
                    side_effect=AssertionError("credential data reader must never prompt")) as prompts:
                for target in valid:
                    path.write_text(base + "NVOS_TARGET_PASSWORD=" + target + "\n", encoding="utf-8")
                    path.chmod(0o600)
                    before = (tuple(getattr(path.lstat(), key) for key in fields), path.read_bytes())
                    result = APP.read_auto_credentials(path)
                    self.assertEqual({"NVOS_INITIAL_PASSWORD", "ZTP_ETH_PASSWORD", "NVOS_TARGET_PASSWORD"}, set(result))
                    self.assertTrue(hmac.compare_digest(result["NVOS_TARGET_PASSWORD"], target),
                                    "the reader must preserve the supplied target, not substitute an OOB value")
                    self.assertTrue(before == (tuple(getattr(path.lstat(), key) for key in fields), path.read_bytes()),
                                    "a valid credential read must preserve file identity and bytes")
                for target in invalid:
                    path.write_text(base + "NVOS_TARGET_PASSWORD=" + target + "\n", encoding="utf-8")
                    path.chmod(0o600)
                    before = (tuple(getattr(path.lstat(), key) for key in fields), path.read_bytes())
                    with self.assertRaises(APP.SetupError):
                        APP.read_auto_credentials(path)
                    self.assertTrue(before == (tuple(getattr(path.lstat(), key) for key in fields), path.read_bytes()),
                                    "rejected credential data must remain untouched")
                self.assertEqual(0, verify.call_count, "data parsing does not grant project authority")
                self.assertEqual(0, prompts.call_count, "auto credential data parsing cannot become interactive")


if __name__ == "__main__":
    unittest.main()
