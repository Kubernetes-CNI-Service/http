#!/usr/bin/env python3
"""Safety and behavior tests for the read-only ZTP diagnostic collector."""

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tarfile
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(name, None)
    return module


COLLECTOR = load_module(
    "ztp_diagnostic_collector", ROOT / "tools/collect-ztp-diagnostics.py"
)
CONTRACT = load_module("diagnostic_project_contract", ROOT / "tools/project_contract.py")


class DiagnosticBundleTests(unittest.TestCase):
    def test_real_project_collector_archive_excludes_management_private_sentinel(self):
        sentinel = b"DOCKER_MGMT_DIAGNOSTIC_SECRET_4b9ee72ae2c14d67\n"
        with tempfile.TemporaryDirectory(prefix="http-key-diagnostic-") as temporary:
            root = Path(temporary)
            project = root / "project"
            private = project / ".ssh/id_ed25519"
            private.parent.mkdir(parents=True)
            private.write_bytes(sentinel)
            for name in (
                "01-global.yaml", "02-devices_config.csv",
                "02-dhcp-subnet_config.csv",
            ):
                (project / name).write_text("safe: example\n", encoding="utf-8")
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "ssh-key-exclusion")
            COLLECTOR.collect_project_inputs(builder, project)
            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                names = archive.getnames()
                self.assertFalse(any(".ssh" in Path(name).parts for name in names))
                payload = b"".join(
                    archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                )
            self.assertNotIn(sentinel, payload)

    def test_imported_main_restores_the_callers_umask_on_failure(self):
        original = os.umask(0o027)
        try:
            with mock.patch.object(
                COLLECTOR, "parse_args",
                side_effect=COLLECTOR.DiagnosticError("synthetic failure"),
            ), mock.patch("sys.stderr", io.StringIO()):
                self.assertEqual(1, COLLECTOR.main([]))
            observed = os.umask(0o027)
            self.assertEqual(0o027, observed)
        finally:
            os.umask(original)

    def test_supervisor_server_evidence_never_uses_systemd_or_journal(self):
        captures = []
        writes = []

        class Builder:
            @staticmethod
            def capture_command(command_id, argv, **_kwargs):
                captures.append((command_id, tuple(argv)))

            @staticmethod
            def write_json(relative, value, *, source):
                writes.append((relative, value, source))

            @staticmethod
            def write(relative, data, *, source, redacted=True):
                writes.append((relative, data.decode(), source, redacted))

            @staticmethod
            def warn(message):
                raise AssertionError(f"unexpected runtime evidence warning: {message}")

        class Backend:
            name = "supervisor"

            @staticmethod
            def is_active(service):
                return service == "apache2"

            @staticmethod
            def is_enabled(_service):
                return None

            @staticmethod
            def read_log(service):
                return f"{service} log\n"

        with mock.patch.object(
            COLLECTOR, "runtime_backend_from_environment", return_value=Backend(),
        ):
            COLLECTOR.collect_server_commands(
                Builder(), 60, Path("/srv/project"),
            )

        flattened = " ".join(
            item for _command_id, argv in captures for item in argv
        )
        self.assertNotIn("systemctl", flattened)
        self.assertNotIn("journalctl", flattened)
        inventory = dict(captures)["dhcp_runtime_inventory"]
        self.assertNotIn("--journal", inventory)
        self.assertTrue(any("runtime" in relative for relative, *_rest in writes))

    def test_remote_probe_prefers_strict_latest_pointer_then_legacy_fallback(self):
        pointer = 'log_pointer="$log_dir/latest-log"'
        persistent = "/var/lib/nvidia-ztp/logs/ztp-result.log_*"
        legacy = '"$HOME"/ztp-result.log_*'
        self.assertIn(pointer, COLLECTOR.REMOTE_PROBE)
        self.assertIn(persistent, COLLECTOR.REMOTE_PROBE)
        self.assertIn(legacy, COLLECTOR.REMOTE_PROBE)
        self.assertLess(
            COLLECTOR.REMOTE_PROBE.index(pointer),
            COLLECTOR.REMOTE_PROBE.index(persistent),
        )
        self.assertLess(
            COLLECTOR.REMOTE_PROBE.index(persistent),
            COLLECTOR.REMOTE_PROBE.index(legacy),
        )
        self.assertIn('[ "$pointer_seen" = false ]', COLLECTOR.REMOTE_PROBE)
        self.assertIn("latest_log_pointer_error=", COLLECTOR.REMOTE_PROBE)

    def test_structured_redaction_removes_secrets_but_keeps_bgp_community(self):
        sentinel = "SENTINEL-diagnostic-secret"
        private_key_label = "PRIVATE " + "KEY"
        source = f"""
set:
  system:
    aaa:
      password: {sentinel}
      hashed-password: $6$salt$hashvalue
  snmp-server:
    community:
      public-secret:
        access: any
  router:
    bgp:
      community: 65000:123
  callback: https://user:{sentinel}@example.test/path?token={sentinel}
  pem: |
    -----BEGIN {private_key_label}-----
    {sentinel}
    -----END {private_key_label}-----
""".encode()
        redacted, error = COLLECTOR.structured_redaction(
            source, ".yaml", require_container=True
        )
        self.assertEqual("", error)
        self.assertIsNotNone(redacted)
        text = redacted.decode()
        self.assertNotIn(sentinel, text)
        self.assertNotIn("$6$salt$hashvalue", text)
        self.assertNotIn("BEGIN " + private_key_label, text)
        self.assertNotIn("public-secret", text)
        self.assertIn("65000:123", text)
        self.assertIn("<redacted", text)

        nested = {
            "diff_excerpt": (
                '{"password":"' + sentinel + '",'
                '"Authorization":"Bearer ' + sentinel + '",'
                '"ssh":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI' + sentinel + '",'
                '"snmp":"snmp-server community ' + sentinel + '"}'
            )
        }
        redacted_json, error = COLLECTOR.structured_redaction(
            json.dumps(nested).encode(), ".json", require_container=True
        )
        self.assertEqual("", error)
        json.loads(redacted_json)
        self.assertNotIn(sentinel, redacted_json.decode())

    def test_unstructured_redaction_covers_dhcp_secret_and_apache_setenv(self):
        sentinel = "SENTINEL-unstructured-secret"
        apache_names = (
            "CONTROL_AUTH", "ADMIN_PW", "SWITCHPASSWORD", "BMC_CREDS",
            "REDFISH_USERPASS", "LDAP_BINDPW", "SNMP_COMMUNITY",
            "VAULT_ROLE_ID", "DHCP_OMAPI",
        )
        source = (
            f'key ddns-key {{ secret "{sentinel}"; }};\n'
            + "".join(
                f"SetEnv {name} {sentinel}-{index}\n"
                for index, name in enumerate(apache_names)
            )
            + "SetEnv CONTROL_REQUIRE_AUTH 1\n"
        )

        redacted = COLLECTOR.sanitize_text(source)

        self.assertNotIn(sentinel, redacted)
        self.assertEqual(
            len(apache_names) + 1, redacted.count("<redacted:secret>"),
        )
        for name in apache_names:
            self.assertIn(f"SetEnv {name} <redacted:secret>", redacted)
        self.assertIn("SetEnv CONTROL_REQUIRE_AUTH 1", redacted)

    def test_sanitize_text_redacts_url_values_without_erasing_url_structure(self):
        sentinels = (
            "SENTINEL-query-repeat-one",
            "SENTINEL-query-repeat-two",
            "SENTINEL-query-token",
            "SENTINEL-query-fragment",
            "SENTINEL-fragment-only",
            "SENTINEL-userinfo-user",
            "SENTINEL-userinfo-password",
            "SENTINEL-user-only",
            "SENTINEL-malformed-user",
            "SENTINEL-malformed-query",
            "SENTINEL-isc-secret",
            "SENTINEL-assignment-secret",
            "SENTINEL-dotted-secret",
            "SENTINEL-authorization-secret",
        )
        safe_query_value = "%3Credacted%3Aquery-value%3E"
        safe_fragment = "%3Credacted%3Afragment%3E"
        safe_userinfo = "%3Credacted%3Auserinfo%3E"
        source = (
            "callback=https://api.example.test:8443/v1/items"
            f"?blank=&repeat={sentinels[0]}&repeat={sentinels[1]}"
            f"&encoded=SENTINEL%2Fpercent&token={sentinels[2]}"
            f"#{sentinels[3]}\n"
            f"status=http://192.0.2.44/ready#{sentinels[4]}\n"
            f"credentials=https://{sentinels[5]}:{sentinels[6]}@"
            "auth.example.test:8443/private"
            f"?token={sentinels[0]}#{sentinels[3]}\n"
            f"owner=https://{sentinels[7]}@owner.example.test/profile"
            f"?view={sentinels[1]}\n"
            f"broken=https://{sentinels[8]}@[2001:db8::1/private"
            f"?token={sentinels[9]}\n"
            "This secret sauce description is ordinary prose.\n"
            "The top secret plan sentence is also ordinary prose.\n"
            f'secret "{sentinels[10]}";\n'
            f"ADMIN_TOKEN={sentinels[11]}\n"
            f"api.key={sentinels[12]}\n"
            f"Authorization: Bearer {sentinels[13]}\n"
        )
        expected_url_lines = (
            "callback=https://api.example.test:8443/v1/items"
            f"?blank={safe_query_value}"
            f"&repeat={safe_query_value}&repeat={safe_query_value}"
            f"&encoded={safe_query_value}&token={safe_query_value}"
            f"#{safe_fragment}",
            f"status=http://192.0.2.44/ready#{safe_fragment}",
            "credentials=https://"
            f"{safe_userinfo}@auth.example.test:8443/private"
            f"?token={safe_query_value}#{safe_fragment}",
            f"owner=https://{safe_userinfo}@owner.example.test/profile"
            f"?view={safe_query_value}",
            "broken=<redacted:url>",
        )

        sanitized = COLLECTOR.sanitize_text(source)

        lines = sanitized.splitlines()
        self.assertEqual(expected_url_lines, tuple(lines[:5]))
        self.assertEqual(
            "This secret sauce description is ordinary prose.", lines[5],
        )
        self.assertEqual(
            "The top secret plan sentence is also ordinary prose.", lines[6],
        )
        self.assertEqual('secret <redacted:secret>;', lines[7])
        self.assertEqual("ADMIN_TOKEN=<redacted:secret>", lines[8])
        self.assertEqual("api.key=<redacted:secret>", lines[9])
        self.assertEqual(
            "Authorization: <redacted:authorization>", lines[10],
        )
        for sentinel in sentinels:
            self.assertNotIn(sentinel, sanitized)
        self.assertNotIn("SENTINEL%2Fpercent", sanitized)
        self.assertEqual(sanitized, COLLECTOR.sanitize_text(sanitized))

    def test_real_bundle_preserves_redacted_url_shape_and_benign_prose(self):
        sentinels = (
            "SENTINEL-bundle-query-one",
            "SENTINEL-bundle-query-two",
            "SENTINEL-bundle-fragment",
            "SENTINEL-bundle-user",
            "SENTINEL-bundle-password-userinfo",
            "SENTINEL-bundle-credential-query",
            "SENTINEL-bundle-credential-fragment",
            "SENTINEL-bundle-isc",
            "SENTINEL-bundle-password",
        )
        safe_query_value = "%3Credacted%3Aquery-value%3E"
        safe_fragment = "%3Credacted%3Afragment%3E"
        safe_userinfo = "%3Credacted%3Auserinfo%3E"
        source_bytes = (
            "endpoint=https://example.test/api/v2"
            f"?item={sentinels[0]}&item={sentinels[1]}&blank="
            f"#{sentinels[2]}\r\n"
            f"credential=https://{sentinels[3]}:{sentinels[4]}@"
            "secure.example.test:8443/export"
            f"?token={sentinels[5]}#{sentinels[6]}\r\n"
            "This secret sauce remains operator-visible.\r"
            "The top secret plan remains operator-visible.\r\n"
            f'secret "{sentinels[7]}";\r'
            f"password: {sentinels[8]}\r\n"
        ).encode()

        with tempfile.TemporaryDirectory(
            prefix="http-diagnostic-url-redaction-",
        ) as temporary:
            root = Path(temporary)
            source = root / "mixed.log"
            source.write_bytes(source_bytes)
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "url-redaction-shape")
            COLLECTOR.capture_file(
                builder,
                source,
                "captured/mixed.log",
                allowed_roots=[root],
            )
            builder.finalize({"project": "example", "scope": "local"})
            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                payload = archive.extractfile(
                    "diagnostic/captured/mixed.log",
                ).read()
                manifest = json.loads(
                    archive.extractfile("diagnostic/manifest.json").read(),
                )
                archive_payload = b"".join(
                    archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                )

        rendered = payload.decode()
        expected_url = (
            "endpoint=https://example.test/api/v2"
            f"?item={safe_query_value}&item={safe_query_value}"
            f"&blank={safe_query_value}#{safe_fragment}\n"
        )
        self.assertIn(expected_url, rendered)
        self.assertIn(
            "credential=https://"
            f"{safe_userinfo}@secure.example.test:8443/export"
            f"?token={safe_query_value}#{safe_fragment}\n",
            rendered,
        )
        self.assertIn(
            "This secret sauce remains operator-visible.\n", rendered,
        )
        self.assertIn(
            "The top secret plan remains operator-visible.\n", rendered,
        )
        self.assertIn("secret <redacted:secret>;\n", rendered)
        self.assertIn("password: <redacted:secret>\n", rendered)
        self.assertNotIn(b"\r", payload)
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), archive_payload)
        self.assertEqual(rendered, COLLECTOR.sanitize_text(rendered))
        self.assertEqual(
            {
                "applies_to": "sanitized_text_members",
                "line_endings": "LF",
                "source_line_endings_preserved": False,
            },
            manifest.get("text_normalization"),
        )

    def test_unstructured_redaction_handles_crlf_and_lone_cr_setenv_assignments(self):
        for newline_name, newline in (("crlf", "\r\n"), ("lone-cr", "\r")):
            with self.subTest(newline=newline_name):
                sentinels = (
                    f"SENTINEL-{newline_name}-setenv-value",
                    f"SENTINEL-{newline_name}-openssh-value",
                    f"SENTINEL-{newline_name}-assignment-value",
                )
                source = newline.join((
                    f"SetEnv ADMIN_TOKEN {sentinels[0]}",
                    f"SetEnv ADMIN_TOKEN={sentinels[1]}",
                    f"ADMIN_TOKEN={sentinels[2]}",
                    "SetEnv CONTROL_REQUIRE_AUTH 1",
                    "SAFE_NEIGHBOR=visible",
                    "",
                ))

                redacted = COLLECTOR.sanitize_text(source)

                for sentinel in sentinels:
                    self.assertNotIn(sentinel, redacted)
                self.assertNotIn("\r", redacted)
                self.assertIn("SetEnv CONTROL_REQUIRE_AUTH 1\n", redacted)
                self.assertIn("SAFE_NEIGHBOR=visible\n", redacted)
                self.assertEqual(redacted, COLLECTOR.sanitize_text(redacted))

    def test_structured_redaction_normalizes_compound_secret_keys(self):
        sentinels = {
            "SWITCHPASSWORD": "SENTINEL-switch-password",
            "MYSECRET": "SENTINEL-my-secret",
            "ADMINTOKEN": "SENTINEL-admin-token",
        }
        source = {
            "safe_root": "visible-root",
            "outer": {
                "safe_before": "visible-before",
                "credentials": {
                    name: value for name, value in sentinels.items()
                },
                "safe_after": "visible-after",
            },
        }

        redacted, error = COLLECTOR.structured_redaction(
            json.dumps(source).encode(), ".json", require_container=True
        )

        self.assertEqual("", error)
        self.assertIsNotNone(redacted)
        rendered = json.loads(redacted)
        for name, sentinel in sentinels.items():
            self.assertNotIn(sentinel, redacted.decode())
            self.assertEqual(
                "<redacted:secret>", rendered["outer"]["credentials"][name],
            )
        self.assertEqual("visible-root", rendered["safe_root"])
        self.assertEqual("visible-before", rendered["outer"]["safe_before"])
        self.assertEqual("visible-after", rendered["outer"]["safe_after"])

    def test_capture_file_redacts_mixed_newline_setenv_without_losing_safe_lines(self):
        sentinels = (
            "SENTINEL-capture-crlf",
            "SENTINEL-capture-lone-cr",
            "SENTINEL-capture-assignment",
        )
        source_bytes = (
            f"SetEnv SWITCHPASSWORD {sentinels[0]}\r\n"
            f"SetEnv MYSECRET {sentinels[1]}\r"
            f"ADMINTOKEN={sentinels[2]}\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        ).encode()
        with tempfile.TemporaryDirectory(prefix="http-diagnostic-redaction-") as temporary:
            root = Path(temporary)
            source = root / "site.conf"
            source.write_bytes(source_bytes)
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "redaction-workflow")

            COLLECTOR.capture_file(
                builder,
                source,
                "server/apache/sites/site.conf",
                allowed_roots=[root],
            )

            payload = (staging / "server/apache/sites/site.conf").read_bytes()
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), payload)
        self.assertNotIn(b"\r", payload)
        self.assertIn(b"SetEnv CONTROL_REQUIRE_AUTH 1\n", payload)
        self.assertIn(b"SAFE_NEIGHBOR=visible\n", payload)

    def test_setenv_redacts_complete_lines_and_is_byte_idempotent(self):
        sentinels = (
            "SENTINEL-multi-value-one",
            "SENTINEL-multi-value-two",
            "SENTINEL-quoted-value",
            "SENTINEL-comment-suffix",
            "SENTINEL-unterminated-value",
            "SENTINEL-unterminated-suffix",
            "SENTINEL-unknown-equals",
        )
        source = (
            f"SetEnv CUSTOM_VALUE {sentinels[0]} {sentinels[1]}\r\n"
            f'SetEnv CUSTOM_QUOTED "{sentinels[2]}" # {sentinels[3]}\r'
            f'SetEnv CUSTOM_BROKEN "{sentinels[4]} {sentinels[5]}\r\n'
            f"SetEnv BMC_CREDS={sentinels[6]}\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        )

        redacted = COLLECTOR.sanitize_text(source)

        for sentinel in sentinels:
            self.assertNotIn(sentinel, redacted)
        self.assertNotIn("\r", redacted)
        self.assertIn("SetEnv CONTROL_REQUIRE_AUTH 1\n", redacted)
        self.assertIn("SAFE_NEIGHBOR=visible\n", redacted)
        self.assertEqual(redacted, COLLECTOR.sanitize_text(redacted))

    def test_dhcp_secret_directives_emit_one_marker_and_are_byte_idempotent(self):
        sentinels = (
            "SENTINEL-dhcp-secret-assignment",
            "SENTINEL-dhcp-key-secret-assignment",
            "SENTINEL-dhcp-secret-directive",
            "SENTINEL-dhcp-key-secret-directive",
        )
        source = (
            f"secret = {sentinels[0]}\r\n"
            f"key-secret = {sentinels[1]}\r"
            f'secret "{sentinels[2]}";\r\n'
            f"key-secret {sentinels[3]};\r\n"
            "SAFE_NEIGHBOR visible\r\n"
        )

        redacted = COLLECTOR.sanitize_text(source)

        for sentinel in sentinels:
            self.assertNotIn(sentinel, redacted)
        directive_lines = redacted.splitlines()[:4]
        self.assertEqual(4, len(directive_lines))
        for line in directive_lines:
            self.assertEqual(1, line.count("<redacted:secret>"), line)
        self.assertIn("secret = <redacted:secret>", directive_lines)
        self.assertIn("key-secret = <redacted:secret>", directive_lines)
        self.assertIn("SAFE_NEIGHBOR visible\n", redacted)
        self.assertEqual(redacted, COLLECTOR.sanitize_text(redacted))

    def test_structured_redaction_handles_dot_separated_secret_key_tokens(self):
        sentinels = (
            "SENTINEL-dot-token-value",
            "SENTINEL-dot-api-key-value",
        )
        document = {
            "outer": {
                "token.value": sentinels[0],
                "api.key.value": sentinels[1],
                "safe.value": "visible-safe-value",
                "route.community": "65000:123",
            }
        }
        payloads = (
            (".json", json.dumps(document).encode()),
            (".yaml", COLLECTOR.yaml.safe_dump(document).encode()),
        )
        for suffix, payload in payloads:
            with self.subTest(suffix=suffix):
                redacted, error = COLLECTOR.structured_redaction(
                    payload, suffix, require_container=True
                )
                self.assertEqual("", error)
                self.assertIsNotNone(redacted)
                rendered = (
                    json.loads(redacted)
                    if suffix == ".json"
                    else COLLECTOR.yaml.safe_load(redacted)
                )
                for sentinel in sentinels:
                    self.assertNotIn(sentinel.encode(), redacted)
                self.assertEqual(
                    "<redacted:secret>", rendered["outer"]["token.value"],
                )
                self.assertEqual(
                    "<redacted:secret>", rendered["outer"]["api.key.value"],
                )
                self.assertEqual(
                    "visible-safe-value", rendered["outer"]["safe.value"],
                )
                self.assertEqual("65000:123", rendered["outer"]["route.community"])
                second, second_error = COLLECTOR.structured_redaction(
                    redacted, suffix, require_container=True
                )
                self.assertEqual("", second_error)
                self.assertEqual(redacted, second)

    def test_real_archive_omits_complete_line_and_dotted_key_sentinels(self):
        sentinels = (
            "SENTINEL-archive-multi-one",
            "SENTINEL-archive-multi-two",
            "SENTINEL-archive-comment",
            "SENTINEL-archive-unterminated",
            "SENTINEL-archive-equals",
            "SENTINEL-archive-dhcp",
            "SENTINEL-archive-key-secret",
            "SENTINEL-archive-dot-token",
            "SENTINEL-archive-dot-api-key",
        )
        config = (
            f"SetEnv CUSTOM_VALUE {sentinels[0]} {sentinels[1]}\r\n"
            f'SetEnv CUSTOM_QUOTED "value" # {sentinels[2]}\r'
            f'SetEnv CUSTOM_BROKEN "{sentinels[3]} trailing\r\n'
            f"SetEnv BMC_CREDS={sentinels[4]}\r\n"
            f"secret = {sentinels[5]}\r\n"
            f"key-secret = {sentinels[6]}\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        ).encode()
        document = {
            "token.value": sentinels[7],
            "api.key.value": sentinels[8],
            "safe.value": "visible-structured-neighbor",
        }
        with tempfile.TemporaryDirectory(prefix="http-diagnostic-archive-") as temporary:
            root = Path(temporary)
            sources = {
                "site.conf": config,
                "nested.json": json.dumps(document).encode(),
                "nested.yaml": COLLECTOR.yaml.safe_dump(document).encode(),
            }
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "hostile-redaction-archive")
            for name, data in sources.items():
                source = root / name
                source.write_bytes(data)
                COLLECTOR.capture_file(
                    builder,
                    source,
                    f"captured/{name}",
                    allowed_roots=[root],
                    structured=source.suffix in {".json", ".yaml"},
                )
            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                members = {
                    Path(member.name).name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }

        all_payloads = b"".join(members.values())
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), all_payloads)
        self.assertNotIn(b"\r", members["site.conf"])
        self.assertIn(b"SetEnv CONTROL_REQUIRE_AUTH 1\n", members["site.conf"])
        self.assertIn(b"SAFE_NEIGHBOR=visible\n", members["site.conf"])
        archive_lines = members["site.conf"].splitlines()
        self.assertEqual(1, archive_lines.count(b"secret = <redacted:secret>"))
        self.assertEqual(
            1, archive_lines.count(b"key-secret = <redacted:secret>")
        )
        for name in ("nested.json", "nested.yaml"):
            self.assertIn(b"visible-structured-neighbor", members[name])

    def test_real_bundle_declares_sanitized_line_ending_normalization(self):
        sentinels = (
            "SENTINEL-bundle-setenv-secret",
            "SENTINEL-bundle-dhcp-secret",
        )
        source_bytes = (
            f"SetEnv ADMIN_TOKEN {sentinels[0]}\r\n"
            f'secret "{sentinels[1]}";\r'
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        ).encode()

        with tempfile.TemporaryDirectory(
            prefix="http-diagnostic-line-ending-authority-",
        ) as temporary:
            root = Path(temporary)
            source = root / "site.conf"
            source.write_bytes(source_bytes)
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(
                staging, "line-ending-normalization-authority",
            )
            COLLECTOR.capture_file(
                builder,
                source,
                "captured/site.conf",
                allowed_roots=[root],
            )
            builder.finalize({"project": "example", "scope": "local"})

            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                manifest = json.loads(
                    archive.extractfile("diagnostic/manifest.json").read(),
                )
                readme = archive.extractfile(
                    "diagnostic/README.txt",
                ).read().decode()
                payload = archive.extractfile(
                    "diagnostic/captured/site.conf",
                ).read()

        with self.subTest(authority="manifest"):
            self.assertEqual(
                {
                    "applies_to": "sanitized_text_members",
                    "line_endings": "LF",
                    "source_line_endings_preserved": False,
                },
                manifest.get("text_normalization"),
                "bundle manifest must disclose normalized source line endings",
            )
        with self.subTest(authority="producer-uses-nested-shape"):
            self.assertNotIn("source_line_endings_preserved", manifest)
        with self.subTest(authority="README"):
            self.assertIn(
                "Sanitized text converts CRLF and lone CR to LF.",
                readme,
            )
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), payload)
        self.assertNotIn(b"\r", payload)
        self.assertIn(b"SetEnv CONTROL_REQUIRE_AUTH 1\n", payload)
        self.assertIn(b"SAFE_NEIGHBOR=visible\n", payload)
        self.assertEqual(
            payload.decode(), COLLECTOR.sanitize_text(payload.decode()),
        )

    def test_only_exact_canonical_benign_setenv_line_is_preserved(self):
        canonical = "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
        variants = (
            "SetEnv CONTROL_REQUIRE_AUTH=1",
            'SetEnv CONTROL_REQUIRE_AUTH "1"',
            "SetEnv CONTROL_REQUIRE_AUTH 1 ",
            "SetEnv CONTROL_REQUIRE_AUTH 1 trailing-SENTINEL",
            "SetEnv CONTROL_REQUIRE_AUTH 1 # comment-SENTINEL",
            "SetEnv CONTROL_REQUIRE_AUTH \x001",
            "SetEnv CONTROL_REQUIRE_AUTH 1\x00",
            " SetEnv CONTROL_REQUIRE_AUTH 1",
            "SetEnv\tCONTROL_REQUIRE_AUTH\t1",
            "SetEnv control_require_auth 1",
            "SetEnv CONTROL_REQUIRE_AUTH_EXTRA 1",
        )

        self.assertEqual(
            "SetEnv CONTROL_REQUIRE_AUTH 1\n",
            COLLECTOR.sanitize_text(canonical),
        )
        for variant in variants:
            with self.subTest(variant=repr(variant)):
                redacted = COLLECTOR.sanitize_text(
                    variant + "\r\nSAFE_NEIGHBOR=visible\r\n"
                )
                self.assertIn("<redacted:secret>", redacted)
                self.assertNotIn("SENTINEL", redacted)
                self.assertIn("SAFE_NEIGHBOR=visible\n", redacted)
                self.assertEqual(redacted, COLLECTOR.sanitize_text(redacted))

    def test_structured_redaction_covers_authorization_key_equivalents(self):
        bearer = "Bear" + "er "
        authorization = {
            "Authorization": bearer + "SENTINEL-authorization",
            "proxy.authorization": "Basic SENTINEL-proxy-dot",
            "PROXY_AUTHORIZATION": bearer + "SENTINEL-proxy-underscore",
            "Proxy Authorization": "Basic SENTINEL-proxy-space",
            "proxy-authorization": bearer + "SENTINEL-proxy-hyphen",
        }
        document = {
            "outer": {
                **authorization,
                "authorization_mode": "visible-auth-mode",
                "safe.value": "visible-safe-value",
                "route.community": "65000:123",
            }
        }
        payloads = (
            (".json", json.dumps(document).encode()),
            (".yaml", COLLECTOR.yaml.safe_dump(document).encode()),
        )
        for suffix, payload in payloads:
            with self.subTest(suffix=suffix):
                redacted, error = COLLECTOR.structured_redaction(
                    payload, suffix, require_container=True
                )
                self.assertEqual("", error)
                self.assertIsNotNone(redacted)
                rendered = (
                    json.loads(redacted)
                    if suffix == ".json"
                    else COLLECTOR.yaml.safe_load(redacted)
                )
                for key, sentinel in authorization.items():
                    self.assertNotIn(sentinel.encode(), redacted)
                    self.assertIn("<redacted", rendered["outer"][key])
                self.assertEqual(
                    "visible-auth-mode", rendered["outer"]["authorization_mode"],
                )
                self.assertEqual(
                    "visible-safe-value", rendered["outer"]["safe.value"],
                )
                self.assertEqual("65000:123", rendered["outer"]["route.community"])
                second, second_error = COLLECTOR.structured_redaction(
                    redacted, suffix, require_container=True
                )
                self.assertEqual("", second_error)
                self.assertEqual(redacted, second)

    def test_real_archive_redacts_benign_setenv_variants_and_authorization(self):
        bearer = "Bear" + "er "
        sentinels = (
            "SENTINEL-archive-benign-trailing",
            "SENTINEL-archive-benign-comment",
            "SENTINEL-archive-authorization",
            "SENTINEL-archive-proxy-authorization",
        )
        config = (
            "SetEnv CONTROL_REQUIRE_AUTH=1\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH \"1\"\r\n"
            f"SetEnv CONTROL_REQUIRE_AUTH 1 {sentinels[0]}\r\n"
            f"SetEnv CONTROL_REQUIRE_AUTH 1 # {sentinels[1]}\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH \x001\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\x00\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        ).encode()
        document = {
            "Authorization": bearer + sentinels[2],
            "proxy.authorization": f"Basic {sentinels[3]}",
            "authorization_mode": "visible-auth-mode",
            "safe.value": "visible-structured-neighbor",
        }
        with tempfile.TemporaryDirectory(prefix="http-diagnostic-auth-archive-") as temporary:
            root = Path(temporary)
            sources = {
                "site.conf": config,
                "authorization.json": json.dumps(document).encode(),
                "authorization.yaml": COLLECTOR.yaml.safe_dump(document).encode(),
            }
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "authorization-redaction")
            for name, data in sources.items():
                source = root / name
                source.write_bytes(data)
                COLLECTOR.capture_file(
                    builder,
                    source,
                    f"captured/{name}",
                    allowed_roots=[root],
                    structured=source.suffix in {".json", ".yaml"},
                )
            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                members = {
                    Path(member.name).name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }

        all_payloads = b"".join(members.values())
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), all_payloads)
        self.assertEqual(
            1,
            members["site.conf"].splitlines().count(
                b"SetEnv CONTROL_REQUIRE_AUTH 1"
            ),
        )
        self.assertIn(b"SAFE_NEIGHBOR=visible\n", members["site.conf"])
        for name in ("authorization.json", "authorization.yaml"):
            self.assertIn(b"visible-auth-mode", members[name])
            self.assertIn(b"visible-structured-neighbor", members[name])

    def test_control_and_bidi_setenv_variants_never_synthesize_benign_line(self):
        variants = (
            ("nul-prefix", "\x00SetEnv CONTROL_REQUIRE_AUTH 1"),
            ("nul-keyword", "Set\x00Env CONTROL_REQUIRE_AUTH 1"),
            ("vertical-tab-prefix", "\x0bSetEnv CONTROL_REQUIRE_AUTH 1"),
            ("bidi-prefix", "\u202eSetEnv CONTROL_REQUIRE_AUTH 1"),
            ("bidi-keyword", "Set\u202eEnv CONTROL_REQUIRE_AUTH 1"),
        )
        for label, variant in variants:
            with self.subTest(label=label):
                redacted = COLLECTOR.sanitize_text(
                    variant + "\r\nSAFE_NEIGHBOR=visible\r\n"
                )
                self.assertIn("<redacted:secret>", redacted)
                self.assertNotIn("SetEnv CONTROL_REQUIRE_AUTH 1", redacted)
                self.assertIn("SAFE_NEIGHBOR=visible\n", redacted)
                self.assertEqual(redacted, COLLECTOR.sanitize_text(redacted))

    def test_structured_redaction_covers_compact_proxy_authorization(self):
        bearer = "Bear" + "er "
        authorization = {
            "proxyAuthorization": bearer + "SENTINEL-proxy-camel",
            "ProxyAuthorization": "Basic SENTINEL-proxy-title",
        }
        document = {
            "outer": {
                **authorization,
                "authorization_mode": "visible-auth-mode",
                "proxyAuthorizationMode": "visible-proxy-auth-mode",
                "safe.value": "visible-safe-value",
            }
        }
        payloads = (
            (".json", json.dumps(document).encode()),
            (".yaml", COLLECTOR.yaml.safe_dump(document).encode()),
        )
        for suffix, payload in payloads:
            with self.subTest(suffix=suffix):
                redacted, error = COLLECTOR.structured_redaction(
                    payload, suffix, require_container=True
                )
                self.assertEqual("", error)
                self.assertIsNotNone(redacted)
                rendered = (
                    json.loads(redacted)
                    if suffix == ".json"
                    else COLLECTOR.yaml.safe_load(redacted)
                )
                for key, sentinel in authorization.items():
                    self.assertNotIn(sentinel.encode(), redacted)
                    self.assertIn("<redacted", rendered["outer"][key])
                self.assertEqual(
                    "visible-auth-mode", rendered["outer"]["authorization_mode"],
                )
                self.assertEqual(
                    "visible-proxy-auth-mode",
                    rendered["outer"]["proxyAuthorizationMode"],
                )
                self.assertEqual(
                    "visible-safe-value", rendered["outer"]["safe.value"],
                )
                second, second_error = COLLECTOR.structured_redaction(
                    redacted, suffix, require_container=True
                )
                self.assertEqual("", second_error)
                self.assertEqual(redacted, second)

    def test_real_archive_redacts_control_setenv_and_compact_authorization(self):
        bearer = "Bear" + "er "
        sentinels = (
            "SENTINEL-archive-nul-prefix",
            "SENTINEL-archive-nul-keyword",
            "SENTINEL-archive-vtab-prefix",
            "SENTINEL-archive-bidi-prefix",
            "SENTINEL-archive-bidi-keyword",
            "SENTINEL-archive-proxy-camel",
            "SENTINEL-archive-proxy-title",
        )
        config = (
            "\x00SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "Set\x00Env CONTROL_REQUIRE_AUTH 1\r\n"
            "\x0bSetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "\u202eSetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "Set\u202eEnv CONTROL_REQUIRE_AUTH 1\r\n"
            f"\x00SetEnv CUSTOM_VALUE {sentinels[0]}\r\n"
            f"Set\x00Env CUSTOM_VALUE {sentinels[1]}\r\n"
            f"\x0bSetEnv CUSTOM_VALUE {sentinels[2]}\r\n"
            f"\u202eSetEnv CUSTOM_VALUE {sentinels[3]}\r\n"
            f"Set\u202eEnv CUSTOM_VALUE {sentinels[4]}\r\n"
            "SetEnv CONTROL_REQUIRE_AUTH 1\r\n"
            "SAFE_NEIGHBOR=visible\r\n"
        ).encode()
        document = {
            "proxyAuthorization": bearer + sentinels[5],
            "ProxyAuthorization": f"Basic {sentinels[6]}",
            "authorization_mode": "visible-auth-mode",
            "proxyAuthorizationMode": "visible-proxy-auth-mode",
        }
        with tempfile.TemporaryDirectory(prefix="http-diagnostic-control-archive-") as temporary:
            root = Path(temporary)
            sources = {
                "site.conf": config,
                "authorization.json": json.dumps(document).encode(),
                "authorization.yaml": COLLECTOR.yaml.safe_dump(document).encode(),
            }
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "control-redaction")
            for name, data in sources.items():
                source = root / name
                source.write_bytes(data)
                COLLECTOR.capture_file(
                    builder,
                    source,
                    f"captured/{name}",
                    allowed_roots=[root],
                    structured=source.suffix in {".json", ".yaml"},
                )
            archive_path = root / "diagnostic.tar.gz"
            COLLECTOR.create_archive(staging, archive_path, "diagnostic")
            with tarfile.open(archive_path, "r:gz") as archive:
                members = {
                    Path(member.name).name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }

        all_payloads = b"".join(members.values())
        for sentinel in sentinels:
            self.assertNotIn(sentinel.encode(), all_payloads)
        self.assertEqual(
            1,
            members["site.conf"].splitlines().count(
                b"SetEnv CONTROL_REQUIRE_AUTH 1"
            ),
        )
        self.assertIn(b"SAFE_NEIGHBOR=visible\n", members["site.conf"])
        for name in ("authorization.json", "authorization.yaml"):
            self.assertIn(b"visible-auth-mode", members[name])
            self.assertIn(b"visible-proxy-auth-mode", members[name])

    def test_unparseable_sensitive_config_is_omitted_fail_closed(self):
        sentinel = b"SENTINEL-malformed-password"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "broken.yaml"
            source.write_bytes(b"password: [" + sentinel + b"\n")
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            COLLECTOR.capture_file(
                builder,
                source,
                "project/broken.yaml",
                allowed_roots=[root],
                structured=True,
            )
            self.assertFalse((staging / "project/broken.yaml").exists())
            omitted = staging / "project/broken.yaml.omitted.json"
            self.assertTrue(omitted.is_file())
            self.assertNotIn(sentinel, omitted.read_bytes())
            value = json.loads(omitted.read_text())
            self.assertEqual("omitted", value["status"])
            self.assertIn("unparseable", value["reason"])
            self.assertEqual(len(source.read_bytes()), value["source_size"])

    def test_output_root_and_member_paths_fail_closed(self):
        for value in ("../escape", "/absolute", "a/../../b", "a/./b"):
            with self.subTest(value=value):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.safe_relative(value)
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory).resolve()
            document_root = base / "www"
            document_root.mkdir(mode=0o700)
            inside = document_root / "diagnostics"
            with mock.patch.object(COLLECTOR, "HTTP_ROOT", document_root):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.prepare_output_root(str(inside))
            target = base / "real-output"
            target.mkdir(mode=0o700)
            link = base / "output-link"
            link.symlink_to(target)
            with mock.patch.object(COLLECTOR, "HTTP_ROOT", document_root):
                with self.assertRaises(COLLECTOR.DiagnosticError):
                    COLLECTOR.prepare_output_root(str(link))

    def test_bounded_command_sanitizes_environment_and_caps_output(self):
        secret_name = "ZTP_DIAGNOSTIC_ENV_SENTINEL"
        with mock.patch.dict(os.environ, {secret_name: "must-not-leak"}):
            result = COLLECTOR.run_bounded_command(["env"], timeout=5)
        self.assertEqual(0, result["returncode"])
        self.assertNotIn(secret_name, result["output"])

        result = COLLECTOR.run_bounded_command(
            [sys.executable, "-c", "import sys; sys.stdout.write('x'*100000)"],
            timeout=5,
            max_bytes=1024,
        )
        self.assertTrue(result["truncated"])
        self.assertLessEqual(len(result["output"].encode()), 1024)

    def test_archive_has_one_safe_tree_and_regular_members(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            staging = root / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            builder.write("server/state.txt", b"ok\n", source="test")
            builder.finalize({"project": "project", "scope": "air"})
            destination = root / "bundle.tar.gz"
            COLLECTOR.create_archive(staging, destination, "artifact")
            self.assertEqual(0o600, stat.S_IMODE(destination.stat().st_mode))
            with tarfile.open(destination, "r:gz") as archive:
                names = archive.getnames()
                self.assertTrue(names)
                self.assertTrue(all(name == "artifact" or name.startswith("artifact/") for name in names))
                self.assertTrue(all(member.isdir() or member.isfile() for member in archive.getmembers()))
                self.assertFalse(any(".." in Path(name).parts for name in names))

    def test_runtime_project_resolution_uses_fixed_inventory_link(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            active = day0 / "active-project"
            runtime = root / "ztp/config/isc-dhcp-server"
            active.mkdir(parents=True)
            runtime.mkdir(parents=True)
            inventory = active / "02-devices_config.csv"
            inventory.write_text("hostname,type\nleaf01,eth\n")
            (runtime / "02-devices_config.csv").symlink_to(inventory)
            with mock.patch.multiple(COLLECTOR, ROOT=root, DAY0_ROOT=day0):
                self.assertEqual(active, COLLECTOR.runtime_active_project())
                (runtime / "02-devices_config.csv").unlink()
                outside = root / "outside.csv"
                outside.write_text("x")
                (runtime / "02-devices_config.csv").symlink_to(outside)
                self.assertIsNone(COLLECTOR.runtime_active_project())

    def test_remote_identity_mismatch_never_collects_device_config(self):
        output = """__IDENTITY_BEGIN__
wrong-host
aa:bb:cc:dd:ee:ff

__IDENTITY_END__
__STATE_BEGIN__
password: SENTINEL
__STATE_END__
__ZTP_LOG_BEGIN__
success
__ZTP_LOG_END__
__APPLIED_BEGIN__
__APPLIED_END__
__NV_CONFIG_BEGIN__
set: []
__NV_CONFIG_END__
"""
        result = {
            "argv": ["ssh"], "returncode": 0, "duration_ms": 1,
            "timed_out": False, "truncated": False, "output": output,
        }
        device = {
            "hostname": "leaf01", "type": "eth", "ip": "192.0.2.10",
            "identity_macs": {"eth0": "02:00:00:00:00:55"},
        }
        with tempfile.TemporaryDirectory() as directory:
            staging = Path(directory) / "staging"
            builder = COLLECTOR.BundleBuilder(staging, "artifact")
            with mock.patch.object(COLLECTOR, "run_bounded_command", return_value=result):
                COLLECTOR.collect_live_device(
                    builder, device, identity=None,
                    known_hosts=Path(directory) / "known_hosts",
                )
            device_root = staging / "devices/leaf01"
            self.assertTrue((device_root / "connection-attempts.json").is_file())
            self.assertFalse((device_root / "state.txt").exists())
            self.assertFalse((device_root / "nv-config-show.yaml").exists())
            self.assertTrue(any("identity gates" in warning for warning in builder.warnings))

    def test_live_collection_skips_non_active_project_but_keeps_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            day0 = root / "DAY0-Prepare"
            requested = day0 / "requested"
            active = day0 / "active"
            requested.mkdir(parents=True)
            active.mkdir()
            output = root / "output"
            output.mkdir(mode=0o700)
            document_root = root / "www"
            document_root.mkdir(mode=0o700)
            report = {
                "devices": [{
                    "hostname": "leaf01", "type": "air", "ip": "192.0.2.10",
                    "identity_macs": {"eth0": "02:00:00:00:00:55"},
                }]
            }
            selected = report["devices"]
            no_op = mock.Mock()
            with (
                mock.patch.multiple(
                    COLLECTOR,
                    ROOT=root,
                    DAY0_ROOT=day0,
                    HTTP_ROOT=document_root,
                    DEFAULT_OUTPUT_ROOT=output,
                ),
                mock.patch.object(COLLECTOR, "load_latest_report", return_value=(None, report)),
                mock.patch.object(COLLECTOR, "runtime_active_project", return_value=active),
                mock.patch.object(COLLECTOR, "select_devices", return_value=selected),
                mock.patch.object(COLLECTOR, "collect_project_inputs", no_op),
                mock.patch.object(COLLECTOR, "collect_runtime_files", no_op),
                mock.patch.object(COLLECTOR, "collect_selected_published_configs", no_op),
                mock.patch.object(COLLECTOR, "collect_selected_operation_metadata", no_op),
                mock.patch.object(COLLECTOR, "collect_server_commands", no_op),
                mock.patch.object(COLLECTOR, "collect_public_key_fingerprints", no_op),
                mock.patch.object(COLLECTOR, "collect_monitor_state", no_op),
                mock.patch.object(COLLECTOR, "collect_switch_archives", no_op),
                mock.patch.object(COLLECTOR, "validate_ssh_inputs") as validate_ssh,
            ):
                rc = COLLECTOR.main([
                    "-p", "requested", "--air", "--host", "leaf01",
                    "--output-dir", str(output),
                ])
            self.assertEqual(2, rc)
            validate_ssh.assert_not_called()
            archives = list(output.glob("*.tar.gz"))
            self.assertEqual(1, len(archives))
            with tarfile.open(archives[0], "r:gz") as archive:
                name = next(name for name in archive.getnames() if name.endswith("/manifest.json"))
                manifest = json.load(archive.extractfile(name))
            self.assertTrue(manifest["partial"])
            self.assertTrue(any("active runtime project" in item for item in manifest["warnings"]))

    def test_collector_is_part_of_tools_deployment_contract(self):
        self.assertTrue(CONTRACT.is_tools_deployable_file(
            "tools/collect-ztp-diagnostics.py"
        ))

    def test_help_uses_a_neutral_public_project_example(self):
        parser = COLLECTOR.parse_args
        with mock.patch("sys.stdout", new_callable=io.StringIO) as stdout:
            with self.assertRaises(SystemExit) as raised:
                parser(["--help"])
        self.assertEqual(0, raised.exception.code)
        help_text = stdout.getvalue()
        self.assertIn("2099-example-site", help_text)
        self.assertNotIn("2026-" + "06-vb", help_text)


if __name__ == "__main__":
    unittest.main()
