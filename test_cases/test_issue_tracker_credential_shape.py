"""Isolated fake-only C-11/C-12 info shape; not held-FD or SDK proof."""

import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest import mock


MODULE = Path(__file__).resolve().parents[1] / "monitor/issue_tracker_credential_shape.py"
SECRET = "sentinel"


def info():
    return {"type": "service_account", "project_id": "synthetic-project",
            "private_key_id": "synthetic-key-id", "private_key": SECRET,
            "client_email": "synthetic-account@example.invalid", "client_id": "1234567",
            "auth_uri": "https://accounts.google.com/o/oauth2/auth",
            "token_uri": "https://oauth2.googleapis.com/token",
            "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
            "client_x509_cert_url": "https://www.googleapis.com/robot/v1/metadata/x509/synthetic",
            "universe_domain": "googleapis.com"}


def load():
    if not MODULE.is_file():
        raise AssertionError("credential-shape guard is missing")
    spec = importlib.util.spec_from_file_location("isolated_credential_shape", MODULE)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class CredentialShapeDirectTests(unittest.TestCase):
    def setUp(self):
        self.module = load()

    def test_download_mapping_preserved_without_interpreting_key_or_signing(self):
        raw = info()
        result = self.module.parse_service_account_info(json.dumps(raw).encode())
        self.assertEqual(raw, dict(result.mapping))
        self.assertEqual("https://www.googleapis.com/auth/spreadsheets", result.scope)
        self.assertNotIn(SECRET, repr(result))
        self.assertFalse(hasattr(result, "send"))
        self.assertFalse(hasattr(result, "permit"))
        with self.assertRaises(TypeError):
            result.mapping["private_key"] = "replacement"

    def test_full_token_endpoint_refuses_every_unapproved_url_component(self):
        bad = ("http://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/token/",
               "https://oauth2.googleapis.com:443/token", "https://user@oauth2.googleapis.com/token",
               "https://oauth2.googleapis.com/token?x=1", "https://oauth2.googleapis.com/token#",
               "https://oauth2.googleapis.com/token?", "https://oauth2.googleapis.com/token#part",
               "https://oauth2.googleapis.com./token", "https://OAUTH2.googleapis.com/token",
               " https://oauth2.googleapis.com/token", "https://oauth2.googleapis.com/%74oken",
               "https://sheets.googleapis.com/token", "https://oauth2.googleapis.com\\evil/token",
               True, None)
        for uri in bad:
            value = info(); value["token_uri"] = uri
            with self.subTest(uri_type=type(uri).__name__), self.assertRaises(self.module.CredentialShapeHold) as caught:
                self.module.parse_service_account_info(json.dumps(value).encode())
            self.assertNotIn(SECRET, str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)

    def test_nondefault_universe_delegation_claims_and_adc_shapes_refuse(self):
        for key, value in (("universe_domain", "example.invalid"), ("subject", "user@example.invalid"),
                           ("additional_claims", {"aud": "unapproved"}), ("always_use_jwt_access", True),
                           ("default_scopes", []), ("quota_project_id", "other"),
                           ("type", "authorized_user"), ("type", "external_account")):
            raw = info(); raw[key] = value
            with self.subTest(key=key), self.assertRaises(self.module.CredentialShapeHold):
                self.module.parse_service_account_info(json.dumps(raw).encode())
        raw = info(); raw.pop("universe_domain")
        self.assertEqual(raw, dict(self.module.parse_service_account_info(json.dumps(raw).encode()).mapping))

    def test_duplicate_keys_bad_encoding_bounds_and_nonmapping_refuse_without_echo(self):
        samples = (b'{"private_key":"SYNTHETIC_A","private_key":"SYNTHETIC_B"}',
                   b"[]", b"null", b"true", b"NaN", b"\xff", b"{", b"", b" " * 65537,
                   bytearray(b"{}"), "{}")
        for raw in samples:
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(self.module.CredentialShapeHold) as caught:
                self.module.parse_service_account_info(raw)
            self.assertEqual("credential_shape_invalid", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)

    def test_every_field_is_nonempty_text_and_required_fields_are_present(self):
        for name in info():
            for bad in (None, True, 1, {}, [], "", "   "):
                raw = info(); raw[name] = bad
                with self.subTest(name=name, bad_type=type(bad).__name__), self.assertRaises(self.module.CredentialShapeHold):
                    self.module.parse_service_account_info(json.dumps(raw).encode())
        for name in ("type", "private_key", "client_email", "token_uri"):
            raw = info(); raw.pop(name)
            with self.subTest(missing=name), self.assertRaises(self.module.CredentialShapeHold):
                self.module.parse_service_account_info(json.dumps(raw).encode())


class CredentialShapeTargetWorkflowTests(unittest.TestCase):
    def test_real_shape_and_project_target_checks_grant_neither_file_nor_send_authority(self):
        from monitor.issue_tracker_online_target import freeze_target_allowlist, bind_online_target
        module = load()
        target = "Synthetic_Approved_Target_0001"
        config = {"schema_version": 2, "common": {"mgmt": {"issue-tracker": {
            "status": "enabled", "spreadsheet_id": target}}}}
        with mock.patch("socket.socket", side_effect=AssertionError("network is forbidden")):
            credential = module.parse_service_account_info(json.dumps(info()).encode())
            binding = bind_online_target(config, freeze_target_allowlist(json.dumps([target]).encode()))
        self.assertEqual(target, binding.spreadsheet_id)
        self.assertEqual("https://oauth2.googleapis.com/token", credential.mapping["token_uri"])
        self.assertFalse(hasattr(credential, "permit"))
        self.assertFalse(hasattr(binding, "permit"))
        self.assertNotIn(SECRET, repr(credential))


if __name__ == "__main__":
    unittest.main()
