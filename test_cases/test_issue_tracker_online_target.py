"""Independent C-2/C-7 exact target enumeration; no credentials or network."""

from dataclasses import FrozenInstanceError, replace
import hashlib
import importlib
import importlib.util
import json
import unittest


TARGET = "Synthetic_Approved_Target_0001"
OTHER = "Synthetic_Other_Target_000002"


def document(target=TARGET, status="enabled", cycles=1):
    block = {"status": status, "publish_every_cycles": cycles}
    if status == "enabled":
        block["spreadsheet_id"] = target
    return {"schema_version": 2, "common": {"mgmt": {"issue-tracker": block}}}


class OnlineTargetDirectTests(unittest.TestCase):
    def setUp(self):
        name = "monitor.issue_tracker_online_target"
        self.assertIsNotNone(importlib.util.find_spec(name), "C-2 target loader is missing")
        self.module = importlib.import_module(name)

    def test_exact_array_freezes_original_file_digest_without_normalizing_ids(self):
        raw = (' [ "' + TARGET + '", "' + OTHER + '" ]\n').encode()
        result = self.module.freeze_target_allowlist(raw)
        self.assertEqual((TARGET, OTHER), result.spreadsheet_ids)
        self.assertEqual(raw, result.source_bytes)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), result.sha256)
        with self.assertRaises(FrozenInstanceError):
            result.sha256 = "a" * 64
        self.assertNotIn(TARGET, repr(result))

    def test_empty_enumeration_is_valid_but_denies_every_target(self):
        result = self.module.freeze_target_allowlist(b"[]\n")
        self.assertEqual((), result.spreadsheet_ids)
        with self.assertRaises(self.module.OnlineTargetHold) as caught:
            self.module.bind_online_target(document(), result)
        self.assertEqual("denied_empty_allowlist", caught.exception.reason)

    def test_no_nested_metadata_or_patterns_can_supply_an_allowed_id(self):
        malformed = [
            {"spreadsheet_ids": [], "note": TARGET}, {"deny": [TARGET]}, TARGET,
            None, True, 3, [[TARGET]], [True], [3], [None], [TARGET, TARGET],
            [TARGET + "*"], ["re:" + TARGET], [" " + TARGET], [TARGET + "\n"],
            ["https://sheets.googleapis.com/" + TARGET], ["short"],
        ]
        for value in malformed:
            with self.subTest(value_type=type(value).__name__), self.assertRaises(self.module.OnlineTargetHold):
                self.module.freeze_target_allowlist(json.dumps(value).encode())

    def test_duplicate_json_keys_nonfinite_encoding_and_byte_bounds_fail_closed(self):
        for raw in (b'{"a": [], "a": []}', b"[NaN]", b"[Infinity]", b"[", b"\xff",
                    b"", b" " * 65537, bytearray(b"[]"), "[]"):
            with self.subTest(raw_type=type(raw).__name__), self.assertRaises(self.module.OnlineTargetHold):
                self.module.freeze_target_allowlist(raw)

    def test_exact_binding_does_not_grant_send_authority_or_disclose_target(self):
        allowlist = self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())
        bound = self.module.bind_online_target(document(), allowlist)
        self.assertEqual(TARGET, bound.spreadsheet_id)
        self.assertEqual(allowlist.sha256, bound.allowlist_sha256)
        self.assertEqual(64, len(bound.policy_sha256))
        self.assertFalse(hasattr(bound, "send"))
        self.assertFalse(hasattr(bound, "permit"))
        self.assertNotIn(TARGET, repr(bound))
        with self.assertRaises(self.module.OnlineTargetHold) as caught:
            self.module.bind_online_target(document(TARGET.lower()), allowlist)
        self.assertEqual("target_not_allowlisted", caught.exception.reason)
        self.assertNotIn(TARGET, str(caught.exception))

    def test_forged_allowlist_digest_or_membership_is_not_authority(self):
        original = self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())
        for value in (None, {"spreadsheet_ids": [TARGET]},
                      replace(original, sha256="b" * 64),
                      replace(original, spreadsheet_ids=(OTHER,))):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(self.module.OnlineTargetHold):
                self.module.bind_online_target(document(), value)

    def test_each_revalidation_refuses_changed_target_allowlist_or_cadence(self):
        allowlist = self.module.freeze_target_allowlist(json.dumps([TARGET, OTHER]).encode())
        bound = self.module.bind_online_target(document(), allowlist)
        self.assertEqual(bound, self.module.bind_online_target(document(), allowlist, expected=bound))
        changes = (
            (document(OTHER), allowlist),
            (document(), self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())),
            (document(cycles=2), allowlist),
        )
        for config, listing in changes:
            with self.assertRaises(self.module.OnlineTargetHold) as caught:
                self.module.bind_online_target(config, listing, expected=bound)
            self.assertEqual("stale_target_binding", caught.exception.reason)
        with self.assertRaises(self.module.OnlineTargetHold):
            self.module.bind_online_target(document(), allowlist, expected={"spreadsheet_id": TARGET})

    def test_disabled_and_malformed_policy_never_fall_back_to_old_binding(self):
        allowlist = self.module.freeze_target_allowlist(json.dumps([TARGET]).encode())
        bound = self.module.bind_online_target(document(), allowlist)
        for config, reason in (({"schema_version": 2}, "online_disabled_absent"),
                               (document(status="disabled"), "online_disabled_explicit"),
                               (document(cycles=True), "invalid_online_policy"),
                               (document(" " + TARGET), "invalid_online_policy")):
            with self.assertRaises(self.module.OnlineTargetHold) as caught:
                self.module.bind_online_target(config, allowlist, expected=bound)
            self.assertEqual(reason, caught.exception.reason)
            self.assertIsNone(caught.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
