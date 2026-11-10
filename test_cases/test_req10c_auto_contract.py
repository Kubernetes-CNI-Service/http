"""REQ10C direct contract kept after the --auto retirement: 02-unsetup's old-watch read
window, the day-0 classification and the target cache origin.

Values and safety predicates come from requirements §10C, not the implementation.  The
initial-setup --auto watch and its credential file retired in v3.1.3 (owner 2026-11-02,
guide O3); their tests left with it (guide table 4-1).
"""

from __future__ import annotations

import os
from pathlib import Path
import hashlib
import json
import sys
import tempfile
import unittest
from unittest import mock

from test_cases.module_loader import load_script


ROOT = Path(os.environ.get("REQ10C_TEST_ROOT") or Path(__file__).resolve().parents[1])
INITIAL = ROOT / "infiniband/bringup/xdr-initial-setup/initial-setup.py"
UNSETUP = ROOT / "DAY0-Prepare/02-unsetup.py"


class Req10CAutoDirectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.initial = load_script("req10c_auto_direct_initial", INITIAL)
        cls.unsetup = load_script("req10c_auto_direct_unsetup", UNSETUP)

    def test_crontab_update_requires_two_identical_snapshots(self) -> None:
        # v3.1.3 guide table 4-1: the initial-setup half retired with --auto (O3); the
        # 02-unsetup half is kept unchanged because its old-watch cleanup stays until K6r (O11).
        stable = "1 * * * * /usr/bin/true\n"
        changed = stable + "2 * * * * /usr/bin/false\n"

        with mock.patch.object(
            self.unsetup, "_read_req10c_crontab", side_effect=[stable, stable]
        ) as reads:
            self.assertEqual(stable, self.unsetup._read_stable_req10c_crontab())
        self.assertEqual(2, reads.call_count)

        with mock.patch.object(
            self.unsetup, "_read_req10c_crontab", side_effect=[stable, changed]
        ):
            with self.assertRaisesRegex(
                OSError, "changed during the protected read window"
            ):
                self.unsetup._read_stable_req10c_crontab()

    def test_real_environment_card_has_title_and_remains_not_run(self) -> None:
        document = (ROOT / "test_cases/REAL_ENVIRONMENT.md").read_text(
            encoding="utf-8"
        )
        card_id = "TC-REAL-REQ10C-AUTO-001"
        marker = f"## {card_id}"
        self.assertEqual(document.count(marker), 1)
        section = document.split(marker, 1)[1].split("\n## ", 1)[0]
        self.assertTrue(
            section.startswith(" — 自动部署与同 UID crontab 静默验证\n"),
            "REQ10C real-environment card needs a nonempty fixed title",
        )
        status_lines = [
            line for line in section.splitlines() if line.startswith("- Status:")
        ]
        self.assertEqual(
            status_lines,
            ["- Status: OPEN / NOT RUN. Hermetic tests do not satisfy real cron UID, OOB Leaf, or IB device claims."],
        )
        self.assertIn("Same-user crontab writer exclusion", section)
        self.assertIn("owner explicitly selects", section)
        self.assertIn("foreign crontab", section)

    def cache_fixture(self, base: Path):
        p1 = base / "management-tool"
        p2 = base / "leaf-tool"
        p1.mkdir()
        p2.mkdir()
        global_file = p1 / "01-global.yaml"
        global_file.write_text("system:\n  timezone: UTC\n", encoding="ascii")
        csv = base / "ib.csv"
        csv.write_text("fixture CSV\n", encoding="ascii")
        p2p = base / "p2p.dot"
        p2p.write_text("fixture P2P\n", encoding="ascii")
        cache = base / "targets.json"
        ib = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        eth = self.initial.Device(
            "EXAMPLE-LEAF01", "eth", "192.0.2.10", "192.0.2.10/24",
            "192.0.2.1", "", "", "",
        )
        target = self.initial.Target(ib, eth, "swp7", "eth0")
        self.initial.save_target_cache(
            cache, csv, p2p, 1, [target], global_file=global_file,
            services=None, public_keys=[],
        )
        return p1, p2, global_file, csv, p2p, cache

    @staticmethod
    def resign_cache(cache: Path, payload: dict) -> None:
        raw = (json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n").encode("utf-8")
        cache.write_bytes(raw)
        cache.with_name(cache.name + ".sha256").write_text(
            f"{hashlib.sha256(raw).hexdigest()}  {cache.name}\n",
            encoding="ascii",
        )

    def test_auto_day0_classification_never_treats_partial_config_as_complete(self) -> None:
        device = self.initial.Device(
            "EXAMPLE-IB01", "ib", "203.0.113.2", "203.0.113.2/24",
            "203.0.113.1", "", "", "",
        )
        state = self.initial.DeviceState
        empty = state((), (), (), (), "nvos", "")
        complete = state(("203.0.113.2/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        partial = state(("203.0.113.2/24",), (), (), (), "EXAMPLE-IB01", "")
        conflict = state(("203.0.113.99/24",), (), ("203.0.113.1",), (),
                         "EXAMPLE-IB01", "")
        self.assertEqual("unconfigured", self.initial.classify_auto_day0(device, empty))
        self.assertEqual("complete", self.initial.classify_auto_day0(device, complete))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, partial))
        self.assertEqual("terminal", self.initial.classify_auto_day0(device, conflict))

    def test_p1_missing_current_global_invalidates_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p1-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            global_file.unlink()
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_p2_baked_global_remains_valid_without_local_yaml(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-p2-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            with mock.patch.object(
                self.initial, "_global_yaml_subset",
                side_effect=AssertionError("Leaf must not parse global YAML"),
            ):
                cached = self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                )
            self.assertIsNotNone(cached, "P2 uses authenticated baked global")
            self.assertEqual(1, cached[0])

    def test_p2_changed_input_still_invalidates_baked_cache(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache-stale-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            newer = cache.stat().st_mtime + 30
            os.utime(csv, (newer, newer))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_attestation_binds_source_generator_and_runtime(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-fields-") as directory:
            _, p2, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            payload = json.loads(cache.read_text(encoding="utf-8"))
            authority = payload["cache_authority"]
            self.assertEqual(
                hashlib.sha256(csv.read_bytes()).hexdigest(), authority["ib_csv_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(p2p.read_bytes()).hexdigest(), authority["p2p_sha256"]
            )
            self.assertEqual(
                hashlib.sha256(global_file.read_bytes()).hexdigest(),
                authority["global_sha256"],
            )
            self.assertEqual("initial-setup.py", authority["generator"])
            self.assertEqual(
                hashlib.sha256(INITIAL.read_bytes()).hexdigest(),
                authority["generator_sha256"],
            )
            self.assertEqual(
                f"{sys.implementation.name}:{sys.version_info.major}.{sys.version_info.minor}",
                authority["python"],
            )
            self.assertFalse(authority["pyyaml_required"])
            self.assertEqual("not-required", authority["pyyaml_version"])
            self.assertIsNotNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))

    def test_cache3_content_changes_invalidate_even_when_mtime_is_older(self) -> None:
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-content-") as directory:
            _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            csv.write_text("changed CSV but old mtime\n", encoding="ascii")
            os.utime(csv, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p2,
                allow_baked_missing_global=True,
            ))
        with tempfile.TemporaryDirectory(prefix="req10c-cache3-global-content-") as directory:
            p1, _, global_file, csv, p2p, cache = self.cache_fixture(Path(directory))
            older = cache.stat().st_mtime - 30
            global_file.write_text("system:\n  timezone: Europe/Paris\n", encoding="ascii")
            os.utime(global_file, (older, older))
            self.assertIsNone(self.initial.load_target_cache(
                cache, csv, p2p, public_key_tool=p1,
                allow_baked_missing_global=False,
            ))

    def test_cache3_resigned_identity_mismatch_fails_closed(self) -> None:
        for field, value in (
            ("generator_sha256", "0" * 64),
            ("python", "cpython:0.0"),
            ("pyyaml_required", True),
            ("pyyaml_version", "6.0"),
        ):
            with self.subTest(field=field), tempfile.TemporaryDirectory(
                prefix="req10c-cache3-mutated-"
            ) as directory:
                _, p2, _, csv, p2p, cache = self.cache_fixture(Path(directory))
                payload = json.loads(cache.read_text(encoding="utf-8"))
                payload["cache_authority"][field] = value
                self.resign_cache(cache, payload)
                self.assertIsNone(self.initial.load_target_cache(
                    cache, csv, p2p, public_key_tool=p2,
                    allow_baked_missing_global=True,
                ))


if __name__ == "__main__":
    unittest.main()
