"""REQ7 IB expected-topology identity is the CVT bytes, not a release ID."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]


class IbCvtProvenanceDirectTests(unittest.TestCase):
    def test_standalone_digest_refuses_nonregular_leaf_before_attempting_open(self):
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'owned-pipe'
            os.mkfifo(source, mode=0o600)
            original_open = os.open; attempts = []
            def opening(path, flags, *args, **kwargs):
                if str(path) in (str(source), source.name):
                    attempts.append(str(path))
                    raise AssertionError('a blocking nonregular leaf open was attempted')
                return original_open(path, flags, *args, **kwargs)
            with mock.patch.object(os, 'open', side_effect=opening):
                with self.assertRaises(provenance.ProvenanceError):
                    provenance._regular_digest(source)
            self.assertEqual([], attempts)

    def test_regular_digest_does_not_reuse_old_content_after_inplace_write(self):
        # Kept from the D-70 pipeline-scope variant (REQ7 retirement batch 2, 2026-10-24): the borrowing
        # scope is gone, the retained standalone digest must still hash the current bytes every time.
        from ztp.config import ib_topology_provenance as provenance
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve(); source = root / 'independent-input'
            source.write_bytes(b'original'); before = source.stat()
            self.assertEqual(hashlib.sha256(b'original').hexdigest(), provenance._regular_digest(source))
            source.write_bytes(b'modified'); os.utime(source, ns=(before.st_atime_ns, before.st_mtime_ns))
            self.assertEqual(before.st_ino, source.stat().st_ino)
            self.assertEqual(hashlib.sha256(b'modified').hexdigest(), provenance._regular_digest(source))

    def test_diagnostic_cvt_cannot_replace_day0_project_authority(self):
        source = ROOT / "ztp/config/nvos/template/P2P/p2p-to-validation.py"
        spec = importlib.util.spec_from_file_location("req7_cvt_authority", source)
        self.assertIsNotNone(spec)
        self.assertIsNotNone(spec.loader)
        converter = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = converter
        try:
            spec.loader.exec_module(converter)
        finally:
            sys.modules.pop(spec.name, None)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config_root = root / "ztp/config"
            config_root.mkdir(parents=True)
            project = root / "DAY0-Prepare/demo"
            project.mkdir(parents=True)
            authority = project / "01-global.yaml"
            authority.write_bytes(b"PRESERVE-DAY0-AUTHORITY\n")
            with mock.patch.object(converter, "CONFIG_ROOT", config_root):
                with self.assertRaises(converter.ConversionError):
                    converter.publish_cvt_workbook(authority, [], [], [], [])
                private = root / "private-output"
                private.mkdir()
                (project / "99-output-ztp").symlink_to(
                    private, target_is_directory=True,
                )
                lexical_output = project / "99-output-ztp/report.xlsx"
                with self.assertRaises(converter.ConversionError):
                    converter.publish_cvt_workbook(
                        lexical_output, [], [], [], [],
                    )
            self.assertEqual(b"PRESERVE-DAY0-AUTHORITY\n", authority.read_bytes())
            self.assertFalse(Path(f"{authority}.bak").exists())
            self.assertFalse((private / "report.xlsx").exists())

    def test_cvt_sidecar_binds_exact_source_and_output_bytes(self):
        from ztp.config.ib_topology_provenance import (
            ProvenanceError, read_cvt_provenance, sidecar_path,
            write_cvt_provenance,
        )

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cvt = root / "expected-cvt.xlsx"
            cvt.write_bytes(b"literal-cvt-v1")
            sources = {}
            for role in (
                "p2p", "inventory", "port_map", "splitter",
                "converter", "topology_rules",
            ):
                path = root / role
                path.write_bytes(("literal-" + role).encode("ascii"))
                sources[role] = path
            written = write_cvt_provenance(cvt, sources)
            self.assertTrue(sidecar_path(cvt).is_file())
            self.assertEqual(
                hashlib.sha256(b"literal-cvt-v1").hexdigest(),
                written["cvt_sha256"],
            )
            self.assertEqual(written, read_cvt_provenance(cvt))

            old_time = cvt.stat().st_mtime_ns
            cvt.write_bytes(b"literal-cvt-v2")
            os.utime(cvt, ns=(old_time, old_time))
            with self.assertRaises(ProvenanceError):
                read_cvt_provenance(cvt)


SIX_CVT_ROLES = ("p2p", "inventory", "port_map", "splitter", "converter", "topology_rules")


def rewrite_in_place(path: Path, data: bytes) -> None:
    """New bytes under the old mtime: only the content digest can notice."""
    before = path.stat()
    path.write_bytes(data)
    os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))


class IbCvtDevicesUnboundDirectTests(unittest.TestCase):
    """Owner 2026-11-27 (04 Q-115 (c), v3.1.6 DEVHASH): 02-devices_config.csv only picks the P2P name
    column, so a CVT is no longer bound to its bytes. Writers record exactly the six roles; a sidecar
    written before v3.1.6 may still carry `devices`, which reading accepts without re-reading its
    bytes. The six required roles and the CVT itself stay byte-checked."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.cvt = self.root / "expected-cvt.xlsx"
        self.cvt.write_bytes(b"literal-cvt")
        self.sources = {}
        for role in SIX_CVT_ROLES:
            path = self.root / role
            path.write_bytes(("literal-" + role).encode("ascii"))
            self.sources[role] = path
        self.devices = self.root / "02-devices_config.csv"
        self.devices.write_bytes(b"hostname,type\nleaf01,ib\n")

    def write_legacy_seven_role_sidecar(self):
        """The sidecar a pre-v3.1.6 converter wrote when 02-devices_config.csv was beside it."""
        from ztp.config.ib_topology_provenance import sidecar_path, write_cvt_provenance

        write_cvt_provenance(self.cvt, self.sources)
        sidecar = sidecar_path(self.cvt)
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["sources"]["devices"] = {
            "path": str(self.devices), "resolved_path": str(self.devices.resolve()), "kind": "file",
            "sha256": hashlib.sha256(self.devices.read_bytes()).hexdigest()}
        sidecar.write_text(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
        return record

    def test_a_legacy_devices_entry_is_accepted_and_its_bytes_are_never_reread(self):
        from ztp.config import ib_topology_provenance as provenance

        legacy = self.write_legacy_seven_role_sidecar()
        self.assertEqual(legacy, provenance.read_cvt_provenance(self.cvt))
        changed = getattr(provenance, "devices_changed_since_cvt", None)
        self.assertTrue(callable(changed), "the closed loop asks whether the device list moved on")
        self.assertFalse(changed(legacy))
        rewrite_in_place(self.devices, b"hostname,type\nleaf01,ib\nleaf02,ib\n")
        try:
            record = provenance.read_cvt_provenance(self.cvt)
        except provenance.ProvenanceError as exc:
            self.fail(f"Q-115: editing 02-devices_config.csv must not make the CVT stale: {exc}")
        self.assertEqual(legacy["sources"]["devices"], record["sources"]["devices"], "the record is not rewritten")
        self.assertTrue(changed(record))
        self.devices.unlink()
        try:
            record = provenance.read_cvt_provenance(self.cvt)
        except provenance.ProvenanceError as exc:
            self.fail(f"Q-115: a removed 02-devices_config.csv must not make the CVT stale: {exc}")
        self.assertTrue(changed(record), "an unreadable device list also differs from the one recorded")

    def test_a_cvt_without_a_devices_entry_never_reports_a_device_list_change(self):
        from ztp.config import ib_topology_provenance as provenance

        changed = getattr(provenance, "devices_changed_since_cvt", None)
        self.assertTrue(callable(changed), "the closed loop asks whether the device list moved on")
        record = provenance.write_cvt_provenance(self.cvt, self.sources)
        rewrite_in_place(self.devices, b"hostname,type\nleaf03,ib\n")
        self.assertFalse(changed(provenance.read_cvt_provenance(self.cvt)))

    def test_every_required_role_and_the_cvt_stay_byte_checked_beside_a_legacy_devices_entry(self):
        from ztp.config.ib_topology_provenance import ProvenanceError, read_cvt_provenance

        self.write_legacy_seven_role_sidecar()
        rewrite_in_place(self.devices, b"hostname,type\nleaf09,ib\n")
        for role in SIX_CVT_ROLES:
            with self.subTest(role=role):
                original = self.sources[role].read_bytes()
                rewrite_in_place(self.sources[role], original + b"changed")
                with self.assertRaisesRegex(ProvenanceError, f"^{role} source bytes changed$"):
                    read_cvt_provenance(self.cvt)
                rewrite_in_place(self.sources[role], original)
        rewrite_in_place(self.cvt, b"literal-cvt-changed")
        with self.assertRaisesRegex(ProvenanceError, "^CVT source bytes changed$"):
            read_cvt_provenance(self.cvt)

    def test_a_malformed_legacy_devices_entry_is_still_refused(self):
        from ztp.config.ib_topology_provenance import ProvenanceError, read_cvt_provenance, sidecar_path

        good = self.write_legacy_seven_role_sidecar()
        for field, value in (("sha256", "not-a-digest"), ("path", "relative/02-devices_config.csv"),
                             ("resolved_path", "relative/02-devices_config.csv"), ("kind", "directory")):
            with self.subTest(field=field):
                record = json.loads(json.dumps(good))
                record["sources"]["devices"][field] = value
                sidecar_path(self.cvt).write_text(json.dumps(record), encoding="utf-8")
                with self.assertRaises(ProvenanceError):
                    read_cvt_provenance(self.cvt)
        record = json.loads(json.dumps(good))
        record["sources"]["devices"]["extra"] = "x"
        sidecar_path(self.cvt).write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaises(ProvenanceError):
            read_cvt_provenance(self.cvt)

    def advisory_api(self):
        from ztp.config import ib_topology_provenance as provenance

        api = {name: getattr(provenance, name, None)
               for name in ("devices_advisory", "devices_changed_since_cvt", "recorded_name_column")}
        for name, function in api.items():
            self.assertTrue(callable(function), f"http dev 2026-11-27 (Q-115 (c) detail): {name}")
        return provenance, api

    def expected_advisory(self, name_column="hostname"):
        return {"devices_path": str(self.devices),
                "devices_sha256": hashlib.sha256(self.devices.read_bytes()).hexdigest(),
                "name_column": name_column, "verified": False}

    def test_a_new_cvt_keeps_the_device_list_and_name_column_as_advisory_fields_only(self):
        # http dev 2026-11-27 (Q-115 (c) detail, Codex LC316-066): the list picks the endpoint name column,
        # so a new CVT records its sha256 and the chosen column for a note; neither is ever verified.
        provenance, api = self.advisory_api()
        advisory = api["devices_advisory"](self.devices, "hostname")
        self.assertEqual(self.expected_advisory(), advisory)
        written = provenance.write_cvt_provenance(self.cvt, self.sources, advisory=advisory)
        self.assertEqual(set(SIX_CVT_ROLES), set(written["sources"]), "devices is no verified role")
        self.assertEqual(self.expected_advisory(), written["advisory"])
        self.assertEqual(written, provenance.read_cvt_provenance(self.cvt))
        self.assertFalse(api["devices_changed_since_cvt"](written))
        self.assertEqual("hostname", api["recorded_name_column"](written))
        rewrite_in_place(self.devices, b"hostname,type\nleaf07,ib\n")
        try:
            record = provenance.read_cvt_provenance(self.cvt)
        except provenance.ProvenanceError as exc:
            self.fail(f"Q-115: the advisory device list is never verified: {exc}")
        self.assertTrue(api["devices_changed_since_cvt"](record))
        self.assertEqual("hostname", api["recorded_name_column"](record))
        self.devices.unlink()
        try:
            record = provenance.read_cvt_provenance(self.cvt)
        except provenance.ProvenanceError as exc:
            self.fail(f"Q-115: the advisory device list is never verified: {exc}")
        self.assertTrue(api["devices_changed_since_cvt"](record))

    def test_the_advisory_fields_are_not_checked_against_anything(self):
        provenance, api = self.advisory_api()
        provenance.write_cvt_provenance(self.cvt, self.sources, advisory=api["devices_advisory"](self.devices, ""))
        sidecar = provenance.sidecar_path(self.cvt)
        record = json.loads(sidecar.read_text(encoding="utf-8"))
        record["advisory"]["devices_sha256"] = "0" * 64
        record["advisory"]["name_column"] = "rack label"
        sidecar.write_text(json.dumps(record), encoding="utf-8")
        try:
            read = provenance.read_cvt_provenance(self.cvt)
        except provenance.ProvenanceError as exc:
            self.fail(f"advisory values are not verified: {exc}")
        self.assertTrue(api["devices_changed_since_cvt"](read))
        self.assertEqual("rack label", api["recorded_name_column"](read))

    def test_a_malformed_advisory_is_refused(self):
        provenance, api = self.advisory_api()
        good = provenance.write_cvt_provenance(
            self.cvt, self.sources, advisory=api["devices_advisory"](self.devices, "hostname"))
        for field, value in (("verified", True), ("devices_sha256", "not-a-digest"),
                             ("devices_path", "relative/02-devices_config.csv"), ("name_column", 7),
                             ("extra", "x")):
            with self.subTest(field=field):
                record = json.loads(json.dumps(good))
                record["advisory"][field] = value
                provenance.sidecar_path(self.cvt).write_text(json.dumps(record), encoding="utf-8")
                with self.assertRaises(provenance.ProvenanceError):
                    provenance.read_cvt_provenance(self.cvt)
        with self.assertRaises(provenance.ProvenanceError):
            provenance.write_cvt_provenance(self.cvt, self.sources, advisory={"verified": False})

    def test_every_required_role_and_the_cvt_stay_byte_checked_beside_an_advisory(self):
        provenance, api = self.advisory_api()
        provenance.write_cvt_provenance(
            self.cvt, self.sources, advisory=api["devices_advisory"](self.devices, "hostname"))
        rewrite_in_place(self.devices, b"hostname,type\nleaf09,ib\n")
        for role in SIX_CVT_ROLES:
            with self.subTest(role=role):
                original = self.sources[role].read_bytes()
                rewrite_in_place(self.sources[role], original + b"changed")
                with self.assertRaisesRegex(provenance.ProvenanceError, f"^{role} source bytes changed$"):
                    provenance.read_cvt_provenance(self.cvt)
                rewrite_in_place(self.sources[role], original)
        provenance.read_cvt_provenance(self.cvt)
        rewrite_in_place(self.cvt, b"literal-cvt-changed")
        with self.assertRaisesRegex(provenance.ProvenanceError, "^CVT source bytes changed$"):
            provenance.read_cvt_provenance(self.cvt)

    def test_a_legacy_cvt_has_no_recorded_name_column(self):
        provenance, api = self.advisory_api()
        legacy = self.write_legacy_seven_role_sidecar()
        self.assertNotIn("advisory", legacy)
        self.assertIsNone(api["recorded_name_column"](provenance.read_cvt_provenance(self.cvt)))
        self.assertIsNone(api["recorded_name_column"](provenance.write_cvt_provenance(self.cvt, self.sources)))

    def test_writers_record_exactly_the_six_roles(self):
        from ztp.config.ib_topology_provenance import (
            ProvenanceError, capture_sources, sidecar_path, write_cvt_provenance,
        )

        with self.assertRaises(ProvenanceError, msg="Q-115: devices is never recorded again"):
            write_cvt_provenance(self.cvt, {**self.sources, "devices": self.devices})
        self.assertFalse(sidecar_path(self.cvt).exists())
        with self.assertRaises(ProvenanceError, msg="Q-115: devices is never recorded again"):
            capture_sources({**self.sources, "devices": self.devices})
        with self.assertRaises(ProvenanceError):
            write_cvt_provenance(self.cvt, {**self.sources, "extra": self.devices})
        self.assertEqual(set(SIX_CVT_ROLES), set(write_cvt_provenance(self.cvt, self.sources)["sources"]))


if __name__ == "__main__":
    unittest.main()
