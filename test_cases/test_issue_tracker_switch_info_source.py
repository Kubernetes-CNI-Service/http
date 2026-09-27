"""Direct, literal contract for a bounded Switch Status info-archive preview.

This is deliberately not a runtime cycle, qualification, or workbook writer.
"""

from __future__ import annotations

import hashlib
import io
import json
from dataclasses import replace
from pathlib import Path
import tarfile
import tempfile
import unittest

from monitor.issue_tracker_switch_info_source import (
    SwitchInfoHoldError,
    read_switch_info_preview,
)


def _info(host: str, *, psu_state: str = "ok", fan_state: str = "ok",
          asic_current: str = "40", psu_current: str = "40",
          asic_state: str = "ok", psu_temp_state: str = "ok",
          include_inventory: bool = True, include_temperature: bool = True,
          unnamed_inventory: bool = False) -> bytes:
    sections = [f"Device: {host}\nSwitch Type: ETH (SN5600)\n"]
    if include_inventory:
        if unnamed_inventory:
            sections.append(
                "####\n# Execute Command: nv show platform inventory\n####\n"
                "          HW Version     Model   Serial             State  Type\n"
                "--------  -------------  ------  -----------------  -----  ------\n"
                f"PSU1      N/A            N/A     N/A                {psu_state}     psu\n"
                f"PSU1/FAN1 N/A            N/A     N/A                {fan_state}     fan\n"
            )
        else:
            sections.append(
                "####\n# Execute Command: nv show platform inventory\n####\n"
                "Component  HW Version  Model  Serial  State  Type\n"
                "---------  ----------  -----  ------  -----  ----\n"
                f"PSU1  A3  M1  S1  {psu_state}  psu\n"
                f"PSU1/FAN1  A3  M2  S2  {fan_state}  fan\n"
            )
    if include_temperature:
        sections.append(
            "####\n# Execute Command: nv show platform environment temperature\n####\n"
            "Name  Cur Temp (C)  Crit Temp  Max Temp  Min Temp  State\n"
            "----  ------------  ---------  --------  --------  -----\n"
            f"Asic-Temp-Sensor  {asic_current}  80  70  5  {asic_state}\n"
            f"PSU1-Temp-Sensor  {psu_current}  90  70  5  {psu_temp_state}\n"
        )
    return "".join(sections).encode("utf-8")


def _nvl_info(host: str, *, asic_current: str = "40",
              inventory: bool = True, psu_row: bool = False,
              psu_sensor: bool = False) -> bytes:
    rows = ("Component  HW Version  Model  Serial  State  Type\n"
            "---------  ----------  -----  ------  -----  ----\n"
            "BMC  A3  B1  S1  ok  bmc\n"
            "SWITCH  A3  N1  S2  ok  switch\n") if inventory else "no table\n"
    if psu_row:
        rows += "PSU1  A3  P1  S3  ok  psu\n"
    sensors = (f"ASIC1  {asic_current}  80  70  5  ok\n"
               "ASIC2  42  80  70  5  ok\n")
    if psu_sensor:
        sensors += "PSU1-Temp-Sensor  40  80  70  5  ok\n"
    return (
        f"Device: {host}\nSwitch Type: NVLINK (MNV72)\n"
        "####\n# Execute Command: nv show platform inventory\n####\n"
        + rows +
        "####\n# Execute Command: nv show platform environment temperature\n####\n"
        "Name  Cur Temp (C)  Crit Temp  Max Temp  Min Temp  State\n"
        "----  ------------  ---------  --------  --------  -----\n"
        + sensors
    ).encode("utf-8")


def _archive(path: Path, members: tuple[tuple[str, bytes | None], ...]) -> None:
    # cron.sh archives the timestamp directory, including collection.json.
    stamp = path.name.removesuffix(".tar.gz")
    with tarfile.open(path, "w:gz") as bundle:
        directory = tarfile.TarInfo(stamp + "/")
        directory.type = tarfile.DIRTYPE
        bundle.addfile(directory)
        for name, body in members:
            member = tarfile.TarInfo(stamp + "/" + name)
            if body is None:
                member.type = tarfile.SYMTYPE
                member.linkname = "leaf-a.info"
                bundle.addfile(member)
            else:
                member.size = len(body)
                bundle.addfile(member, io.BytesIO(body))
        metadata = json.dumps({
            "schema_version": 1, "environment": "prod", "collector": "cron.sh",
            "collected_at": "2026-09-25T03:15:00+08:00",
            "device_count": sum(name.endswith(".info") for name, _ in members),
        }, separators=(",", ":")).encode()
        meta = tarfile.TarInfo(stamp + "/collection.json")
        meta.size = len(metadata)
        bundle.addfile(meta, io.BytesIO(metadata))


class SwitchInfoSourceDirectTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.archive = Path(temporary.name) / "20260925-0315-prod.tar.gz"

    def read(self, *, selected_hosts: tuple[str, ...] = ("leaf-a", "leaf-b"),
             max_archive_bytes: int = 8 * 1024 * 1024,
             max_member_bytes: int = 1024 * 1024):
        raw = self.archive.read_bytes()
        return read_switch_info_preview(
            self.archive,
            expected_sha256=hashlib.sha256(raw).hexdigest(),
            expected_size_bytes=len(raw),
            source_slot="ethernet/prod",
            selected_hosts=selected_hosts,
            max_archive_bytes=max_archive_bytes,
            max_member_bytes=max_member_bytes,
        )

    def test_literal_psu_fan_asic_and_psu_temperature_alarms_are_preview_only(self):
        _archive(self.archive, (
            ("leaf-a.info", _info("leaf-a", psu_state="fail", fan_state="fail",
                                  asic_current="82")),
            ("leaf-b.info", _info("leaf-b", psu_current="76")),
        ))
        preview = self.read()
        self.assertEqual("ethernet/prod", preview.source_slot)
        self.assertEqual(("leaf-a", "leaf-b"), preview.selected_hosts)
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).hexdigest(),
                         preview.archive_sha256)
        self.assertEqual({
            ("leaf-a", "psu", "PSU1"),
            ("leaf-a", "fan", "PSU1/FAN1"),
            ("leaf-a", "asic_temp", "Asic-Temp-Sensor"),
            ("leaf-b", "psu_temp", "PSU1-Temp-Sensor"),
        }, set(preview.abnormal_keys))
        self.assertFalse(preview.qualified)

    def test_typed_abnormal_values_preserve_literal_state_and_thresholds(self):
        from monitor.issue_tracker_switch_info_source import map_switch_source_rows
        _archive(self.archive, (("leaf-a.info", _info(
            "leaf-a", psu_state="fail", fan_state="fail", asic_current="82",
            psu_current="76",
        )),))
        preview = self.read(selected_hosts=("leaf-a",))
        by_key = {(value.hostname, value.category, value.component_or_sensor): value
                  for value in preview.abnormal_values}
        self.assertEqual(set(preview.abnormal_keys), set(by_key))
        self.assertEqual(("fail", None, None, None),
                         (by_key[("leaf-a", "fan", "PSU1/FAN1")].state,
                          by_key[("leaf-a", "fan", "PSU1/FAN1")].current_c,
                          by_key[("leaf-a", "fan", "PSU1/FAN1")].maximum_c,
                          by_key[("leaf-a", "fan", "PSU1/FAN1")].critical_c))
        self.assertEqual(("ok", 82.0, 70.0, 80.0),
                         (by_key[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].state,
                          by_key[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].current_c,
                          by_key[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].maximum_c,
                          by_key[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].critical_c))
        rows = map_switch_source_rows(preview)
        self.assertEqual(tuple(preview.abnormal_values), tuple(row.value for row in rows))
        self.assertTrue(all(row.qualified is False for row in rows))
        self.assertEqual("PSU1/FAN1: state=fail",
                         by_key[("leaf-a", "fan", "PSU1/FAN1")].evidence_description)
        self.assertEqual(
            "Asic-Temp-Sensor: state=ok; current=82 C; max=70 C; critical=80 C",
            by_key[("leaf-a", "asic_temp", "Asic-Temp-Sensor")].evidence_description,
        )

    def test_same_key_changed_temperature_value_is_not_collapsed(self):
        _archive(self.archive, (("leaf-a.info", _info("leaf-a", asic_current="82")),))
        first = self.read(selected_hosts=("leaf-a",))
        _archive(self.archive, (("leaf-a.info", _info("leaf-a", asic_current="83")),))
        second = self.read(selected_hosts=("leaf-a",))
        self.assertEqual(first.abnormal_keys, second.abnormal_keys)
        self.assertNotEqual(first.abnormal_values, second.abnormal_values)
        self.assertEqual((82.0, 83.0),
                         (first.abnormal_values[0].current_c,
                          second.abnormal_values[0].current_c))

    def test_missing_or_malformed_abnormal_value_holds_without_inventing(self):
        for info in (
            _info("leaf-a", asic_current=""),
            _info("leaf-a", asic_current="NaN"),
            _info("leaf-a", asic_current="inf"),
            _info("leaf-a", asic_state="unknown"),
            _info("leaf-a", fan_state="unknown"),
        ):
            with self.subTest(info=info[-120:]):
                _archive(self.archive, (("leaf-a.info", info),))
                with self.assertRaises(SwitchInfoHoldError):
                    self.read(selected_hosts=("leaf-a",))

    def test_value_witness_revalidation_rejects_missing_or_forged_payload(self):
        from monitor.issue_tracker_switch_info_source import map_switch_source_rows
        _archive(self.archive, (("leaf-a.info", _info("leaf-a", asic_current="82")),))
        preview = self.read(selected_hosts=("leaf-a",))
        actual = preview.abnormal_values[0]
        for forged in (
            replace(preview, abnormal_values=()),
            replace(preview, abnormal_values=(replace(actual, current_c=float("nan")),)),
            replace(preview, abnormal_values=(replace(actual, hostname="other"),)),
            replace(preview, abnormal_values=(replace(actual, state="unknown"),)),
            replace(preview, abnormal_values=(replace(actual, maximum_c=None),)),
            replace(preview, abnormal_values=(actual, actual)),
        ):
            with self.subTest(forged=forged), self.assertRaises(SwitchInfoHoldError):
                map_switch_source_rows(forged)

    def test_missing_or_extra_selected_host_never_means_healthy(self):
        _archive(self.archive, (("leaf-a.info", _info("leaf-a")),))
        with self.assertRaises(SwitchInfoHoldError):
            self.read()
        _archive(self.archive, (
            ("leaf-a.info", _info("leaf-a")),
            ("leaf-b.info", _info("leaf-b")),
            ("leaf-c.info", _info("leaf-c")),
        ))
        with self.assertRaises(SwitchInfoHoldError):
            self.read()

    def test_real_captured_unnamed_component_layout_retains_fan_failure(self):
        _archive(self.archive, ((
            "leaf-a.info", _info("leaf-a", fan_state="fail", unnamed_inventory=True),
        ),))
        preview = self.read(selected_hosts=("leaf-a",))
        self.assertEqual({("leaf-a", "fan", "PSU1/FAN1")},
                         set(preview.abnormal_keys))
        self.assertFalse(preview.qualified)

    def test_duplicate_exact_member_or_duplicate_basename_holds(self):
        for members in (
            (("leaf-a.info", _info("leaf-a")),
             ("leaf-a.info", _info("leaf-a")),
             ("leaf-b.info", _info("leaf-b"))),
            (("leaf-a.info", _info("leaf-a")),
             ("nested/leaf-a.info", _info("leaf-a")),
             ("leaf-b.info", _info("leaf-b"))),
        ):
            with self.subTest(members=tuple(name for name, _ in members)):
                _archive(self.archive, members)
                with self.assertRaises(SwitchInfoHoldError):
                    self.read()

    def test_symlink_nonregular_and_traversal_member_hold(self):
        for extra in (("leaf-b.info", None),
                      ("../leaf-b.info", _info("leaf-b"))):
            with self.subTest(extra=extra[0]):
                _archive(self.archive, (("leaf-a.info", _info("leaf-a")), extra))
                with self.assertRaises(SwitchInfoHoldError):
                    self.read()

    def test_external_sha_size_and_read_bounds_are_authoritative(self):
        _archive(self.archive, (
            ("leaf-a.info", _info("leaf-a")),
            ("leaf-b.info", _info("leaf-b")),
        ))
        raw = self.archive.read_bytes()
        for kwargs in (
            {"expected_sha256": "0" * 64, "expected_size_bytes": len(raw)},
            {"expected_sha256": hashlib.sha256(raw).hexdigest(),
             "expected_size_bytes": len(raw) + 1},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(SwitchInfoHoldError):
                read_switch_info_preview(
                    self.archive, source_slot="ethernet/prod",
                    selected_hosts=("leaf-a", "leaf-b"), **kwargs,
                )
        with self.assertRaises(SwitchInfoHoldError):
            self.read(max_archive_bytes=len(raw) - 1)
        with self.assertRaises(SwitchInfoHoldError):
            self.read(max_member_bytes=16)

    def test_truncated_gzip_and_source_symlink_hold_even_with_matching_new_digest(self):
        _archive(self.archive, (("leaf-a.info", _info("leaf-a")),))
        self.archive.write_bytes(self.archive.read_bytes()[:-8])
        with self.assertRaises(SwitchInfoHoldError):
            self.read(selected_hosts=("leaf-a",))
        _archive(self.archive, (("leaf-a.info", _info("leaf-a")),))
        alias_dir = self.archive.parent / "alias"
        alias_dir.mkdir()
        alias = alias_dir / self.archive.name
        alias.symlink_to(self.archive)
        raw = self.archive.read_bytes()
        with self.assertRaises(SwitchInfoHoldError):
            read_switch_info_preview(
                alias, expected_sha256=hashlib.sha256(raw).hexdigest(),
                expected_size_bytes=len(raw), source_slot="ethernet/prod",
                selected_hosts=("leaf-a",),
            )

    def test_missing_telemetry_or_unknown_component_state_holds(self):
        for malformed in (
            _info("leaf-a", include_inventory=False),
            _info("leaf-a", include_temperature=False),
            _info("leaf-a", fan_state="unknown"),
            _info("leaf-a", asic_current="not-a-number"),
        ):
            with self.subTest(malformed=malformed[:60]):
                _archive(self.archive, (
                    ("leaf-a.info", malformed),
                    ("leaf-b.info", _info("leaf-b")),
                ))
                with self.assertRaises(SwitchInfoHoldError):
                    self.read()

    def test_only_ethernet_slot_is_in_scope(self):
        _archive(self.archive, (("leaf-a.info", _info("leaf-a")),))
        raw = self.archive.read_bytes()
        for slot in ("infiniband/prod", "ethernet/unknown"):
            with self.subTest(slot=slot), self.assertRaises(SwitchInfoHoldError):
                read_switch_info_preview(
                    self.archive,
                    expected_sha256=hashlib.sha256(raw).hexdigest(),
                    expected_size_bytes=len(raw),
                    source_slot=slot, selected_hosts=("leaf-a",),
                )

    def test_nvl_real_shape_has_asic_alarm_and_explicit_psu_fan_not_applicable(self):
        from monitor.issue_tracker_switch_info_source import map_switch_source_rows
        self.archive = self.archive.with_name("20260925-0315.tar.gz")
        _archive(self.archive, (("nvsw01.info", _nvl_info("nvsw01", asic_current="75")),))
        raw = self.archive.read_bytes()
        preview = read_switch_info_preview(
            self.archive, expected_sha256=hashlib.sha256(raw).hexdigest(),
            expected_size_bytes=len(raw), source_slot="nvlink/prod",
            selected_hosts=("nvsw01",),
        )
        self.assertEqual((("nvsw01", ("fan", "psu")),),
                         preview.not_applicable_by_host)
        self.assertEqual((("nvsw01", "asic_temp", "ASIC1"),),
                         preview.abnormal_keys)
        rows = map_switch_source_rows(preview)
        self.assertEqual(("ok", 75.0, 70.0, 80.0),
                         (rows[0].value.state, rows[0].value.current_c,
                          rows[0].value.maximum_c, rows[0].value.critical_c))
        self.assertEqual(("nvlink/prod", "nvsw01", "asic_temp", "ASIC1",
                          preview.archive_sha256),
                         (rows[0].source_slot, rows[0].hostname, rows[0].category,
                          rows[0].component_or_sensor, rows[0].archive_sha256))
        self.assertFalse(preview.qualified)
        self.assertFalse(rows[0].qualified)

    def test_nvl_missing_asic_or_inventory_and_psu_fan_conflict_hold(self):
        self.archive = self.archive.with_name("20260925-0315.tar.gz")
        for info in (
            _nvl_info("nvsw01", inventory=False),
            _nvl_info("nvsw01").replace(
                b"BMC  A3  B1  S1  ok  bmc\nSWITCH  A3  N1  S2  ok  switch\n",
                b"",
            ),
            _nvl_info("nvsw01", asic_current="unknown"),
            _nvl_info("nvsw01", psu_row=True),
            _nvl_info("nvsw01", psu_sensor=True),
        ):
            with self.subTest(info=info[-100:]):
                _archive(self.archive, (("nvsw01.info", info),))
                raw = self.archive.read_bytes()
                with self.assertRaises(SwitchInfoHoldError):
                    read_switch_info_preview(
                        self.archive,
                        expected_sha256=hashlib.sha256(raw).hexdigest(),
                        expected_size_bytes=len(raw), source_slot="nvlink/prod",
                        selected_hosts=("nvsw01",),
                    )

    def test_source_row_mapping_cannot_turn_not_applicable_or_manual_claim_into_issue(self):
        from monitor.issue_tracker_switch_info_source import map_switch_source_rows
        self.archive = self.archive.with_name("20260925-0315.tar.gz")
        _archive(self.archive, (("nvsw01.info", _nvl_info("nvsw01")),))
        raw = self.archive.read_bytes()
        preview = read_switch_info_preview(
            self.archive, expected_sha256=hashlib.sha256(raw).hexdigest(),
            expected_size_bytes=len(raw), source_slot="nvlink/prod",
            selected_hosts=("nvsw01",),
        )
        self.assertEqual((), map_switch_source_rows(preview))
        for forged in (
            replace(preview, qualified=True),
            replace(preview, not_applicable_by_host=()),
            replace(preview, abnormal_keys=(("nvsw01", "psu", "PSU1"),)),
            replace(preview, abnormal_keys=(("foreign", "asic_temp", "ASIC1"),)),
        ):
            with self.subTest(forged=forged), self.assertRaises(SwitchInfoHoldError):
                map_switch_source_rows(forged)

    def test_archive_name_is_slot_specific_not_interchangeable(self):
        for slot, name, host, body in (
            ("nvlink/prod", "20260925-0315-prod.tar.gz", "nvsw01", _nvl_info("nvsw01")),
            ("ethernet/prod", "20260925-0315.tar.gz", "leaf-a", _info("leaf-a")),
        ):
            with self.subTest(slot=slot):
                archive = self.archive.with_name(name)
                _archive(archive, ((host + ".info", body),))
                raw = archive.read_bytes()
                with self.assertRaises(SwitchInfoHoldError):
                    read_switch_info_preview(
                        archive, expected_sha256=hashlib.sha256(raw).hexdigest(),
                        expected_size_bytes=len(raw), source_slot=slot,
                        selected_hosts=(host,),
                    )


if __name__ == "__main__":
    unittest.main()
