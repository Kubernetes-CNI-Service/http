"""Observed NVOS output, fail-closed cases and real-module offline workflows."""
import contextlib
import io
import json
from pathlib import Path
import socket
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import test_upgrade_cli as fixtures
import ibsw_upgrade_contract as contract
import ibsw_upgrade_component as component
import ibsw_upgrade_executor as executor

app, driver, observer = fixtures.app, fixtures.driver, fixtures.observer
DATA = Path(__file__).resolve().parents[1] / "fixtures"
OS = (DATA / "nvos-25.02.8008-system-version.txt").read_bytes()
FW = (DATA / "nvos-six-cpld-firmware.txt").read_bytes()
HEALTH = (DATA / "nvos-system-health.txt").read_bytes()
COMPLETE_GLOBAL = fixtures.GLOBAL + """        bios:
          file: 0ACQF.cab
          version: '0ACQF_06.01.009'
        cpld:
          burn:
            file: FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
          refresh:
            file: FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme
"""
EXPECTED_FIRMWARE = (
    ("BIOS", "0ACQF_06.01.009"),
    ("CPLD1", "CPLD000232_REV0900"), ("CPLD2", "CPLD000383_REV0800"),
    ("CPLD3", "CPLD000389_REV0600"), ("CPLD4", "CPLD000368_REV0300"),
    ("CPLD5", "CPLD000389_REV0600"), ("CPLD6", "CPLD000368_REV0300"),
)


def record(kind, payload, status=0, stderr=b""):
    argv = {"os": ("nv","show","system","version"),
            "firmware": ("nv","show","platform","firmware"),
            "health": ("nv","show","system","health")}[kind]
    return contract.record_readonly_query(argv, payload, stderr, status)


class ObservationParserTests(unittest.TestCase):
    def test_observed_hierarchical_os_table(self):
        parsed = contract.parse_readonly_query_data(record("os", OS))
        self.assertEqual(parsed.state, "TEXT_DATA_PARSED", parsed.reason)
        self.assertEqual(dict(parsed.fields), {"image": "nvos-25.02.8008", "image_version_text": "25.02.8008"})

    def test_existing_flat_os_table_remains_supported(self):
        parsed = contract.parse_readonly_query_data(record("os", fixtures.OS_TABLE))
        self.assertEqual(parsed.state, "TEXT_DATA_PARSED")
        self.assertEqual(dict(parsed.fields)["image_version_text"], "25.03.1010")

    def test_conflicting_product_release_and_build_id_are_rejected(self):
        parsed = contract.parse_readonly_query_data(record("os", OS.replace(b"product-release  25.02.8008", b"product-release  25.03.1010")))
        self.assertEqual(parsed.state, "HOLD")

    def test_hierarchical_os_does_not_guess_from_other_fields(self):
        for payload in (OS.replace(b"  build-id       nvos-25.02.8008\n", b""),
                        OS.replace(b"  build-id       nvos-25.02.8008", b"  build-id       nvos-25.02.8008-unknown"),
                        OS.replace(b"  build-date     Sun May 31 14:10:17 UTC 2026\n", b""),
                        OS.replace(b"  build-id", b"build-id"),
                        OS.replace(b"kernel           6.1.0-22-2-amd64\n", b""),
                        OS + b"product-release  25.02.8008\n"):
            with self.subTest(payload=payload):
                self.assertEqual(contract.parse_readonly_query_data(record("os", payload)).state, "HOLD")

    def test_blank_rows_controls_and_duplicate_image_children_remain_rejected(self):
        for payload in (OS.replace(b"image\n", b"image\n\n"),
                        OS + b"  build-id       nvos-25.02.8008\n",
                        OS.replace(b"image\n", b"image\x1b\n")):
            self.assertEqual(contract.parse_readonly_query_data(record("os", payload)).state, "HOLD")

    def test_observed_firmware_retains_all_six_slots_not_just_first_three(self):
        parsed = contract.parse_readonly_query_data(record("firmware", FW))
        self.assertEqual(parsed.state, "TEXT_DATA_PARSED", parsed.reason)
        self.assertEqual(parsed.fields, EXPECTED_FIRMWARE)

    def test_bios_only_selection_ignores_non_target_na_and_extra_slots(self):
        actual = contract._documented_firmware_fields(contract._documented_table_lines(FW), targets=("BIOS",))
        self.assertEqual(actual, (EXPECTED_FIRMWARE[0],))

    def test_cpld_group_contains_every_observed_slot_and_no_bios(self):
        actual = contract._documented_firmware_fields(contract._documented_table_lines(FW), targets=("CPLD",))
        self.assertEqual(actual, EXPECTED_FIRMWARE[1:])

    def test_duplicate_missing_and_unknown_cpld_values_are_not_silently_accepted(self):
        for payload in (FW.replace(b"CPLD6", b"CPLD5"), FW.replace(b"CPLD3", b"CPLD0"),
                        FW.replace(b"CPLD000389_REV0600", b"N/A", 1)):
            with self.subTest(payload=payload):
                self.assertEqual(contract.parse_readonly_query_data(record("firmware", payload)).state, "HOLD")

    def test_observed_health_heading_and_existing_heading_both_parse(self):
        for payload in (HEALTH, HEALTH.replace(b"Health Issues", b"Health issues")):
            parsed = contract.parse_readonly_query_data(record("health", payload))
            self.assertEqual(parsed.state, "TEXT_HEALTH_DATA_PARSED", parsed.reason)
            self.assertEqual(dict(parsed.fields)["global_status"], "OK")
            self.assertEqual(json.loads(dict(parsed.fields)["issues_json"]), [])

    def test_health_ok_with_issues_or_nonzero_query_is_not_success(self):
        for payload, status in ((HEALTH.replace(b"status      OK", b"status      Not OK"), 0), (HEALTH, 1)):
            self.assertNotEqual(contract.parse_readonly_query_data(record("health", payload, status)).state, "TEXT_HEALTH_DATA_PARSED")

    def test_query_stderr_and_failure_are_never_ignored(self):
        for status, stderr in ((1,b""),(0,b"warning")):
            self.assertEqual(contract.parse_readonly_query_data(record("os",OS,status,stderr)).state, "HOLD")


class ObservationWorkflowTests(unittest.TestCase):
    def fixture(self, root):
        project, home, known = fixtures.WorkflowTests().fixture(root)
        (project / "01-global.yaml").write_text(COMPLETE_GLOBAL)
        return project, home, known

    def invoke(self, root, os_bytes=OS, fw_bytes=FW, failed_query=None):
        project, home, known = self.fixture(root)
        @contextlib.contextmanager
        def session(leaf, **kwargs):
            yield object(), 99999999999, (b"ew-spine01.example\n02:00:00:00:00:01\n", b"", 0), "password", "synthetic-pin"
        def query(leaf, transport, command, deadline):
            data = (os_bytes if command == "nv show system version" else
                    fixtures.HEALTH_TABLE if command == 'nv show system health' else fw_bytes)
            return (data, b"", 1 if command == failed_query else 0, True)
        out, err = io.StringIO(), io.StringIO()
        with patch.object(observer,"_signed_session",side_effect=session) as session_io, \
             patch.object(executor,"_signed_session",session_io), \
             patch.object(observer,"_read_channel",side_effect=query) as read_io, \
             patch.object(executor,"_read_channel",read_io), \
             patch.object(Path,"home",return_value=home), patch.object(app,"_check_runtime"), \
             patch.object(app,"_read_password",return_value="PRIVATE_PASSWORD") as prompt, \
             patch.object(socket,"socket",side_effect=AssertionError("No network")), \
             contextlib.redirect_stdout(out),contextlib.redirect_stderr(err):
            self.assertIs(observer._signed_session, executor._signed_session)
            self.assertIs(observer._read_channel, executor._read_channel)
            code=app.main(["--project",str(project),"--devices","ew-spine01*","--all"])
        return code,out.getvalue(),err.getvalue(),prompt.call_count

    def test_cli_uses_real_observation_parser_and_plan_with_six_slot_device(self):
        with tempfile.TemporaryDirectory() as directory:
            code,out,err,prompts = self.invoke(Path(directory).resolve())
            self.assertEqual(code,0,err)
            report=json.loads(out)
            self.assertEqual(report["ready_ib_count"],1)
            self.assertEqual(report["execution_state"],"NOT_EXECUTED")

    def test_unknown_os_has_specific_safe_reason_not_generic_query_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            code,out,err,prompts = self.invoke(Path(directory).resolve(),os_bytes=b"PRIVATE_OUTPUT")
            self.assertEqual(code,3,err)
            self.assertEqual(json.loads(out)["skipped_devices"][0]["reasons"],["OS_VERSION_PARSE_FAILED"])
            self.assertNotIn("PRIVATE_OUTPUT",out+err)

    def test_unknown_firmware_layout_has_specific_safe_reason(self):
        with tempfile.TemporaryDirectory() as directory:
            code,out,err,prompts=self.invoke(Path(directory).resolve(),fw_bytes=b"PRIVATE_FIRMWARE_OUTPUT")
            self.assertEqual(code,3,err)
            report=json.loads(out)
            self.assertEqual(report["ready_ib_count"],1)
            self.assertEqual([row['reason_code'] for row in report['component_precheck_issues']],
                             ['BIOS_VERSION_CHECK_FAILED','CPLD_VERSION_CHECK_FAILED'])
            self.assertNotIn("PRIVATE_FIRMWARE_OUTPUT",out+err)

    def test_command_failure_is_distinct_from_parser_failure(self):
        for command,expected in (("nv show system version","OS_VERSION_QUERY_FAILED"),
                                 ("nv show platform firmware","FIRMWARE_QUERY_FAILED")):
            with self.subTest(command=command),tempfile.TemporaryDirectory() as directory:
                code,out,err,prompts=self.invoke(Path(directory).resolve(),failed_query=command)
                self.assertEqual(code,3,err)
                report=json.loads(out)
                if command=='nv show system version':
                    self.assertEqual(report["skipped_devices"][0]["reasons"],[expected])
                else:
                    self.assertEqual(report['ready_ib_count'],1)
                    self.assertEqual([r['reason_code'] for r in report['component_precheck_issues']],
                                     [expected,expected])

    def test_unlisted_os_is_reported_as_path_rejection(self):
        with tempfile.TemporaryDirectory() as directory:
            code,out,err,prompts=self.invoke(Path(directory).resolve(),os_bytes=OS.replace(b"25.02.8008",b"25.02.7002"))
            self.assertEqual(code,3,err)
            self.assertEqual(json.loads(out)["skipped_devices"][0]["reasons"],["OS_UPGRADE_PATH_REJECTED"])

    def test_executor_component_selection_sees_repeated_package_id_in_later_slot(self):
        with tempfile.TemporaryDirectory() as directory:
            project,home,known=self.fixture(Path(directory).resolve())
            # Final OS remains 8008 in this isolated policy, so firmware is eligible.
            text=COMPLETE_GLOBAL.replace("version: '25.03.1010'","version: '25.02.8008'").replace("          - file: nvos-amd64-25.03.1010.bin\n","")
            (project/"01-global.yaml").write_text(text)
            args=("--project",str(project),"--all","--method","local")
            prepared=driver.prepare_not_executed_run(app.__file__,str(project),args)
            with driver.open_prepared_run(app.__file__,str(project),args,prepared["run_directory"]) as scope:
                with scope.open_readonly_query_inputs("ew-spine01.example",known_hosts_path=str(known),identity_path=None,management_public_path=None,user="admin") as leaf:
                    current=executor._component_step_data(leaf,"cpld",record("os",OS),record("firmware",FW))
                    self.assertFalse(current["needed"])
                    parsed_slots=json.loads(current["current_text"])
                    self.assertEqual(len(parsed_slots),6)
                    older=FW.replace(b"CPLD5        CPLD000389_REV0600",b"CPLD5        CPLD000389_REV0500")
                    changed=executor._component_step_data(leaf,"cpld",record("os",OS),record("firmware",older))
                    self.assertTrue(changed["needed"])
                    newer=FW.replace(b"CPLD5        CPLD000389_REV0600",b"CPLD5        CPLD000389_REV0700")
                    with self.assertRaisesRegex(ValueError,"newer than target"):
                        executor._component_step_data(leaf,"cpld",record("os",OS),record("firmware",newer))

    def test_completion_checks_later_duplicate_slot_instead_of_certifying_first_three_only(self):
        policy=contract.normalize_upgrade(contract.load_global_text(COMPLETE_GLOBAL),selected=("os","bios","cpld"),method="local")
        dispatch=SimpleNamespace(component="cpld",target_version="CPLD000232_REV0900+CPLD000383_REV0800+CPLD000389_REV0600")
        before=b"nv set system hostname ew-spine01\n"
        final_os=record("os",OS.replace(b"25.02.8008",b"25.03.1010"))
        health=record("health",HEALTH)
        result=observer._assess_component_postconditions(policy,dispatch,before,before,health,final_os,record("firmware",FW),health)
        self.assertEqual(result,"25.03.1010")
        older=FW.replace(b"CPLD5        CPLD000389_REV0600",b"CPLD5        CPLD000389_REV0500")
        with self.assertRaisesRegex(ValueError,"actual target CPLD revision differs"):
            observer._assess_component_postconditions(policy,dispatch,before,before,health,final_os,record("firmware",older),health)

    def test_package_target_absent_from_observed_slots_is_not_certified(self):
        text=COMPLETE_GLOBAL.replace("CPLD000383_REV0800_CPLD000389_REV0600","CPLD000324_REV0300")
        policy=contract.normalize_upgrade(contract.load_global_text(text),selected=("os","bios","cpld"),method="local")
        slots=tuple((slot,value.split("_")[0],value.split("_")[1]) for slot,value in EXPECTED_FIRMWARE[1:])
        with self.assertRaisesRegex(ValueError,"observations incomplete"):
            component._cpld_upgrade_needed(policy,slots)


if __name__ == "__main__":
    unittest.main()
