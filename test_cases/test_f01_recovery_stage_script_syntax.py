"""Independent fixed local syntax expectations; never execute stage commands.

Actual workflow uses the original selected GLOBAL/CSV -> builder -> /bin/bash -n.
No successful child callback or arbitrary caller command is a workflow proof.
The direct invalid-script probe exercises only the private original-FD primitive.
"""
import contextlib
import hashlib
import inspect
import importlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest
from unittest import mock

SUBJECT = "tools.ufm_deployment_script_syntax"
_fixtures = importlib.import_module("test_cases.test_f01_recovery_stage_script_builder")

def subject(test):
    spec = importlib.util.find_spec(SUBJECT)
    test.assertIsNotNone(spec, "fixed local original-FD syntax entry is absent")
    return importlib.import_module(SUBJECT)


@contextlib.contextmanager
def actual_child_observer(api):
    """Only this fixed private call's actual child and two pipe pairs.

    Delegate originals exactly once. Never wait, poll, close, signal or query a
    PID on behalf of the subject. Parent stdio is intentionally original int
    pipe ends, not BufferedReader/FileIO ownership of a potentially reused slot.
    The original pipe EOF and identity-matched close are independent facts.
    """
    original_init = subprocess.Popen.__init__
    original_waitpid = os.waitpid
    original_pipe = os.pipe
    original_read = os.read
    original_close = os.close
    observed = {"children": [], "pipes": [], "waitpid": [], "errors": []}
    def pipe_once():
        value = original_pipe()
        frame = inspect.currentframe().f_back
        if (frame.f_code.co_filename == api.__file__
                and frame.f_code.co_name == "_run_syntax_child"):
            # Actual descriptors first, before optional stat evidence.
            pair = {"fds": value, "keys": {}, "eof": False, "closed": set()}
            observed["pipes"].append(pair)
            try:
                for fd in value:
                    actual = os.fstat(fd)
                    pair["keys"][fd] = (actual.st_dev, actual.st_ino)
            except BaseException as error:
                observed["errors"].append(("pipe-metadata", type(error).__name__))
        del frame
        return value
    def init_once(self, *args, **kwargs):
        value = original_init(self, *args, **kwargs)
        # A real created self/PID must be retained before optional metadata.
        record = {"self": self, "pid": self.pid}
        observed["children"].append(record)
        try:
            record.update(argv=args[0] if args else kwargs["args"],
                          pass_fds=kwargs["pass_fds"], close_fds=kwargs["close_fds"],
                          stdout=kwargs["stdout"], stderr=kwargs["stderr"])
        except BaseException as error:
            observed["errors"].append(("popen-metadata", type(error).__name__))
        return value
    def waitpid_once(pid, flags):
        value = original_waitpid(pid, flags)
        if any(record["pid"] == pid for record in observed["children"]):
            observed["waitpid"].append((pid, flags, value))
        return value
    def matched(fd):
        actual = os.fstat(fd)
        return [pair for pair in observed["pipes"]
                if pair["keys"].get(fd) == (actual.st_dev, actual.st_ino)]
    def read_once(fd, size):
        pairs = matched(fd) if any(fd in pair["fds"] for pair in observed["pipes"]) else []
        value = original_read(fd, size)
        for pair in pairs:
            if fd == pair["fds"][0] and value == b"":
                pair["eof"] = True
        return value
    def close_once(fd):
        pairs = matched(fd) if any(fd in pair["fds"] for pair in observed["pipes"]) else []
        value = original_close(fd)
        for pair in pairs:
            pair["closed"].add(fd)
        return value
    with mock.patch.object(os, "pipe", new=pipe_once), \
            mock.patch.object(subprocess.Popen, "__init__", new=init_once), \
            mock.patch.object(os, "waitpid", side_effect=waitpid_once), \
            mock.patch.object(os, "read", side_effect=read_once), \
            mock.patch.object(os, "close", side_effect=close_once):
        yield observed

def assert_actual_child(test, facts, observed):
    test.assertEqual([], observed["errors"])
    test.assertEqual(1, len(observed["children"]))
    original = observed["children"][0]
    test.assertEqual(original["pid"], facts["pid"])
    actual_reaps = [value for pid, flags, value in observed["waitpid"]
                    if value[0] == original["pid"]]
    test.assertEqual(1, len(actual_reaps))
    test.assertEqual(actual_reaps[0][0], facts["actual_waitpid_return"])
    test.assertEqual(os.waitstatus_to_exitcode(actual_reaps[0][1]), facts["exit_code"])
    test.assertEqual(2, len(observed["pipes"]))
    test.assertEqual([pair["fds"][1] for pair in observed["pipes"]],
                     [original["stdout"], original["stderr"]])
    for pair in observed["pipes"]:
        test.assertTrue(pair["eof"], "original owned read actually returned EOF")
        test.assertEqual(set(pair["fds"]), pair["closed"],
                         "each original dev/inode FD actual close returned")
    test.assertIsNone(original["self"].stdout)
    test.assertIsNone(original["self"].stderr)
    test.assertEqual(facts["argv"], original["argv"])
    test.assertEqual(tuple(facts["pass_fds"]), original["pass_fds"])
    test.assertTrue(original["close_fds"])
    test.assertIs(type(facts["pid"]), int)
    test.assertGreater(facts["pid"], 0)
    test.assertEqual(facts["pid"], facts["actual_waitpid_return"])
    test.assertTrue(facts["kernel_reap_confirmed"])
    test.assertTrue(facts["stdout_eof"])
    test.assertTrue(facts["stderr_eof"])
    test.assertTrue(facts["owned_pipe_cleanup_confirmed"])
    test.assertEqual([], facts["cleanup_unconfirmed"])
    test.assertEqual("/bin/bash", facts["argv"][0])
    test.assertEqual(["-n", "--"], facts["argv"][1:3])
    test.assertRegex(facts["argv"][3], r"^/dev/fd/[0-9]+$")
    test.assertEqual([int(facts["argv"][3].split("/")[-1])], facts["pass_fds"])
    test.assertTrue(facts["close_fds"])

class F01StageScriptSyntaxDirectTests(unittest.TestCase):
    def test_actual_invalid_original_fd_syntax_refuses_with_kernel_reap_and_both_eof(self):
        api = subject(self)
        with tempfile.TemporaryDirectory() as temporary:
            owned = Path(temporary).resolve()
            source = owned / "invalid.sh"
            source.write_bytes(b"#!/usr/bin/env bash\nif then\n")
            source.chmod(0o600)
            fd = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
            before = os.fstat(fd)
            try:
                with actual_child_observer(api) as observed:
                    with self.assertRaises(api.SyntaxCheckHold) as caught:
                        api._run_syntax_child(script_fd=fd, cwd=owned, deadline=time.monotonic() + 10.0)
                facts = caught.exception.child_facts
                assert_actual_child(self, facts, observed)
                self.assertNotEqual(0, facts["exit_code"])
                self.assertGreater(facts["stderr_bytes"], 0)
                self.assertFalse(facts["execution_permitted"])
                self.assertFalse(facts["completion"])
                after = os.fstat(fd)
                self.assertEqual((before.st_dev, before.st_ino), (after.st_dev, after.st_ino))
                self.assertEqual(b"#!/usr/bin/env bash\nif then\n", os.pread(fd, 64, 0))
            finally:
                os.close(fd)

    def test_cleanup_foreign_original_object_offset_bytes_survive_and_failure_is_not_success(self):
        api = subject(self)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            original = root / "original"; original.write_bytes(b"original owned bytes")
            foreign = root / "foreign"; foreign.write_bytes(b"foreign bytes must remain unchanged")
            original_fd = os.open(original, os.O_RDONLY)
            foreign_fd = os.open(foreign, os.O_RDWR)
            actual = os.fstat(original_fd)
            expected = (actual.st_dev, actual.st_ino)
            os.lseek(foreign_fd, 3, os.SEEK_SET)
            foreign_before = os.fstat(foreign_fd)
            try:
                os.dup2(foreign_fd, original_fd)
                with self.assertRaises(api.SyntaxCheckHold):
                    api._close_owned_fd(original_fd, expected)
                self.assertEqual(3, os.lseek(foreign_fd, 0, os.SEEK_CUR))
                self.assertEqual(b"foreign bytes must remain unchanged", os.pread(original_fd, 128, 0))
                after = os.fstat(original_fd)
                self.assertEqual((foreign_before.st_dev, foreign_before.st_ino), (after.st_dev, after.st_ino))
                self.assertEqual(b"original owned bytes", original.read_bytes())
            finally:
                os.close(original_fd)
                os.close(foreign_fd)

class F01StageScriptSyntaxInputWorkflowTests(unittest.TestCase):
    def test_actual_two_nodes_input_builder_original_fd_bash_syntax_only_and_unique_private_evidence(self):
        api = subject(self)
        builder = importlib.import_module("tools.ufm_deployment_script_builder")
        with _fixtures.actual_site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
            input_before = {(project / name): (project / name).read_bytes()
                for name in ("01-global.yaml", "02-devices_config.csv")}
            evidence_paths = []
            for address, hostname in (("192.0.2.21", "EXAMPLE-UFM01"), ("192.0.2.22", "EXAMPLE-UFM02")):
                artifact = builder.generate_stage_script(address=address, private_logs_root=logs)
                script_before = artifact.script_path.read_bytes()
                manifest_before = artifact.manifest_path.read_bytes()
                with actual_child_observer(api) as observed:
                    result = api.check_stage_script_syntax(script_path=artifact.script_path)
                self.assertEqual("CHECKED_NOT_EXECUTED", result.state)
                self.assertFalse(result.execution_permitted); self.assertFalse(result.completion)
                self.assertNotEqual(artifact.manifest_path, result.evidence_path)
                self.assertEqual(artifact.script_path.parent, result.evidence_path.parent)
                evidence_paths.append(result.evidence_path)
                self.assertEqual(0o600, result.evidence_path.stat().st_mode & 0o777)
                self.assertEqual(1, result.evidence_path.stat().st_nlink)
                proof = json.loads(result.evidence_path.read_bytes())
                self.assertEqual("CHECKED_NOT_EXECUTED", proof["state"])
                self.assertEqual(hostname, proof["node"])
                self.assertEqual(address, proof["node_ipv4"])
                self.assertEqual(artifact.run_id, proof["run_id"])
                self.assertEqual("phase1_readonly_preflight", proof["stage"])
                self.assertEqual(hashlib.sha256(script_before).hexdigest(), proof["script_sha256"])
                self.assertEqual({"01-global.yaml": hashlib.sha256(_fixtures.GLOBAL_BYTES).hexdigest(),
                    "02-devices_config.csv": hashlib.sha256(_fixtures.CSV_BYTES).hexdigest()}, proof["input_sha256"])
                assert_actual_child(self, proof["child"], observed)
                self.assertEqual(0, proof["child"]["exit_code"])
                self.assertFalse(proof["execution_permitted"]); self.assertFalse(proof["completion"])
                self.assertEqual(script_before, artifact.script_path.read_bytes())
                self.assertEqual(manifest_before, artifact.manifest_path.read_bytes())
                self.assertEqual("NOT_RUN", json.loads(manifest_before)["syntax_check"])
                self.assertNotIn(b"secret-value", result.evidence_path.read_bytes())
            self.assertEqual(2, len(set(evidence_paths)))
            for path, raw in input_before.items():
                self.assertEqual(raw, path.read_bytes())

    def test_actual_child_success_then_input_or_original_drift_retains_failure_not_permission(self):
        api = subject(self)
        builder = importlib.import_module("tools.ufm_deployment_script_builder")
        for drift in ("input", "original"):
            with self.subTest(drift=drift), _fixtures.actual_site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
                artifact = builder.generate_stage_script(address="192.0.2.21", private_logs_root=logs)
                manifest_before = artifact.manifest_path.read_bytes()
                original_child = api._run_syntax_child
                observations = []
                def once_original_then_drift(*args, **kwargs):
                    value = original_child(*args, **kwargs)
                    observations.append(value)
                    if drift == "input":
                        (project / "01-global.yaml").write_bytes(_fixtures.GLOBAL_BYTES + b"# changed after local check\n")
                    else:
                        raw = artifact.script_path.read_bytes()
                        with artifact.script_path.open("r+b") as owned:
                            owned.write(b"!" + raw[1:])
                    return value
                with actual_child_observer(api) as observed, mock.patch.object(api, "_run_syntax_child", side_effect=once_original_then_drift):
                    with self.assertRaises(api.SyntaxCheckHold):
                        api.check_stage_script_syntax(script_path=artifact.script_path)
                self.assertEqual(1, len(observations))
                assert_actual_child(self, observations[0], observed)
                self.assertEqual(0, observations[0]["exit_code"])
                self.assertEqual(manifest_before, artifact.manifest_path.read_bytes())
                proofs = list(artifact.script_path.parent.glob("syntax-check-*.json"))
                self.assertEqual(1, len(proofs))
                proof = json.loads(proofs[0].read_bytes())
                self.assertEqual("FAILED_NOT_EXECUTED", proof["state"])
                self.assertFalse(proof["execution_permitted"]); self.assertFalse(proof["completion"])
                self.assertNotIn(b"secret-value", proofs[0].read_bytes())
