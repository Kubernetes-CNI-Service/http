"""Independent held-stage/deployment-owner boundaries; pure files, zero transport.

The positive workflow proves source/key/pin admission and real original FD close,
not native KEX, SFTP staging, remote inode identity or any execution permission.
The two tests that reach the production F01 SDK identity run unchanged in the
venv-ibsw-upgrade child when the runner is not a venv (test_cases/f01_sdk_venv.py).
"""
import contextlib
import fcntl
import hashlib
import importlib
import importlib.util
import io
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

import paramiko
from test_cases import test_f01_recovery_stage_script_builder as fixture
from test_cases.f01_sdk_venv import sdk_identity_test

SUBJECT = "tools.ufm_deployment_staging_owner"

def subject(test):
    test.assertIsNotNone(importlib.util.find_spec(SUBJECT), "independent deployment staging owner is absent")
    api = importlib.import_module(SUBJECT)
    test.assertTrue(callable(getattr(api, "_held_project_stage", None)))
    test.assertTrue(callable(getattr(api, "_owned_direct_deployment_session", None)))
    return api

@contextlib.contextmanager
def actual_stage(test):
    from tools import ufm_deployment_script_builder as builder
    with fixture.actual_site() as (http, project, logs), mock.patch.object(builder, "HTTP_ROOT", http):
        server = paramiko.ECDSAKey.generate(bits=256)
        management = paramiko.ECDSAKey.generate(bits=256)
        laptop = paramiko.ECDSAKey.generate(bits=256)
        for name, key in (("mgmt-server.pub", management), ("laptop.pub", laptop)):
            (project / name).write_text(key.get_name() + " " + key.get_base64() + " current-project\n")
        private = logs.parent / "explicit-management-private"
        raw = io.StringIO()
        management.write_private_key(raw)
        private.write_text(raw.getvalue()); private.chmod(0o600)
        known = logs.parent / "known_hosts"
        approved = ("192.0.2.21 " + server.get_name() + " " + server.get_base64() + "\n").encode()
        known.write_bytes(approved); known.chmod(0o600)
        artifact = builder.generate_stage_script(address="192.0.2.21", private_logs_root=logs)
        yield artifact, project, known, hashlib.sha256(approved).hexdigest(), private

class F01DeploymentStagingOwnerDirectTests(unittest.TestCase):
    def test_closed_or_caller_records_cannot_become_fresh_deployment_owner(self):
        api = subject(self)
        from tools import ufm_bootstrap_auth_adapter as auth
        calls = []
        def refuse_connect(*args, **kwargs):
            calls.append((args, kwargs))
            raise AssertionError("no connection may be issued from caller/closed source")
        with mock.patch.object(auth, "_direct_ipv4_connected_stream", new=refuse_connect):
            for record in (True, {"execution_permitted": True, "client": object()},
                           types.SimpleNamespace(active=True, client=object(), phase="configured")):
                with self.subTest(kind=type(record).__name__):
                    with self.assertRaises(api.StagingOwnerHold):
                        with api._owned_direct_deployment_session(record):
                            self.fail("caller record admitted")
            with actual_stage(self) as (artifact, project, known, pin, private):
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                    self.assertTrue(held.active)
                self.assertFalse(held.active)
                with self.assertRaises(api.StagingOwnerHold):
                    with api._owned_direct_deployment_session(held):
                        self.fail("closed source admitted")
        self.assertEqual([], calls)

    def test_original_pin_and_stage_drift_refuse_before_connection_without_source_replacement(self):
        api = subject(self)
        from tools import ufm_bootstrap_auth_adapter as auth
        for fault in ("pin", "stage"):
            with self.subTest(fault=fault), actual_stage(self) as (artifact, project, known, pin, private):
                calls = []
                def reject_connect(*args, **kwargs):
                    calls.append(True)
                    raise AssertionError("drift must be rejected before connect")
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                    original = os.fstat(held.script_fd)
                    if fault == "pin":
                        known.write_bytes(known.read_bytes() + b"# changed independent pin\n")
                    else:
                        fd = os.open(artifact.script_path, os.O_WRONLY)
                        try:
                            before = os.pread(held.script_fd, 1, 0)
                            self.assertEqual(b"#", before)
                            os.pwrite(fd, b"!", 0)
                        finally:
                            os.close(fd)
                    with mock.patch.object(auth, "_direct_ipv4_connected_stream", new=reject_connect):
                        with self.assertRaises(api.StagingOwnerHold):
                            with api._owned_direct_deployment_session(held):
                                self.fail("changed originals admitted")
                    self.assertEqual([], calls)
                    self.assertEqual((original.st_dev, original.st_ino),
                                     (os.fstat(held.script_fd).st_dev, os.fstat(held.script_fd).st_ino))

class F01DeploymentStagingOwnerInputWorkflowTests(unittest.TestCase):
    @sdk_identity_test
    def test_actual_project_builder_held_original_key_pin_deadline_and_close_do_not_issue_permission(self):
        api = subject(self)
        from tools import ufm_bootstrap_auth_adapter as auth
        class WorkInterrupted(BaseException):
            pass
        primary = WorkInterrupted()
        connected = []
        original_close = os.close
        closed = []
        original_fd = None
        expected_key = None
        def close_once(fd):
            value = os.fstat(fd)
            matched = fd == original_fd and (value.st_dev, value.st_ino) == expected_key
            result = original_close(fd)
            if matched: closed.append(fd)
            return result
        def stop_at_original_connector(address, timeout):
            self.assertEqual("192.0.2.21", address)
            self.assertGreater(timeout, 0)
            self.assertLessEqual(timeout, 5)
            connected.append(address)
            raise primary
        with actual_stage(self) as (artifact, project, known, pin, private), \
                mock.patch.object(os, "close", new=close_once):
            with self.assertRaises(WorkInterrupted) as caught:
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                    original_fd = held.script_fd
                    value = os.fstat(original_fd)
                    expected_key = (value.st_dev, value.st_ino)
                    self.assertEqual(os.O_RDONLY, fcntl.fcntl(original_fd, fcntl.F_GETFL) & os.O_ACCMODE)
                    self.assertEqual(1, value.st_nlink)
                    self.assertEqual(0o600, value.st_mode & 0o777)
                    self.assertEqual(project, held.project)
                    self.assertEqual("EXAMPLE-UFM01", held.node.hostname)
                    self.assertEqual("192.0.2.21", held.node.address)
                    self.assertEqual("02:00:00:00:00:21", held.node.management_mac)
                    self.assertEqual("eno8303", held.interface)
                    self.assertEqual("SOURCE_HELD_NOT_SESSION", held.state)
                    self.assertFalse(held.execution_permitted)
                    self.assertFalse(held.completion)
                    self.assertEqual(fixture.expected_script(artifact.run_id),
                                     os.pread(original_fd, 524289, 0))
                    self.assertEqual(hashlib.sha256(fixture.expected_script(artifact.run_id)).hexdigest(),
                                     held.script_sha256)
                    held.verify()
                    with mock.patch.object(auth, "_direct_ipv4_connected_stream", new=stop_at_original_connector):
                        with api._owned_direct_deployment_session(held):
                            self.fail("pure fixture must not reach any native Transport")
            self.assertIs(primary, caught.exception)
            self.assertFalse(held.active)
            self.assertEqual([original_fd], closed)
        self.assertEqual(["192.0.2.21"], connected)
        # Caller work-body primary is also preserved for ordinary Exceptions,
        # not only the BaseException interruption at the native boundary.
        ordinary = OSError("independent work-body primary")
        observed = None
        with actual_stage(self) as (artifact, project, known, pin, private):
            try:
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5):
                    raise ordinary
            except BaseException as error:
                observed = error
        self.assertIs(ordinary, observed)

class F01DeploymentStagingIssuanceDirectTests(unittest.TestCase):
    def _reject_before_connect(self, api, holder):
        from tools import ufm_bootstrap_auth_adapter as auth
        class ForbiddenNativeBoundary(BaseException):
            pass
        calls = []
        def stop_native(*args, **kwargs):
            calls.append(True)
            raise ForbiddenNativeBoundary()
        observed = None
        with mock.patch.object(auth, "_direct_ipv4_connected_stream", new=stop_native):
            try:
                with api._owned_direct_deployment_session(holder):
                    self.fail("unissued source entered deployment owner")
            except BaseException as error:
                observed = error
        self.assertEqual([], calls, "registered original must be checked before actual connect")
        self.assertIsInstance(observed, api.StagingOwnerHold)

    def test_same_class_object_new_and_replaced_verify_cannot_forge_live_issuance(self):
        api = subject(self)
        with actual_stage(self) as (artifact, project, known, pin, private):
            with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                    expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                forged = object.__new__(api._HeldStage)
                forged.__dict__.update(dict(held.__dict__))
                forged.verify = lambda: None
                self._reject_before_connect(api, forged)

    def test_closed_genuine_source_remains_revoked_after_active_and_verify_replacement(self):
        api = subject(self)
        with actual_stage(self) as (artifact, project, known, pin, private):
            with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                    expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                original_fields = dict(held.__dict__)
            held.__dict__.update(original_fields)
            held.active = True
            held.verify = lambda: None
            self._reject_before_connect(api, held)

    def test_live_original_holder_pin_key_guard_fd_and_deadline_replacement_refuse(self):
        api = subject(self)
        for field in ("_key_bytes", "_pinned_key", "_verify_stage", "script_fd", "work_deadline"):
            with self.subTest(field=field), actual_stage(self) as (artifact, project, known, pin, private):
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                    original_fields = dict(held.__dict__)
                    if field == "_key_bytes":
                        changed = list(held._key_bytes)
                        changed[0] = b"not independently approved"
                        held._key_bytes = tuple(changed)
                    elif field == "_pinned_key":
                        held._pinned_key = object()
                    elif field == "_verify_stage":
                        held._verify_stage = lambda: None
                    elif field == "script_fd":
                        foreign = project / "foreign"
                        foreign.write_bytes(b"foreign unchanged")
                        foreign_fd = os.open(foreign, os.O_RDONLY)
                        held.script_fd = foreign_fd
                    else:
                        held.work_deadline = held.work_deadline + 100
                    held.verify = lambda: None
                    try:
                        self._reject_before_connect(api, held)
                    finally:
                        if field == "script_fd":
                            self.assertEqual(b"foreign unchanged", os.pread(foreign_fd, 64, 0))
                            os.close(foreign_fd)
                        held.__dict__.clear()
                        held.__dict__.update(original_fields)

    @sdk_identity_test
    def test_cleanup_operator_interrupt_outprioritizes_ordinary_primary_in_both_owned_finally(self):
        api = subject(self)
        from tools import ufm_bootstrap_auth_adapter as auth
        for edge in ("held-source", "deployment-session"):
            with self.subTest(edge=edge), actual_stage(self) as (artifact, project, known, pin, private):
                ordinary = OSError("independent ordinary work failure")
                operator = KeyboardInterrupt()
                observed = None
                if edge == "held-source":
                    original_close = api._NamedOriginals.close
                    actual_closed = []
                    def close_then_interrupt(owner):
                        result = original_close(owner)
                        actual_closed.append(True)
                        raise operator
                    try:
                        with mock.patch.object(api._NamedOriginals, "close", new=close_then_interrupt):
                            with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                                    expected_known_hosts_sha256=pin, management_identity=private, timeout=5):
                                raise ordinary
                    except BaseException as error:
                        observed = error
                    self.assertEqual([True], actual_closed)
                else:
                    class OwnedPureStream:
                        closed = False
                        def close(self):
                            self.closed = True
                            raise operator
                    stream = OwnedPureStream()
                    sdk_identity = auth._direct_sdk_identity
                    sdk_calls = []
                    def actual_sdk_then_body_failure():
                        result = sdk_identity()
                        sdk_calls.append(True)
                        if len(sdk_calls) == 3:
                            raise ordinary
                        return result
                    try:
                        with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                                expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                            with mock.patch.object(auth, "_direct_sdk_identity", new=actual_sdk_then_body_failure), \
                                    mock.patch.object(auth, "_direct_ipv4_connected_stream", return_value=stream):
                                with api._owned_direct_deployment_session(held):
                                    self.fail("pure pre-Transport failure should stop the scope")
                    except BaseException as error:
                        observed = error
                    self.assertEqual(3, len(sdk_calls))
                    self.assertTrue(stream.closed)
                self.assertIs(operator, observed, "operator must not be hidden below ordinary primary/HOLD")

    def test_foreign_pid_or_thread_context_refuses_before_connection(self):
        api = subject(self)
        import threading
        for boundary in ("pid", "thread"):
            with self.subTest(boundary=boundary), actual_stage(self) as (artifact, project, known, pin, private):
                with api._held_project_stage(script_path=artifact.script_path, known_hosts=known,
                        expected_known_hosts_sha256=pin, management_identity=private, timeout=5) as held:
                    if boundary == "pid":
                        changing_context = mock.patch.object(os, "getpid", return_value=os.getpid() + 1)
                    else:
                        changing_context = mock.patch.object(threading, "get_ident",
                                                             return_value=threading.get_ident() + 1)
                    with changing_context:
                        self._reject_before_connect(api, held)
