"""UNRUN SOURCE: actual local declaration/request/runner -> durable source DATA.

This is NOT a legal SCP dispatch fixture. The real plan stays method=local.
No native observation, signed session, launch, ACK, socket, keygen or device.
Missing proposed API is a capability FAIL, not a reproduced exploit.
"""
import contextlib
import hashlib
import json
from pathlib import Path
import socket
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch

import test_cases
from test_cases.ibsw225_fixture_support.runtime_source_support import support
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures

ROOT = Path(test_cases.__file__).resolve().parent.parent
RUNTIME = support(unittest.TestCase())
FIXED = install_fixed_fixtures()
import test_manual_execution as manual

driver = RUNTIME.driver
app = RUNTIME.app
HOST = 'ew-spine01.example'
NAME = 'package-source.json'
ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
RETAINED_TREES = []


from test_cases.ibsw3_scp_test_isolation import isolated_whole

class StagePackageSourceBoundaryV3Tests(unittest.TestCase):
    def capabilities(self):
        self.assertTrue(callable(getattr(driver._PreparedRunScope, 'freeze_package_sources', None)),
                        'MISSING_SCOPE_OWNED_SOURCE_CAPTURE_API_NOT_AN_EXPLOIT')
        self.assertTrue(callable(getattr(driver._PreparedRunScope, '_capture_package_source_data_locked', None)),
                        'MISSING_DURABLE_PRELAUNCH_DATA_API_NOT_AN_EXPLOIT')

    @contextlib.contextmanager
    def owned_tree(self):
        # Keep failed original graphs on disk. Unknown FDs are NOT rescued here.
        root = Path(tempfile.mkdtemp(prefix='stage-source-v3-')).resolve()
        try:
            yield str(root)
        except BaseException:
            RETAINED_TREES.append(str(root))
            raise
        else:
            shutil.rmtree(root)

    @contextlib.contextmanager
    def original_graph(self, *, after_close=None, after_child_close=None):
        fixture = manual.ManualTests()
        with self.owned_tree() as temporary:
            root = Path(temporary).resolve()
            project, home, known, logs = fixture.fixture(root)
            packages = root/'packages'
            packages.mkdir(mode=0o700)
            package = packages/'nvos-amd64-25.03.1010.bin'
            package.write_bytes(b'abc')
            package.chmod(0o600)
            args = (*fixture.arguments(project), '--package-dir', str(packages))
            with fixture.no_deployment_or_filesystem_locks(), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('no process in DATA capture')), \
                 patch.object(socket, 'create_connection', side_effect=AssertionError('no network in DATA capture')):
                prepared = driver.prepare_manual_run(app.__file__, str(project), args)
                with driver.open_manual_run(app.__file__, str(project), args, prepared['run_directory']) as parent:
                    # Parent API derives paths from its held policy. No caller path/hash/record.
                    owner = parent.freeze_package_sources((('os', 1),),
                        deadline=time.monotonic()+4, max_fds=64)
                    with parent.fork_readiness_scope(HOST) as child:
                        self.assertIs(parent, child._readiness_parent)
                        child.prepare_requested_step(HOST, 'os', 1)
                        child.request_prepared_step(HOST, 'os', 1)
                        with child.open_readonly_query_inputs(HOST, known_hosts_path=str(known),
                                identity_path=None, management_public_path=None, user='admin') as leaf:
                            remote = (child.parsed.switch_dir+'/.ibsw-'+child.run_id+'-'
                                      +HOST+'-os-0001-'+'1'*32+'/step.sh')
                            child.prepare_owned_runner_data(leaf, 'os', 1, remote_script=remote)
                            stage = child.session._directory(child.run_directory/HOST/'os-0001')
                            names = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
                            held = {name: child._hold(stage, name) for name in names}
                            yield parent, child, leaf, owner, package, stage, held
                    if after_child_close is not None:
                        after_child_close(parent, child, owner)
            # Test-only evidence readback: original scopes and the package
            # holder have closed, but this fixture's temporary tree still lives.
            if after_close is not None:
                after_close()

    def expected(self, child, package, held):
        # Fixed field names/outcomes. Hashes refer to actual held prerequisite
        # bytes, not a calculated capture result or copied implementation schema.
        return {
            'schema_version': 1,
            'state': 'PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY',
            'execution_state': 'NOT_EXECUTED',
            'activation_state': 'UNKNOWN',
            'binding': json.loads(held['step-binding.json'].payload),
            'declared_method': 'local',
            'originals_sha256': {name: hashlib.sha256(held[name].payload).hexdigest()
                for name in ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')},
            'packages': {str(package): {'size': 3, 'sha256': ABC_SHA}},
        }

    @isolated_whole
    def test_literal_record_is_scope_derived_and_durably_retained_without_dispatch(self):
        self.capabilities()
        evidence = {}
        def cold_readback():
            evidence['readback'] = evidence['path'].read_bytes()
            evidence['closed_fds'] = all(obj.fd is None for obj in evidence['originals'])
            evidence['owner_refuses'] = False
            try:
                evidence['owner'].verify()
            except ValueError:
                evidence['owner_refuses'] = True
        with self.original_graph(after_close=cold_readback) as (parent, child, leaf, owner, package, stage, held):
            originals = {name: (obj, obj.fd, obj.payload) for name, obj in held.items()}
            with child._request_namespace_lease():
                child._capture_package_source_data_locked(leaf, 'os', 1)
            saved = child._hold(stage, NAME)
            expected = self.expected(child, package, held)
            self.assertEqual(expected, json.loads(saved.payload))
            for name, (obj, fd, payload) in originals.items():
                self.assertIs(obj, child._hold(stage, name))
                self.assertEqual((fd, payload), (obj.fd, obj.payload))
            self.assertIs(owner, parent._package_source_owner)
            owner.verify()
            path = stage.path/NAME
            payload = saved.payload
            evidence.update(path=path, originals=tuple(held.values()), owner=owner)
            self.assertFalse((stage.path/'component-dispatch.json').exists())
            self.assertFalse((stage.path/'download-ack').exists())
        # Evidence readback only, never a reopened authorization object.
        self.assertEqual(payload, evidence['readback'])
        self.assertTrue(evidence['closed_fds'])
        self.assertTrue(evidence['owner_refuses'])

    @isolated_whole
    def test_capture_requires_actual_active_namespace_lease(self):
        self.capabilities()
        failure = None
        with self.original_graph() as (parent, child, leaf, owner, package, stage, held):
            try:
                child._capture_package_source_data_locked(leaf, 'os', 1)
            except Exception as error:
                failure = error
            absent = not (stage.path/NAME).exists()
        self.assertIsNotNone(failure, 'no capture outside actual request lease')
        self.assertIsInstance(failure, (driver.PreparationHold, driver.SharedUpgradeHold, ValueError))
        self.assertTrue(absent)

    @isolated_whole
    def test_changed_request_has_both_body_refusal_and_explicit_cleanup_hold(self):
        self.capabilities()
        body_error = cleanup_error = None
        facts = {}
        try:
            with self.original_graph() as (parent, child, leaf, owner, package, stage, held):
                request = held['request.json']
                original_fd = request.fd
                replacement = stage.path/'replacement'
                replacement.write_bytes(b'foreign replacement request')
                replacement.chmod(0o600)
                replacement.replace(stage.path/'request.json')
                try:
                    with child._request_namespace_lease():
                        child._capture_package_source_data_locked(leaf, 'os', 1)
                except Exception as error:
                    body_error = error
                facts['same_object'] = child.files[(str(stage.path), 'request.json')] is request
                facts['same_fd'] = request.fd == original_fd
                facts['absent'] = not (stage.path/NAME).exists()
                facts['replacement'] = (stage.path/'request.json').read_bytes()
                facts['root'] = str(package.parent.parent)
        except Exception as error:
            cleanup_error = error
        # Root runs this method in a bounded, owned independent interpreter.
        # Real scope cleanup stays strict; no manual FD close/retry is performed.
        self.assertIsNotNone(body_error)
        self.assertIsInstance(body_error, (driver.SharedUpgradeHold, driver.PreparationHold, ValueError))
        self.assertIsNotNone(cleanup_error, 'original replaced request cleanup must remain HOLD')
        self.assertIsInstance(cleanup_error, ValueError)
        self.assertTrue(facts['same_object'])
        self.assertTrue(facts['same_fd'])
        self.assertTrue(facts['absent'])
        self.assertEqual(b'foreign replacement request', facts['replacement'])
        self.assertIn(facts['root'], RETAINED_TREES, 'failed original tree must not be recursively cleaned')

    @isolated_whole
    def test_early_parent_close_stops_parent_and_borrower_without_mutating_evidence(self):
        self.capabilities()
        errors = {}
        facts = {}
        cleanup_error = None
        try:
            with self.original_graph() as (parent, child, leaf, owner, package, stage, held):
                before = {name: obj.payload for name, obj in held.items()}
                original_objects = dict(held)
                original_fds = {name: obj.fd for name, obj in held.items()}
                for label, operation in (('close', parent.close), ('parent', parent.verify), ('child', child.verify)):
                    try:
                        operation()
                    except Exception as error:
                        errors[label] = error
                try:
                    with child._request_namespace_lease():
                        child._capture_package_source_data_locked(leaf, 'os', 1)
                except Exception as error:
                    errors['capture'] = error
                facts['originals_unchanged'] = all((stage.path/name).read_bytes() == payload for name, payload in before.items())
                facts['objects_unchanged'] = all(child.files[(str(stage.path), name)] is obj for name, obj in original_objects.items())
                facts['fds_unchanged'] = all(obj.fd == original_fds[name] for name, obj in original_objects.items())
                facts['no_capture'] = not (stage.path/NAME).exists()
                facts['no_dispatch'] = not (stage.path/'component-dispatch.json').exists()
        except Exception as error:
            cleanup_error = error
        self.assertIsInstance(errors.get('close'), driver.SharedUpgradeHold)
        self.assertIsNotNone(errors.get('parent'), 'failed close cannot leave parent reusable')
        self.assertIsNotNone(errors.get('child'), 'failed parent close cannot leave borrower reusable')
        self.assertIsNotNone(errors.get('capture'), 'failed parent close cannot release new DATA')
        for name in ('originals_unchanged', 'objects_unchanged', 'fds_unchanged', 'no_capture', 'no_dispatch'):
            self.assertTrue(facts[name], name)
        self.assertIsNotNone(cleanup_error, 'real leaf final verify must keep the parent failure visible')
        self.assertIsInstance(cleanup_error, ValueError)

    @isolated_whole
    def test_normal_child_close_keeps_parent_owner_live_until_parent_natural_close(self):
        self.capabilities()
        facts = {}
        def after_child(parent, child, owner):
            parent.verify()
            owner.verify()
            facts['child_closed'] = child.closed
            facts['parent_live'] = not parent.closed
            facts['same_owner'] = parent._package_source_owner is owner
            facts['no_borrowers'] = not parent._package_source_borrowers
        def after_parent():
            facts['parent_closed'] = facts['parent'].closed
            try:
                facts['owner'].verify()
            except ValueError:
                facts['owner_closed'] = True
        with self.original_graph(after_child_close=after_child, after_close=after_parent) as (parent, child, leaf, owner, package, stage, held):
            facts.update(parent=parent, owner=owner)
        for name in ('child_closed', 'parent_live', 'same_owner', 'no_borrowers', 'parent_closed', 'owner_closed'):
            self.assertTrue(facts.get(name), name)


if __name__ == '__main__':
    unittest.main()
