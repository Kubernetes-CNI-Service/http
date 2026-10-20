"""Distinct SCP request/source DATA; never native dispatch or ACK.

Requires the separately reviewed lexical SCP declaration capability. Missing
new API is an explicit capability FAIL before any fixture/descriptor opens.
Each whole must execute in its own owned child via the fixed helper.
"""
import contextlib
import copy
import errno
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import time
import unittest
from unittest.mock import patch

from test_cases import test_ibsw3_scp_stage_scope as BASE
from test_cases.ibsw3_scp_request_test_isolation import isolated_whole

driver = BASE.driver
NAME = 'scp-source-request.json'
ORIGINALS = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh', 'runner-binding.json')
ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'


def canonical(document):
    return (json.dumps(document, ensure_ascii=True, sort_keys=True, indent=2) + '\n').encode('utf-8')


class ScpScopeRequestContentTests(unittest.TestCase):
    def capabilities(self):
        for name in ('freeze_scp_package_sources', '_capture_scp_request_content_locked'):
            self.assertTrue(callable(getattr(driver._PreparedRunScope, name, None)),
                            'MISSING_SCP_SCOPE_SOURCE_API_NOT_AN_ACK_VULNERABILITY: ' + name)
        self.assertTrue(callable(getattr(driver, '_validate_scp_request_content_graph', None)),
                        'MISSING_SCP_REQUEST_CONTENT_DATA_VALIDATOR')

    def expected(self, held, package):
        return dict(schema_version=2, state='SCP_REQUEST_CONTENT_DATA_ONLY',
            execution_state='NOT_EXECUTED', activation_state='UNKNOWN',
            binding=json.loads(held['step-binding.json'].payload), declared_method='scp',
            request_id=json.loads(held['request.json'].payload)['request_id'],
            originals_sha256={name: hashlib.sha256(held[name].payload).hexdigest() for name in ORIGINALS},
            packages={str(package): dict(size=3, sha256=ABC_SHA)})

    @contextlib.contextmanager
    def original_graph(self, *, after_close=None, read_state=None):
        fixture = BASE.StagePackageSourceBoundaryV3Tests()
        manual = BASE.manual.ManualTests()
        with fixture.owned_tree() as raw:
            root = Path(raw)
            project, home, known, logs = manual.fixture(root)
            packages = root / 'packages'
            packages.mkdir(mode=0o700)
            package = packages / 'nvos-amd64-25.03.1010.bin'
            package.write_bytes(b'abc')
            package.chmod(0o600)
            if read_state is not None:
                info = package.stat()
                read_state['package_key'] = (info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
            args = ('--project', str(project), '--standalone-inputs', '--os-only',
                    '--method', 'scp', '--yes', '--package-dir', str(packages))
            with manual.no_deployment_or_filesystem_locks(), \
                 patch.object(subprocess, 'Popen', side_effect=AssertionError('no native process')), \
                 patch.object(socket, 'create_connection', side_effect=AssertionError('no network')):
                prepared = driver.prepare_manual_run(BASE.app.__file__, str(project), args)
                with driver.open_manual_run(BASE.app.__file__, str(project), args,
                                            prepared['run_directory']) as parent:
                    owner = parent.freeze_scp_package_sources((('os', 1),),
                        deadline=time.monotonic() + 8, max_fds=64)
                    with parent.fork_readiness_scope(BASE.HOST) as child:
                        child.prepare_requested_step(BASE.HOST, 'os', 1)
                        child.request_prepared_step(BASE.HOST, 'os', 1)
                        with child.open_readonly_query_inputs(BASE.HOST, known_hosts_path=str(known),
                                identity_path=None, management_public_path=None, user='admin') as leaf:
                            remote = (child.parsed.switch_dir + '/.ibsw-' + child.run_id + '-'
                                      + BASE.HOST + '-os-0001-' + '1' * 32 + '/step.sh')
                            child.prepare_owned_runner_data(leaf, 'os', 1, remote_script=remote)
                            stage = child.session._directory(child.run_directory / BASE.HOST / 'os-0001')
                            held = {name: child._hold(stage, name) for name in ORIGINALS}
                            yield parent, child, leaf, owner, package, stage, held
            if after_close is not None:
                after_close()  # Parent/child closed; private temporary still lives.

    @isolated_whole
    def test_literal_schema2_and_fixed_api_do_not_accept_local_or_permission_data(self):
        self.capabilities()
        freeze = inspect.signature(driver._PreparedRunScope.freeze_scp_package_sources)
        self.assertEqual(('self', 'selections', 'deadline', 'max_fds'), tuple(freeze.parameters))
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, freeze.parameters['deadline'].kind)
        self.assertEqual(inspect.Parameter.KEYWORD_ONLY, freeze.parameters['max_fds'].kind)
        capture = inspect.signature(driver._PreparedRunScope._capture_scp_request_content_locked)
        self.assertEqual(('self', 'leaf', 'component', 'package_index'), tuple(capture.parameters))
        # Synthetic parser DATA only; this does not satisfy the full held graph.
        binding = dict(component='os', run_id='literal-scp-data', stage='os-0001')
        request = canonical(dict(schema_version=1, state='REQUESTED', activation_state='UNKNOWN',
            execution_state='NOT_EXECUTED', binding=binding, request_id='1' * 32))
        raw = dict(zip(ORIGINALS, (request, b'IBSW_METHOD=scp\n', canonical(binding),
                                  b'runner DATA only\n', b'runner binding DATA only\n')))
        document = dict(schema_version=2, state='SCP_REQUEST_CONTENT_DATA_ONLY',
            execution_state='NOT_EXECUTED', activation_state='UNKNOWN', binding=binding,
            declared_method='scp', request_id='1' * 32,
            originals_sha256={name: hashlib.sha256(raw[name]).hexdigest() for name in ORIGINALS},
            packages={'/synthetic/image.bin': dict(size=3, sha256=ABC_SHA)})
        raw[NAME] = canonical(document)
        validate = driver._validate_scp_request_content_graph
        self.assertIsNone(validate(set(raw), binding, raw.__getitem__))
        mutations = (
            ('schema_version', 1), ('declared_method', 'local'),
            ('request_id', '2' * 32), ('activation_state', 'COMPLETE'),
            ('execution_state', 'DISPATCHED'), ('state', 'PACKAGE_SOURCE_PRELAUNCH_DATA_ONLY'),
            ('permit', True), ('automatic_sending_enabled', True),
        )
        for key, value in mutations:
            changed = copy.deepcopy(document)
            changed[key] = value
            files = dict(raw, **{NAME: canonical(changed)})
            with self.subTest(field=key), self.assertRaises(ValueError):
                validate(set(files), binding, files.__getitem__)
        for name in ORIGINALS:
            files = dict(raw)
            files[name] += b'changed original bytes'
            with self.subTest(original=name), self.assertRaises(ValueError):
                validate(set(files), binding, files.__getitem__)
        for packages in ({}, {'relative.bin': dict(size=3, sha256=ABC_SHA)},
                         {'/synthetic/image.bin': dict(size=0, sha256=ABC_SHA)},
                         {'/synthetic/image.bin': dict(size=3, sha256='0' * 63)}):
            changed = copy.deepcopy(document)
            changed['packages'] = packages
            files = dict(raw, **{NAME: canonical(changed)})
            with self.subTest(packages=packages), self.assertRaises(ValueError):
                validate(set(files), binding, files.__getitem__)

    @isolated_whole
    def test_real_scp_parent_hash_once_borrow_and_cold_companion_keep_five_originals(self):
        self.capabilities()
        state = dict(chunks=[])
        real_read, real_fstat = os.read, os.fstat
        def reading(fd, count):
            data = real_read(fd, count)
            info = real_fstat(fd)
            # Exact current fixture object generation, not a size/path grant.
            if ((info.st_dev, info.st_ino, stat.S_IFMT(info.st_mode))
                    == state.get('package_key')):
                state['chunks'].append(data)
            return data
        def cold():
            state['cold'] = state['path'].read_bytes()
            state['five_closed'] = all(obj.fd is None for obj in state['objects'])
            try:
                state['owner'].verify()
            except ValueError:
                state['owner_refused_after_close'] = True
        with patch.object(os, 'read', reading):
            with self.original_graph(after_close=cold, read_state=state) as (parent, child, leaf, owner, package, stage, held):
                before = {name: (obj, obj.fd, obj.payload) for name, obj in held.items()}
                self.assertIs(owner, parent._package_source_owner)
                self.assertIs(owner, child._package_source_owner)
                self.assertIs(parent, child._package_source_parent)
                self.assertIn(child, parent._package_source_borrowers)
                writers, events = [], []
                init, finish = driver._JournalWriter.__init__, driver._JournalWriter.finish
                sync, link, close = os.fsync, os.link, os.close
                def initialize(writer, scope, directory):
                    init(writer, scope, directory)
                    if scope is child and directory is stage: writers.append(writer)
                def matching_owner(fd):
                    return next((o for w in writers for o in w.owners if o.fd == fd), None)
                def syncing(fd):
                    result = sync(fd)
                    if matching_owner(fd) is not None: events.append('file-fsync-return')
                    elif fd == stage.fd: events.append('directory-fsync-return')
                    return result
                def linking(old, new, *args, **kwargs):
                    result = link(old, new, *args, **kwargs)
                    if new == NAME and kwargs.get('dst_dir_fd') == stage.fd:
                        events.append('exclusive-link-return')
                    return result
                def closing(fd):
                    owned = matching_owner(fd)
                    if owned is not None:
                        actual = os.fstat(fd)
                        self.assertEqual(owned.owner.key,
                            (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)))
                    result = close(fd)
                    if owned is not None: events.append('writer-close-return')
                    return result
                def finishing(writer):
                    result = finish(writer)
                    if any(writer is w for w in writers): events.append('writer-finish-return')
                    return result
                with patch.object(driver._JournalWriter, '__init__', initialize), \
                     patch.object(driver._JournalWriter, 'finish', finishing), \
                     patch.object(os, 'fsync', syncing), patch.object(os, 'link', linking), \
                     patch.object(os, 'close', closing):
                    with child._request_namespace_lease():
                        self.assertIsNone(child._capture_scp_request_content_locked(leaf, 'os', 1))
                    events.append('capture-return')
                    with child._request_namespace_lease():
                        child._capture_scp_request_content_locked(leaf, 'os', 1)
                record = child._hold(stage, NAME)
                self.assertEqual(self.expected(held, package), json.loads(record.payload))
                self.assertIs(record, child._hold(stage, NAME))
                self.assertEqual(1, len(writers), 'existing exact record is not rewritten')
                ordered = ('file-fsync-return', 'exclusive-link-return', 'directory-fsync-return',
                           'writer-close-return', 'writer-finish-return', 'capture-return')
                for event in ordered:
                    self.assertIn(event, events, 'actual critical boundary return must be witnessed')
                self.assertEqual(sorted(events.index(name) for name in ordered),
                                 [events.index(name) for name in ordered])
                self.assertEqual('UNKNOWN', child.inspect_step(BASE.HOST, 'os', 1)['state'])
                for name, (obj, fd, payload) in before.items():
                    self.assertIs(obj, child._hold(stage, name))
                    self.assertEqual((fd, payload), (obj.fd, obj.payload))
                self.assertFalse((stage.path / 'package-source.json').exists(), 'LOCAL schema is not relabelled')
                self.assertFalse((stage.path / 'component-dispatch.json').exists())
                self.assertFalse((stage.path / 'download-ack').exists())
                state.update(path=stage.path / NAME, owner=owner, objects=tuple(held.values()),
                             payload=record.payload)
        self.assertEqual([b'abc', b''], state['chunks'], 'actual source bytes hashed once, not on each capture')
        self.assertEqual(state['payload'], state['cold'])
        self.assertTrue(state['five_closed'])
        self.assertTrue(state.get('owner_refused_after_close'))

    @isolated_whole
    def test_real_scp_capture_without_lease_cannot_write_a_companion(self):
        self.capabilities()
        failure = None
        with self.original_graph() as (parent, child, leaf, owner, package, stage, held):
            try:
                child._capture_scp_request_content_locked(leaf, 'os', 1)
            except Exception as error:
                failure = error
            absent = not (stage.path / NAME).exists()
            parent.verify()
            child.verify()
        self.assertIsInstance(failure, (driver.SharedUpgradeHold, driver.PreparationHold, ValueError))
        self.assertTrue(absent)

    def fault_capture(self, mode):
        self.capabilities()
        state = dict(events=[], writers=[], writes=0, links=0, fired=False, errors={})
        try:
            with self.original_graph() as (parent, child, leaf, owner, package, stage, held):
                originals = {name: (obj, obj.fd, obj.payload) for name, obj in held.items()}
                init, finish = driver._JournalWriter.__init__, driver._JournalWriter.finish
                sync, close, write, link = os.fsync, os.close, os.write, os.link
                active_finish = []
                fault = OSError(errno.EIO, 'literal SCP companion critical failure')
                def initialize(writer, scope, directory):
                    init(writer, scope, directory)
                    if scope is child and directory is stage:
                        state['writers'].append(writer)
                def writer_fd(fd):
                    return any(any(owned.fd == fd for owned in w.owners) for w in state['writers'])
                def fail(label):
                    state['fired'] = True
                    state['events'].append(label)
                    state['at_fault'] = (state['writes'], state['links'], len(state['writers']))
                    raise fault
                def syncing(fd):
                    if not state['fired']:
                        if mode == 'file-fsync' and writer_fd(fd): fail(mode)
                        if mode == 'directory-fsync' and fd == stage.fd: fail(mode)
                    return sync(fd)
                def writing(fd, data):
                    result = write(fd, data)
                    if writer_fd(fd): state['writes'] += 1
                    return result
                def linking(old, new, *args, **kwargs):
                    result = link(old, new, *args, **kwargs)
                    if new == NAME and kwargs.get('dst_dir_fd') == stage.fd: state['links'] += 1
                    return result
                def finishing(writer):
                    selected = any(writer is original for original in state['writers'])
                    if selected: active_finish.append(writer)
                    try:
                        return finish(writer)
                    finally:
                        if selected: active_finish.pop()
                def closing(fd):
                    if mode == 'writer-close' and active_finish and not state['fired']:
                        owned = next((x for x in active_finish[-1].owners if x.fd == fd), None)
                        if owned is not None:
                            actual = os.fstat(fd)
                            if owned.owner.key != (actual.st_dev, actual.st_ino, stat.S_IFMT(actual.st_mode)):
                                raise AssertionError('fault lost actual original writer generation')
                            fail(mode)  # Before native close; UNKNOWN retained until child exit.
                    return close(fd)
                if mode == 'source-drift':
                    package.write_bytes(b'xyz')
                    state['fired'] = True
                    state['at_fault'] = (0, 0, 0)
                with patch.object(driver._JournalWriter, '__init__', initialize), \
                     patch.object(driver._JournalWriter, 'finish', finishing), \
                     patch.object(os, 'fsync', syncing), patch.object(os, 'close', closing), \
                     patch.object(os, 'write', writing), patch.object(os, 'link', linking):
                    try:
                        with child._request_namespace_lease():
                            child._capture_scp_request_content_locked(leaf, 'os', 1)
                        state['returned'] = True
                    except Exception as error:
                        state['errors']['capture'] = error
                    for label, operation in (('parent', parent.verify), ('child', child.verify)):
                        try: operation()
                        except Exception as error: state['errors'][label] = error
                    try:
                        with child._request_namespace_lease():
                            child._capture_scp_request_content_locked(leaf, 'os', 1)
                    except Exception as error:
                        state['errors']['retry'] = error
                    sibling = None
                    try: sibling = parent.fork_readiness_scope(BASE.HOST)
                    except Exception as error: state['errors']['sibling'] = error
                    finally:
                        if sibling is not None: sibling.close()
                    state['after_checks'] = (state['writes'], state['links'], len(state['writers']))
                state['unchanged'] = all(child.files[(str(stage.path), name)] is obj
                    and obj.fd == fd and obj.payload == payload for name, (obj, fd, payload) in originals.items())
                state['no_dispatch'] = not (stage.path / 'component-dispatch.json').exists()
                state['no_ack'] = not (stage.path / 'download-ack').exists()
        except Exception as error:
            state['cleanup'] = error
        self.assertTrue(state['fired'], 'must reach actual intended boundary, not an earlier unsupported branch')
        self.assertNotIn('returned', state)
        for label in ('capture', 'parent', 'child', 'retry', 'sibling'):
            self.assertIsNotNone(state['errors'].get(label), label + ' must remain HOLD')
        self.assertEqual(state['at_fault'], state['after_checks'], 'no new writer/link or automatic record repair')
        self.assertTrue(state['unchanged'])
        self.assertTrue(state['no_dispatch'])
        self.assertTrue(state['no_ack'])
        self.assertIsNotNone(state.get('cleanup'), 'real final verification preserves shared poison')

    @isolated_whole
    def test_scp_source_drift_revokes_parent_child_and_new_borrow_without_record_repair(self):
        self.fault_capture('source-drift')

    @isolated_whole
    def test_scp_file_fsync_failure_revokes_the_whole_source_group(self):
        self.fault_capture('file-fsync')

    @isolated_whole
    def test_scp_directory_fsync_failure_cannot_be_adopted_by_capture_retry(self):
        self.fault_capture('directory-fsync')

    @isolated_whole
    def test_scp_critical_writer_close_failure_is_not_a_successful_record(self):
        self.fault_capture('writer-close')
