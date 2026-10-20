"""SOURCE draft: real LOCAL scope -> fixed lazy SCP-holder dependency only.

No guard implementation, SCP/SSH dispatch, remote server or device is used.
The root runner must supply a coherent fixed runtime bundle containing the
candidate driver AND its sibling ibsw_upgrade_scp.py. Loading only a private
driver against main tools is not proof of canonical/flat source admission.
SUBJECT may be replaced by that root-owned coherent bundle's actual driver;
the original fixture provider must use that same object for preparation.

The observations start AFTER actual project/run preparation and end BEFORE
scope cleanup. Profile records only exact original code/globals call events,
never changes a return, invokes a factory, or supplies permission.
"""
import contextlib
import importlib
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import types
import unittest
from unittest import mock

from test_cases.ibsw225_fixture_support.runtime_source_support import support
from test_cases.ibsw225_fixture_support.fixed_fixture_registry import install_fixed_fixtures

RUNTIME = support(unittest.TestCase())
FIXED = install_fixed_fixtures()
import test_manual_execution as manual

SUBJECT = RUNTIME.driver
APP = RUNTIME.app
ABC_SHA = 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
RETAINED_TREES = []


def _foreign_factory(root, paths, *, deadline, max_fds):
    # A real call here is itself forbidden. No native resource is acquired.
    raise ValueError('independent foreign factory body entered')


class _ForeignOwner:
    def __init__(self, root, paths, *, deadline, max_fds):
        raise ValueError('independent foreign class body entered')


@contextlib.contextmanager
def exact_module_slot(name, replacement):
    # Alter this ONE existing slot, not a whole sys.modules snapshot/restore.
    original = sys.modules[name]
    sys.modules[name] = replacement
    try:
        yield
    finally:
        sys.modules[name] = original


@contextlib.contextmanager
def observe_original_calls(functions):
    counts = {name: 0 for name, function in functions}
    held = tuple((name, function.__code__, function.__globals__)
                 for name, function in functions)
    prior = sys.getprofile()
    if prior is not None:
        raise RuntimeError('this fixture cannot replace an existing profile/ownership observer')

    def observer(frame, event, arg):
        if event == 'call':
            for name, code, namespace in held:
                if frame.f_code is code and frame.f_globals is namespace:
                    counts[name] += 1

    sys.setprofile(observer)
    try:
        yield counts
    finally:
        sys.setprofile(prior)


class LazyScpSourceBindingTests(unittest.TestCase):
    @contextlib.contextmanager
    def original_scope(self):
        self.assertTrue(callable(getattr(SUBJECT._PreparedRunScope,
            'freeze_package_sources', None)),
            'ROOT_MUST_SELECT_THE_REVIEWED_NEW_API_NOT_MISSING_API_AS_EXPLOIT')
        # Do not silently repair a stale test provider or fake a driver path.
        self.assertIs(SUBJECT, manual.driver, 'original fixture must use the same actual driver')
        fixture = manual.ManualTests()
        root = Path(tempfile.mkdtemp(prefix='ib-lazy-source-owned-')).resolve()
        known_closed = False
        try:
            project, _home, _known, _logs = fixture.fixture(root)
            packages = root / 'packages'; packages.mkdir(mode=0o700)
            package = packages / 'nvos-amd64-25.03.1010.bin'
            package.write_bytes(b'abc'); package.chmod(0o600)
            args = (*fixture.arguments(project), '--package-dir', str(packages))
            with fixture.no_deployment_or_filesystem_locks(), \
                 mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('no process in source admission')), \
                 mock.patch.object(socket, 'create_connection', side_effect=AssertionError('no network in source admission')):
                prepared = SUBJECT.prepare_manual_run(APP.__file__, str(project), args)
                with SUBJECT.open_manual_run(APP.__file__, str(project), args,
                        prepared['run_directory']) as parent:
                    yield parent, package
            known_closed = True
        finally:
            if known_closed:
                shutil.rmtree(root)
            else:
                # No FD rescue, re-open/adoption or cleanup of an uncertain tree.
                RETAINED_TREES.append(str(root))

    def test_original_fixed_factory_reads_real_package_then_closes_normally(self):
        source = importlib.import_module('ibsw_upgrade_scp')
        factory, owner_class = source.package_content_owner, source._PackageContentOwner
        with self.original_scope() as (parent, package):
            # Preparation is complete BEFORE this observation window.
            with observe_original_calls((('factory', factory),
                    ('constructor', owner_class.__init__),
                    ('package_open', owner_class._open_original))) as counts:
                owner = parent.freeze_package_sources((('os', 1),),
                    deadline=time.monotonic() + 4, max_fds=64)
            actual_type = type(owner)
            actual_sha = owner._files[package][4]
            actual_size = owner._files[package][3][6]
            owner.verify()
            same_owner = parent._package_source_owner is owner
        self.assertIs(source, sys.modules['ibsw_upgrade_scp'])
        self.assertIs(factory, source.package_content_owner)
        self.assertIs(owner_class, source._PackageContentOwner)
        self.assertIs(actual_type, owner_class)
        self.assertEqual({'factory': 1, 'constructor': 1},
                         {key: counts[key] for key in ('factory', 'constructor')})
        self.assertGreater(counts['package_open'], 0)
        self.assertEqual((3, ABC_SHA), (actual_size, actual_sha))
        self.assertIs(same_owner, True)
        self.assertIs(owner._closed, True)
        self.assertEqual([], owner.cleanup_issues)

    def test_foreign_module_reexports_cannot_borrow_original_factory_identity(self):
        source = importlib.import_module('ibsw_upgrade_scp')
        factory, owner_class = source.package_content_owner, source._PackageContentOwner
        foreign = types.ModuleType('ibsw_upgrade_scp')
        foreign.__dict__.update(source.__dict__)  # Includes matching file/spec metadata.
        self.assertIsNot(foreign, source)
        self.assertIs(foreign.package_content_owner, factory)
        self.assertIsNot(factory.__globals__, foreign.__dict__)
        with self.original_scope() as (parent, _package):
            error = None
            with exact_module_slot('ibsw_upgrade_scp', foreign), \
                 observe_original_calls((('factory', factory),
                    ('constructor', owner_class.__init__),
                    ('package_open', owner_class._open_original))) as counts:
                try:
                    parent.freeze_package_sources((('os', 1),),
                        deadline=time.monotonic() + 4, max_fds=64)
                except Exception as caught:
                    error = caught
        # No assertions inside owned contexts: cleanup cannot normalize them.
        self.assertEqual({'factory': 0, 'constructor': 0, 'package_open': 0}, counts,
                         'FOREIGN_MODULE_MUST_STOP_BEFORE_ORIGINAL_FACTORY_OR_PACKAGE_IO')
        self.assertIs(type(error), SUBJECT.SharedUpgradeHold)
        self.assertIs(sys.modules['ibsw_upgrade_scp'], source)

    def test_replaced_factory_or_class_stops_before_any_foreign_call_or_package_read(self):
        source = importlib.import_module('ibsw_upgrade_scp')
        factory, owner_class = source.package_content_owner, source._PackageContentOwner
        forged = types.FunctionType(_foreign_factory.__code__, source.__dict__,
                                    'package_content_owner')
        forged.__module__ = source.__name__
        forged.__qualname__ = 'package_content_owner'
        foreign_class = type('_PackageContentOwner', (), {
            '__module__': source.__name__, '__init__': _ForeignOwner.__init__})
        for label, attribute, replacement, foreign_call in (
                ('foreign-factory', 'package_content_owner', _foreign_factory, _foreign_factory),
                ('matching-globals-factory', 'package_content_owner', forged, forged),
                ('foreign-owner-class', '_PackageContentOwner', foreign_class, foreign_class.__init__)):
            with self.subTest(case=label):
                with self.original_scope() as (parent, _package):
                    error = None
                    with mock.patch.object(source, attribute, replacement), \
                         observe_original_calls((('factory', factory),
                            ('constructor', owner_class.__init__),
                            ('package_open', owner_class._open_original),
                            ('foreign_call', foreign_call))) as counts:
                        try:
                            parent.freeze_package_sources((('os', 1),),
                                deadline=time.monotonic() + 4, max_fds=64)
                        except Exception as caught:
                            error = caught
                self.assertEqual({'factory': 0, 'constructor': 0,
                    'package_open': 0, 'foreign_call': 0}, counts,
                    'SOURCE_AUDIT_MUST_PRECEDE_FACTORY_CLASS_AND_PACKAGE_READS')
                self.assertIs(type(error), SUBJECT.SharedUpgradeHold)
                self.assertIs(source.package_content_owner, factory)
                self.assertIs(source._PackageContentOwner, owner_class)


if __name__ == '__main__':
    unittest.main()
