"""SOURCE-only positive: actual fixed provider bootstrap from ONE absent slot.

No import repair or permission DTO is supplied. The fixed driver executes its
held sibling source; the resulting new namespace must really construct/read/
verify/close the private package holder. Only this slot is restored afterward.
"""
import importlib
import os
import sys
import time
import unittest
from unittest import mock

from test_cases import test_ibsw3_scp_provider_source as original_fixture


class LazyScpAbsentTests(unittest.TestCase):
    def test_absent_slot_bootstraps_fixed_source_and_reads_actual_package(self):
        name = 'ibsw_upgrade_scp'
        prior = importlib.import_module(name)
        prior_profile = sys.getprofile()
        self.assertIsNone(prior_profile, 'fixture cannot replace a profile owner')
        counts = {'factory': 0, 'constructor': 0, 'package_open': 0}
        facts = {}
        try:
            with original_fixture.LazyScpSourceBindingTests.original_scope(self) as (parent, package):
                raw_open = os.open
                literals = (str(package), package.name,
                            os.fsencode(str(package)), os.fsencode(package.name))

                def opened(path, *args, **kwargs):
                    if isinstance(path, (str, bytes, os.PathLike)) and os.fspath(path) in literals:
                        counts['package_open'] += 1
                    return raw_open(path, *args, **kwargs)

                def observed(frame, event, arg):
                    if event != 'call':
                        return
                    current = sys.modules.get(name)
                    if current is None or current is prior or frame.f_globals is not vars(current):
                        return
                    factory = vars(current).get('package_content_owner')
                    cls = vars(current).get('_PackageContentOwner')
                    if factory is not None and frame.f_code is factory.__code__:
                        counts['factory'] += 1
                    if cls is not None and frame.f_code is vars(cls)['__init__'].__code__:
                        counts['constructor'] += 1

                # The source/object admission itself, not a test loader, must
                # supply the missing provider. Preparation is already complete.
                del sys.modules[name]
                with mock.patch.object(os, 'open', side_effect=opened):
                    sys.setprofile(observed)
                    try:
                        owner = parent.freeze_package_sources((('os', 1),),
                            deadline=time.monotonic() + 4, max_fds=64)
                    finally:
                        sys.setprofile(prior_profile)
                current = sys.modules[name]
                owner.verify()
                facts['new_namespace'] = current is not prior
                facts['factory_globals'] = current.package_content_owner.__globals__ is vars(current)
                facts['owner_type'] = type(owner) is current._PackageContentOwner
                facts['registered'] = parent._package_source_owner is owner
                facts['size'] = owner._files[package][3][6]
                facts['sha'] = owner._files[package][4]
            # Actual original scope exit closed the new namespace's holder.
            facts['closed'] = owner._closed
            facts['cleanup'] = list(owner.cleanup_issues)
        finally:
            sys.setprofile(prior_profile)
            sys.modules[name] = prior
        self.assertEqual(1, counts['factory'])
        self.assertEqual(1, counts['constructor'])
        self.assertGreater(counts['package_open'], 0)
        self.assertIs(facts['new_namespace'], True)
        self.assertIs(facts['factory_globals'], True)
        self.assertIs(facts['owner_type'], True)
        self.assertIs(facts['registered'], True)
        self.assertEqual((3, original_fixture.ABC_SHA), (facts['size'], facts['sha']))
        self.assertIs(facts['closed'], True)
        self.assertEqual([], facts['cleanup'])
        self.assertIs(sys.modules[name], prior)


if __name__ == '__main__':
    unittest.main()
