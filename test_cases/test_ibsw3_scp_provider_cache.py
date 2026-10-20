"""SOURCE-only cached-None negative for the actual lazy provider edge.

Use the real prepared LOCAL scope from the frozen original three controls.
Only ONE existing sys.modules slot is temporarily None. A cached None is not
permission to bootstrap/adopt another module. No package owner may be created.

The older code/globals profiler cannot prove package-open absence here: exec
would create new globals and new class/function identities. Instead this case
transparently spies on the same actual os.open used by both old/new namespaces,
only in the freeze window. It delegates every call unchanged and counts only
opens naming the private fixture package; it is not a generic FD ledger or a
claim of zero filesystem IO. Fixture preparation and cleanup are outside it.
"""
import importlib
import os
import sys
import time
import unittest
from unittest import mock

from test_cases import test_ibsw3_scp_provider_source as original_fixture


class LazyScpCachedNoneTests(unittest.TestCase):
    def test_existing_none_slot_is_not_bootstrapped_before_package_reads(self):
        name = 'ibsw_upgrade_scp'
        source = importlib.import_module(name)
        self.assertIs(source, sys.modules[name])
        facts = {}
        error = None
        with original_fixture.LazyScpSourceBindingTests.original_scope(self) as (parent, package):
            raw_open = os.open
            package_opens = []
            literals = (str(package), package.name,
                        os.fsencode(str(package)), os.fsencode(package.name))

            def observe_open(path, *args, **kwargs):
                # No FD inspection/adoption and no altered result/exception.
                # Both the canonical module and a wrongly exec-created module
                # use this original os module, so namespace replacement cannot
                # make this witness miss the original package leaf open.
                if isinstance(path, (str, bytes, os.PathLike)):
                    value = os.fspath(path)
                    if value in literals:
                        package_opens.append(True)
                return raw_open(path, *args, **kwargs)

            prior = sys.modules[name]
            sys.modules[name] = None
            try:
                with mock.patch.object(os, 'open', side_effect=observe_open):
                    try:
                        parent.freeze_package_sources((('os', 1),),
                            deadline=time.monotonic() + 4, max_fds=64)
                    except Exception as caught:
                        error = caught
                # Capture BEFORE restoring the original module slot and BEFORE
                # real parent cleanup. Assertions are outside the owner scope.
                facts['slot_present'] = name in sys.modules
                facts['slot_still_none'] = sys.modules.get(name) is None
                facts['parent_has_no_owner'] = parent._package_source_owner is None
                facts['package_open_attempts'] = len(package_opens)
            finally:
                # Restore this exact slot only, never a whole module-cache set.
                sys.modules[name] = prior
        self.assertEqual(0, facts['package_open_attempts'],
                         'CACHED_NONE_MUST_STOP_BEFORE_PRIVATE_PACKAGE_OPEN')
        self.assertIs(facts['slot_present'], True)
        self.assertIs(facts['slot_still_none'], True,
                      'CACHED_NONE_MUST_NOT_BE_REPLACED_OR_DELETED_AS_ABSENCE')
        self.assertIs(facts['parent_has_no_owner'], True)
        self.assertIs(type(error), original_fixture.SUBJECT.SharedUpgradeHold)
        self.assertIs(sys.modules[name], source)


if __name__ == '__main__':
    unittest.main()
