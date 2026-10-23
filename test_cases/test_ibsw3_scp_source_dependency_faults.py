"""UNRUN: natural entry must reject foreign source dependencies before calling.

The four faults delegate to genuine implementation; none fabricates a source,
verification result, bound graph, factory return or native authority.
"""
import contextlib
import importlib
import io
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI


class ScpSourceDependencyFaultTests(unittest.TestCase):
    def test_natural_entry_refuses_foreign_delegating_source_dependencies_before_prompt(self):
        provider = importlib.import_module('ibsw_upgrade_scp')
        for dependency in ('__init__', '_read_trust', 'verify', 'verify_source_shared'):
            with self.subTest(dependency=dependency), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                trust = root/'scp-source-known_hosts'
                literal = CLI.known_line(17)
                trust.write_bytes(literal)
                trust.chmod(0o600)
                CLI.ScpSourceCliPromptBindingTests().required_cli(
                    root/'project', root/'home/.ssh/known_hosts', trust)
                # Healthy original factory/verification PRECEDES every fault.
                healthy = provider.source_from_known_hosts(
                    '198.51.100.44', 'source_test', 2222, trust, '')
                self.assertIs(type(healthy), provider.ScpSource)
                healthy.verify()
                provider.verify_source_shared(healthy)
                original_identity = healthy._identity
                self.assertEqual(literal, healthy.host_keys)
                original_stat = trust.stat()
                facts = lambda st: (st.st_dev, st.st_ino, st.st_mode, st.st_nlink,
                                    st.st_size, st.st_mtime_ns, st.st_ctime_ns)
                target = provider.ScpSource if dependency in ('__init__', 'verify') else provider
                original = getattr(target, dependency)
                foreign_calls = []

                def foreign(*args, **kwargs):
                    foreign_calls.append(dependency)
                    return original(*args, **kwargs)

                # Same label, genuinely foreign code/globals; identity must not
                # be inferred from name or from a truthful eventual return.
                foreign.__name__ = original.__name__
                foreign.__qualname__ = original.__qualname__
                self.assertIsNot(foreign.__code__, original.__code__)
                freeze = FIXTURE.driver._PreparedRunScope.freeze_scp_package_sources
                counts = dict(freeze=0)
                self.assertIsNone(sys.getprofile())
                # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
                self.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())

                def observe(frame, event, argument):
                    if (event == 'call' and frame.f_code is freeze.__code__
                            and frame.f_globals is freeze.__globals__):
                        counts['freeze'] += 1

                output = io.StringIO()
                try:
                    sys.setprofile(observe)
                    threading.setprofile(observe)
                    with patch.object(target, dependency, foreign), \
                         patch.object(sys, 'stdin', CLI.UnitTTY()), \
                         patch.object(FIXTURE.app.getpass, 'getpass',
                                      return_value=CLI.SECRET) as prompt, \
                         contextlib.redirect_stdout(output):
                        code, report, error, calls, installs = FIXTURE.ThreeComponentWorkflowTests().invoke(
                            root, selection=('--os-only',), controlled_grace=True)
                finally:
                    threading.setprofile(None)
                    sys.setprofile(None)
                self.assertEqual([], foreign_calls,
                    'foreign source dependency must be refused before delegate invocation')
                self.assertEqual(0, prompt.call_count, 'source hidden input must not be requested')
                self.assertEqual(0, counts['freeze'], 'no package acquisition after foreign provider fault')
                self.assertEqual([], installs)
                self.assertNotEqual(0, code, 'foreign provider must not claim CLI success')
                self.assertEqual(literal, trust.read_bytes(), 'no repair/adoption of source original')
                self.assertEqual(facts(original_stat), facts(trust.stat()))
                self.assertEqual(original_identity, healthy._identity)
                self.assertEqual(literal, healthy.host_keys)
                self.assertIs(original, getattr(target, dependency), 'fault restored before next subcase')
                self.assertNotIn(CLI.SECRET, output.getvalue()+error+repr(report))
