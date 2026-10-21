"""UNRUN: reviewed init semantics, not rejection of every same-code clone."""
import contextlib
import importlib
import io
from pathlib import Path
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI


def cell(value):
    return (lambda: value).__closure__[0]


class ScpConstructorSemanticsTests(unittest.TestCase):
    def test_genuine_init_semantics_reject_wrong_cells_defaults_annotations_and_class_metadata(self):
        provider = importlib.import_module('ibsw_upgrade_scp')
        for case in ('exact_clone', 'wrong_closure', 'wrong_annotations', 'defaults',
                     'kwdefaults', 'class_annotations', 'class_frozen_flag'):
            with self.subTest(case=case), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                trust = root/'scp-source-known_hosts'
                literal = CLI.known_line(17)
                trust.write_bytes(literal)
                trust.chmod(0o600)
                CLI.ScpSourceCliPromptBindingTests().required_cli(root/'project', root/'known', trust)
                healthy = provider.source_from_known_hosts('198.51.100.44','source_test',2222,trust,'')
                healthy.verify()
                provider.verify_source_shared(healthy)
                source_class = provider.ScpSource
                original = source_class.__init__
                self.assertTrue(original.__closure__, 'reviewed frozen dataclass init has a builtin cell')
                closure = original.__closure__
                if case == 'wrong_closure':
                    closure = (cell(None),)+closure[1:]
                replacement = types.FunctionType(original.__code__, original.__globals__,
                    original.__name__, original.__defaults__, closure)
                replacement.__module__ = original.__module__
                replacement.__qualname__ = original.__qualname__
                replacement.__annotations__ = dict(original.__annotations__)
                replacement.__kwdefaults__ = original.__kwdefaults__
                self.assertIs(original.__code__, replacement.__code__)
                self.assertIs(original.__globals__, replacement.__globals__)
                if case == 'wrong_annotations':
                    replacement.__annotations__['host'] = 'object'
                elif case == 'defaults':
                    replacement.__defaults__ = (None,)
                elif case == 'kwdefaults':
                    replacement.__kwdefaults__ = {'host': None}
                calls = []
                self.assertIsNone(sys.getprofile())
                self.assertIsNone(threading.getprofile())
                def observe(frame, event, argument):
                    if (event == 'call' and frame.f_code is original.__code__
                            and frame.f_globals is original.__globals__
                            and type(frame.f_locals.get('self')) is source_class):
                        calls.append(case)
                output = io.StringIO()
                try:
                    sys.setprofile(observe)
                    threading.setprofile(observe)
                    with contextlib.ExitStack() as stack:
                        stack.enter_context(patch.object(source_class,'__init__',replacement))
                        if case == 'class_annotations':
                            metadata = dict(source_class.__annotations__)
                            metadata['host'] = 'object'
                            stack.enter_context(patch.object(source_class,'__annotations__',metadata))
                        elif case == 'class_frozen_flag':
                            stack.enter_context(patch.object(source_class.__dataclass_params__,'frozen',False))
                        stack.enter_context(patch.object(sys,'stdin',CLI.UnitTTY()))
                        prompt = stack.enter_context(patch.object(FIXTURE.app.getpass,'getpass',return_value=CLI.SECRET))
                        stack.enter_context(contextlib.redirect_stdout(output))
                        code, report, error, queries, installs = FIXTURE.ThreeComponentWorkflowTests().invoke(
                            root, selection=('--os-only',), controlled_grace=True)
                finally:
                    threading.setprofile(None)
                    sys.setprofile(None)
                if case == 'exact_clone':
                    self.assertTrue(calls, 'a semantically exact same-code clone is not categorically foreign')
                    self.assertEqual(1,prompt.call_count)
                else:
                    self.assertEqual([],calls,'wrong generated-init semantics must fail before constructor call')
                    self.assertEqual(0,prompt.call_count)
                self.assertEqual([],installs)
                self.assertNotEqual(0,code,'configuration must not impersonate native completion')
                self.assertEqual(literal,trust.read_bytes())
                self.assertEqual(literal,healthy.host_keys)
                self.assertIs(original,source_class.__init__)
                self.assertNotIn(CLI.SECRET,output.getvalue()+error+repr(report))
