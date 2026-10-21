"""UNRUN SOURCE: source CLI/prompt trust, not real secret send or SCP launch."""
import base64
import contextlib
import importlib
import io
from pathlib import Path
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE

HOST = '198.51.100.44'
USER = 'source_test'
PORT = 2222
SECRET = 'PRIVATE-UNIT-SOURCE-CREDENTIAL-DO-NOT-PERSIST'


def known_line(byte):
    # Independent, structurally valid synthetic public key; no real key IO.
    kind = b'ssh-ed25519'
    wire = struct.pack('>I', len(kind))+kind+struct.pack('>I', 32)+bytes((byte,))*32
    return b'[198.51.100.44]:2222 ssh-ed25519 '+base64.b64encode(wire)+b'\n'


class UnitTTY:
    def isatty(self):
        return True

    def readline(self, *args):
        raise AssertionError('explicit source address/user must not read an extra prompt')


class ScpSourceCliPromptBindingTests(unittest.TestCase):
    def required_cli(self, project, known, source_trust):
        argv = ('--project', str(project), '--os-only', '--upgrade', '--yes',
                '--method', 'scp', '--known-hosts', str(known), '--user', 'admin',
                '--mgmt-server', HOST, '--mgmt-user', USER, '--mgmt-port', '2222',
                '--scp-known-hosts', str(source_trust))
        try:
            parsed = FIXTURE.app._parse_cli(argv)
        except FIXTURE.app._InspectionHold:
            self.fail('MISSING_SCP_SOURCE_CLI_CAPABILITY; source factory/prompt/secret-send=NOT_REACHED')
        return parsed

    def test_source_flags_keep_original_meaning_without_password_argv_or_http_fallback(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            project, home, known, logs = FIXTURE.manual.ManualTests().fixture(root)
            source_trust = root/'scp-source-known_hosts'
            source_trust.write_bytes(known_line(17)); source_trust.chmod(0o600)
            parsed = self.required_cli(project, known, source_trust)
            self.assertEqual('scp', parsed.method)
            self.assertEqual(HOST, getattr(parsed, 'mgmt_server', None))
            self.assertEqual(USER, getattr(parsed, 'mgmt_user', None))
            self.assertEqual(2222, getattr(parsed, 'mgmt_port', None))
            self.assertEqual(str(source_trust), getattr(parsed, 'scp_known_hosts', None))
            self.assertEqual('admin', parsed.user)
            for value in ('--mgmt-server','--mgmt-user','--mgmt-port','--scp-known-hosts',
                          HOST,USER,'2222',str(source_trust),'--known-hosts',str(known),'--user','admin'):
                self.assertNotIn(value, parsed.prepare_args)
            for forbidden in ('--mgmt-password','--scp-password'):
                with self.assertRaises(FIXTURE.app._InspectionHold):
                    FIXTURE.app._parse_cli(('--method','scp',forbidden,'not-accepted'))
            default = FIXTURE.app._parse_cli(('--project',str(project),'--inspect-only',
                                             '--known-hosts',str(known)))
            original = FIXTURE.driver.parse_prepare_args(
                FIXTURE.app.__file__,str(project),
                FIXTURE.app._local_input_arguments(default,str(project)))
            self.assertEqual('http', original.method)
            with self.assertRaises(FIXTURE.app._InspectionHold):
                FIXTURE.app._parse_cli(('--method','https'))
            with self.assertRaises(FIXTURE.app._InspectionHold):
                FIXTURE.app._parse_cli(('--method','http','--mgmt-server',HOST))

    def configuration_workflow(self, mutate):
        provider = importlib.import_module('ibsw_upgrade_scp')
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            # Syntax capability gate only; real invoke creates its own real
            # project and submits a natural argv with these fixed source flags.
            source_trust = root/'scp-source-known_hosts'
            source_trust.write_bytes(known_line(17)); source_trust.chmod(0o600)
            self.required_cli(root/'project', root/'home/.ssh/known_hosts', source_trust)
            configure = getattr(FIXTURE.app, '_configure_scp_source', None)
            self.assertTrue(callable(configure),
                            'MISSING_SOURCE_CONFIGURATION_CAPABILITY; factory/prompt=NOT_REACHED')
            self.assertIsNone(sys.getprofile())
            self.assertIsNone(threading.getprofile())
            factory = provider.source_from_known_hosts
            prepare = FIXTURE.driver.prepare_manual_run
            freeze = FIXTURE.driver._PreparedRunScope.freeze_scp_package_sources
            originals, returned, runs, prompted = [], [], [], []
            counts = dict(configure=0, freeze=0)

            def observe(frame, event, argument):
                if frame.f_code is configure.__code__ and frame.f_globals is configure.__globals__:
                    if event == 'call': counts['configure'] += 1
                    elif event == 'return' and argument is not None: returned.append(argument)
                elif (event == 'return' and frame.f_code is factory.__code__
                      and frame.f_globals is factory.__globals__ and argument is not None):
                    originals.append(argument)
                elif (event == 'return' and frame.f_code is prepare.__code__
                      and frame.f_globals is prepare.__globals__ and type(argument) is dict):
                    runs.append(argument['run_directory'])
                elif (event == 'call' and frame.f_code is freeze.__code__
                      and frame.f_globals is freeze.__globals__):
                    counts['freeze'] += 1

            def hidden_input(*args, **kwargs):
                # Explicit UNIT input injection, not an actual terminal secret
                # channel or a mocked factory/verification result.
                prompted.append(tuple(originals))
                if mutate: source_trust.write_bytes(known_line(34))
                return SECRET

            captured = io.StringIO()
            try:
                sys.setprofile(observe); threading.setprofile(observe)
                with patch.object(sys, 'stdin', UnitTTY()), \
                     patch.object(FIXTURE.app.getpass, 'getpass', side_effect=hidden_input) as prompt, \
                     contextlib.redirect_stdout(captured):
                    code, report, err, calls, installs = FIXTURE.ThreeComponentWorkflowTests().invoke(
                        root, selection=('--os-only',), controlled_grace=True)
            finally:
                threading.setprofile(None); sys.setprofile(None)
            self.assertEqual(1, prompt.call_count)
            self.assertEqual(1, counts['configure'])
            self.assertEqual(1, len(prompted))
            self.assertTrue(prompted[0], 'real source factory must pin trust before requesting the secret')
            self.assertEqual([], installs, 'this phase has no execution wire')
            self.assertNotEqual(0, code, 'source configuration must not impersonate native completion')
            persisted = []
            for run in runs:
                run_path = Path(run)
                run_path.relative_to(root)
                persisted.extend(p.read_bytes() for p in run_path.rglob('*') if p.is_file())
            for data in persisted+[err.encode(),captured.getvalue().encode(),repr(report).encode()]:
                self.assertFalse(SECRET.encode() in data, 'UNIT source secret must not enter evidence/output')
            return provider, returned, originals, prompted[0], counts, source_trust.read_bytes()

    def test_real_entry_configures_independent_source_without_persisting_unit_secret(self):
        provider, returned, originals, pinned, counts, final_trust = self.configuration_workflow(False)
        self.assertEqual(1, len(returned), 'healthy source configuration must actually return its real source')
        source = returned[0]
        self.assertIs(type(source), provider.ScpSource)
        self.assertEqual((HOST,USER,PORT), (source.host,source.user,source.port))
        self.assertEqual(known_line(17), source.host_keys)
        self.assertTrue(source.password == SECRET, 'the independent source UNIT credential must be retained only in memory')
        self.assertEqual(pinned[0]._identity, source._identity)
        for original in originals:
            self.assertEqual(pinned[0]._identity, original._identity)
            self.assertEqual(pinned[0].host_keys, original.host_keys)
        self.assertEqual(known_line(17), final_trust)

    def test_real_entry_does_not_adopt_replaced_source_trust_after_hidden_prompt(self):
        provider, returned, originals, pinned, counts, final_trust = self.configuration_workflow(True)
        self.assertEqual([], returned, 'changed trust must not return a newly adopted source')
        self.assertEqual(0, counts['freeze'], 'source trust refusal must precede package acquisition')
        self.assertEqual(known_line(17), pinned[0].host_keys)
        self.assertEqual(known_line(34), final_trust, 'no automatic repair of the changed trust original')
