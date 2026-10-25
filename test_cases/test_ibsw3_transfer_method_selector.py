"""UNRUN: fixed nonsecret selector/prepare chain + real local Python/PTY.

No app.main, credentials, project contents, source packages or device IO.
"""
import errno
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import pty
import select
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

from test_cases import scp_source_cli_fixture as FIXTURE


class MenuInput:
    def __init__(self, answer, tty=True):
        self.answer, self.tty, self.reads = answer, tty, 0

    def isatty(self):
        return self.tty

    def readline(self, limit):
        self.reads += 1
        return self.answer


CHILD = r'''
import json,sys,time
from test_cases import scp_source_cli_fixture as F
parsed=F.app._parse_cli(('--project',sys.argv[1],'--inspect-only'))
function=getattr(F.app,'_choose_transfer_method',None)
if not callable(function): raise AssertionError('MISSING_TRANSFER_SELECTOR_CAPABILITY')
started=time.monotonic()
method=function(parsed)
print('RESULT_JSON='+json.dumps(dict(method=method,elapsed=time.monotonic()-started)),flush=True)
'''


class TransferMethodSelectorTests(unittest.TestCase):
    def selector(self):
        function = getattr(FIXTURE.app, '_choose_transfer_method', None)
        self.assertTrue(callable(function),
                        'MISSING_TRANSFER_SELECTOR_CAPABILITY; menu/prepare chain NOT_REACHED')
        self.assertEqual(('parsed',), tuple(inspect.signature(function).parameters))
        return function

    def test_real_parse_selector_prepare_chain_preserves_fixed_choice_and_nonwaiting_modes(self):
        function = self.selector()
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            cases = (
                ('enter', (), '\n', True, True, 'http', 1),
                ('http', (), 'http\n', True, True, 'http', 1),
                ('scp', (), 'scp\n', True, True, 'scp', 1),
                ('timeout', (), '', True, False, 'http', 1),
                ('explicit_http', ('--method','http'), '', True, False, 'http', 0),
                ('explicit_scp', ('--method','scp'), '', True, False, 'scp', 0),
                ('non_tty', (), '', False, False, 'http', 0),
            )
            for label, extra, answer, tty, readable, expected, waits in cases:
                with self.subTest(case=label):
                    parsed = FIXTURE.app._parse_cli(('--project',str(root),'--inspect-only')+extra)
                    source = MenuInput(answer, tty)
                    def ready(read, write, exceptional, timeout):
                        self.assertEqual([source], read)
                        self.assertEqual([], write)
                        self.assertEqual([], exceptional)
                        self.assertEqual(15.0, timeout, 'literal user menu budget')
                        return ([source] if readable else [], [], [])
                    with patch.object(sys, 'stdin', source), \
                         patch.object(sys, 'stderr', io.StringIO()), \
                         patch.object(select, 'select', side_effect=ready) as wait:
                        parsed.method = function(parsed)
                    self.assertEqual(expected, parsed.method)
                    self.assertEqual(waits, wait.call_count)
                    self.assertEqual(int(waits and readable), source.reads)
                    argv = FIXTURE.app._local_input_arguments(parsed, str(root))
                    # Mirrors original main: a selected method must actually
                    # reach pure prepare argument parsing, not remain UI DATA.
                    prepared = FIXTURE.driver.parse_prepare_args(FIXTURE.app.__file__, str(root), argv)
                    self.assertEqual(expected, prepared.method)
                    self.assertEqual(1, tuple(argv).count('--method'))
            for answer in ('unknown\n', 'https\n'):
                with self.subTest(refused=answer):
                    parsed = FIXTURE.app._parse_cli(('--project',str(root),'--inspect-only'))
                    source = MenuInput(answer)
                    with patch.object(sys, 'stdin', source), \
                         patch.object(sys, 'stderr', io.StringIO()), \
                         patch.object(select, 'select', return_value=([source],[],[])) as wait:
                        with self.assertRaises(FIXTURE.app._InspectionHold):
                            function(parsed)
                    self.assertEqual(1, wait.call_count)
                    self.assertEqual(1, source.reads)
            with self.assertRaises(FIXTURE.app._InspectionHold):
                FIXTURE.app._parse_cli(('--method','https'))

    def test_real_child_pty_enter_and_actual_fifteen_second_timeout_choose_http(self):
        import yaml
        yaml_root = Path(yaml.__file__).resolve().parents[1]
        self.selector()
        repository = Path(importlib.import_module('test_cases').__file__).resolve().parent.parent
        for enter in (True, False):
            with self.subTest(enter=enter), tempfile.TemporaryDirectory() as raw:
                root = Path(raw).resolve()
                master, slave = pty.openpty()
                process = None
                transcript = bytearray()
                sent = False
                try:
                    # HOME is private, so the user site is not visible; on the formal CLT
                    # interpreter PyYAML (tools/project_contract.py) lives only there, so the
                    # child gets exactly that dependency directory after the repository.
                    environment = dict(PATH='/usr/bin:/bin', HOME=str(root), TMPDIR=str(root),
                                       LC_ALL='C', PYTHONDONTWRITEBYTECODE='1',
                                       PYTHONPATH=os.pathsep.join((str(repository), str(yaml_root))))
                    process = subprocess.Popen([sys.executable,'-B','-c',CHILD,str(root)],
                        cwd=repository, env=environment, stdin=slave, stdout=slave, stderr=slave,
                        close_fds=True)
                    os.close(slave)
                    slave = None
                    deadline = time.monotonic()+30
                    eof = False
                    while not eof:
                        if time.monotonic() >= deadline:
                            self.fail('own selector child exceeded 30s diagnostic budget')
                        ready,_,_ = select.select([master],[],[],.1)
                        if ready:
                            try:
                                chunk = os.read(master,65536)
                            except OSError as error:
                                if error.errno != errno.EIO:
                                    raise
                                chunk = b''
                            if not chunk:
                                eof = True
                            else:
                                transcript.extend(chunk)
                                self.assertLessEqual(len(transcript),65536)
                        if enter and not sent and b'Transfer method [http/scp' in transcript:
                            self.assertEqual(1,os.write(master,b'\n'))
                            sent = True
                    self.assertEqual(0,process.wait(timeout=5), transcript.decode(errors='replace'))
                    lines = transcript.decode().replace('\r\n','\n').splitlines()
                    results = [json.loads(line.split('RESULT_JSON=',1)[1])
                               for line in lines if 'RESULT_JSON=' in line]
                    self.assertEqual(1,len(results))
                    self.assertEqual('http',results[0]['method'])
                    self.assertIn(b'[METHOD] Selected HTTP',transcript)
                    if enter:
                        self.assertTrue(sent)
                        self.assertLess(results[0]['elapsed'],5.0)
                    else:
                        self.assertFalse(sent)
                        self.assertGreaterEqual(results[0]['elapsed'],14.5)
                        self.assertLess(results[0]['elapsed'],25.0)
                    for forbidden in (b'Management-server SSH password', b'Switch password:'):
                        self.assertNotIn(forbidden,transcript)
                finally:
                    if process is not None and process.poll() is None:
                        process.kill()
                        process.wait(timeout=5)
                    os.close(master)
                    if slave is not None:
                        os.close(slave)
