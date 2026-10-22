"""Literal seventeen-code originals before imports; known-FD first results."""
import errno
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import threading
import unittest

LEAVES = (
    'google/oauth2/service_account.py', 'google/oauth2/credentials.py',
    'google/auth/credentials.py', 'google/auth/_credentials_base.py',
    'google/auth/crypt/rsa.py', 'google_auth_httplib2.py',
    'googleapiclient/discovery.py', 'googleapiclient/http.py',
    'googleapiclient/_helpers.py', 'google/auth/crypt/_cryptography_rsa.py',
    'google/auth/crypt/base.py', 'google/auth/_helpers.py',
    'google/auth/_service_account_info.py', 'google/auth/transport/__init__.py',
    'httplib2/__init__.py', 'google/auth/_refresh_worker.py',
    'google/auth/_regional_access_boundary_utils.py',
)


class ObservedOS:
    def __init__(self, original, first=None, late=None):
        self.original = original
        self.first = first
        self.late = late
        self.opens = []
        self.paths = {}
        self.closes = []
        self.faults = []
        self.identity_errors = []

    def __getattr__(self, name):
        return getattr(self.original, name)

    def open(self, path, flags, mode=0o777, *, dir_fd=None):
        fd = self.original.open(path, flags, mode, dir_fd=dir_fd)
        facts = self.original.fstat(fd)
        text = os.fsdecode(path)
        full = text if os.path.isabs(text) else os.path.join(self.paths[dir_fd], text)
        self.paths[fd] = full
        self.opens.append((fd, facts.st_dev, facts.st_ino, full, facts.st_mode))
        return fd

    def close(self, fd):
        matches = [row for row in self.opens if row[0] == fd]
        if len(matches) != 1:
            raise RuntimeError('UNOWNED_OR_REUSED_OBSERVED_CODE_FD')
        row = matches[0]
        facts = self.original.fstat(fd)
        if (facts.st_dev, facts.st_ino) != row[1:3]:
            self.identity_errors.append(fd)
            raise RuntimeError('OBSERVED_CODE_FD_REBOUND')
        self.closes.append(fd)
        self.original.close(fd)
        try:
            self.original.fstat(fd)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise
        else:
            raise RuntimeError('ACTUAL_CLOSE_NOT_EBADF')
        if row[3].endswith('/google/auth/_regional_access_boundary_utils.py') and self.first is not None:
            self.faults.append('REGIONAL_REAL_CLOSE_THEN_FIRST_NI')
            raise self.first
        if row[3].endswith('/google/auth/_refresh_worker.py') and self.late is not None:
            self.faults.append('REFRESH_REAL_CLOSE_THEN_LATER_EIO')
            raise self.late


class ConstructorCodeResourceTests(unittest.TestCase):
    def entry(self):
        from monitor import issue_tracker_publish_runtime as runtime
        function = getattr(runtime, '_hold_current_cable_sdk_credential_prerequisite', None)
        self.assertTrue(callable(function), 'MISSING_ACTUAL_CREDENTIAL_PREREQUISITE')
        return runtime, function

    def capture(self, runtime, function, first=None, late=None):
        original = runtime.os
        view = ObservedOS(original, first, late)
        previous = sys.getprofile()
        owner_thread = threading.get_ident()
        active = [False]
        effects = []
        module_entries = []
        constructors = []
        incoming = None
        incoming_cause = None
        entered = False

        def audit(event, args):
            if not active[0] or threading.get_ident() != owner_thread:
                return
            forbidden = (event.startswith('socket.') or event in
                ('subprocess.Popen', 'os.system', 'os.fork', 'os.exec', 'os.posix_spawn'))
            credential = (event == 'open' and args and isinstance(args[0], (str, bytes))
                and os.path.basename(os.fsdecode(args[0])) == 'cre.json')
            if forbidden or credential:
                effects.append(event)
                raise RuntimeError('FOREIGN_CALLER_CODE_PHASE_FORBIDDEN_IO')

        def observe(frame, event, value):
            if previous is not None:
                previous(frame, event, value)
            if event != 'call':
                return
            name = frame.f_globals.get('__name__', '')
            if frame.f_code.co_name == '<module>' and (name == 'google' or
                    name.startswith('google.') or name == 'google_auth_httplib2' or
                    name == 'googleapiclient' or name.startswith('googleapiclient.') or
                    name == 'httplib2' or name.startswith('httplib2.')):
                known = []
                for fd, dev, ino, path, mode in view.opens:
                    if stat.S_ISREG(mode):
                        try:
                            facts = original.fstat(fd)
                        except OSError:
                            held = False
                        else:
                            held = (facts.st_dev, facts.st_ino) == (dev, ino)
                        known.append((path, held))
                module_entries.append((name, known))
            if frame.f_code.co_name == '__init__' and name in (
                    'google.oauth2.service_account', 'google.oauth2.credentials',
                    'google.auth.crypt.rsa', 'google.auth.crypt._cryptography_rsa'):
                constructors.append(name)

        sys.addaudithook(audit)
        runtime.os = view
        sys.setprofile(observe)
        active[0] = True
        try:
            try:
                with function(object(), http_root=Path('/private/tmp')):
                    entered = True
            except BaseException as error:
                incoming = error
                incoming_cause = error.__cause__
        finally:
            active[0] = False
            sys.setprofile(previous)
            runtime.os = original
        # First-result known original facts before assertion/reuse/recovery.
        states = []
        recovery = []
        for fd, dev, ino, path, mode in view.opens:
            try:
                facts = original.fstat(fd)
            except OSError as error:
                states.append((fd, error.errno == errno.EBADF))
            else:
                states.append((fd, False))
                if (facts.st_dev, facts.st_ino) == (dev, ino):
                    recovery.append((fd, dev, ino))
        recovered = []
        for fd, dev, ino in reversed(recovery):
            facts = original.fstat(fd)
            if (facts.st_dev, facts.st_ino) == (dev, ino):
                original.close(fd)
                recovered.append(fd)
        return dict(opens=view.opens, closes=view.closes, states=states,
            faults=view.faults, identity_errors=view.identity_errors,
            incoming=incoming, incoming_cause=incoming_cause, entered=entered,
            module_entries=module_entries, constructors=constructors, effects=effects,
            recovery=recovered, restored=(runtime.os is original and sys.getprofile() is previous))

    def check_resources(self, result):
        self.assertFalse(result['entered'], 'FOREIGN_CALLER_ADMITTED')
        self.assertEqual([], result['effects'])
        self.assertEqual([], result['constructors'])
        self.assertEqual([], result['identity_errors'])
        files = [path for _fd, _dev, _ino, path, mode in result['opens'] if stat.S_ISREG(mode)]
        for leaf in LEAVES:
            self.assertEqual(1, sum(path.endswith('/' + leaf) for path in files),
                'FIXED_CODE_ORIGINAL_NOT_ONCE_' + leaf)
        self.assertEqual(17, len(files), 'CONSTRUCTOR_CODE_NOT_SEVENTEEN_ORIGINALS')
        known = [row[0] for row in result['opens']]
        self.assertEqual(len(known), len(set(known)))
        self.assertGreater(len(known), 17)
        self.assertEqual(list(reversed(known)), result['closes'])
        self.assertTrue(all(closed for _fd, closed in result['states']))
        self.assertEqual([], result['recovery'], 'FIXTURE_RECOVERY_IS_NOT_PRODUCT_CLEANUP')
        self.assertTrue(result['restored'])


    def run_owned_cold_import_case(self):
        # Test-only isolation, not a provider/native success flag. Always cold,
        # regardless of canonical module order or earlier SDK tests.
        from monitor import issue_tracker_publish_runtime as runtime
        root = Path(runtime.__file__).parent.parent
        bootstrap = """from pathlib import Path
import importlib.machinery,importlib.util,json,sys,unittest
root=Path(sys.argv[1]);sys.path.insert(0,str(root));sys.path.insert(0,str(root/'tools'))
loader=importlib.machinery.SourceFileLoader('owned_cold_constructor_resource',sys.argv[2])
spec=importlib.util.spec_from_loader(loader.name,loader);module=importlib.util.module_from_spec(spec);sys.modules[loader.name]=module;loader.exec_module(module)
case=module.ConstructorCodeResourceTests('test_a_cold_first_sdk_module_requires_all_seventeen_originals_already_held')
case._owned_cold_child=True
result=unittest.TestResult();case.run(result)
for kind,rows in (('FAIL',result.failures),('ERROR',result.errors)):
 for _case,trace in rows:print('OWNED_COLD_RESOURCE_'+kind+'\\n'+trace,flush=True)
state=dict(tests=result.testsRun,failures=len(result.failures),errors=len(result.errors),skipped=len(result.skipped),expected_failures=len(result.expectedFailures),unexpected_successes=len(result.unexpectedSuccesses))
print('OWNED_COLD_RESOURCE_INNER_RESULT='+json.dumps(state,sort_keys=True),flush=True)
raise SystemExit(not result.wasSuccessful())
"""
        command = [sys.executable, '-B', '-c', bootstrap, str(root), str(Path(__file__))]
        child = subprocess.run(command, cwd=root, stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE='1'), timeout=120,
            check=False)
        output = child.stdout.decode('utf-8', errors='strict')
        print(output, end='' if output.endswith('\n') else '\n', flush=True)
        marker = 'OWNED_COLD_RESOURCE_INNER_RESULT='
        results = [json.loads(line[len(marker):]) for line in output.splitlines()
                   if line.startswith(marker)]
        # A successful exit alone, absent a complete actual TestResult, fails.
        self.assertEqual([dict(tests=1,failures=0,errors=0,skipped=0,
            expected_failures=0,unexpected_successes=0)], results)
        self.assertEqual(0, child.returncode, 'OWNED_COLD_RESOURCE_CHILD_FAILED')

    def test_a_cold_first_sdk_module_requires_all_seventeen_originals_already_held(self):
        if not getattr(self, '_owned_cold_child', False):
            self.run_owned_cold_import_case()
            return
        runtime, function = self.entry()
        already = [name for name in sys.modules if (name.startswith('google.') or
            name.startswith('googleapiclient') or name == 'google_auth_httplib2' or
            name == 'httplib2' or name.startswith('httplib2.'))]
        self.assertEqual([], already, 'COLD_MODULE_BOUNDARY_NOT_AVAILABLE')
        result = self.capture(runtime, function)
        self.assertTrue(result['module_entries'], 'NO_ACTUAL_FIRST_SDK_MODULE_OBSERVED')
        first_name, originals = result['module_entries'][0]
        print('CONSTRUCTOR_FIRST_SDK_IMPORT=' + json.dumps(dict(module=first_name,
            held_regulars=len(originals), all_held=all(held for _path, held in originals))), flush=True)
        # Cold-order assertions independently literal, not product-table-derived.
        for leaf in LEAVES:
            self.assertEqual(1, sum(path.endswith('/' + leaf) and held for path, held in originals),
                'SDK_IMPORTED_BEFORE_HELD_ORIGINAL_' + leaf)
        self.assertEqual(17, len(originals))
        self.assertIs(type(result['incoming']), runtime.CableSourceHold)
        self.check_resources(result)

    def test_b_extra_two_real_closes_preserve_first_NI_and_attempt_remaining_slots(self):
        runtime, function = self.entry()
        first = KeyboardInterrupt('OWNED_REGIONAL_CODE_CLOSE_NI')
        cause = ValueError('OWNED_LITERAL_NON_SECRET_CAUSE')
        first.__cause__ = cause
        late = OSError(errno.EIO, 'OWNED_REFRESH_CODE_CLOSE_EIO')
        result = self.capture(runtime, function, first, late)
        print('EXTRA_TWO_CODE_CLOSE_FACTS=' + json.dumps(dict(faults=result['faults'],
            first_NI=(result['incoming'] is first), known_closed=all(v for _fd, v in result['states']))), flush=True)
        self.assertEqual(['REGIONAL_REAL_CLOSE_THEN_FIRST_NI',
            'REFRESH_REAL_CLOSE_THEN_LATER_EIO'], result['faults'])
        self.assertIs(first, result['incoming'])
        self.assertIs(cause, result['incoming_cause'])
        self.assertIs(cause, first.__cause__)
        self.check_resources(result)


if __name__ == '__main__':
    unittest.main(verbosity=2)
