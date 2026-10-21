"""SOURCE test carrier proposal; no permission, network or SDK mock success.

V2 requires the separate six-hunk opt-in callback/real-IB-IO patch in the
original protected fixture. Root must also qualify/fix the cleanup finalizer
under its independent direct2 tests before claiming successful outer cleanup.
"""
from contextlib import contextmanager, ExitStack
import errno
import hashlib
import inspect
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
from unittest import mock

from test_cases.test_req7_spreadsheet_owner import scoped_fixture

TARGET = 'synthetic_spreadsheet_id_0001'
SYNTHETIC_CREDENTIAL = (
    b'{"type":"service_account","client_email":"fixture@example.invalid",'
    b'"private_key":"SYNTHETIC-NOT-A-KEY",'
    b'"token_uri":"https://oauth2.googleapis.com/token"}\n'
)


def api(test):
    from monitor import issue_tracker_publish_runtime as runtime
    function = getattr(runtime, '_hold_current_cable_cycle_source', None)
    test.assertTrue(callable(function), 'MISSING_PROTECTED_POST_C6_HELD_SOURCE_API')
    error = getattr(runtime, 'CableSourceHold', None)
    test.assertTrue(isinstance(error, type) and issubclass(error, Exception),
                    'MISSING_FIXED_POST_C6_HOLD_TYPE')
    return runtime, function, error


def identity(path):
    info = os.stat(path, follow_symlinks=False)
    return info.st_dev, info.st_ino


def local_evidence(case, committed):
    generation = case.project / '.tracker/generations' / committed.receipt.generation_id
    workbook = case.publication / (committed.receipt.generation_id + '.xlsx')
    paths = (generation / 'MANIFEST', generation / 'RECEIPT', workbook)
    return {path: path.read_bytes() for path in paths}


def rebind(path):
    data = path.read_bytes()
    previous = path.with_name(path.name + '.test-retained-original')
    if previous.exists():
        raise AssertionError('private retained-original collision')
    mode = os.stat(path, follow_symlinks=False).st_mode & 0o777
    old = identity(path)
    path.rename(previous)
    path.write_bytes(data)
    path.chmod(mode)
    return old, identity(path), data, previous


class FixtureCleanupError(AssertionError):
    """Test-only composed fixture cleanup failed; no production meaning."""


def _run_fixture_action_with_cleanup(original, action):
    # doCleanups records ordinary cleanup failures/SkipTest and returns False;
    # composing TestCase instances must propagate that failure to the caller.
    # No private _Outcome layout or replacement cleanup/result is involved.
    primary = None
    traceback = None
    try:
        action()
    except BaseException as error:
        primary, traceback = error, error.__traceback__
    cleanup_error = None
    cleanup_ok = False
    try:
        cleanup_ok = original.doCleanups()
    except BaseException as error:
        cleanup_error = error
    if primary is not None:
        if cleanup_error is not None or cleanup_ok is not True:
            # Fixed, sanitized evidence; never expose original exception data.
            # A reporting error must not mask the already pending body error.
            try:
                sys.stderr.write('POST_C6_FIXTURE_CLEANUP_FAILED_BODY_EXCEPTION_PRESERVED\n')
            except BaseException:
                pass
        raise primary.with_traceback(traceback)
    if cleanup_error is not None:
        if not isinstance(cleanup_error, Exception):
            raise cleanup_error
        raise FixtureCleanupError('post-C6 fixture cleanup failed') from None
    if cleanup_ok is not True:
        raise FixtureCleanupError('post-C6 fixture cleanup failed') from None


def run_protected(test, body):
    """Compose an instance, never inherit/discover old TestCase methods."""
    from test_cases.test_issue_tracker_stage_l_consumer_workflow import ProdStageLConsumerWorkflowTests
    original = ProdStageLConsumerWorkflowTests('runTest')
    function = original._exercise_real_protected_three_panel_fixture
    test.assertIn('post_c6_fixture', inspect.signature(function).parameters,
                  'SOURCE_CARRIER_CALLBACK_NOT_INSTALLED_NOT_A_PRODUCT_FAILURE')
    entered = []
    def after(case, committed, artifacts):
        entered.append(True)
        test.assertEqual(1, len(entered))
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        test.assertIs(type(committed), CommittedProdWorkbook)
        test.assertEqual(hashlib.sha256(committed.prepared.xlsx_bytes).hexdigest(),
                         committed.receipt.published_sha256)
        # Actual body owns fresh scopes; the old C6 writer has already exited.
        body(case, committed, artifacts)
    def action():
        original.setUp()
        function(skip_history=False, post_c6_fixture=after)
    _run_fixture_action_with_cleanup(original, action)
    test.assertEqual([True], entered)


@contextmanager
def fixed_inputs(test, case):
    """Only module-local root/UID facade; real private files/FDs/locks remain.

    Target global and C5/C6 project files keep their actual paths. '/' mapping
    applies only to fixed credential reader's synthetic private root. No
    qualification, owner, target-binding or verification result is replaced.
    """
    from monitor import issue_tracker_credential_shape as private
    from monitor import issue_tracker_online_target as target
    base = case.root / 'var/lib/http-ztp-container/service-account'
    base.mkdir(parents=True, mode=0o700)
    base.chmod(0o700)
    cre = base / 'cre.json'
    allow = base / 'issue-tracker-spreadsheet-whitelist.json'
    cre.write_bytes(SYNTHETIC_CREDENTIAL)
    allow.write_bytes(json.dumps([TARGET]).encode() + b'\n')
    for path in (cre, allow):
        path.chmod(0o600)
    opened = []
    with ExitStack() as stack:
        stack.enter_context(scoped_fixture(case.root, private))
        stack.enter_context(scoped_fixture(case.root, target))
        original_open = private.os.open
        def opening(name, flags, *args, **kwargs):
            fd = original_open(name, flags, *args, **kwargs)
            if name in ('cre.json', 'issue-tracker-spreadsheet-whitelist.json'):
                info = os.fstat(fd)
                opened.append((name, fd, (info.st_dev, info.st_ino)))
            return fd
        stack.enter_context(mock.patch.object(private.os, 'open', side_effect=opening))
        # The new A context may read local originals, but must not send or
        # launch B/C transport. These are deny-only IO guards, never grants.
        network = stack.enter_context(mock.patch.object(socket, 'socket', side_effect=AssertionError('NETWORK_FORBIDDEN')))
        children = stack.enter_context(mock.patch.object(subprocess, 'Popen', side_effect=AssertionError('TRANSPORT_CHILD_FORBIDDEN')))
        yield {'cre': cre, 'allow': allow, 'opened': opened,
               'private': private, 'network': network, 'children': children}


def fds_live(opened):
    result = []
    for name, fd, key in opened:
        info = os.fstat(fd)
        result.append((name, key == (info.st_dev, info.st_ino)))
    return result


def fds_closed(opened):
    result = []
    for name, fd, _key in opened:
        try:
            os.fstat(fd)
        except OSError as error:
            result.append((name, error.errno == errno.EBADF))
        else:
            result.append((name, False))
    return result


@contextmanager
def writer_tokens():
    """Observe original current_k calls, never replace the owner/check result."""
    from monitor import issue_tracker_state_owner as state
    original = state.current_k
    prior = sys.getprofile()
    if prior is not None:
        raise AssertionError('existing profile cannot be replaced by this fixture')
    observed = []
    def profile(frame, event, value):
        if (event == 'call' and frame.f_code is original.__code__
                and frame.f_globals is original.__globals__):
            token = frame.f_locals.get('token')
            if token is not None:
                observed.append(token)
    try:
        sys.setprofile(profile)
        yield observed
    finally:
        sys.setprofile(prior)


def actual_writer(observed, project):
    from monitor import issue_tracker_local_commit as local
    for token in reversed(observed):
        try:
            owner = local._owner(token)
        except local.LocalCommitHold:
            continue
        if owner.project == project:
            return token
    raise AssertionError('no real active post-C6 writer captured; carrier NOT REACHED')


def post_c6_ib_original_io(root, record, identity):
    """Post-only real producer authority/attestation IO, not real UFM/root.

    Construct BEFORE entering the old Mock context, enter AFTER its members.
    This captures original functions before replacement, then keeps their real
    local file IO active through production and the post-C6 callback.
    """
    from types import FunctionType, SimpleNamespace
    from monitor import collection_ib_producer as producer

    if producer.os is not os:
        raise AssertionError('producer OS already scoped before post-only setup')
    originals = (
        producer.load_ib_producer_authority,
        producer.recheck_ib_producer_authority,
        producer._open_protected_attestation_dir,
    )
    if any(type(value) is not FunctionType or value.__globals__ is not vars(producer)
           for value in originals):
        raise AssertionError('original producer authority functions unavailable')
    project_key = identity['project_key']
    cycle_id = identity['cycle_id']
    raw = (json.dumps(record, ensure_ascii=False, sort_keys=True,
                      separators=(',', ':'), allow_nan=False) + '\n').encode('utf-8')
    expected_sha = hashlib.sha256(raw).hexdigest()

    @contextmanager
    def held():
        # All files are private test-owned original inputs created BEFORE
        # produce, never reconstructed/retagged after attestation or C6.
        for relative in ('var', 'var/lib', 'var/lib/http-ztp-container'):
            path = root / relative
            path.mkdir(exist_ok=True)
            path.chmod(0o755)
        authority_dir = root / 'var/lib/http-ztp-container/ib-producer-authority'
        attestations = root / 'var/lib/http-ztp-container/ib-producer-attestations'
        attestation_dir = attestations / project_key
        for path in (authority_dir, attestations, attestation_dir):
            path.mkdir(mode=0o700)
            path.chmod(0o700)
        authority_path = authority_dir / (project_key + '.json')
        with authority_path.open('xb') as stream:
            stream.write(raw)
        authority_path.chmod(0o600)
        native_info = os.stat(authority_path, follow_symlinks=False)
        # Capture the independently written original's actual identity. The
        # one synthetic UID is applied only inside producer's private facade.
        expected_identity = (
            native_info.st_dev, native_info.st_ino, native_info.st_mode,
            native_info.st_nlink, 0, native_info.st_size,
            native_info.st_mtime_ns, native_info.st_ctime_ns,
        )
        facade = SimpleNamespace(**{name: getattr(os, name) for name in dir(os)})
        def metadata(info):
            result = SimpleNamespace(**{name: getattr(info, name) for name in dir(info)
                                        if name.startswith('st_')})
            result.st_uid = 0
            return result
        def mapped(path):
            return root if path == '/' else path
        facade.geteuid = lambda: 0
        facade.open = lambda path, flags, *a, **k: os.open(mapped(path), flags, *a, **k)
        facade.fstat = lambda descriptor: metadata(os.fstat(descriptor))
        facade.stat = lambda path, *a, **k: metadata(os.stat(mapped(path), *a, **k))
        # Shared os and Path operations are untouched. Both producer open('/')
        # and producer stat('/') refer to the same actual private root.
        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(producer, 'os', facade))
            stack.enter_context(mock.patch.object(producer, '_ROOT_UID', 0))
            for name, original in zip(
                ('load_ib_producer_authority', 'recheck_ib_producer_authority',
                 '_open_protected_attestation_dir'), originals):
                stack.enter_context(mock.patch.object(producer, name, original))
            if facade.open is os.open or producer.os is os:
                raise AssertionError('post-only producer facade not installed')
            root_fd = producer.os.open('/', os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                held_root = producer.os.fstat(root_fd)
                named_root = producer.os.stat('/', follow_symlinks=False)
                actual_root = os.stat(root, follow_symlinks=False)
                if ((held_root.st_dev, held_root.st_ino) !=
                    (actual_root.st_dev, actual_root.st_ino) or
                    (named_root.st_dev, named_root.st_ino) !=
                    (actual_root.st_dev, actual_root.st_ino)):
                    raise AssertionError('producer root open/stat mapping differs')
            finally:
                os.close(root_fd)
            snapshot = originals[0](project_key=project_key,
                                    project_root=Path(record['project_root']))
            if snapshot.sha256 != expected_sha or snapshot.file_identity != expected_identity:
                raise AssertionError('producer authority did not read exact original bytes/stat')
            originals[1](snapshot)
            # production generate/verify and the callback execute within this
            # scope. No observer returns a fabricated producer result.
            yield
            originals[1](snapshot)
            attestation_raw = producer._read_protected_attestation(project_key, cycle_id)
            attestation = json.loads(attestation_raw)
            if (attestation.get('authority_sha256') != expected_sha or
                attestation.get('project_key') != project_key or
                attestation.get('cycle_id') != cycle_id or
                authority_path.read_bytes() != raw):
                raise AssertionError('post-only original authority/attestation changed')
    return held()
