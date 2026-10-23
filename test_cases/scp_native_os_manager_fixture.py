"""NOTRUN natural OS workflow carrier: passive originals + finite IO faults.

No parsed DTO, owner/verifier/dispatch/manager result or ACK is replaced. The
old invoke supplies explicit target query/SDK/home doubles and manual request
transactions (NOT real host/project flock proof). All retained trees are owned
by the root driver; uncertainty is preserved, not silently cleaned/adopted.
"""
import dis
import errno
import base64
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from types import SimpleNamespace
from unittest.mock import patch

from test_cases import scp_native_cpld_bridge_fixture as BASE
from test_cases import test_ibsw3_scp_source_cli_prompt_binding as CLI
from test_cases.native_os_physical_bridge import NativeOsPhysicalBridge
from test_cases.native_os_stub_sources import SECRET

SharedUpgradeHold = BASE.driver.SharedUpgradeHold
RETAINED_TREES = []
ORIGINALS = ('request.json', 'step.sh', 'step-binding.json', 'runner.sh',
             'runner-binding.json', 'scp-source-request.json')
PACKAGE = 'nvos-amd64-25.03.1010.bin'


class TestOwnerCancellation(SharedUpgradeHold):
    """TEST ONLY owner stop, NOT a product Shared/source-integrity finding."""


class _MarkerWaitCancellation:
    """Only revoke this fixture's waiting operation after real manager False.

    This test helper cannot acknowledge content, change a manager result,
    poison a source, clear an in-flight slot or authorize another dispatch.
    """
    def __init__(self):
        self.requests = 0
        self.delivered = False
        self.error = None
        self.original_stop = None

    def after_manager_return(self, *, fault, original_stop, value, normal_return, ack_absent):
        if (self.requests or fault != 'missing_content' or normal_return is not True
                or value is not False or ack_absent is not True):
            return None
        if type(original_stop) is not threading.Event:
            raise AssertionError('original fixture Event required for cancellation')
        self.original_stop = original_stop
        self.error = TestOwnerCancellation('TEST_OWNER_CANCELLED_AFTER_ORIGINAL_MANAGER_FALSE')
        self.requests = 1
        original_stop.set()
        return None  # The passive profile callback never throws this cancellation.

    def before_idle(self):
        # An active body/NI is not replaced by the test owner's pending request.
        if sys.exc_info()[1] is not None:
            return None
        if self.requests:
            self.delivered = True
            raise self.error
        return None


def _normal(frame):
    return frame.f_lasti >= 0 and dis.opname[frame.f_code.co_code[frame.f_lasti]] in (
        'RETURN_VALUE', 'RETURN_CONST')


def _key(info):
    return info.st_dev, info.st_ino


def _host(path):
    name = Path(path).parent.name
    for value in ('ew-spine01.example', 'ew-spine02.example'):
        if value in name:
            return value
    raise AssertionError('actual generated namespace must identify one literal target')


def exercise(case, *, two, fault):
    if type(two) is not bool or fault not in (None, 'missing_content', 'wrong_content',
            'record_file_sync', 'record_directory_sync', 'record_writer_close'):
        raise AssertionError('fixed natural OS scenario only')
    root = Path(tempfile.mkdtemp(prefix='native-os-bridge-owned-', dir='/private/tmp')).resolve()
    root.chmod(0o700)
    print('IBSW_NATIVE_OS_FLOW_OWNED_ROOT=' + str(root), flush=True)
    RETAINED_TREES.append(str(root))
    trust = root / 'scp-source-known_hosts'
    trust.write_bytes(CLI.known_line(17)); trust.chmod(0o600)
    image = Path(__file__).resolve().parents[1]
    bridge = NativeOsPhysicalBridge(root, image)
    cancellation = _MarkerWaitCancellation()
    bridge.before_idle = cancellation.before_idle
    original_stops = {}
    r = SimpleNamespace(root=root, switch=bridge.switch, carrier_error=None,
        invoke_error=None, result=None, factories=[], freezes=[], preflights=[], contexts=[],
        dispatches=[], dispatches_after_fault=[], bound=[], manager_results=[], records=[],
        acks=[], nv_calls=[], invocation_installs=[], selected_nonempty_reads=[], unselected_reads=[],
        after_freeze_reads=[], owner_receipts=[], cancelled=False, secret_leaks=[],
        fault_fired=False, fault_same_inode=False, success_line_preserved=False,
        fault_attempts=0, real_close_ebadf=False, record_shared_errors=[], shared_stop=False)
    events = {}
    diagnostic_calls, diagnostic_returns, diagnostic_errors = {}, {}, []
    r.events_for = lambda host: events[host]
    r.nv_order_for = lambda host: min(row['time_ns'] for row in r.nv_calls if row['host'] == host)
    provider = importlib.import_module('ibsw_upgrade_scp')
    scope = BASE.driver._PreparedRunScope
    watched = {
        'factory': provider.source_from_known_hosts,
        'freeze': scope.freeze_scp_package_sources,
        'context': scope._native_scp_launch_context,
        'preflight': scope._preflight_native_scp_source,
        'execute': BASE.executor._execute_component_once,
        'bound': BASE.executor._bound_component_postcondition_inputs,
        'manager': BASE.executor._probe_component_exit_once,
        'record': scope._record_download_attempt,
        'finish': BASE.driver._JournalWriter.finish,
        'commit': scope._commit_exclusive_binding,
        'invoke': BASE.ThreeComponentWorkflowTests.invoke,
        'main': BASE.app.main,
        'parallel': BASE.app._parallel_component_upgrade,
        'begin': BASE.pipeline.NativeAdapter.begin,
        'native_source': scope._native_scp_source,
        'needed': scope._native_scp_needed_indices,
    }
    identities = {(function.__code__, id(function.__globals__)): name
                  for name, function in watched.items()}
    original_read, original_sync, original_close = os.read, os.fsync, os.close
    frozen = False

    def record_frame():
        frame = sys._getframe(1)
        while frame is not None:
            if (frame.f_code is watched['commit'].__code__
                    and frame.f_globals is watched['commit'].__globals__
                    and frame.f_locals.get('final_name') == 'download-attempt-01.json'):
                return frame
            frame = frame.f_back
        return None

    def commit_host(frame):
        return frame.f_locals['directory'].path.parent.name

    def observe(frame, event, value):
        nonlocal frozen
        name = identities.get((frame.f_code, id(frame.f_globals)))
        if name is None:
            return
        local = frame.f_locals
        if event == 'call':
            diagnostic_calls[name] = diagnostic_calls.get(name, 0) + 1
        if name == 'invoke' and event == 'return':
            r.invocation_installs = list(local.get('installs', ()))
        if event != 'return' or not _normal(frame):
            return
        diagnostic_returns[name] = diagnostic_returns.get(name, 0) + 1
        if name == 'factory' and value is not None:
            r.factories.append(value)
        elif name == 'freeze':
            r.freezes.append((local['self'], value)); frozen = True
        elif name == 'preflight':
            r.preflights.append(local['self'])
        elif name == 'execute' and value is not None:
            row = (local['leaf'], value)
            r.dispatches.append(row)
            if r.fault_fired:
                r.dispatches_after_fault.append(row)
        elif name == 'bound':
            r.bound.append((local['leaf'], local['dispatch'], value))
        elif name == 'begin':
            child, stop = local.get('scope'), local.get('stop')
            if (child is not None and getattr(child, '_pipeline_stop_event', None) is stop
                    and type(stop) is threading.Event):
                original_stops[id(child)] = (child, stop)
        elif name == 'manager':
            if type(value) is dict:
                r.manager_results.append(value)
            if fault == 'missing_content' and r.fault_fired and value is False:
                leaf, dispatch = local['leaf'], local['dispatch']
                child = local.get('scope')
                original = original_stops.get(id(child))
                bounds = [values for actual_leaf, actual_dispatch, values in r.bound
                          if actual_leaf is leaf and actual_dispatch is dispatch]
                if (original is not None and original[0] is child and leaf.scope is child
                        and child._pipeline_stop_event is original[1]
                        and child._active_request_lease is None and bounds
                        and bounds[-1][0] is child and not r.acks
                        and getattr(leaf, '_download_acknowledged', False) is False):
                    ack = Path(bounds[-1][4]).parent / 'download-ack'
                    if bridge.switch in ack.parents and not os.path.lexists(ack):
                        # Already behind original _normal(frame): this exact
                        # manager completed, including its actual finally/close.
                        # No exception path/manager result is replaced or masked.
                        cancellation.after_manager_return(fault=fault,
                            original_stop=original[1], value=value,
                            normal_return=True, ack_absent=True)
        elif name == 'context' and type(value) is bytes:
            child, leaf = local['self'], local['leaf']
            stage = child.run_directory / leaf.node.hostname / BASE.driver.declared_step_key(
                child.policy, local['component'], local['package_index'])
            held = {key: child.files[(str(stage), key)] for key in ORIGINALS}
            r.contexts.append((child, leaf, child._native_parent, stage, held, value))
        elif name == 'finish':
            caller = frame.f_back
            if (caller is not None and caller.f_code is watched['commit'].__code__
                    and caller.f_globals is watched['commit'].__globals__
                    and caller.f_locals.get('final_name') == 'download-attempt-01.json'):
                events.setdefault(commit_host(caller), {})['writer_finish'] = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        elif name == 'record':
            leaf = local['leaf']; child = local['self']
            stage = child.run_directory / leaf.node.hostname / local['dispatch'].stage
            path = stage / 'download-attempt-01.json'
            # Observation only: a normal manager call that persisted no original
            # file cannot manufacture a record fact.
            if path.is_file():
                events.setdefault(leaf.node.hostname, {}).setdefault('record_return', time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW))
                if not any(item['path'] == path for item in r.records):
                    r.records.append(dict(host=leaf.node.hostname, path=path))

    def trace(frame, event, value):
        name = identities.get((frame.f_code, id(frame.f_globals)))
        if name in ('main', 'parallel', 'freeze', 'begin', 'native_source', 'execute', 'preflight'):
            if event == 'exception' and len(diagnostic_errors) < 24:
                error = value[1]
                # No exception args/str/repr: frame/type facts cannot echo a
                # secret-returning remote channel or a credential-bearing DTO.
                diagnostic_errors.append(dict(role=name, function=frame.f_code.co_name,
                    file=frame.f_code.co_filename, line=frame.f_lineno,
                    type=type(error).__name__, cause_type=(type(error.__cause__).__name__
                    if error.__cause__ is not None else None)))
            return trace
        if (frame.f_code is watched['record'].__code__
                and frame.f_globals is watched['record'].__globals__):
            if event == 'exception' and isinstance(value[1], SharedUpgradeHold):
                r.record_shared_errors.append(value[1])
            return trace
        return None

    def read(fd, size):
        info = os.fstat(fd)
        selected = None
        # Exact six files created by the preserved invoke fixture. No rglob,
        # broad package-directory inventory or real source inputs are adopted.
        for relative in (
                'image/nvos-amd64-25.02.8008.bin',
                'image/nvos-amd64-25.02.9000.bin', 'image/' + PACKAGE,
                'firmware/0ACQF.cab',
                'firmware/FUI1_BURN_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme',
                'firmware/FUI1_REFRESH_CPLD000232_REV0900_CPLD000383_REV0800_CPLD000389_REV0600.vme'):
            path = root / 'packages' / relative
            try:
                if _key(path.lstat()) == _key(info):
                    selected = relative; break
            except FileNotFoundError:
                pass
        raw = original_read(fd, size)
        if selected is not None:
            if selected != 'image/' + PACKAGE:
                r.unselected_reads.append((selected, len(raw)))
            if raw and selected == 'image/' + PACKAGE:
                r.selected_nonempty_reads.append(len(raw))
            if frozen:
                r.after_freeze_reads.append((selected, len(raw)))
        return raw

    def sync(fd):
        frame = record_frame()
        if frame is None:
            return original_sync(fd)
        local = frame.f_locals
        directory = local['directory']
        is_directory = fd == directory.fd
        kind = 'directory_sync' if is_directory else 'file_sync'
        # A non-directory fsync must be the current actual write frame's fd;
        # unrelated process FDs or other record writes are never injected.
        caller = sys._getframe(1)
        if not is_directory and not (caller.f_code is BASE.driver._OutputScope.write.__code__
                and caller.f_globals is BASE.driver._OutputScope.write.__globals__
                and caller.f_locals.get('fd') == fd):
            return original_sync(fd)
        value = original_sync(fd)
        events.setdefault(commit_host(frame), {})[kind] = time.clock_gettime_ns(time.CLOCK_MONOTONIC_RAW)
        if fault == 'record_' + kind:
            r.fault_attempts += 1
            if not r.fault_fired:
                r.fault_fired = True
                raise OSError(errno.EIO, 'private exact download record durability failure')
        return value

    def close(fd):
        frame = record_frame()
        writer = frame.f_locals.get('writer') if frame is not None else None
        if (fault == 'record_writer_close' and writer is not None and writer.files
                and writer.files[0][1] == fd):
            expected = writer.files[0][2]
            if _key(os.fstat(fd)) != _key(expected):
                raise AssertionError('no adoption of a foreign numeric slot')
            r.fault_attempts += 1
            if not r.fault_fired:
                original_close(fd)
                try:
                    os.fstat(fd)
                except OSError as error:
                    if error.errno != errno.EBADF: raise
                    r.real_close_ebadf = True
                else:
                    raise AssertionError('original close must really make this slot EBADF')
                r.fault_fired = True
                raise OSError(errno.EIO, 'private actual critical close then unknown result')
        return original_close(fd)

    def before_lstat(path):
        if (fault not in ('missing_content', 'wrong_content') or r.fault_fired
                or path.name != 'execution.stdout' or not path.is_file()):
            return
        before = path.lstat()
        payload = path.read_bytes()
        lines = payload.splitlines(keepends=True)
        content = [index for index, line in enumerate(lines)
                   if line.startswith(b'IBSW_SCP_CONTENT_VERIFIED=1|') and line.endswith(b'\n')]
        numeric = [line for line in lines if line.startswith(b'IBSW_SCP_DOWNLOAD_RESULT=1|')
                   and line.endswith(b'\n')]
        if len(content) != 1 or len(numeric) != 1 or b'IBSW_STAGE=WAIT_DOWNLOAD_RECORD\n' not in lines:
            return
        index = content[0]
        if fault == 'missing_content':
            lines[index] = b' ' * (len(lines[index]) - 1) + b'\n'
        else:
            parts = lines[index].rstrip(b'\n').split(b'|')
            parts[-1] = (b'0' if parts[-1][:1] != b'0' else b'1') + parts[-1][1:]
            lines[index] = b'|'.join(parts) + b'\n'
        changed = b''.join(lines)
        if len(changed) != len(payload):
            raise AssertionError('same-shape marker fault required')
        with path.open('r+b') as stream:
            stream.write(changed); stream.flush()
        r.fault_same_inode = _key(before) == _key(path.lstat())
        r.success_line_preserved = all(line in changed for line in numeric)
        r.fault_fired = True

    def after_ack(old, path, started, finished):
        raw = path.read_bytes()
        stdout = (path.parent / 'execution.stdout').read_bytes()
        lines = stdout.splitlines()
        marker = [line for line in lines if line.startswith(b'IBSW_SCP_CONTENT_VERIFIED=1|')]
        numeric = [line for line in lines if line.startswith(b'IBSW_SCP_DOWNLOAD_RESULT=1|')]
        if len(marker) != 1 or len(numeric) != 1:
            raise AssertionError('actual ACK cannot hide malformed complete stdout')
        r.acks.append(dict(host=_host(path), bytes=raw, content=marker[0], line=numeric[0],
                           order=started, rename_returned=finished))

    bridge.before_lstat, bridge.after_ack = before_lstat, after_ack
    case.assertIsNone(sys.getprofile()); case.assertIsNone(sys.gettrace())
    # threading.getprofile()/gettrace() are 3.10+; on 3.9 they are read from the hooks threading.setprofile()/settrace() store.
    case.assertIsNone(getattr(threading, 'getprofile', lambda: threading._profile_hook)())
    case.assertIsNone(getattr(threading, 'gettrace', lambda: threading._trace_hook)())
    try:
        sys.setprofile(observe); threading.setprofile(observe)
        sys.settrace(trace); threading.settrace(trace)
        with patch.object(os, 'read', read), patch.object(os, 'fsync', sync), \
                patch.object(os, 'close', close), patch.object(sys, 'stdin', CLI.UnitTTY()), \
                patch.object(BASE.app.getpass, 'getpass', return_value=SECRET):
            try:
                r.result = BASE.ThreeComponentWorkflowTests().invoke(root,
                    selection=('--os-only',), old_os=True, two=two, skip_canary=True,
                    controlled_grace=True, bridge=bridge)
            except BaseException as error:
                r.invoke_error = error
    finally:
        threading.settrace(None); sys.settrace(None)
        threading.setprofile(None); sys.setprofile(None)
        try:
            r.owner_receipts, r.cancelled = bridge.finish()
        except BaseException as error:
            r.carrier_error = error  # Never turn UNKNOWN cleanup into business success.
    r.shared_stop = any(getattr(child, '_pipeline_stop_event', None) is not None
        and child._pipeline_stop_event.is_set() for child, *_ in r.contexts)
    for path in bridge.switch.rglob('nv.os.trace'):
        for line in path.read_text().splitlines():
            value = json.loads(line); value['host'] = _host(path); r.nv_calls.append(value)
    # The known synthetic secret is not logged by this carrier. Inspect only
    # this owned runtime tree and actual in-memory wire/argv/output evidence.
    secret = SECRET.encode()
    for path in root.rglob('*'):
        if path.is_file() and not path.is_symlink() and secret in path.read_bytes():
            r.secret_leaks.append(str(path))
    for number, channel in enumerate(bridge.channels):
        if any(secret in raw for raw in channel.collected):
            r.secret_leaks.append('channel-output-' + str(number))
        for process in (channel.process, getattr(channel.owner, 'coordinator', None)):
            if process is not None and SECRET in repr(process.args):
                r.secret_leaks.append('channel-argv-' + str(number))
    if r.result is not None and SECRET in repr(r.result[:3]):
        r.secret_leaks.append('actual-invoke-result')
    # Root-only diagnosis of the real normal app result. This does not turn a
    # failed return into capability evidence or change any original assertion.
    # Only JSON primitives are retained; arbitrary object repr/str is forbidden.
    forbidden = (SECRET, 'SYNTHETIC', base64.b64encode(SECRET.encode()).decode())
    def safe(value, depth=0):
        if depth > 12:
            return '<DEPTH_LIMIT>'
        if value is None or type(value) in (bool, int, float):
            return value
        if type(value) is str:
            for secret_value in forbidden:
                value = value.replace(secret_value, '<REDACTED_TEST_SECRET>')
            return value[:4096]
        if type(value) in (list, tuple):
            return [safe(item, depth + 1) for item in value[:64]]
        if type(value) is dict:
            return {safe(key): ('<WITHHELD>' if any(token in key.casefold()
                for token in ('password', 'secret', 'token', 'base64', 'raw', 'argv'))
                else safe(item, depth + 1)) for key, item in value.items()
                if type(key) is str}
        return {'type_only': type(value).__name__}
    actual = None if r.result is None else dict(code=r.result[0], report=r.result[1], stderr=r.result[2])
    diagnostic = safe(dict(root=str(root), two=two, fault=fault, actual_result=actual,
        invoke_error_type=type(r.invoke_error).__name__ if r.invoke_error is not None else None,
        carrier_error_type=type(r.carrier_error).__name__ if r.carrier_error is not None else None,
        calls=diagnostic_calls, returns=diagnostic_returns, errors=diagnostic_errors,
        factory_count=len(r.factories), freeze_count=len(r.freezes),
        preflight_count=len(r.preflights), context_count=len(r.contexts),
        dispatch_count=len(r.dispatches), channels=len(bridge.channels),
        fault_fired=r.fault_fired, records=len(r.records), acks=len(r.acks),
        test_owner_cancellation=dict(requests=cancellation.requests,
            delivered=cancellation.delivered,
            classification='TEST_OWNER_STOP_NOT_PRODUCT_SHARED_OR_BATCH_STOP',
            error_type=type(cancellation.error).__name__ if cancellation.error is not None else None)))
    public = json.dumps(diagnostic, sort_keys=True, ensure_ascii=True)
    if any(secret_value in public for secret_value in forbidden):
        raise AssertionError('diagnostic secret check failed; no payload emitted')
    print('IBSW_NATIVE_OS_FLOW_DIAGNOSTIC=' + public, flush=True)
    return r
