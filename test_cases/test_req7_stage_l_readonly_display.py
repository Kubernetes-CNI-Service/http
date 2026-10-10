"""C25 fixed last-observation projection, not qualification or send authority."""
import io
import errno
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_cases.test_monitor_stack_review import load_module, ROOT
from test_cases import test_issue_tracker_manual_ui as ui
from test_cases import test_issue_tracker_stage_l_consumer as fixtures
from test_cases import test_issue_tracker_stage_l_consumer_workflow as consumers
from test_cases import test_collection_cycle_persistence as cycles
from test_cases import test_req7_online_observation_status as online

CGI = load_module('req7_stage_l_display_cgi', ROOT/'monitor/switch-collection-control.cgi')
PANELS = ('Switch Status', 'Eth Link Validation', 'IB Link Validation')
STAMP = '2026-01-01T00:00:00+00:00'
AUTH = {**online.AUTH, 'QUERY_STRING': 'view=issue_tracker_stage_l'}


def source():
    return {'schema_version': 1, 'state': 'pending', 'updated_at': STAMP,
        'k': 2, 'k_revision': 1, 'online': 'disabled_no_send_authority',
        'panels': {name: {'state': 'pending', 'progress_text': 'pending 1/2',
            'per_key': [{'activity_key': 'PRIVATE DEVICE'}]} for name in PANELS},
        'cycle_summary': {'published': 0, 'skipped': None, 'pending': 2,
            'pending_count_complete': False},
        'project_key': 'PRIVATE PROJECT', 'scope': 'PRIVATE SCOPE',
        'template_sha256': 'PRIVATE DIGEST', 'terminal_detail': 'PRIVATE ERROR',
        'token': 'PRIVATE TOKEN', 'wire': 'PRIVATE WIRE'}


def expected():
    return {'schema_version': 1, 'state': 'pending', 'updated_at': STAMP,
        'k': '2', 'k_revision': '1', 'publish_every_cycles': None,
        'online': 'disabled_no_send_authority', 'read_only': True,
        'mutation_disabled': True,
        'panels': {name: {'state': 'pending', 'progress_text': 'pending 1/2'} for name in PANELS},
        'cycle_summary': {'published': '0', 'skipped': None, 'pending': '2',
            'pending_count_complete': False}}


def browser(payload):
    script = getattr(ui.HTML, '_ISSUE_TRACKER_STAGE_L_STATUS_SCRIPT', None)
    if not isinstance(script, str): raise AssertionError('default Stage-L display script missing')
    node = online.shutil.which('node') or str(Path.home()/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node')
    fixture = '''
const labels = Object.fromEntries(['eth','etop','itop'].map(id =>
  [`issue-tracker-${id}-stage-l-state`, {textContent: ''}]));
const document = {getElementById: id => labels[id]};
const SWITCH_COLLECTION_URL = '/monitor/control/switch-collection';
const calls = [];
async function fetch(url, options) {calls.push({url, options});
  return {ok: true, async json(){return PAYLOAD}};}
'''.replace('PAYLOAD', json.dumps(payload))
    result = online.subprocess.run([node, '-e', fixture+script+'''
refreshIssueTrackerStageLStatus().then(() => console.log(JSON.stringify({
  texts: Object.fromEntries(Object.entries(labels).map(([id, value]) => [id,value.textContent])), calls
}))).catch(error => {console.error(error); process.exitCode=1});
'''], capture_output=True, text=True, stdin=online.subprocess.DEVNULL, timeout=15)
    if result.returncode: raise AssertionError(result.stderr)
    return json.loads(result.stdout)


def read():
    api = getattr(CGI, 'issue_tracker_stage_l_status', None)
    if not callable(api): raise AssertionError('fixed Stage-L readonly reader missing')
    return api()


def authenticated_get():
    raw = io.BytesIO()
    output = io.TextIOWrapper(raw, encoding='utf-8', write_through=True)
    with mock.patch.dict(os.environ, AUTH, clear=True), mock.patch('sys.stdout', output):
        CGI.main()
    output.flush()
    header, body = raw.getvalue().decode('utf-8').split('\r\n\r\n', 1)
    if 'Status: 400' in header: raise AssertionError('default Stage-L GET route missing')
    return json.loads(body)


class StageLReadonlyDisplayDirectTests(unittest.TestCase):
    def test_exact_projection_excludes_all_private_fields_and_accepts_real_large_cache(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            path = Path(directory)/'issue-tracker-stage-l.status.json'
            value = source(); value['private_evidence'] = 'PRIVATE'*1024
            path.write_text(json.dumps(value)); path.chmod(0o644)
            self.assertGreater(path.stat().st_size, 4096)
            self.assertEqual(expected(), read())
            self.assertNotIn('PRIVATE', json.dumps(read()))

    def test_uncapped_counts_are_decimal_strings_not_browser_float_numbers(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            value = source(); value.update(k=9007199254740993, k_revision=9007199254740995, publish_every_cycles=9007199254740997)
            for panel in value['panels'].values(): panel['progress_text'] = 'pending 1/9007199254740993'
            value['cycle_summary']['published'] = 9007199254740999
            (Path(directory)/'issue-tracker-stage-l.status.json').write_text(json.dumps(value))
            result = read()
            self.assertEqual(('9007199254740993','9007199254740995','9007199254740997','9007199254740999'),
                (result['k'],result['k_revision'],result['publish_every_cycles'],result['cycle_summary']['published']))
            rendered = browser(result)
            self.assertIn('9007199254740993', rendered['texts']['issue-tracker-eth-stage-l-state'])

    def test_sparse_worker_hold_stays_unknown_without_fabricated_zero_or_default_k(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            value = {'schema_version':1,'state':'hold','updated_at':STAMP,
                'reason':'local_c6_admission_refused','online':'disabled_no_send_authority'}
            (Path(directory)/'issue-tracker-stage-l.status.json').write_text(json.dumps(value))
            result = read()
            self.assertEqual('hold', result['state']); self.assertIsNone(result['k'])
            self.assertEqual({'published':None,'skipped':None,'pending':None,'pending_count_complete':False}, result['cycle_summary'])
            for text in browser(result)['texts'].values():
                self.assertIn('HOLD', text); self.assertIn('未知', text); self.assertNotIn('pending 0/3', text)

    def test_initial_k_revision_zero_remains_real_and_is_not_missing_or_one(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            value = source(); value['k_revision'] = 0
            (Path(directory)/'issue-tracker-stage-l.status.json').write_text(json.dumps(value))
            result = read()
            self.assertEqual('0',result['k_revision']); self.assertEqual('pending',result['state'])
            for text in browser(result)['texts'].values(): self.assertIn('pending 1/2',text)

    def test_special_file_hardlink_symlink_or_same_bytes_rebound_image_is_unproved(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI,'STATUS_DIR',Path(directory)):
            root=Path(directory); path=root/'issue-tracker-stage-l.status.json'; other=root/'foreign'
            other.write_text(json.dumps(source())); original=other.read_bytes()
            path.symlink_to(other); self.assertEqual('unproved',read()['state']); path.unlink()
            os.link(other,path); self.assertEqual('unproved',read()['state']); path.unlink()
            os.mkfifo(path); self.assertEqual('unproved',read()['state']); path.unlink()
            path.write_bytes(original); replacement=root/'replacement'; replacement.write_bytes(original)
            pread=os.pread; changed=[]
            def replace_after_read(fd,*args):
                value=pread(fd,*args)
                if not changed: replacement.replace(path); changed.append(True)
                return value
            with mock.patch.object(CGI.os,'pread',side_effect=replace_after_read):
                self.assertEqual('unproved',read()['state'])
            self.assertEqual([True],changed); self.assertEqual(original,other.read_bytes())

    def first_stat_fault(self, phase, replace_with_foreign):
        real_open, real_fstat = os.open, os.fstat
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory); (root/'issue-tracker-stage-l.status.json').write_text(json.dumps(source()))
            foreign=root/'foreign'; foreign.write_bytes(b'FOREIGN MUST SURVIVE')
            foreign_fd=real_open(foreign,os.O_RDONLY); foreign_identity=real_fstat(foreign_fd)
            opened={}; faulted=[]; survivors=[]
            def open_actual(path,flags,**kwargs):
                fd=real_open(path,flags,**kwargs)
                kind='image' if str(path)=='issue-tracker-stage-l.status.json' else 'parent'
                opened[fd]=(kind,real_fstat(fd)); return fd
            def first_fault(fd):
                if fd in opened and opened[fd][0]==phase and not faulted:
                    faulted.append(fd)
                    if replace_with_foreign: os.dup2(foreign_fd,fd)
                    raise OSError(errno.EIO,'independent original first-stat fault')
                return real_fstat(fd)
            try:
                with mock.patch.object(CGI,'STATUS_DIR',root), mock.patch.object(CGI.os,'open',side_effect=open_actual), \
                        mock.patch.object(CGI.os,'fstat',side_effect=first_fault):
                    self.assertEqual('unproved',read()['state'])
                self.assertEqual(1,len(faulted))
                for fd in opened:
                    try: current=real_fstat(fd)
                    except OSError as error: self.assertEqual(errno.EBADF,error.errno)
                    else:
                        survivors.append(fd)
                        self.assertTrue(replace_with_foreign and fd==faulted[0],'actual owned FD leaked')
                        self.assertEqual((foreign_identity.st_dev,foreign_identity.st_ino),(current.st_dev,current.st_ino))
                self.assertEqual([faulted[0]] if replace_with_foreign else [],survivors)
                self.assertEqual(b'FOREIGN MUST SURVIVE',os.pread(foreign_fd,100,0))
            finally:
                # Only fixture-created open/dup2 targets, no foreign PID/FD scan.
                for fd in (*opened,foreign_fd):
                    try: os.close(fd)
                    except OSError: pass

    def test_first_fstat_fault_closes_only_actual_owned_parent_and_image(self):
        for phase in ('parent','image'):
            with self.subTest(phase=phase): self.first_stat_fault(phase,False)

    def test_first_fstat_foreign_rebind_does_not_close_foreign_parent_or_image(self):
        for phase in ('parent','image'):
            with self.subTest(phase=phase): self.first_stat_fault(phase,True)

    def test_invalid_missing_duplicate_future_or_permission_cache_is_unproved(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(CGI, 'STATUS_DIR', Path(directory)):
            path = Path(directory)/'issue-tracker-stage-l.status.json'
            self.assertEqual('unproved', read()['state'])
            cases = (b'{}', b'{"schema_version":1,"schema_version":1}',
                json.dumps({**source(),'schema_version':True}).encode(),
                json.dumps({**source(),'k':True}).encode(),
                json.dumps({**source(),'online':'GO'}).encode(),
                json.dumps({**source(),'updated_at':'2999-01-01T00:00:00+00:00'}).encode(),
                json.dumps({**source(),'panels':{'Switch Status':{'state':'pending','progress_text':'PRIVATE TOKEN'}}}).encode())
            for raw in cases:
                with self.subTest(raw_size=len(raw)):
                    path.write_bytes(raw); path.chmod(0o644)
                    self.assertEqual('unproved', read()['state']); self.assertEqual(raw,path.read_bytes())
            path.write_text(json.dumps(source())); path.chmod(0o666)
            self.assertEqual('unproved', read()['state'])

    def test_authentication_precedes_get_reader_and_get_does_not_touch_collector_or_request(self):
        self.assertTrue(callable(getattr(CGI,'issue_tracker_stage_l_status',None)))
        with mock.patch.dict(os.environ,{**AUTH,'REMOTE_USER':'foreign'},clear=True), \
                mock.patch.object(CGI,'issue_tracker_stage_l_status') as reader, mock.patch.object(CGI,'process_state') as process, \
                mock.patch.object(CGI,'respond') as respond:
            CGI.main(); reader.assert_not_called(); process.assert_not_called()
            self.assertEqual('403 Forbidden',respond.call_args.args[1])
        with mock.patch.dict(os.environ,AUTH,clear=True), mock.patch.object(CGI,'issue_tracker_stage_l_status',return_value=expected()) as reader, \
                mock.patch.object(CGI,'process_state') as process, mock.patch.object(CGI,'request_action') as request, mock.patch.object(CGI,'respond') as respond:
            CGI.main(); reader.assert_called_once_with(); process.assert_not_called(); request.assert_not_called()
            respond.assert_called_once_with(expected())

    def test_default_page_three_readonly_labels_and_get_only_no_manual_activation(self):
        rendered = ui.page()
        for panel_id in ('eth','etop','itop'):
            self.assertTrue('id="issue-tracker-'+panel_id+'-stage-l-state"' in rendered,
                'default '+panel_id+' readonly observation label missing')
        self.assertNotIn('onclick="issueTrackerManualPreview(',rendered)
        self.assertNotIn('onclick="issueTrackerSettingsSave(',rendered)
        result = browser(expected())
        self.assertEqual([{'url':'/monitor/control/switch-collection?view=issue_tracker_stage_l',
            'options':{'method':'GET','credentials':'same-origin','cache':'no-store'}}], result['calls'])
        for text in result['texts'].values():
            self.assertIn('pending 1/2',text); self.assertIn('本地 published 0',text)
            self.assertIn('pending 2',text); self.assertIn('非当前准入证明',text)

    def test_browser_rejects_raw_extra_fields_and_invalid_counts_without_echo(self):
        for value in ({**expected(),'token':'PRIVATE TOKEN'}, {**expected(),'k':2},
                {**expected(),'read_only':False}, {**expected(),'online':'APPLIED'},
                {**expected(),'panels':{'Switch Status':{'state':'qualified','progress_text':'<img PRIVATE>'}}}):
            for text in browser(value)['texts'].values():
                self.assertIn('未证明',text); self.assertNotIn('PRIVATE',text); self.assertNotIn('<img',text)


class StageLReadonlyDisplayWorkflowTests(fixtures.ProdStageLFixture):
    def displayed(self):
        status_path = self.root/'monitor/status/issue-tracker-stage-l.status.json'
        with mock.patch.object(CGI,'STATUS_DIR',status_path.parent):
            result = authenticated_get()
        self.assertNotIn('PRIVATE',json.dumps(result))
        self.assertEqual('disabled_no_send_authority',result['online'])
        self.assertTrue(result['read_only']); self.assertTrue(result['mutation_disabled'])
        return result, browser(result)

    def publish(self):
        path = self.root/'monitor/status/issue-tracker-stage-l.status.json'
        (self.root/'monitor/Issue_Tracker_Template_v1.xlsx').write_bytes(self.template.read_bytes())
        with mock.patch.object(cycles.WORKER,'HTTP_ROOT',self.root), mock.patch.object(cycles.WORKER,'STATUS_DIR',path.parent), \
                mock.patch.object(cycles.WORKER,'ISSUE_TRACKER_STAGE_L_STATUS_FILE',path):
            cycles.WORKER._publish_stage_l_status_after_completion(self.store)

    def test_actual_worker_completed_cycle_to_authenticated_get_to_default_js_pending(self):
        self._cycle(activity=True,derivation=True); self.publish()
        result, rendered = self.displayed()
        self.assertEqual('pending',result['state']); self.assertEqual('2',result['k'])
        self.assertEqual('pending 1/2',result['panels']['Switch Status']['progress_text'])
        self.assertIn('pending 1/2',rendered['texts']['issue-tracker-eth-stage-l-state'])
        self.assertEqual('0',result['cycle_summary']['published'])
        self.assertFalse(result['cycle_summary']['pending_count_complete'])
        self.assertEqual((),tuple(self.publication.iterdir()))

    def test_actual_archive_gap_stays_hold_unknown_through_get_and_js(self):
        self.two_cycles(activity=True,derivation=True)
        for path in (self.store.start_path(1),self.store.launch_path(1),self.store.completion_path(1)):
            path.unlink()  # Only this actual owned fixture.
        self.publish(); result, rendered = self.displayed()
        self.assertEqual('hold',result['state']); self.assertIsNone(result['cycle_summary']['published'])
        self.assertEqual('pending ?/2 — archive sequence gap', result['panels']['Switch Status']['progress_text'])
        self.assertIn('archive sequence gap',rendered['texts']['issue-tracker-eth-stage-l-state'])
        self.assertEqual((),tuple(self.publication.iterdir()))

    def test_actual_local_c6_receipt_is_local_applied_not_online_permission_in_display(self):
        from monitor.issue_tracker_local_workbook_commit import CommittedProdWorkbook
        real_publish = cycles.WORKER._publish_stage_l_local_after_completion
        witnessed = []
        def after_publish(store):
            result = real_publish(store)
            if isinstance(result,CommittedProdWorkbook): witnessed.append(self.displayed())
            return result
        with mock.patch.object(cycles.WORKER,'_publish_stage_l_local_after_completion',side_effect=after_publish):
            consumers.ProdStageLConsumerWorkflowTests._exercise_real_protected_three_panel_fixture(
                self,skip_history=False,automatic_first=True)
        self.assertEqual(1,len(witnessed))
        result,rendered = witnessed[0]
        self.assertEqual('local_applied',result['state'])
        self.assertEqual({'published':'1','skipped':'0','pending':'0','pending_count_complete':True},result['cycle_summary'])
        for text in rendered['texts'].values():
            self.assertIn('本地完成',text); self.assertIn('非当前准入证明',text)
            self.assertNotIn('在线完成',text)
