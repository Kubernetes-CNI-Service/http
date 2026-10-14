"""REQ7 prod Stage L source binding must remain HOLD without all three panels."""

from __future__ import annotations

import hashlib
import os
import unittest
from unittest import mock

from monitor.issue_tracker_cycle_source import read_completed_cycle_evidence
from monitor.issue_tracker_ib_runtime import IbBoundCycleReport, IbReportLink
from monitor.issue_tracker_state_owner import (
    current_k, initialize_tracker_state, set_k, tracker_writer,
)
from monitor.issue_tracker_whitelist_workbook import read_whitelist_workbook
from test_cases.test_issue_tracker_whitelist_workbook import literal_xlsx


class ProdStageLFixture(unittest.TestCase):
    def _archive(self, *args, **kwargs):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        return ProdSwitchSourceWorkflowTests._archive(self, *args, **kwargs)

    def _cycle(self, *args, **kwargs):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        return ProdSwitchSourceWorkflowTests._cycle(self, *args, **kwargs)

    def setUp(self):
        from test_cases.test_issue_tracker_switch_runtime_workflow import (
            ProdSwitchSourceWorkflowTests,
        )
        ProdSwitchSourceWorkflowTests.setUp(self)
        self.publication = self.project / "99-output-monitor"
        self.publication.mkdir()
        initialize_tracker_state(
            self.project, self.publication,
            initialized_at="2026-09-25T00:00:00Z",
            acquisition_id="prod-three-panel-source-gate",
        )
        with tracker_writer(self.project, self.publication) as token:
            set_k(token, new_k=2, actor="operator:fixture",
                  recorded_at="2026-09-25T00:01:00Z", request_id="prod-k-two",
                  expected_revision=0)
            self.settings = current_k(token)
        self.template = self.project / "local-template.xlsx"
        self.template.write_bytes(literal_xlsx())
        self.snapshot = read_whitelist_workbook(self.template)

    def two_cycles(self, *, activity=False, derivation=False, **kwargs):
        first, _ = self._cycle(activity=activity, derivation=derivation,
                               **kwargs)
        second, artifacts = self._cycle(activity=activity,
                                        derivation=derivation, **kwargs)
        return first, second, artifacts


class ProdStageLConsumerDirectTests(ProdStageLFixture):
    def test_native_projection_returns_its_original_switch_pair_without_another_query(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_ib_runtime import IbKWindow, IbWhitelistedKWindow
        from monitor.issue_tracker_switch_runtime import ProdEthActivityKWindow, ProdSwitchKWindow
        core = getattr(consumer, '_project_observed_stage_l_source_candidates_with_windows', None)
        self.assertTrue(callable(core), 'native pure derivation must retain its actual freshly queried Switch pair')
        switch = consumer.ProdStageLSourceSnapshot(('cycle-one',), ('a'*64,), 'b'*64, 'c'*64, 'd'*64, ())
        ib = IbWhitelistedKWindow(IbKWindow('history_sufficient', '', 1, 1,
            ('cycle-one',), ('e'*64,), 'f'*64, (), recorded_at_utc='2026-09-26T04:20:00Z'),
            'd'*64, 'c'*64, (), ())
        eth = ProdEthActivityKWindow(('cycle-one',), ('a'*64,), ('0'*64,), (), (), 'b'*64, 'c'*64, 'd'*64)
        source = consumer.ProdStageLComposedSourceSnapshot(consumer.ProdStageLBoundSourceSnapshot(switch, ib), eth, ())
        windows = tuple(ProdSwitchKWindow(slot, ('cycle-one',), ('a'*64,), (), (),
            (digest*64,), (), 'b'*64, 'c'*64, 'd'*64)
            for slot, digest in (('ethernet/prod', '1'), ('nvlink/prod', '2')))
        args = dict(http_root=self.root, settings=self.settings, whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template)
        with mock.patch.object(consumer, 'read_prod_switch_k_window', side_effect=windows) as reads:
            projection, originals = core(source, self.store, **args)
        self.assertEqual(['ethernet/prod', 'nvlink/prod'], [call.kwargs['source_slot'] for call in reads.call_args_list])
        self.assertEqual(2, len(originals))
        for expected, actual in zip(windows, originals): self.assertIs(expected, actual)
        self.assertEqual((), projection.candidates)
        self.assertEqual((), projection.whitelist_skips)
        self.assertFalse(projection.qualified)
        self.assertEqual('hold', projection.state)
        # The original projection API still makes its own two fresh queries.
        with mock.patch.object(consumer, 'read_prod_switch_k_window', side_effect=windows) as reads:
            public = consumer._project_observed_stage_l_source_candidates(source, self.store, **args)
        self.assertEqual(projection, public)
        self.assertEqual(2, reads.call_count)

    def test_native_switch_pair_derivation_keeps_independent_final_projection_and_ib_replay(self):
        import ast, inspect, textwrap
        from monitor import issue_tracker_stage_l_consumer as consumer
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer.qualify_prod_stage_l)))
        calls = [node.func.id for node in ast.walk(tree)
                 if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)]
        self.assertEqual(1, calls.count('_project_observed_stage_l_source_candidates_with_windows'))
        self.assertEqual(0, calls.count('read_prod_switch_k_window'),
                         'pure native derivation must use the original pair just read by its projection')
        self.assertEqual(1, calls.count('validate_prod_stage_l_source_projection'))
        self.assertEqual(1, calls.count('validate_prod_ib_k_window'))
        self.assertEqual(2, calls.count('read_completed_cycle_evidence'))

    def test_native_qualification_projects_its_own_ib_observation_and_keeps_final_replay(self):
        import ast, inspect, textwrap
        from monitor import issue_tracker_stage_l_consumer as consumer
        tree = ast.parse(textwrap.dedent(inspect.getsource(consumer.qualify_prod_stage_l)))
        calls = [node.func.id for node in ast.walk(tree)
            if isinstance(node,ast.Call) and isinstance(node.func,ast.Name)]
        self.assertEqual(0,calls.count('read_prod_ib_k_window'),
            'native qualification must not recursively reread the intermediate already-observed IB window')
        self.assertEqual(1,calls.count('ProdIbKWindow'))
        self.assertEqual(1,calls.count('inspect_prod_stage_l_composed_sources'))
        self.assertEqual(1,calls.count('validate_prod_ib_k_window'),
            'last independent protected IB/W1 replay must remain before qualification return')
        self.assertEqual(1,calls.count('validate_prod_stage_l_source_projection'))

    def test_fresh_switch_leg_reads_each_family_once_without_granting_authority(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_switch_runtime import ProdSwitchKWindow
        observe = getattr(consumer, '_observe_prod_stage_l_switch_sources', None)
        self.assertTrue(callable(observe), 'composition needs one fresh Switch-family leg, not a nested standalone inspection')
        cycles = (mock.Mock(cycle_id='cycle-one', sequence=1),
                  mock.Mock(cycle_id='cycle-two', sequence=2))
        windows = tuple(ProdSwitchKWindow(slot, ('cycle-one', 'cycle-two'),
            ('a'*64, 'b'*64), (), (), ('c'*64, 'd'*64), (),
            'e'*64, 'f'*64, '0'*64)
            for slot in ('ethernet/prod', 'nvlink/prod'))
        args = dict(http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template)
        with mock.patch.object(consumer, 'read_completed_cycle_evidence', return_value=cycles), \
                mock.patch.object(consumer, 'read_prod_switch_k_window', side_effect=windows) as reads, \
                mock.patch.object(consumer, '_latest_rows', return_value=((), ())) as rows:
            result = observe(self.store, **args)
        self.assertEqual(['ethernet/prod', 'nvlink/prod'],
                         [call.kwargs['source_slot'] for call in reads.call_args_list])
        self.assertEqual(2, rows.call_count)
        self.assertEqual(('cycle-one', 'cycle-two'), result.cycle_ids)
        self.assertFalse(result.qualified)
        self.assertEqual('hold', result.state)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_standalone_switch_inspection_still_rejects_changed_fresh_leg(self):
        from dataclasses import replace
        from monitor import issue_tracker_stage_l_consumer as consumer
        observe = getattr(consumer, '_observe_prod_stage_l_switch_sources', None)
        self.assertTrue(callable(observe), 'the standalone API must compare two independent fresh Switch legs')
        original = consumer.ProdStageLSourceSnapshot(
            ('cycle-one',), ('a'*64,), 'b'*64, 'c'*64, 'd'*64, ())
        args = dict(http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template)
        with mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources',
                               return_value=original) as reads:
            self.assertEqual(original, consumer.inspect_prod_stage_l_sources(self.store, **args))
        self.assertEqual(2, reads.call_count)
        with mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources',
                side_effect=(original, replace(original, template_sha256='e'*64))) as changed:
            with self.assertRaises(consumer.StageLConsumerHold):
                consumer.inspect_prod_stage_l_sources(self.store, **args)
        self.assertEqual(2, changed.call_count)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_composed_observes_fresh_bound_legs_before_and_after_eth_without_recursive_rechecks(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_ib_runtime import IbKWindow, IbWhitelistedKWindow
        from monitor.issue_tracker_switch_runtime import ProdEthActivityKWindow
        switch = consumer.ProdStageLSourceSnapshot(
            ('cycle-one', 'cycle-two'), ('a'*64, 'b'*64),
            'c'*64, 'd'*64, 'e'*64, ())
        ib = IbWhitelistedKWindow(IbKWindow(
            'history_sufficient', '', 2, 2, switch.cycle_ids,
            ('f'*64, '0'*64), '1'*64, (),
            recorded_at_utc='2026-09-26T04:20:00Z'),
            switch.template_sha256, switch.whitelist_sha256, (), ())
        eth = ProdEthActivityKWindow(
            switch.cycle_ids, switch.completion_sha256, ('2'*64, '3'*64),
            (), (), switch.k_event_sha256, switch.whitelist_sha256,
            switch.template_sha256)
        cycles = (mock.Mock(cycle_id='cycle-one'), mock.Mock(cycle_id='cycle-two'))
        args = dict(http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template)
        observed_order = []
        def observe(label, value):
            def read(*_args, **_kwargs):
                observed_order.append(label)
                return value
            return read
        # Literal source values are independent of implementation. These seams
        # isolate observation order only, not protected IB/report acceptance.
        with mock.patch.object(consumer, 'read_completed_cycle_evidence', return_value=cycles), \
                mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources', side_effect=observe('switch', switch)) as switches, \
                mock.patch.object(consumer, 'read_whitelisted_ib_k_window', side_effect=observe('ib', ib)) as ibs, \
                mock.patch.object(consumer, 'read_prod_eth_activity_k_window', side_effect=observe('eth', eth)) as eths:
            result = consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
        self.assertEqual(2, switches.call_count,
                         'composed start/end each need one independently validated Switch leg')
        self.assertEqual(2, ibs.call_count,
                         'IB must be reopened on both sides of the actual ETH observation')
        self.assertEqual(2, eths.call_count)
        self.assertEqual(['switch', 'ib', 'eth', 'switch', 'ib', 'eth'], observed_order)
        self.assertEqual(consumer.ProdStageLBoundSourceSnapshot(switch, ib), result.switch_ib_source)
        self.assertFalse(result.qualified)
        self.assertEqual('hold', result.state)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_composed_post_domain_drift_remains_hold_and_standalone_bound_rechecks(self):
        from dataclasses import replace
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_ib_runtime import IbKWindow, IbWhitelistedKWindow
        from monitor.issue_tracker_switch_runtime import ProdEthActivityKWindow
        switch = consumer.ProdStageLSourceSnapshot(
            ('cycle-one', 'cycle-two'), ('a'*64, 'b'*64),
            'c'*64, 'd'*64, 'e'*64, ())
        ib = IbWhitelistedKWindow(IbKWindow(
            'history_sufficient', '', 2, 2, switch.cycle_ids,
            ('f'*64, '0'*64), '1'*64, (),
            recorded_at_utc='2026-09-26T04:20:00Z'),
            switch.template_sha256, switch.whitelist_sha256, (), ())
        eth = ProdEthActivityKWindow(switch.cycle_ids, switch.completion_sha256,
            ('2'*64, '3'*64), (), (), switch.k_event_sha256,
            switch.whitelist_sha256, switch.template_sha256)
        cycles = (mock.Mock(cycle_id='cycle-one'), mock.Mock(cycle_id='cycle-two'))
        args = dict(http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template)
        for domain in ('switch', 'ib', 'eth'):
            with self.subTest(domain=domain), \
                    mock.patch.object(consumer, 'read_completed_cycle_evidence', return_value=cycles), \
                    mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources',
                        side_effect=[switch, replace(switch, template_sha256='4'*64)]
                        if domain == 'switch' else None, return_value=switch), \
                    mock.patch.object(consumer, 'read_whitelisted_ib_k_window',
                        side_effect=[ib, replace(ib, window=replace(ib.window, report_sha256s=('5'*64, '0'*64)))]
                        if domain == 'ib' else None, return_value=ib), \
                    mock.patch.object(consumer, 'read_prod_eth_activity_k_window',
                        side_effect=[eth, replace(eth, template_sha256='6'*64)]
                        if domain == 'eth' else None, return_value=eth):
                with self.assertRaises(consumer.StageLConsumerHold):
                    consumer.inspect_prod_stage_l_composed_sources(self.store, **args)
        with mock.patch.object(consumer, '_observe_prod_stage_l_switch_sources', return_value=switch) as switches, \
                mock.patch.object(consumer, 'read_whitelisted_ib_k_window', return_value=ib) as ibs:
            result = consumer.inspect_prod_stage_l_bound_sources(self.store, **args)
        self.assertEqual(2, switches.call_count, 'standalone bound API retains its own start/end checks')
        self.assertEqual(2, ibs.call_count)
        self.assertFalse(result.qualified)
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_observed_projection_is_literal_hold_only_and_preserves_switch_rechecks(self):
        from dataclasses import replace
        from monitor import issue_tracker_stage_l_consumer as consumer
        from monitor.issue_tracker_ib_runtime import IbKWindow, IbWhitelistedKWindow
        from monitor.issue_tracker_switch_runtime import ProdEthActivityKWindow, ProdSwitchKWindow
        project = getattr(consumer, '_project_observed_stage_l_source_candidates', None)
        self.assertTrue(callable(project), 'qualification must project its already observed source without recursive requalification')
        switch = consumer.ProdStageLSourceSnapshot(
            ('cycle-one',), ('a'*64,), 'b'*64, 'c'*64, 'd'*64, ())
        row = IbReportLink('Link Down', ('leaf01','1/1','server01','mlx5_0'),
                           ('',''), 'Missing_Links', 2)
        ib = IbWhitelistedKWindow(IbKWindow('history_sufficient','',1,1,
            ('cycle-one',),('e'*64,),'f'*64,(row,),recorded_at_utc='2026-09-26T04:20:00Z'),
            'd'*64,'c'*64,(row,),())
        eth = ProdEthActivityKWindow(('cycle-one',),('a'*64,),('0'*64,),(),(),
                                    'b'*64,'c'*64,'d'*64)
        source = consumer.ProdStageLComposedSourceSnapshot(
            consumer.ProdStageLBoundSourceSnapshot(switch,ib),eth,())
        windows = [ProdSwitchKWindow(slot,('cycle-one',),('a'*64,),(),(),
            ('1'*64,),(),'b'*64,'c'*64,'d'*64)
            for slot in ('ethernet/prod','nvlink/prod')]
        args = dict(http_root=self.root,settings=self.settings,
                    whitelist_snapshot=self.snapshot,whitelist_path=self.template)
        with mock.patch.object(consumer,'read_prod_switch_k_window',side_effect=windows) as reads:
            result = project(source,self.store,**args)
        self.assertEqual(2,reads.call_count)
        self.assertFalse(result.qualified)
        self.assertEqual('hold',result.state)
        self.assertEqual('qualification_not_implemented',result.reason)
        self.assertEqual(('cycle-one',),result.cycle_ids)
        self.assertEqual((),result.whitelist_skips)
        self.assertEqual(1,len(result.candidates))
        literal = result.candidates[0]
        self.assertEqual(('ib_cabling','leaf01','1/1','Link Down'),literal.activity_key)
        self.assertEqual(('leaf01','1/1','server01','mlx5_0'),literal.expected_endpoints)
        self.assertEqual(('','','',''),literal.actual_endpoints)
        self.assertEqual('Missing_Links!2: leaf01:1/1 -> server01:mlx5_0',literal.evidence_description)
        self.assertFalse(literal.qualified)
        with self.assertRaises(consumer.StageLConsumerHold):
            project(replace(source,qualified=True),self.store,**args)
        with mock.patch.object(consumer,'read_prod_switch_k_window',
                               return_value=replace(windows[0],template_sha256='2'*64)):
            with self.assertRaises(consumer.StageLConsumerHold):
                project(source,self.store,**args)

    def test_original_manual_source_projection_preserves_full_digests_and_exact_panel_decisions(self):
        from copy import deepcopy
        from monitor import issue_tracker_stage_l_consumer as consumer
        qualified = consumer.ProdStageLQualifiedSet(
            b'[]', (), (
                consumer.StageLQualifiedSkip('switch','leaf-a',
                    record_id='switch:leaf-a:fan:PSU1/FAN1'),
                consumer.StageLQualifiedSkip('eth_cabling','leaf-a',
                    endpoints=('leaf-a','swp1','leaf-z','swp2')),
            ), ('a'*64,), ('b'*64,), 'c'*64, 'd'*64, 'e'*64,
            'f'*64, '1'*64, '2'*64, 'prod', 1, '2026-09-26T04:20:00Z')
        source = {
            'cycle_ids':['a'*64], 'completion_sha256':['b'*64],
            'source_authority_sha256':'c'*64, 'observations_sha256':'d'*64,
            'k_event_sha256':'e'*64, 'whitelist_sha256':'f'*64,
            'project_key':'2'*64, 'scope':'prod', 'mode':'prod-runtime-protected-v1',
            'k':1, 'recorded_at_utc':'2026-09-26T04:20:00Z',
            'whitelist_skips':[{'source':'switch','matched_rule':'leaf-a',
                'record_id':'switch:leaf-a:fan:PSU1/FAN1'}],
            'selected_panel':'Switch Status', 'panel_evaluation':{
                'Switch Status':{'state':'evaluated','whitelist_skips':'skips-present'},
                'Eth Link Validation':{'state':'not-evaluated-in-this-manifest'},
                'IB Link Validation':{'state':'not-evaluated-in-this-manifest'}},
        }
        validate = getattr(consumer, '_require_original_source_projection', None)
        self.assertTrue(callable(validate), 'native replay needs exact manual projection validation')
        self.assertIsNone(validate(source, qualified))
        self.assertEqual(2, len(qualified.whitelist_skips), 'full native source must not be filtered')
        eth_source = deepcopy(source)
        eth_source.update(selected_panel='Eth Link Validation', whitelist_skips=[{
            'source':'eth_cabling', 'matched_rule':'leaf-a',
            'endpoints':['leaf-a','swp1','leaf-z','swp2']}], panel_evaluation={
            'Switch Status':{'state':'not-evaluated-in-this-manifest'},
            'Eth Link Validation':{'state':'evaluated','whitelist_skips':'skips-present'},
            'IB Link Validation':{'state':'not-evaluated-in-this-manifest'}})
        self.assertIsNone(validate(eth_source, qualified))
        ib_source = deepcopy(source)
        ib_source.update(selected_panel='IB Link Validation', whitelist_skips=[], panel_evaluation={
            'Switch Status':{'state':'not-evaluated-in-this-manifest'},
            'Eth Link Validation':{'state':'not-evaluated-in-this-manifest'},
            'IB Link Validation':{'state':'evaluated','whitelist_skips':'no-skips'}})
        self.assertIsNone(validate(ib_source, qualified))
        bad = []
        changed = deepcopy(source); changed['whitelist_skips']=[]; bad.append(changed)
        changed = deepcopy(source); changed['selected_panel']='Foreign'; bad.append(changed)
        changed = deepcopy(source); del changed['panel_evaluation']; bad.append(changed)
        changed = deepcopy(source); changed['panel_evaluation']['Eth Link Validation']={'state':'evaluated','whitelist_skips':'no-skips'}; bad.append(changed)
        changed = deepcopy(source); changed['source_authority_sha256']='0'*64; bad.append(changed)
        changed = deepcopy(source); changed['extra_field']='invented'; bad.append(changed)
        changed = deepcopy(source); changed['k']=True; bad.append(changed)
        changed = deepcopy(source); changed['panel_evaluation']['Switch Status']['whitelist_skips']='no-skips'; bad.append(changed)
        for index, changed in enumerate(bad):
            with self.subTest(invalid=index), self.assertRaises(consumer.StageLConsumerHold):
                validate(changed, qualified)

    def test_original_replay_rejects_record_directory_swap_back_even_with_all_original_files_restored(self):
        import shutil
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        (self.project/'01-global.yaml').write_bytes(b'schema_version: 2\ncommon: {}\n')
        records = self.store.records_dir
        inode = records.stat().st_ino
        images = {p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()}
        original = self.project/'owned-swapped-back-original-records'
        clone = self.project/'owned-swapped-back-clone-records'
        shutil.copytree(records, clone)
        with self.assertRaises(consumer.StageLConsumerHold):
            with consumer._hold_original_replay_inputs(self.store,self.project,self.template) as verify:
                records.rename(original)
                clone.rename(records)
                records.rename(clone)
                original.rename(records)
                self.assertEqual(inode, records.stat().st_ino)
                self.assertEqual(images,{p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()})
                verify()
        self.assertEqual(inode, records.stat().st_ino)
        self.assertEqual(images,{p.name:(p.stat().st_ino,p.read_bytes()) for p in records.iterdir()})

    def test_original_replay_pins_record_directory_before_first_namespace_read(self):
        from pathlib import Path
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        (self.project / '01-global.yaml').write_bytes(b'schema_version: 2\ncommon: {}\n')
        records = self.store.records_dir
        original = records.stat()
        image = {p.name: (p.read_bytes(), p.stat().st_mode & 0o777)
                 for p in records.iterdir()}
        backup = self.project / 'owned-original-record-directory'
        abandoned = self.project / 'owned-replacement-record-directory'
        native_listdir = os.listdir
        reached = []

        def replace_after_first_namespace_read(path):
            names = native_listdir(path)
            if isinstance(path, int):
                info = os.fstat(path)
                selected = (info.st_dev, info.st_ino) == (original.st_dev, original.st_ino)
            else:
                selected = Path(path) == records
            if selected and not reached:
                records.rename(backup)
                records.mkdir(mode=original.st_mode & 0o777)
                for name, (raw, mode) in image.items():
                    member = records / name
                    member.write_bytes(raw)
                    member.chmod(mode)
                reached.append(True)
            return names

        try:
            with mock.patch.object(consumer.os, 'listdir', side_effect=replace_after_first_namespace_read):
                with self.assertRaises(consumer.StageLConsumerHold):
                    with consumer._hold_original_replay_inputs(self.store, self.project, self.template) as verify:
                        verify()
            self.assertEqual([True], reached, 'fault must follow the real first namespace read')
            self.assertNotEqual(original.st_ino, records.stat().st_ino)
            for name, (raw, _mode) in image.items():
                self.assertEqual(raw, (backup / name).read_bytes())
                self.assertEqual(raw, (records / name).read_bytes())
        finally:
            if backup.exists():
                records.rename(abandoned)
                backup.rename(records)
        self.assertEqual(original.st_ino, records.stat().st_ino)

    def test_original_replay_input_scope_holds_named_policy_whitelist_and_full_current_chain(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        self.two_cycles(activity=True, derivation=True)
        policy = self.project / '01-global.yaml'
        policy.write_bytes(b'schema_version: 2\ncommon: {}\n')
        paths = (policy, self.template, self.store.witness_path,
                 self.store.completion_path(2))
        for number, path in enumerate(paths):
            with self.subTest(original=path.name):
                raw = path.read_bytes()
                inode = path.stat().st_ino
                backup = self.project / ('owned-pin-original-' + str(number))
                replacement = self.project / ('owned-pin-replacement-' + str(number))
                replacement.write_bytes(raw)
                replacement.chmod(path.stat().st_mode & 0o777)
                try:
                    with self.assertRaises(consumer.StageLConsumerHold):
                        with consumer._hold_original_replay_inputs(self.store, self.project, self.template) as verify:
                            path.rename(backup)
                            replacement.rename(path)
                            self.assertNotEqual(inode, path.stat().st_ino)
                            verify()
                    self.assertEqual(raw, path.read_bytes())
                    self.assertEqual(raw, backup.read_bytes())
                finally:
                    if backup.exists():
                        path.rename(replacement)
                        backup.rename(path)
                self.assertEqual(inode, path.stat().st_ino)

    def test_original_source_replay_refuses_unreceipted_generation_without_creating_evidence(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        before = {p.relative_to(self.project).as_posix(): p.read_bytes()
                  for p in (self.project / '.tracker').rglob('*') if p.is_file()}
        with tracker_writer(self.project, self.publication) as token:
            with mock.patch.object(consumer, 'qualify_prod_stage_l') as native:
                with self.assertRaises(consumer.StageLConsumerHold):
                    consumer.replay_original_receipted_prod_source(
                        self.store, http_root=self.root, settings=current_k(token),
                        whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                        expected_template_sha256=self.snapshot.workbook_sha256,
                        local_generation_id='gen-00000000000000000001-' + 'a' * 32,
                        writer_token=token)
                native.assert_not_called()
        self.assertEqual(before, {p.relative_to(self.project).as_posix(): p.read_bytes()
            for p in (self.project / '.tracker').rglob('*') if p.is_file()})

    def test_original_source_replay_refuses_released_owner_before_native_reads(self):
        from monitor import issue_tracker_stage_l_consumer as consumer
        with tracker_writer(self.project, self.publication) as token:
            settings = current_k(token)
        with mock.patch.object(consumer, 'qualify_prod_stage_l') as native:
            with self.assertRaises(consumer.StageLConsumerHold):
                consumer.replay_original_receipted_prod_source(
                    self.store, http_root=self.root, settings=settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                    expected_template_sha256=self.snapshot.workbook_sha256,
                    local_generation_id='gen-00000000000000000001-' + 'a' * 32,
                    writer_token=token)
            native.assert_not_called()

    def test_source_file_identity_requires_regular_named_bytes_and_records_mtime(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, _bound_source_file,
        )

        source = self.root / "monitor/status/synthetic-panel-source.bin"
        source.write_bytes(b"independent fixture source\n")
        digest = hashlib.sha256(b"independent fixture source\n").hexdigest()
        relative = source.relative_to(self.root).as_posix()
        first = _bound_source_file(self.root, relative, digest)
        self.assertEqual(relative, first.path)
        self.assertEqual(digest, first.sha256)
        self.assertEqual(source.stat().st_mtime_ns, first.mtime_ns)
        self.assertTrue(first.recorded_at_utc.endswith("Z"))
        with self.assertRaises(StageLConsumerHold):
            _bound_source_file(self.root, relative, "0" * 64)
        old = source.stat().st_mtime_ns
        os.utime(source, ns=(old + 2_000_000_000, old + 2_000_000_000))
        second = _bound_source_file(self.root, relative, digest)
        self.assertNotEqual(first, second)  # same bytes but stale timestamp
        alias = source.with_name("synthetic-panel-alias.bin")
        alias.symlink_to(source.name)
        with self.assertRaises(StageLConsumerHold):
            _bound_source_file(self.root, alias.relative_to(self.root).as_posix(),
                               digest)

    def test_source_validation_rejects_same_bytes_same_mtime_inode_replacement(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, _bound_source_file,
            validate_prod_stage_l_panel_source_files,
        )

        content = b"independent fixture source\n"
        digest = hashlib.sha256(content).hexdigest()
        source = self.root / "monitor/status/synthetic-panel-source.bin"
        source.write_bytes(content)
        relative = source.relative_to(self.root).as_posix()
        original = _bound_source_file(self.root, relative, digest)

        replacement = source.with_name("synthetic-panel-replacement.bin")
        replacement.write_bytes(content)
        os.utime(replacement, ns=(original.mtime_ns, original.mtime_ns))
        os.replace(replacement, source)
        current = _bound_source_file(self.root, relative, digest)
        self.assertEqual(original.sha256, current.sha256)
        self.assertEqual(original.size_bytes, current.size_bytes)
        self.assertEqual(original.mtime_ns, current.mtime_ns)
        self.assertNotEqual(original.inode, current.inode)

        with mock.patch(
            "monitor.issue_tracker_stage_l_consumer.read_prod_stage_l_panel_source_files",
            return_value=(current,),
        ) as reread:
            with self.assertRaisesRegex(StageLConsumerHold, "changed; preview again"):
                validate_prod_stage_l_panel_source_files(
                    (original,), object(), object(), panel="Switch Status",
                    http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot,
                    whitelist_path=self.template,
                )
        reread.assert_called_once()

    def test_panel_source_identity_rejects_unbound_caller_rows(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, read_prod_stage_l_panel_source_files,
        )

        with self.assertRaises(StageLConsumerHold):
            read_prod_stage_l_panel_source_files(
                {"project_key": self.store.project_key}, self.store,
                panel="Switch Status", http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )

    def test_dynamic_switch_host_without_frozen_fabric_identity_holds(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
        )

        self._cycle(dynamic_eth=True)
        self._cycle(dynamic_eth=True)
        with self.assertRaisesRegex(StageLConsumerHold, "Fabric"):
            inspect_prod_stage_l_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )

    def test_fabric_classifier_refuses_unresolved_identity_instead_of_guessing(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, classify_stage_l_fabric,
        )

        self.assertEqual(("Compute", "type"), classify_stage_l_fabric(
            "eth_spx", "tan-leaf", "oob-leaf",
        ))
        self.assertEqual(("OOB", "template"), classify_stage_l_fabric(
            "eth", "oob-leaf", "tan-leaf",
        ))
        self.assertEqual(("Inband", "hostname-fallback"),
                         classify_stage_l_fabric("eth", "", "tan-leaf"))
        with self.assertRaises(StageLConsumerHold):
            classify_stage_l_fabric("eth", "", "leaf-a")

    def test_source_projection_rejects_caller_dict_not_a_bound_witness(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, project_prod_stage_l_source_candidates,
        )

        with self.assertRaises(StageLConsumerHold):
            project_prod_stage_l_source_candidates(
                {"qualified": True}, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )

    def test_qualification_holds_without_protected_ib_and_fabric(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, qualify_prod_stage_l,
        )

        self.two_cycles(activity=True, derivation=True)
        with self.assertRaises(StageLConsumerHold):
            qualify_prod_stage_l(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )

    def test_composed_source_never_infers_missing_ib_from_real_eth_activity(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_composed_sources,
            validate_prod_stage_l_composed_sources,
        )

        self.two_cycles(activity=True, derivation=True)
        with self.assertRaises(StageLConsumerHold):
            inspect_prod_stage_l_composed_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_composed_sources(
                {"cycle_ids": ("0" * 64,)}, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_switch_and_ib_source_requires_real_ib_completed_role(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        with self.assertRaises(StageLConsumerHold):
            inspect_prod_stage_l_bound_sources(
                self.store, http_root=self.root, settings=self.settings,
                whitelist_snapshot=self.snapshot, whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_switch_and_ib_source_rejects_foreign_ib_cycle_or_topology(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_bound_sources,
        )

        self.two_cycles()
        cycles = read_completed_cycle_evidence(self.store)
        row = IbReportLink(
            "Mis-wiring", ("leaf-ib", "1/1", "server01", "mlx5_0"),
            ("server02", "mlx5_1"), "Miswired_Links", 2,
        )
        reports = {
            cycle.sequence: IbBoundCycleReport(
                cycle.cycle_id, cycle.sequence, cycle.completion_sha256,
                f"{cycle.sequence}" * 64, "a" * 64, (row,),
            ) for cycle in cycles
        }
        reports[cycles[-1].sequence] = IbBoundCycleReport(
            "foreign-cycle", cycles[-1].sequence,
            cycles[-1].completion_sha256, "2" * 64, "a" * 64, (row,),
        )
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaises(StageLConsumerHold):
                inspect_prod_stage_l_bound_sources(
                    self.store, http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                )
        reports[cycles[-1].sequence] = IbBoundCycleReport(
            cycles[-1].cycle_id, cycles[-1].sequence,
            cycles[-1].completion_sha256, "2" * 64, "b" * 64, (row,),
        )
        with mock.patch(
            "monitor.issue_tracker_ib_runtime.read_completed_ib_cycle_report",
            side_effect=lambda _store, *, http_root, sequence: reports[sequence],
        ):
            with self.assertRaises(StageLConsumerHold):
                inspect_prod_stage_l_bound_sources(
                    self.store, http_root=self.root, settings=self.settings,
                    whitelist_snapshot=self.snapshot, whitelist_path=self.template,
                )

    def test_latest_rows_follow_cycle_sequence_not_k_window_length(self):
        from monitor.issue_tracker_stage_l_consumer import inspect_prod_stage_l_sources
        from test_cases import test_issue_tracker_switch_runtime_workflow as workflow

        self.two_cycles()
        with mock.patch.object(workflow, "TOKEN_2", "abcdef01234546778899aabbccddeeff"):
            third, _ = self._cycle()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual(third["cycle_id"], source.cycle_ids[-1])
        self.assertEqual(2, len(source.cycle_ids))

    def test_real_prod_switch_values_are_bound_but_ib_absence_prevents_qualification(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            require_complete_stage_l_sources,
        )

        first, second, _ = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual((first["cycle_id"], second["cycle_id"]), source.cycle_ids)
        self.assertEqual("hold", source.state)
        self.assertFalse(source.qualified)
        self.assertEqual("ib_report_not_bound_to_completed_cycle", source.reason)
        self.assertEqual(("leaf-a", "fan", "PSU1/FAN1"),
                         (source.switch_rows[0].hostname,
                          source.switch_rows[0].category,
                          source.switch_rows[0].component_or_sensor))
        self.assertIn("state=fail", source.switch_rows[0].value.evidence_description)
        self.assertTrue(any(row.source_slot == "nvlink/prod"
                            for row in source.switch_rows))
        with self.assertRaisesRegex(StageLConsumerHold,
                                    "IB report.*completed cycle"):
            require_complete_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings,
                whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.assertEqual((), tuple(self.publication.iterdir()))

    def test_k_whitelist_or_last_cycle_drift_never_becomes_source_authority(self):
        from monitor.issue_tracker_stage_l_consumer import (
            StageLConsumerHold, inspect_prod_stage_l_sources,
            validate_prod_stage_l_sources,
        )

        _, _, artifacts = self.two_cycles()
        source = inspect_prod_stage_l_sources(
            self.store, http_root=self.root, settings=self.settings,
            whitelist_snapshot=self.snapshot, whitelist_path=self.template,
        )
        self.assertEqual(source, validate_prod_stage_l_sources(
            source, self.store, http_root=self.root,
            settings=self.settings, whitelist_snapshot=self.snapshot,
            whitelist_path=self.template,
        ))
        self.template.write_bytes(literal_xlsx(rules=("nvsw01",)))
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )
        self.template.write_bytes(literal_xlsx())
        latest_info = artifacts["ethernet/prod"]["info"]
        latest_info.write_bytes(latest_info.read_bytes() + b"late drift")
        with self.assertRaises(StageLConsumerHold):
            validate_prod_stage_l_sources(
                source, self.store, http_root=self.root,
                settings=self.settings, whitelist_snapshot=self.snapshot,
                whitelist_path=self.template,
            )


if __name__ == "__main__":
    unittest.main()
