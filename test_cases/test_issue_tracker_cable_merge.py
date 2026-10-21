"""Independent business-key merge tests against literal current online cells."""
from dataclasses import replace
import importlib
from pathlib import Path
import unittest

from monitor.issue_tracker_source_model import CablingSourceRow, SwitchSourceWorkbookRow, TrackerChanges
from test_cases.test_issue_tracker_local_workbook import CABLING_HEADERS, SWITCH_HEADERS


def load(case):
    location = Path(__file__).resolve().parents[1]/'monitor/issue_tracker_cable_merge.py'
    case.assertTrue(location.is_file(), 'CableTracker-style current-online merge module is required')
    return importlib.import_module('monitor.issue_tracker_cable_merge')


def text(value):
    return {'stringValue': value}


def columns(width, values):
    row = [{} for _ in range(width)]
    for column, value in values.items():
        index = 0
        for char in column:
            index = index*26+ord(char)-64
        row[index-1] = value if type(value) is dict else text(value)
    return tuple(row)


def book(module, *, eth=(), ib=(), switch=None):
    if switch is None:
        switch = ((2, columns(21, {'A':'NV10001', 'D':{'formulaValue':'=1'},
                                 'E':{'formulaValue':'=2'}, 'G':{'formulaValue':'=3'},
                                 'H':{'formulaValue':'=4'}, 'I':{'formulaValue':'=5'}})),)
    return (
        module.SheetImage('ETH&IB Switch', 12, SWITCH_HEADERS, switch),
        module.SheetImage('ETH Cabling', 13, CABLING_HEADERS, eth),
        module.SheetImage('IB Cabling', 14, CABLING_HEADERS, ib),
    )


def cabling(sheet='ETH Cabling', kind='Link Down'):
    family = 'eth_cabling' if sheet == 'ETH Cabling' else 'ib_cabling'
    return CablingSourceRow(sheet, (family,'leaf01','swp1',kind),
        ('leaf01','swp1','spine01','swp9'), (), 'DOWN', '=literal evidence', '2026-10-21T03:30:00Z')


class CableMergeTests(unittest.TestCase):
    def test_absent_empty_tool_cells_are_nochange_but_formulas_are_not_empty(self):
        module=load(self)
        from monitor.issue_tracker_online_cells import source_tool_values
        row=cabling()
        values=source_tool_values(row,'insert',reserved_id='NV40000')
        for column in ('M','N','S','T'):
            values.pop(column)
        image=book(module,eth=((2,columns(29,values)),))
        plan=module.plan_current_online(TrackerChanges((row,),()),image)
        self.assertEqual(plan.requests_json,b'[]\n')
        self.assertEqual(plan.actions,())
        for nonempty in ({'formulaValue':'=""'},{'numberValue':0},{'boolValue':False}):
            altered=dict(values,M=nonempty)
            with self.subTest(nonempty=nonempty):
                update=module.plan_current_online(TrackerChanges((row,),()),
                    book(module,eth=((2,columns(29,altered)),)))
                self.assertNotEqual(update.requests_json,b'[]\n')

    def test_nonliteral_active_business_keys_are_unknown_not_absent(self):
        module=load(self)
        from monitor.issue_tracker_online_cells import source_tool_values
        row=cabling()
        values=source_tool_values(row,'insert',reserved_id='NV40000')
        for column in ('K','L','F'):
            for unknown in ({'formulaValue':'="leaf01"'},{'numberValue':1},{'boolValue':True}):
                changed=dict(values,**{column:unknown})
                with self.subTest(column=column,unknown=unknown),self.assertRaises(module.CableMergeHold):
                    module.plan_current_online(TrackerChanges((row,),()),
                        book(module,eth=((2,columns(29,changed)),)))
        switch=SwitchSourceWorkbookRow(('switch','leaf02','fan','PSU1/FAN'),'unhealthy',
                                       'Inband','template','P2','2026-10-21T03:30:00Z')
        base=dict(zip('ABCDEFGHIJKLMNOPQRSTU',book(module)[0].rows[0][1]))
        occupied=dict(base,F={'formulaValue':'="leaf02"'},
                      L=text('[MONITOR][fan][PSU1/FAN] old'),N=text('New'))
        spare=dict(base,A=text('NV10002'),I={})
        with self.assertRaises(module.CableMergeHold):
            module.plan_current_online(TrackerChanges((),(switch,)),book(module,switch=(
                (2,tuple(occupied[key] for key in 'ABCDEFGHIJKLMNOPQRSTU')),
                (3,tuple(spare[key] for key in 'ABCDEFGHIJKLMNOPQRSTU')))))

    def test_source_order_does_not_reassign_online_shared_sequence(self):
        module=load(self)
        eth=cabling();ib=cabling('IB Cabling')
        forward=module.plan_current_online(TrackerChanges((eth,ib),()),book(module))
        reverse=module.plan_current_online(TrackerChanges((ib,eth),()),book(module))
        self.assertEqual(forward.requests_json,reverse.requests_json)
        self.assertEqual(forward.actions,reverse.actions)

    def test_repeated_source_uses_online_business_key_not_local_row_or_identifier(self):
        module = load(self)
        row = cabling()
        # The local workbook NV IDs/row coordinates do not enter this API.
        initial = book(module, ib=((2,columns(29,{'A':'NV90000','U':'Closed'})),))
        plan = module.plan_current_online(TrackerChanges((row,),()), initial)
        import json
        requests = json.loads(plan.requests_json)
        cells = requests[0]['appendCells']['rows'][0]['values']
        self.assertEqual(cells[0], {'userEnteredValue':text('NV90001')})
        self.assertEqual(cells[6]['userEnteredValue']['stringValue'][-17:], '=literal evidence')
        self.assertEqual(plan.actions, (('ETH Cabling','Insert',row.activity_key),))
        self.assertNotIn('formulaValue', plan.requests_json.decode())

    def test_merge_preserves_online_id_date_status_and_every_operator_column(self):
        module = load(self)
        from monitor.issue_tracker_online_cells import source_tool_values
        row = cabling()
        old_values = source_tool_values(row,'insert',reserved_id='NV45678')
        old_values.update({'G':old_values['G'].split(' ',1)[0]+' old', 'D':'2025-01-01',
                          'U':'In Progress','V':'human notes','W':'AI','X':'NV comments',
                          'Y':'human owner','Z':'engineer','AA':'action','AB':'P1'})
        original = columns(29,old_values)
        image = book(module,eth=((9,original),))
        plan = module.plan_current_online(TrackerChanges((row,),()),image)
        import json
        requests = json.loads(plan.requests_json)
        self.assertTrue(requests)
        written = set()
        for req in requests:
            update = req['updateCells']
            self.assertEqual(update['start']['rowIndex'],9)
            self.assertEqual(update['start']['sheetId'],13)
            start = update['start']['columnIndex']
            written.update(range(start,start+len(update['rows'][0]['values'])))
        self.assertEqual(written,{6,12,13,18,19})
        self.assertEqual(image[1].rows[0][1], original)
        self.assertEqual(plan.actions,(('ETH Cabling','Update',row.activity_key),))

    def test_no_change_still_retains_closed_history_and_new_type_gets_new_id(self):
        module = load(self)
        from monitor.issue_tracker_online_cells import source_tool_values
        row = cabling()
        values = source_tool_values(row,'insert',reserved_id='NV40000')
        exact = columns(29,values)
        image = book(module,eth=((2,exact),))
        no_change = module.plan_current_online(TrackerChanges((row,),()),image)
        self.assertEqual(no_change.requests_json,b'[]\n')
        self.assertEqual(no_change.actions,())
        changed_type = replace(row,activity_key=('eth_cabling','leaf01','swp1','Mis-wiring'))
        plan = module.plan_current_online(TrackerChanges((changed_type,),()),image)
        import json
        self.assertEqual(json.loads(plan.requests_json)[0]['appendCells']['rows'][0]['values'][0],
                         {'userEnteredValue':text('NV40001')})
        self.assertEqual(image[1].rows,((2,exact),))
        closed = dict(values,U='Closed')
        recurrence = module.plan_current_online(TrackerChanges((row,),()),
            book(module,eth=((2,columns(29,closed)),)))
        self.assertEqual(json.loads(recurrence.requests_json)[0]['appendCells']['rows'][0]['values'][0],
                         {'userEnteredValue':text('NV40001')})

    def test_switch_uses_reserved_formula_slot_and_update_changes_description_only(self):
        module = load(self)
        row = SwitchSourceWorkbookRow(('switch','leaf02','fan','PSU1/FAN'),'unhealthy',
                                       'Inband','template','P2','2026-10-21T03:30:00Z')
        import json
        plan = module.plan_current_online(TrackerChanges((),(row,)),book(module))
        written=set()
        for req in json.loads(plan.requests_json):
            update=req['updateCells'];self.assertEqual(update['start']['rowIndex'],2)
            start=update['start']['columnIndex']
            written.update(range(start,start+len(update['rows'][0]['values'])))
        self.assertEqual(written,{1,2,5,9,10,11,13})
        from monitor.issue_tracker_online_cells import source_tool_values
        used=source_tool_values(row,'insert')
        reserved=dict(zip('ABCDEFGHIJKLMNOPQRSTU',book(module)[0].rows[0][1]))
        reserved.update({k:text(v) for k,v in used.items()})
        reserved.update({'L':text('[MONITOR][fan][PSU1/FAN] old'), 'O':text('operator')})
        image=book(module,switch=((2,tuple(reserved[k] for k in 'ABCDEFGHIJKLMNOPQRSTU')),))
        update=module.plan_current_online(TrackerChanges((),(row,)),image)
        self.assertEqual(len(json.loads(update.requests_json)),1)
        self.assertEqual(json.loads(update.requests_json)[0]['updateCells']['start'],
                         {'sheetId':12,'rowIndex':2,'columnIndex':11})

    def test_duplicate_or_unowned_active_keys_headers_ids_and_sources_refuse_before_plan(self):
        module=load(self)
        from monitor.issue_tracker_online_cells import source_tool_values
        row=cabling()
        values=source_tool_values(row,'insert',reserved_id='NV40000')
        for image in (
            book(module,eth=((2,columns(29,values)),(3,columns(29,dict(values,A='NV40001'))))),
            book(module,eth=((2,columns(29,dict(values,G='human issue'))),)),
            book(module,eth=((2,columns(29,values)),),ib=((2,columns(29,{'A':'NV40000'})),)),
            (replace(book(module)[0],headers=('wrong',)*21),*book(module)[1:]),
            (book(module)[0],book(module)[1]),
        ):
            with self.subTest(image=image),self.assertRaises(module.CableMergeHold):
                module.plan_current_online(TrackerChanges((row,),()),image)
        with self.assertRaises(module.CableMergeHold):
            module.plan_current_online(TrackerChanges((row,row),()),book(module))


if __name__=='__main__':unittest.main()
