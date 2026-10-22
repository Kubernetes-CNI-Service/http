"""Independent literal full-grid DATA decode contract; not source or send authority."""
import copy,importlib.util,json,unittest
from test_cases.test_issue_tracker_local_workbook import SWITCH_HEADERS,CABLING_HEADERS

TARGET='synthetic_spreadsheet_id_0001'
FIELDS='spreadsheetId,sheets(properties(sheetId,title,sheetType,gridProperties(rowCount,columnCount)),data(startRow,startColumn,rowData(values(userEnteredValue))))'
RANGES=("'ETH&IB Switch'!A2:U5002","'ETH Cabling'!A2:AC10002","'IB Cabling'!A2:AC10002")

def entry(test):
    test.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_cable_grid'),
                         'MISSING_FIXED_FULL_GRID_DECODER')
    from monitor import issue_tracker_cable_grid as grid
    test.assertTrue(callable(getattr(grid,'decode_current_grid',None)))
    test.assertTrue(callable(getattr(grid,'sheet_images_from_sdk',None)))
    return grid

def cell(value):
    return {'userEnteredValue':value if type(value) is dict else {'stringValue':value}}

def row(width,values):
    cells=[{} for _ in range(width)]
    for index,value in values.items():cells[index]=cell(value)
    return {'values':cells}

def document():
    switch=row(21,{0:'NV10001',1:'2025-01-01',3:{'formulaValue':'=1'},
      4:{'formulaValue':'=2'},5:'leaf01',6:{'formulaValue':'=3'},7:{'formulaValue':'=4'},
      8:{'formulaValue':'=5'},11:'[MONITOR][fan][PSU1/FAN] old',13:'Investigating',
      14:'human-owner',20:'human-comment'})
    eth=row(29,{0:'NV40000',3:'2024-01-02',5:'Link Down',10:'leaf01',11:'swp1',
      20:'Closed',21:'human note',22:{'formulaValue':'=1+2'},23:{'boolValue':False},
      24:'human-assignee'})
    ib=row(29,{0:'NV40005',3:'2024-02-03',5:'Link Down',10:'leaf01',11:'swp1',
      20:'Closed',21:'keep closed IB',28:{'formulaValue':'="CVT human"'}})
    return {'spreadsheetId':TARGET,'sheets':[
      {'properties':{'sheetId':12,'title':'ETH&IB Switch','sheetType':'GRID',
        'gridProperties':{'rowCount':5,'columnCount':21}},
       'data':[{'startRow':1,'startColumn':0,'rowData':[row(21,dict(enumerate(SWITCH_HEADERS))),switch]}]},
      {'properties':{'sheetId':13,'title':'ETH Cabling','sheetType':'GRID',
        'gridProperties':{'rowCount':6,'columnCount':29}},
       'data':[{'startRow':1,'rowData':[row(29,dict(enumerate(CABLING_HEADERS))),eth]}]},
      {'properties':{'sheetId':14,'title':'IB Cabling','sheetType':'GRID',
        'gridProperties':{'rowCount':4,'columnCount':29}},
       'data':[{'startRow':1,'startColumn':0,'rowData':[row(29,dict(enumerate(CABLING_HEADERS))),ib]}]}]}

def raw(value):
    return json.dumps(value,ensure_ascii=False,separators=(',',':')).encode('utf-8')

class FullGridDecodeTests(unittest.TestCase):
    def test_literal_three_sheet_geometry_headers_capacity_and_original_cells(self):
        grid=entry(self)
        from monitor.issue_tracker_cable_merge import SheetImage
        original=document();encoded=raw(original)
        images=grid.decode_current_grid(TARGET,encoded)
        self.assertEqual(('ETH&IB Switch','ETH Cabling','IB Cabling'),tuple(x.name for x in images))
        self.assertEqual((12,13,14),tuple(x.sheet_id for x in images))
        self.assertTrue(all(type(x) is SheetImage for x in images))
        self.assertEqual((SWITCH_HEADERS,CABLING_HEADERS,CABLING_HEADERS),tuple(x.headers for x in images))
        self.assertEqual((2,2,2),tuple(x.rows[0][0] for x in images))
        self.assertEqual((21,29,29),tuple(len(x.rows[0][1]) for x in images))
        self.assertEqual({'formulaValue':'=1+2'},images[1].rows[0][1][22])
        self.assertEqual({'boolValue':False},images[1].rows[0][1][23])
        self.assertEqual({'stringValue':'Closed'},images[1].rows[0][1][20])
        self.assertEqual(images,grid.sheet_images_from_sdk(TARGET,original))
        original['sheets'][1]['data'][0]['rowData'][1]['values'][21]['userEnteredValue']['stringValue']='changed caller'
        self.assertEqual({'stringValue':'human note'},images[1].rows[0][1][21])
        mutations=[]
        def changed(path,value):
            d=document();node=d
            for key in path[:-1]:node=node[key]
            node[path[-1]]=value;mutations.append(d)
        changed(('spreadsheetId',),'foreign_target')
        changed(('sheets',0,'properties','sheetId'),True)
        changed(('sheets',1,'properties','sheetId'),12)
        changed(('sheets',0,'properties','sheetType'),'OBJECT')
        changed(('sheets',0,'properties','gridProperties','rowCount'),5003)
        changed(('sheets',1,'properties','gridProperties','rowCount'),10003)
        changed(('sheets',1,'properties','gridProperties','columnCount'),30)
        changed(('sheets',2,'properties','gridProperties','rowCount'),2)
        changed(('sheets',0,'data',0,'startRow'),0)
        changed(('sheets',0,'data',0,'startColumn'),1)
        changed(('sheets',0,'data'),[])
        changed(('sheets',0,'data',0,'rowData',0,'values',0),cell('WRONG HEADER'))
        changed(('sheets',0,'data',0,'rowData',1,'values',20),{'effectiveValue':{'stringValue':'not entered'}})
        changed(('sheets',1,'data',0,'rowData',1,'values',22),cell({'formulaValue':''}))
        changed(('sheets',1,'data',0,'rowData',1,'values',23),cell({'numberValue':True}))
        changed(('sheets',2,'data',0,'rowData',1,'values'),[{}]*30)
        d=document();d['sheets'].append(copy.deepcopy(d['sheets'][0]));mutations.append(d)
        d=document();d['sheets'][0]['data'].append(copy.deepcopy(d['sheets'][0]['data'][0]));mutations.append(d)
        d=document();d['sheets'][2]['data'][0]['rowData'] += [{}]*4;mutations.append(d)
        d=document();d['unrequested']='extra';mutations.append(d)
        for number,d in enumerate(mutations):
            with self.subTest(invalid=number):
                caught=None
                try:grid.decode_current_grid(TARGET,raw(d))
                except grid.CableGridHold as error:caught=error
                self.assertIsNotNone(caught)
                self.assertEqual('current_grid_invalid',str(caught))
                self.assertIsNone(caught.__context__);self.assertIsNone(caught.__cause__)
        for bad in (b'\xff',b'{"spreadsheetId":1,"spreadsheetId":2}',b'{"x":NaN}',b' '*2097153):
            with self.subTest(raw=bad[:25]),self.assertRaises(grid.CableGridHold):
                grid.decode_current_grid(TARGET,bad)

if __name__=='__main__':unittest.main(verbosity=2)
