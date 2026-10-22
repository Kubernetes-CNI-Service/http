"""Real SDK + owned TLS complete grid -> existing merge DATA, not authorization."""
import importlib.util,json,unittest
from urllib.parse import urlencode
from test_cases import fixed_https_peer_fixture as fixture
from test_cases import test_req7_cable_fullgrid as literal

class FullGridSdkMergeWorkflowTests(unittest.TestCase):
    def test_real_sdk_tls_three_current_sheets_decode_merge_and_preserve_human_history(self):
        grid=literal.entry(self)
        self.assertIsNotNone(importlib.util.find_spec('monitor.issue_tracker_cable_fixed_https'),
                             'MISSING_FIXED_FULL_GRID_WIRE_ROLE')
        from monitor import issue_tracker_cable_fixed_https as transport
        from monitor.issue_tracker_cable_merge import plan_current_online
        from monitor.issue_tracker_source_model import TrackerChanges,CablingSourceRow,SwitchSourceWorkbookRow
        from google.oauth2.credentials import Credentials
        from google_auth_httplib2 import AuthorizedHttp
        from googleapiclient.discovery import build
        document=literal.document();body=literal.raw(document)
        unit=transport._protocol_only_http('sheets-grid',target=literal.TARGET)
        # Owned protocol bearer only; no claim of actual current-source/SA grant.
        frozen=Credentials(token='owned-grid-token')
        result=None
        with fixture.peer(self,[fixture.response(200,body)]) as peer:
            with peer.client(transport) as sockets:
                service=build('sheets','v4',http=AuthorizedHttp(frozen,http=unit,max_refresh_attempts=0),
                              static_discovery=True,cache_discovery=False)
                request=service.spreadsheets().get(spreadsheetId=literal.TARGET,includeGridData=True,
                                                  ranges=list(literal.RANGES),fields=literal.FIELDS)
                result=request.execute(num_retries=0)
                first=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                self.assertEqual(3,len(peer.closed))
                self.assertTrue(all(closed for _name,closed in peer.closed))
                with self.assertRaises(transport.FixedHttpsHold):request.execute(num_retries=0)
                self.assertEqual(first,(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed)))
                service.close()
            self.assertEqual([],peer.errors)
            self.assertEqual([('sheets.googleapis.com',443)],sockets.lookups)
            self.assertEqual(['sheets.googleapis.com'],peer.sni)
            self.assertEqual(1,len(peer.accepts));self.assertEqual(1,len(peer.records))
            line,headers,request_body=peer.records[0]
            query=urlencode([('includeGridData','true'),*[('ranges',r) for r in literal.RANGES],
                             ('fields',literal.FIELDS),('alt','json')])
            self.assertEqual(('GET /v4/spreadsheets/synthetic_spreadsheet_id_0001?'+query+' HTTP/1.1\r\n').encode('ascii'),line)
            self.assertIn(b'Host: sheets.googleapis.com\r\n',headers)
            self.assertIn(b'Authorization: Bearer owned-grid-token\r\n',headers)
            self.assertEqual(b'',request_body)
        self.assertEqual(document,result,'REAL_SDK_MUST_PARSE_COMPLETE_PEER_BODY')
        images=grid.sheet_images_from_sdk(literal.TARGET,result)
        self.assertEqual((12,13,14),tuple(image.sheet_id for image in images))
        self.assertEqual((literal.SWITCH_HEADERS,literal.CABLING_HEADERS,literal.CABLING_HEADERS),
                         tuple(image.headers for image in images))
        before=tuple((image.name,image.sheet_id,image.rows) for image in images)
        change=CablingSourceRow('IB Cabling',('ib_cabling','leaf01','swp1','Link Down'),
            ('leaf01','swp1','spine01','swp9'),(),'DOWN','=literal evidence','2026-10-21T03:30:00Z')
        switch=SwitchSourceWorkbookRow(('switch','leaf01','fan','PSU1/FAN'),'new evidence',
            'Inband','template','P2','2026-10-21T03:30:00Z')
        plan=plan_current_online(TrackerChanges((change,),(switch,)),images)
        self.assertEqual((('IB Cabling','Insert',('ib_cabling','leaf01','swp1','Link Down')),
                          ('ETH&IB Switch','Update',('switch','leaf01','fan','PSU1/FAN'))),plan.actions)
        requests=json.loads(plan.requests_json)
        self.assertEqual(2,len(requests))
        append=requests[0]['appendCells']
        self.assertEqual(14,append['sheetId']);self.assertEqual('userEnteredValue',append['fields'])
        cells=append['rows'][0]['values']
        self.assertEqual({'userEnteredValue':{'stringValue':'NV40006'}},cells[0])
        self.assertEqual({'userEnteredValue':{'stringValue':'2026-10-21'}},cells[3])
        self.assertEqual({'userEnteredValue':{'stringValue':'IB'}},cells[4])
        self.assertEqual({'userEnteredValue':{'stringValue':'Link Down'}},cells[5])
        self.assertTrue(cells[6]['userEnteredValue']['stringValue'].endswith('DOWN: =literal evidence'))
        self.assertEqual({'userEnteredValue':{'stringValue':'New'}},cells[20])
        self.assertEqual({'updateCells':{'start':{'sheetId':12,'rowIndex':2,'columnIndex':11},
            'rows':[{'values':[{'userEnteredValue':{'stringValue':'[MONITOR][fan][PSU1/FAN] [fabric_source=template] new evidence'}}]}],
            'fields':'userEnteredValue'}},requests[1])
        self.assertEqual(before,tuple((image.name,image.sheet_id,image.rows) for image in images))
        self.assertEqual({'stringValue':'Closed'},images[1].rows[0][1][20])
        self.assertEqual({'stringValue':'human note'},images[1].rows[0][1][21])
        self.assertEqual({'formulaValue':'=1+2'},images[1].rows[0][1][22])
        self.assertEqual({'boolValue':False},images[1].rows[0][1][23])
        self.assertEqual({'stringValue':'keep closed IB'},images[2].rows[0][1][21])
        self.assertEqual({'formulaValue':'="CVT human"'},images[2].rows[0][1][28])
        self.assertEqual({'stringValue':'human-owner'},images[0].rows[0][1][14])
        self.assertEqual({'formulaValue':'=1'},images[0].rows[0][1][3])
        self.assertEqual(2,len(plan.history_rows)) # DATA only; never append History.

if __name__=='__main__':unittest.main(verbosity=2)
