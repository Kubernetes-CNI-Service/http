"""Independent literal HTTP transcript expectations; no SDK/business permit."""
import unittest
from test_cases import fixed_https_peer_fixture as fixture


class FixedHttpsDirectTests(unittest.TestCase):
    def test_fixed_post_and_get_consume_once_and_all_denials_have_no_second_emission(self):
        transport=fixture.entry(self)
        for kind in ('token','sheets-read'):
            for fault in ('healthy','redirect','unauthorized','half-response','server-error','quota'):
                with self.subTest(kind=kind,fault=fault):
                    reply=(fixture.response(200) if fault=='healthy' else
                        fixture.response(302,location=True) if fault=='redirect' else
                        fixture.response(401) if fault=='unauthorized' else
                        fixture.response(500) if fault=='server-error' else
                        fixture.response(429) if fault=='quota' else
                        fixture.response(200,length=99))
                    http=transport._protocol_only_http(kind,target=None if kind=='token' else fixture.TARGET)
                    uri=fixture.TOKEN_URL if kind=='token' else fixture.READ_URL
                    method='POST' if kind=='token' else 'GET'
                    payload=b'fixture=literal' if kind=='token' else None
                    headers=({'Content-Type':'application/x-www-form-urlencoded'} if kind=='token'
                             else {'Authorization':'Bearer owned-direct-token'})
                    value=error=None
                    with fixture.peer(self,[reply]) as peer:
                        with peer.client(transport) as sockets:
                            try:value=http.request(uri,method=method,body=payload,headers=headers)
                            except transport.FixedHttpsHold as caught:error=caught
                            first=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                            with self.assertRaises(transport.FixedHttpsHold):
                                http.request(uri,method=method,body=payload,headers=headers)
                            after=(len(sockets.lookups),len(sockets.created),len(peer.records),tuple(peer.closed))
                        self.assertEqual(first,after,'REUSE_MUST_NOT_ADD_IO_OR_CLEANUP')
                        self.assertEqual([],peer.errors)
                        self.assertEqual(1,len(peer.accepts))
                        self.assertEqual([('oauth2.googleapis.com' if kind=='token' else 'sheets.googleapis.com',443)],sockets.lookups)
                        self.assertEqual(['oauth2.googleapis.com' if kind=='token' else 'sheets.googleapis.com'],peer.sni)
                        self.assertEqual(1,len(peer.records))
                        line,actual_headers,body=peer.records[0]
                        if kind=='token':
                            self.assertEqual(b'POST /token HTTP/1.1\r\n',line)
                            self.assertEqual((b'Host: oauth2.googleapis.com\r\n',b'Connection: close\r\n',
                                b'Accept-Encoding: identity\r\n',b'Content-Length: 15\r\n',
                                b'Content-Type: application/x-www-form-urlencoded\r\n'),actual_headers)
                            self.assertEqual(b'fixture=literal',body)
                        else:
                            self.assertEqual(b'GET /v4/spreadsheets/synthetic_spreadsheet_id_0001?fields=spreadsheetId&alt=json HTTP/1.1\r\n',line)
                            self.assertEqual((b'Host: sheets.googleapis.com\r\n',b'Connection: close\r\n',
                                b'Accept-Encoding: identity\r\n',b'Authorization: Bearer owned-direct-token\r\n'),actual_headers)
                            self.assertEqual(b'',body)
                        self.assertEqual(3,len(peer.closed))
                        self.assertTrue(all(closed for _kind,closed in peer.closed))
                    if fault=='healthy':
                        self.assertIsNone(error)
                        self.assertEqual(200,value[0].status)
                        self.assertEqual(b'{}',value[1])
                    else:
                        self.assertIsNone(value)
                        self.assertIsNotNone(error)
                        self.assertEqual('fixed_https_denied',str(error))
                        self.assertIsNone(error.__context__)
                        self.assertIsNone(error.__cause__)

        # Invalid destination consumes BEFORE DNS/CA/connect. No new URL,
        # proxy, CA or mutable-header permission is obtained by a second call.
        with fixture.peer(self,[]) as peer:
            with peer.client(transport) as sockets:
                for uri in ('https://foreign.invalid/token',fixture.TOKEN_URL+'?foreign=1'):
                    http=transport._protocol_only_http('token')
                    with self.assertRaises(transport.FixedHttpsHold):
                        http.request(uri,method='POST',body=b'fixture=literal',
                                     headers={'Content-Type':'application/x-www-form-urlencoded'})
                    with self.assertRaises(transport.FixedHttpsHold):
                        http.request(fixture.TOKEN_URL,method='POST',body=b'fixture=literal',
                                     headers={'Content-Type':'application/x-www-form-urlencoded'})
                self.assertEqual([],sockets.lookups)
                self.assertEqual([],sockets.created)
            self.assertEqual([],peer.records)
            self.assertEqual([],peer.accepts)
            self.assertEqual([],peer.errors)


if __name__=='__main__':unittest.main(verbosity=2)
