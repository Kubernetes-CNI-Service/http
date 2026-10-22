import hashlib
import importlib
import importlib.util
import json
import unittest


class FixedReadV2ProtocolTests(unittest.TestCase):
    def test_literal_capacity_ack_shape_and_strict_framing(self):
        spec = importlib.util.find_spec('monitor.issue_tracker_read_live_protocol_v2')
        self.assertIsNotNone(spec, 'MISSING_FIXED_READ_V2_PROTOCOL')
        codec = importlib.import_module('monitor.issue_tracker_read_live_protocol_v2')
        nonce = 'a' * 64
        data = {'unicode': '界' * 690000, 'literal': ['A', 7, None, True]}
        canonical = json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode('utf-8')
        self.assertGreater(len(canonical), 2 * 1024 * 1024 - 30000)
        digest = hashlib.sha256(canonical).hexdigest()
        ready = dict(v=2, nonce=nonce, event='READY', data=data,
                     ready_at=100.0, expires_at=160.0, digest=digest)
        raw = (json.dumps(ready, ensure_ascii=False, separators=(',', ':')) + '\n').encode('utf-8')
        self.assertEqual(codec.decode_event(raw, nonce), ready)
        self.assertEqual(codec.data_digest(data), digest)
        self.assertEqual(json.loads(codec.encode_ready(nonce, data, 100.0)), ready)
        live = dict(v=2, nonce=nonce, event='LIVE', serial=17, digest=digest)
        self.assertEqual(json.loads(codec.encode_live(nonce, 17, digest)), live)
        self.assertLess(len(codec.encode_live(nonce, 17, digest)), 256)
        self.assertNotIn('data', live)
        self.assertEqual(json.loads(codec.encode_command(nonce, 'CHECK', 17)),
                         dict(v=2, nonce=nonce, command='CHECK', serial=17))
        self.assertEqual(json.loads(codec.encode_command(nonce, 'CLOSE')),
                         dict(v=2, nonce=nonce, command='CLOSE'))
        faults = [raw + b'\n', raw.replace(b'"v":2', b'"v":2,"v":2', 1),
                  raw.replace(b'"expires_at":160.0', b'"expires_at":161.0', 1),
                  raw.replace(digest.encode(), b'0' * 64, 1),
                  b'{"v":2,"nonce":"' + nonce.encode() + b'","event":"LIVE","serial":true,"digest":"' + digest.encode() + b'"}\n',
                  codec.encode_live(nonce, 17, digest).replace(b'"serial":17', b'"serial":17,"data":{}'),
                  b'{"v":2,"nonce":"' + nonce.encode() + b'","event":"READY","data":{},"ready_at":NaN,"expires_at":60,"digest":"' + digest.encode() + b'"}\n']
        for fault in faults:
            with self.subTest(fault_size=len(fault)):
                with self.assertRaises(codec.ProtocolHold):
                    codec.decode_event(fault, nonce)
        with self.assertRaises(codec.ProtocolHold):
            codec.encode_ready(nonce, {'x': '界' * 700000}, 100.0)
        for serial in (0, 1025, True, '1'):
            with self.assertRaises(codec.ProtocolHold):
                codec.encode_command(nonce, 'CHECK', serial)
