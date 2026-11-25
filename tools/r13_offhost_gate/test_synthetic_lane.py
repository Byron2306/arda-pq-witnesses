import io
import json
import os
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
import gateway
from synthetic_lane import deadline, active, synthetic_capture, MARKER

class TestLane(unittest.TestCase):
    def setUp(self):
        self.now=int(time.time())
    def test_no_test_mode_default(self):
        self.assertIsNone(deadline({'ARDA_RELAY_STANDBY_ONLY':'1'},now=self.now))
    def test_requires_standby(self):
        with self.assertRaisesRegex(RuntimeError,'TEST_REQUIRES_STANDBY'):
            deadline({'ARDA_RELAY_STANDBY_ONLY':'0','ARDA_RELAY_TEST_UNTIL':str(self.now+120)},now=self.now)
    def test_bounded_deadline(self):
        with self.assertRaisesRegex(RuntimeError,'TEST_DEADLINE_NOT_BOUNDED'):
            deadline({'ARDA_RELAY_STANDBY_ONLY':'1','ARDA_RELAY_TEST_UNTIL':str(self.now+901)},now=self.now)
        v=deadline({'ARDA_RELAY_STANDBY_ONLY':'1','ARDA_RELAY_TEST_UNTIL':str(self.now+120)},now=self.now)
        self.assertTrue(active(v,now=self.now))
        self.assertFalse(active(v,now=self.now+121))
    def test_expired_deadline_starts_safe_standby(self):
        val=deadline({'ARDA_RELAY_STANDBY_ONLY':'1','ARDA_RELAY_TEST_UNTIL':str(self.now-1)},now=self.now)
        self.assertIsNone(val)
        fake_server=type('FakeServer',(),{'serve_forever':lambda self: None})
        with patch.dict(os.environ,{'ARDA_RELAY_STANDBY_ONLY':'1','ARDA_RELAY_TEST_UNTIL':str(self.now-1)},clear=True):
            with patch.object(gateway,'ThreadingHTTPServer',return_value=fake_server()):
                with patch.object(gateway,'require_config',side_effect=AssertionError('must not read secrets')):
                    gateway.main()
        self.assertIsNone(gateway.Handler.relay)
    def test_test_lane_refuses_unmarked_or_nonempty_evidence(self):
        base={'schema':'arda.r13.capture.v2','issued_challenge':{'challenge':{}},'evidence':{},'receipt':{'test_only':MARKER}}
        self.assertTrue(synthetic_capture(json.dumps(base).encode()))
        self.assertFalse(synthetic_capture(b'{}'))
        self.assertFalse(synthetic_capture(json.dumps({**base,'receipt':{}}).encode()))
        self.assertFalse(synthetic_capture(json.dumps({**base,'evidence':{'evil':True}}).encode()))
    def test_default_standby_rejects_test_submit(self):
        h=object.__new__(gateway.Handler);h.path='/v1/test-submit';h.relay=None;h.test_until=None
        replies=[];h.reply=lambda code,body:replies.append((code,body))
        h.do_POST()
        self.assertEqual(replies[0][0],503)
    def test_test_window_keeps_normal_ingest_closed(self):
        h=object.__new__(gateway.Handler);h.path='/v1/submit';h.relay=object();h.test_until=self.now+120
        replies=[];h.reply=lambda code,body:replies.append((code,body))
        h.do_POST()
        self.assertEqual(replies[0][0],503)
        self.assertEqual(replies[0][1]['interlock'],'KEEP_CLOSED')
    def test_expired_window_refuses_even_claim(self):
        h=object.__new__(gateway.Handler);h.path='/v1/claim';h.relay=object();h.test_until=self.now-1
        replies=[];h.reply=lambda code,body:replies.append((code,body))
        h.do_POST()
        self.assertEqual(replies[0][0],503)
    def test_marked_synthetic_reaches_mock_relay(self):
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'x'*64}
            def submit(self,raw):return {'accepted':True}
        h=object.__new__(gateway.Handler);h.path='/v1/test-submit';h.relay=R();h.test_until=self.now+120
        cap={'schema':'arda.r13.capture.v2','issued_challenge':{'challenge':{}},'evidence':{},'receipt':{'test_only':MARKER}}
        raw=json.dumps(cap).encode()
        h.headers={'Authorization':'Bearer '+('x'*64),'Content-Type':'application/json','Content-Length':str(len(raw))}
        h.rfile=io.BytesIO(raw)
        replies=[];h.reply=lambda code,body:replies.append((code,body))
        h.do_POST()
        self.assertEqual(replies,[(202,{'accepted':True})])
