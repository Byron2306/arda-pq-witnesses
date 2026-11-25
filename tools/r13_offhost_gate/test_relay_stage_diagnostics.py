import io
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
from gateway import DurableLedger, Relay, RelayStageError, Handler

class HTTPRefusal:
    def __init__(self,status):self.status=status
    def open(self,*args,**kwargs):
        raise urllib.error.HTTPError('https://secret.invalid',self.status,'SECRET',{},io.BytesIO(b'SECRET'))
class NetworkFailure:
    def open(self,*args,**kwargs):raise urllib.error.URLError('SECRET')
class StageTests(unittest.TestCase):
    def test_ledger_http_and_conflict(self):
        l=DurableLedger('https://example.test','SECRET',opener=HTTPRefusal(403))
        with self.assertRaises(RelayStageError) as e:l.call('reserve',{})
        self.assertEqual(e.exception.stage,'LEDGER_HTTP_REFUSAL')
        self.assertNotIn('SECRET',str(e.exception))
        l.opener=HTTPRefusal(409)
        self.assertEqual(l.call('reserve',{}),(409,{}))
    def test_ledger_network(self):
        l=DurableLedger('https://example.test','SECRET',opener=NetworkFailure())
        with self.assertRaises(RelayStageError) as e:l.call('reserve',{})
        self.assertEqual(e.exception.stage,'LEDGER_TRANSPORT_FAILURE')
    def test_github_http(self):
        r=Relay({'ARDA_RELAY_GITHUB_REPO':'Byron2306/arda-pq-witnesses','ARDA_RELAY_GITHUB_TOKEN':'SECRET'},b'0'*32,None)
        with patch('gateway.urllib.request.build_opener',return_value=HTTPRefusal(403)):
            with self.assertRaises(RelayStageError) as e:r._dispatch({'event_type':'test'})
        self.assertEqual(e.exception.stage,'GITHUB_HTTP_REFUSAL')
        self.assertEqual(e.exception.http_status,403)
        self.assertNotIn('SECRET',str(e.exception))
    def test_github_network(self):
        r=Relay({'ARDA_RELAY_GITHUB_REPO':'Byron2306/arda-pq-witnesses','ARDA_RELAY_GITHUB_TOKEN':'SECRET'},b'0'*32,None)
        with patch('gateway.urllib.request.build_opener',return_value=NetworkFailure()):
            with self.assertRaises(RelayStageError) as e:r._dispatch({'event_type':'test'})
        self.assertEqual(e.exception.stage,'GITHUB_TRANSPORT_FAILURE')
    def test_http_response_only_stage(self):
        class Fake:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'x'*64}
            def submit(self,raw):raise RelayStageError('LEDGER_HTTP_REFUSAL')
        h=object.__new__(Handler)
        h.path='/v1/test-submit';h.test_until=9999999999;h.relay=Fake()
        h.headers={'Authorization':'Bearer '+('x'*64),'Content-Type':'application/json','Content-Length':'2'}
        h.rfile=io.BytesIO(b'{}')
        answers=[];h.reply=lambda code,data:answers.append((code,data))
        with patch('gateway.active',return_value=True),patch('gateway.synthetic_capture',return_value=True):
            h.do_POST()
        self.assertEqual(answers,[(503,{'error':'RELAY_UNAVAILABLE','stage':'LEDGER_HTTP_REFUSAL','interlock':'KEEP_CLOSED'})])

    def test_handler_reports_only_github_status_no_provider_body(self):
        class Fake:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'x'*64}
            def submit(self,raw):raise RelayStageError('GITHUB_HTTP_REFUSAL',http_status=403)
        h=object.__new__(Handler)
        h.path='/v1/test-submit';h.test_until=9999999999;h.relay=Fake()
        h.headers={'Authorization':'Bearer '+('x'*64),'Content-Type':'application/json','Content-Length':'2'}
        h.rfile=io.BytesIO(b'{}')
        answers=[];h.reply=lambda code,data:answers.append((code,data))
        with patch('gateway.active',return_value=True),patch('gateway.synthetic_capture',return_value=True):
            h.do_POST()
        self.assertEqual(answers,[(503,{'error':'RELAY_UNAVAILABLE','stage':'GITHUB_HTTP_REFUSAL','interlock':'KEEP_CLOSED','upstream_http_status':403})])
    def test_invalid_upstream_status_refused(self):
        with self.assertRaisesRegex(ValueError,'INVALID_HTTP_STATUS'):
            RelayStageError('GITHUB_HTTP_REFUSAL',http_status=204)
