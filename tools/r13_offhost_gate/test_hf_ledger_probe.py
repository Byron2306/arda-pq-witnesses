import io
import socket
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
from gateway import DurableLedger, Handler

class Response400:
    def open(self,*args,**kwargs):
        raise urllib.error.HTTPError('https://example.invalid',400,'invalid',{},io.BytesIO(b'{"claimed":false,"error":"INVALID_CLAIM"}'))
class Deny403:
    def open(self,*args,**kwargs):
        raise urllib.error.HTTPError('https://example.invalid',403,'blocked',{},io.BytesIO(b'secret data'))
class DNSFailure:
    def open(self,*args,**kwargs):
        raise urllib.error.URLError(socket.gaierror(-3,'internal details'))
class TestProbe(unittest.TestCase):
    def test_400_means_reachable_without_ledger_mutation(self):
        ledger=DurableLedger('https://example.invalid','s'*64,opener=Response400())
        self.assertEqual(ledger.probe_transport(),{'probe':'LEDGER_REACHABLE','http':400})
    def test_http_refusal_is_redacted(self):
        ledger=DurableLedger('https://example.invalid','s'*64,opener=Deny403())
        got=ledger.probe_transport()
        self.assertEqual(got,{'probe':'LEDGER_HTTP_REFUSAL','http':403})
        self.assertNotIn('secret',repr(got))
    def test_dns_classification_redacted(self):
        ledger=DurableLedger('https://example.invalid','s'*64,opener=DNSFailure())
        self.assertEqual(ledger.probe_transport(),{'probe':'LEDGER_TRANSPORT_FAILURE','category':'DNS'})
    def test_endpoint_closed_in_normal_standby(self):
        h=object.__new__(Handler)
        h.path='/v1/test-ledger-probe';h.test_until=None;h.relay=None
        output=[];h.reply=lambda status,data:output.append((status,data))
        h.do_POST()
        self.assertEqual(output,[(503,{'error':'RELAY_STANDBY','interlock':'KEEP_CLOSED'})])
    def test_probe_requires_bearer(self):
        class Relay:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
        h=object.__new__(Handler)
        h.path='/v1/test-ledger-probe';h.test_until=9999999999;h.relay=Relay()
        h.headers={'Authorization':'','Content-Type':'application/json'}
        output=[];h.reply=lambda status,data:output.append((status,data))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(output,[(401,{'error':'UNAUTHORIZED'})])
    def test_probe_rejects_nonempty_request(self):
        class Ledger:
            def probe_transport(self):raise AssertionError('must not call')
        class Relay:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            ledger=Ledger()
        h=object.__new__(Handler)
        h.path='/v1/test-ledger-probe';h.test_until=9999999999;h.relay=Relay()
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':'2'}
        h.rfile=io.BytesIO(b'[]')
        output=[];h.reply=lambda status,data:output.append((status,data))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(output,[(400,{'error':'INVALID_PROBE'})])
