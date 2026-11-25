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

    def test_environment_probe_never_sends_ledger_bearer(self):
        class SafeOpener:
            def open(self,request,**kwargs):
                self.request=request
                raise urllib.error.HTTPError('https://example.invalid',401,'no credentials',{},io.BytesIO(b''))
        opener=SafeOpener()
        ledger=DurableLedger('https://example.invalid','SECRET_LEDGER_TOKEN',opener=Response400())
        with patch('gateway.urllib.request.build_opener',return_value=opener):
            got=ledger.probe_environment_egress()
        self.assertEqual(got,{'probe':'ENVIRONMENT_ROUTE_HTTP','http':401})
        self.assertNotIn('Authorization',opener.request.headers)
        self.assertNotIn('SECRET_LEDGER_TOKEN',repr(got))
    def test_environment_probe_fails_closed_on_timeout(self):
        class TimeoutOpener:
            def open(self,request,**kwargs):
                raise urllib.error.URLError(TimeoutError('secret detail'))
        ledger=DurableLedger('https://example.invalid','SECRET_LEDGER_TOKEN')
        with patch('gateway.urllib.request.build_opener',return_value=TimeoutOpener()):
            self.assertEqual(ledger.probe_environment_egress(),{'probe':'ENVIRONMENT_ROUTE_FAILURE','category':'TIMEOUT'})

    def test_phase_probe_dns_failure_redacts_hostname(self):
        ledger=DurableLedger('https://secret-host.example','SECRET_LEDGER_TOKEN')
        with patch('gateway.socket.getaddrinfo',side_effect=socket.gaierror(-2,'SECRET_DNS_DETAILS')):
            output=ledger.probe_connection_phases()
        self.assertEqual(output['probe'],'PHASE_REFUSE')
        self.assertEqual(output['phase'],'DNS')
        self.assertNotIn('secret-host',repr(output))
        self.assertNotIn('SECRET',repr(output))
    def test_phase_probe_has_no_outbound_http_credentials(self):
        ledger=DurableLedger('https://secret-host.example','SECRET_LEDGER_TOKEN')
        with patch('gateway.socket.getaddrinfo',return_value=[]):
            result=ledger.probe_connection_phases()
        self.assertEqual(result['category'],'NO_SUPPORTED_ADDRESS')
        self.assertNotIn('SECRET',repr(result))
    def test_phase_endpoint_requires_auth_and_active_window(self):
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
        h=object.__new__(Handler);h.path='/v1/test-ledger-probe'
        h.test_until=9999999999;h.relay=R()
        h.headers={'Authorization':'','Content-Type':'application/json'}
        answers=[];h.reply=lambda code,body:answers.append((code,body))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(answers[0][0],401)
    def test_phase_endpoint_calls_only_phase_probe(self):
        class L:
            def probe_connection_phases(self):return {'probe':'PHASE_RESULTS','dns_ms':1,'routes':[]}
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            ledger=L()
        h=object.__new__(Handler);h.path='/v1/test-ledger-probe'
        h.test_until=9999999999;h.relay=R()
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':'17'}
        h.rfile=io.BytesIO(b'{"mode":"phases"}')
        answers=[];h.reply=lambda code,body:answers.append((code,body))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(answers,[(200,{'probe':'PHASE_RESULTS','dns_ms':1,'routes':[]})])
