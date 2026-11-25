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

    def test_tcp_timeout_is_attributed_to_tcp(self):
        class Socket:
            def settimeout(self, seconds): self.seconds=seconds
            def connect(self, address): raise socket.timeout('hidden network detail')
            def close(self): pass
        ledger=DurableLedger('https://private-ledger.example','SECRET_TOKEN')
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443))]
        with patch('gateway.socket.getaddrinfo',return_value=addresses), patch('gateway.socket.socket',return_value=Socket()):
            value=ledger.probe_connection_phases()
        self.assertEqual(value['routes'][0]['phase'],'TCP')
        self.assertEqual(value['routes'][0]['status'],'TIMEOUT')
        self.assertIn('tcp_ms',value['routes'][0])
        self.assertNotIn('tls_ms',value['routes'][0])
        self.assertNotIn('hidden network detail',repr(value))
    def test_tls_timeout_is_attributed_to_tls(self):
        class Socket:
            def settimeout(self, seconds): pass
            def connect(self, address): pass
            def close(self): pass
        class SSL:
            def wrap_socket(self, connection, server_hostname):
                raise socket.timeout('hidden tls detail')
        ledger=DurableLedger('https://private-ledger.example','SECRET_TOKEN')
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443))]
        with patch('gateway.socket.getaddrinfo',return_value=addresses), patch('gateway.socket.socket',return_value=Socket()), patch('gateway.ssl.create_default_context',return_value=SSL()):
            value=ledger.probe_connection_phases()
        self.assertEqual(value['routes'][0]['phase'],'TLS')
        self.assertEqual(value['routes'][0]['status'],'TIMEOUT')
        self.assertIn('tcp_ms',value['routes'][0])
        self.assertIn('tls_ms',value['routes'][0])
        self.assertNotIn('hidden tls detail',repr(value))

    def test_tls_differential_caps_addresses_and_attempts(self):
        class FakeSocket:
            def settimeout(self,n):pass
            def connect(self,address):self.address=address
            def close(self):pass
        class FakeTLS:
            def __enter__(self):return self
            def __exit__(self,*args):return False
        class FakeContext:
            minimum_version=None
            maximum_version=None
            def wrap_socket(self,conn,server_hostname):
                self.hostname=server_hostname
                return FakeTLS()
        ledger=DurableLedger('https://private-ledger.example','SECRET_TOKEN')
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',(f'192.0.2.{i}',443)) for i in (1,1,2,3)]
        with patch('gateway.socket.getaddrinfo',return_value=addresses),patch('gateway.socket.socket',side_effect=lambda *a:FakeSocket()),patch('gateway.ssl.create_default_context',side_effect=lambda:FakeContext()):
            data=ledger.probe_tls_differential()
        self.assertEqual(data['probe'],'TLS_DIFFERENTIAL_RESULTS')
        self.assertEqual(data['targets'],2)
        self.assertEqual(len(data['attempts']),8)
        self.assertEqual({i['tls_version'] for i in data['attempts']},{'TLS1_2','TLS1_3'})
        self.assertEqual({i['status'] for i in data['attempts']},{'PASS'})
        self.assertNotIn('192.0.2',repr(data))
        self.assertNotIn('private-ledger.example',repr(data))
        self.assertNotIn('SECRET_TOKEN',repr(data))
    def test_tls_differential_classifies_timeout_and_redacts(self):
        class TimeoutSocket:
            def settimeout(self,n):pass
            def connect(self,address):raise socket.timeout('INTERNAL_CONNECTION_DETAIL')
            def close(self):pass
        ledger=DurableLedger('https://private-ledger.example','SECRET_TOKEN')
        addresses=[(socket.AF_INET,socket.SOCK_STREAM,6,'',('192.0.2.1',443))]
        with patch('gateway.socket.getaddrinfo',return_value=addresses),patch('gateway.socket.socket',return_value=TimeoutSocket()):
            data=ledger.probe_tls_differential()
        self.assertEqual(len(data['attempts']),4)
        self.assertTrue(all(i['phase']=='TCP' and i['status']=='TIMEOUT' for i in data['attempts']))
        self.assertNotIn('INTERNAL_CONNECTION_DETAIL',repr(data))
    def test_tls_differential_route_is_gated_by_bearer(self):
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
        h=object.__new__(Handler);h.path='/v1/test-ledger-probe';h.test_until=9999999999;h.relay=R()
        h.headers={'Authorization':'','Content-Type':'application/json'}
        answers=[];h.reply=lambda code,body:answers.append((code,body))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(answers[0][0],401)
    def test_tls_differential_route_requires_active_test_window(self):
        class L:
            def probe_tls_differential(self):raise AssertionError('should not be invoked')
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            ledger=L()
        h=object.__new__(Handler);h.path='/v1/test-ledger-probe';h.test_until=9999999999;h.relay=R()
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':'27'}
        h.rfile=io.BytesIO(b'{"mode":"tls-differential"}')
        answers=[];h.reply=lambda code,body:answers.append((code,body))
        with patch('gateway.active',return_value=False):h.do_POST()
        self.assertEqual(answers[0][0],503)
    def test_tls_differential_dispatches_no_other_operation(self):
        class L:
            def probe_tls_differential(self):return {'probe':'TLS_DIFFERENTIAL_RESULTS','targets':0,'attempts':[]}
            def reserve(self,*args):raise AssertionError('reserve forbidden')
            def claim(self,*args):raise AssertionError('claim forbidden')
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            ledger=L()
        h=object.__new__(Handler);h.path='/v1/test-ledger-probe';h.test_until=9999999999;h.relay=R()
        body=b'{"mode":"tls-differential"}'
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':str(len(body))}
        h.rfile=io.BytesIO(body)
        answers=[];h.reply=lambda code,body:answers.append((code,body))
        with patch('gateway.active',return_value=True):h.do_POST()
        self.assertEqual(answers[0][0],200)
        self.assertEqual(answers[0][1]['probe'],'TLS_DIFFERENTIAL_RESULTS')
