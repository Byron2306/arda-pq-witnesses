"""Diagnostic repository_dispatch POST must never route to R13 ledger workflow."""
import io
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
from gateway import Handler, Relay, RelayStageError

class ProbeTests(unittest.TestCase):
    def test_single_harmless_event(self):
        captured=[]
        relay=Relay({},b'',None,dispatch=lambda payload:captured.append(payload))
        with patch.object(relay,'_dispatch',side_effect=lambda payload:captured.append(payload)):
            result=relay.probe_github_dispatch_write()
        self.assertEqual(result,{'probe':'GITHUB_DISPATCH_HTTP','http':204,'ledger':'NOT_ATTEMPTED'})
        self.assertEqual(len(captured),1)
        self.assertEqual(captured[0]['event_type'],'arda_r13_dispatch_permission_probe_v1')
        self.assertEqual(captured[0]['client_payload'],{'schema':'arda.r13.dispatch_permission_probe.v1'})
        self.assertNotIn('box',repr(captured))
    def test_refused_http_is_redacted(self):
        relay=Relay({},b'',None)
        with patch.object(relay,'_dispatch',side_effect=RelayStageError('GITHUB_HTTP_REFUSAL',http_status=403)):
            result=relay.probe_github_dispatch_write()
        self.assertEqual(result,{'probe':'GITHUB_DISPATCH_HTTP','stage':'GITHUB_HTTP_REFUSAL',
                                 'http':403,'ledger':'NOT_ATTEMPTED'})
    def test_transport_refusal_is_redacted(self):
        relay=Relay({},b'',None)
        with patch.object(relay,'_dispatch',side_effect=RelayStageError('GITHUB_TRANSPORT_FAILURE')):
            result=relay.probe_github_dispatch_write()
        self.assertEqual(result,{'probe':'GITHUB_DISPATCH_HTTP','stage':'GITHUB_TRANSPORT_FAILURE','ledger':'NOT_ATTEMPTED'})
    def test_route_refuses_without_v6_backend(self):
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            def probe_github_dispatch_write(self):raise AssertionError('must not execute')
        h=object.__new__(Handler)
        h.path='/v1/test-ledger-probe'
        h.test_until=9999999999
        h.relay=R()
        body=b'{"mode":"github-dispatch-write"}'
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':str(len(body))}
        h.rfile=io.BytesIO(body)
        answers=[];h.reply=lambda code,data:answers.append((code,data))
        with patch('gateway.active',return_value=True),patch.dict('gateway.os.environ',{'ARDA_RELAY_TEST_BACKEND':'legacy'}):
            h.do_POST()
        self.assertEqual(answers[0][0],403)
        self.assertEqual(answers[0][1]['error'],'V6_BACKEND_REQUIRED')
    def test_route_v6_calls_only_probe(self):
        class R:
            cfg={'ARDA_RELAY_INGEST_TOKEN':'a'*64}
            def probe_github_dispatch_write(self):return {'probe':'GITHUB_DISPATCH_HTTP','http':204,'ledger':'NOT_ATTEMPTED'}
        h=object.__new__(Handler)
        h.path='/v1/test-ledger-probe'
        h.test_until=9999999999
        h.relay=R()
        body=b'{"mode":"github-dispatch-write"}'
        h.headers={'Authorization':'Bearer '+('a'*64),'Content-Type':'application/json','Content-Length':str(len(body))}
        h.rfile=io.BytesIO(body)
        answers=[];h.reply=lambda code,data:answers.append((code,data))
        with patch('gateway.active',return_value=True),patch.dict('gateway.os.environ',{'ARDA_RELAY_TEST_BACKEND':'github-v6'}):
            h.do_POST()
        self.assertEqual(answers[0],(200,{'probe':'GITHUB_DISPATCH_HTTP','http':204,'ledger':'NOT_ATTEMPTED'}))
    def test_event_unmatched_in_checked_workflows(self):
        root=Path(__file__).resolve().parents[2]/'.github/workflows'
        for workflow in ('arda-r13-encrypted-relay-v4.yml','arda-r13-github-ledger-v6.yml'):
            content=(root/workflow).read_text()
            self.assertNotIn('arda_r13_dispatch_permission_probe_v1',content)
if __name__=='__main__':unittest.main()
