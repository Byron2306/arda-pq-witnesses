import http.client
import json
import threading
import unittest
from unittest.mock import Mock
from arda_quorum.enrollment_http import SetupOnce,make_setup_server
from arda_quorum.enrollment import new_ceremony
from arda_quorum.quorum import canonical,sha

class SetupHTTPTests(unittest.TestCase):
    def setUp(self):
        self.c=new_ceremony(nonce='ab'*32,image_digest='sha256:'+'cd'*32,identities={'github':'operator/github','hf':'operator/hf','cloudflare':'cf-release'},now=1000)
        self.call=Mock(return_value={'payload':{'public':'only'},'signature_b64':'public-proof'})
        self.once=SetupOnce(self.c,{},clock=lambda:1000,provisioner=self.call)
        self.s=make_setup_server(self.once,'aa'*32,host='127.0.0.1',port=0)
        self.t=threading.Thread(target=self.s.serve_forever,kwargs={'poll_interval':0.01},daemon=True);self.t.start()
    def tearDown(self):self.s.shutdown();self.s.server_close();self.t.join(2)
    def request(self,raw=None,token='aa'*32,path='/v1/enroll-hf',method='POST',headers=None):
        c=http.client.HTTPConnection(*self.s.server_address,timeout=10)
        try:
            c.request(method,path,body=raw if raw is not None else canonical({'action':'provision_hf_key','ceremony_sha256':sha(canonical(self.c))}),
                headers=headers or {'X-ARDA-Setup-Token':token,'Content-Type':'application/json'})
            r=c.getresponse();return r.status,json.loads(r.read())
        finally:c.close()
    def test_startup_and_health_do_not_generate_keys(self):
        status,body=self.request(path='/healthz',method='GET',raw=b'')
        self.assertEqual(status,200);self.assertEqual(body['state'],'WAITING');self.call.assert_not_called()
    def test_authenticated_trigger_is_once_and_returns_only_public_record(self):
        for i in range(2):
            status,body=self.request();self.assertEqual(status,200);self.assertFalse(body['production_authorized']);self.assertIn('registration',body)
        self.call.assert_called_once()
    def test_wrong_token_and_wrong_ceremony_do_not_generate(self):
        self.assertEqual(self.request(raw=b'invalid',token='bb'*32)[0],401)
        self.assertEqual(self.request(raw=canonical({'action':'provision_hf_key','ceremony_sha256':'ef'*32}))[0],400)
        self.call.assert_not_called()
    def test_no_vote_or_arbitrary_action_route(self):
        self.assertEqual(self.request(path='/v1/review-vote')[0],404)
        self.assertEqual(self.request(raw=canonical({'action':'sign','ceremony_sha256':sha(canonical(self.c))}))[0],400)
        self.call.assert_not_called()
    def test_failed_upload_does_not_retry_in_process_or_expose_errors(self):
        self.call.side_effect=RuntimeError('sensitive-token')
        for i in range(2):
            status,body=self.request();self.assertEqual(status,409);self.assertNotIn('sensitive',str(body))
        self.call.assert_called_once()
    def test_malformed_framing_and_large_body_refused(self):
        self.assertEqual(self.request(raw=b'x'*1025)[0],413)
        self.assertEqual(self.request(raw=b'{"a":1,"a":2}')[0],400)
        headers={'Content-Type':'application/json','X-ARDA-Setup-Token':'aa'*32,'Transfer-Encoding':'chunked'}
        self.assertEqual(self.request(raw=b'{}',headers=headers)[0],415)
        self.call.assert_not_called()
    def test_concurrent_setup_is_refused_without_second_generation(self):
        entered=threading.Event();release=threading.Event();results=[]
        def slow(*args,**kwargs):entered.set();release.wait(3);return {'public':'record'}
        self.once.provisioner=slow
        thread=threading.Thread(target=lambda:results.append(self.once.trigger()));thread.start()
        try:
            self.assertTrue(entered.wait(2))
            with self.assertRaises(ValueError):self.once.trigger()
        finally:release.set();thread.join(3)
        self.assertEqual(results,[{'public':'record'}])
    def test_expiry_between_upload_and_return_refuses_record(self):
        # trigger checks before starting, before upload, and after upload.
        self.once.clock=iter([1000,1000,87400]).__next__
        with self.assertRaises(ValueError):self.once.trigger()
        self.assertEqual(self.once.state,'FAILED')
