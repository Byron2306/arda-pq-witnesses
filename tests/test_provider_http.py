import http.client
import json
import threading
import unittest
from arda_quorum import provider_http
from arda_quorum import provider_witness
from arda_quorum.quorum import canonical
from provider_fixtures import ProviderFixtures as F

class ProviderHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        F.start();cls.witness=provider_witness.ReviewWitness(**F.kwargs('hf'))
        cls.server=provider_http.make_server(cls.witness,'aa'*32,host='127.0.0.1',port=0)
        cls.thread=threading.Thread(target=cls.server.serve_forever,kwargs={'poll_interval':0.05},daemon=True);cls.thread.start()
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown();cls.server.server_close();cls.thread.join(3);F.stop()
    def request(self,body=None,token='aa'*32,path='/v1/review-vote',method='POST',headers=None):
        c=http.client.HTTPConnection(*self.server.server_address,timeout=10)
        try:
            raw=canonical(F.request) if body is None else body
            c.request(method,path,body=raw,headers=headers or {'Content-Type':'application/json','Authorization':'Bearer '+token})
            response=c.getresponse();return response.status,json.loads(response.read())
        finally:c.close()
    def test_real_http_vote_has_assigned_algorithm_and_closed_authority(self):
        status,body=self.request();self.assertEqual(status,200,body)
        self.assertEqual(body['vote']['payload']['algorithm'],'SLH-DSA-SHA2-192s')
        self.assertFalse(body['production_authorized'])
    def test_wrong_token_refused_before_body_parsing(self):
        status,body=self.request(body=b'not json',token='bb'*32)
        self.assertEqual(status,401);self.assertNotIn('vote',body)
    def test_duplicate_json_key_refused(self):
        self.assertEqual(self.request(body=b'{"schema":"a","schema":"b"}')[0],400)
    def test_large_body_refused(self):self.assertEqual(self.request(body=b'x'*65537)[0],413)
    def test_unknown_path_and_method_refused(self):
        self.assertEqual(self.request(path='/admin/enroll')[0],404)
        self.assertEqual(self.request(method='PUT')[0],405)
    def test_content_type_encoding_and_transfer_encoding_refused(self):
        for extra in ({'Content-Type':'text/plain'},{'Content-Type':'application/json','Content-Encoding':'gzip'},
                      {'Content-Type':'application/json','Transfer-Encoding':'chunked'}):
            headers={'Authorization':'Bearer '+'aa'*32,**extra}
            self.assertIn(self.request(body=b'{}',headers=headers)[0],(400,415))
    def test_health_exposes_public_identity_only(self):
        status,body=self.request(path='/healthz',method='GET',body=b'')
        self.assertEqual(status,200);self.assertEqual(set(body),{'status','provider','algorithm','key_sha256','production_authorized'})
    def test_duplicate_content_length_refused(self):
        c=http.client.HTTPConnection(*self.server.server_address,timeout=10)
        try:
            c.putrequest('POST','/v1/review-vote');c.putheader('Content-Type','application/json')
            c.putheader('Authorization','Bearer '+'aa'*32);c.putheader('Content-Length','2');c.putheader('Content-Length','3');c.endheaders(b'{}')
            self.assertEqual(c.getresponse().status,400)
        finally:c.close()
    def test_private_gateway_auth_and_application_auth_have_separate_headers(self):
        status,body=self.request(headers={'Content-Type':'application/json','Authorization':'Bearer hf_gateway_placeholder',
            'X-ARDA-Review-Token':'aa'*32})
        self.assertEqual(status,200,body);self.assertIn('vote',body)
    def test_wrong_custom_token_cannot_fall_back_to_valid_legacy_token(self):
        self.assertEqual(self.request(headers={'Content-Type':'application/json','Authorization':'Bearer '+'aa'*32,
            'X-ARDA-Review-Token':'bb'*32})[0],401)
