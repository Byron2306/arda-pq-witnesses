import base64
import copy
import json
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from github_review_inbox import canonical,decode_response

class InboxTests(unittest.TestCase):
    def setUp(self):
        self.session='a'*64
        self.envelope=dict(schema='arda.github.review_inbox.v1',session=self.session,run_id='123',run_attempt='1',request=dict(schema='arda.pq.witness_request.v1',proposal={},capture={}))
    def body(self,envelope=None,data=None):
        raw=canonical(envelope or self.envelope) if data is None else data
        return json.dumps(dict(encoding='base64',content=base64.b64encode(raw).decode())).encode()
    def test_accept_only_bound_run(self):
        self.assertEqual(decode_response(self.body(),self.session,'123','1'),canonical(self.envelope['request']))
    def test_session_run_attempt_schema_and_fields_refused(self):
        for key,value in [('session','b'*64),('run_id','124'),('run_attempt','2'),('schema','other'),('extra',1)]:
            with self.subTest(key=key):
                envelope=copy.deepcopy(self.envelope);envelope[key]=value
                with self.assertRaises(ValueError):decode_response(self.body(envelope),self.session,'123','1')
    def test_duplicate_json_and_noncanonical_refused(self):
        for data in [canonical(self.envelope)+b'\n',canonical(self.envelope).replace(b'"run_id":"123"',b'"run_id":"123","run_id":"123"')]:
            with self.assertRaises(ValueError):decode_response(self.body(data=data),self.session,'123','1')
    def test_oversize_request_refused(self):
        self.envelope['request']['capture']={'data':'x'*65536}
        with self.assertRaises(ValueError):decode_response(self.body(),self.session,'123','1')
    def test_unknown_request_fields_refused(self):
        self.envelope['request']['extra']=True
        with self.assertRaises(ValueError):decode_response(self.body(),self.session,'123','1')

if __name__=='__main__':unittest.main()
