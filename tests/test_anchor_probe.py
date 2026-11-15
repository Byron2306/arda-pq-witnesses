import threading
import unittest
from tools.probe_hss_anchor import AnchorProbe,REPO,GENESIS,RULESET_ID

class Network:
    def __init__(self):self.refs={};self.tags={};self.lock=threading.Lock();self.allow_update=False;self.allow_delete=False;self.bypass=False;self.creation=False;self.calls=[]
    def request(self,method,path,body=None):
        with self.lock:
            self.calls.append((method,path))
            if path=='':return 200,{'full_name':REPO,'private':False,'archived':False,'fork':False}
            if path==f'/rulesets/{RULESET_ID}':return 200,{'id':RULESET_ID,'target':'tag','enforcement':'active','bypass_actors':[{'actor_id':1}] if self.bypass else [],'conditions':{'ref_name':{'include':['refs/tags/arda-hss-leaf-*'],'exclude':[]}},'rules':[{'type':'update'},{'type':'deletion'}]+([{'type':'creation'}] if self.creation else [])}
            if path=='/git/commits/'+GENESIS:return 200,{'sha':GENESIS}
            if method=='POST' and path=='/git/tags':
                sha=f'{len(self.tags)+1:040x}';self.tags[sha]=body;return 201,{'sha':sha}
            if method=='POST' and path=='/git/refs':
                name=body['ref']
                if name in self.refs:return 422,{'message':'Reference already exists'}
                self.refs[name]=body['sha'];return 201,{'ref':name,'object':{'type':'tag','sha':body['sha']}}
            if method=='GET' and path.startswith('/git/ref/tags/'):
                name='refs/tags/'+path.split('/git/ref/tags/',1)[1]
                return 200,{'ref':name,'object':{'type':'tag','sha':self.refs[name]}}
            if method=='PATCH':
                if self.allow_update:
                    name='refs/tags/'+path.split('/git/refs/tags/',1)[1];self.refs[name]=body['sha'];return 200,{}
                return 422,{'message':'Repository rule violations found'}
            if method=='DELETE':
                if self.allow_delete:
                    name='refs/tags/'+path.split('/git/refs/tags/',1)[1];del self.refs[name];return 204,{}
                return 422,{'message':'Repository rule violations found'}
            raise AssertionError((method,path))

class AnchorProbeTests(unittest.TestCase):
    def test_race_has_one_winner_and_rules_block_mutation(self):
        n=Network();r=AnchorProbe('test-token',request=n.request).run()
        self.assertTrue(r['protection_enforced']);self.assertFalse(r['live_hss_key_used']);self.assertFalse(r['production_authorized'])
        self.assertEqual(len(n.refs),1);self.assertIn('refs/tags/arda-hss-leaf-',r['probe_ref'])
    def test_update_success_is_failure_not_accepted_protection(self):
        n=Network();n.allow_update=True
        with self.assertRaises(ValueError):AnchorProbe('test-token',request=n.request).run()
    def test_delete_success_is_failure_not_accepted_protection(self):
        n=Network();n.allow_delete=True
        with self.assertRaises(ValueError):AnchorProbe('test-token',request=n.request).run()
    def test_bypass_or_creation_restriction_refuses_before_any_mutation(self):
        for field in ('bypass','creation'):
            n=Network();setattr(n,field,True)
            with self.assertRaises(ValueError):AnchorProbe('test-token',request=n.request).run()
            self.assertFalse(any(method!='GET' for method,path in n.calls))
    def test_rate_limit_cannot_masquerade_as_protection(self):
        n=Network()
        def request(method,path,body=None):
            if method in ('PATCH','DELETE'):return 403,{'message':'API rate limit exceeded'}
            return n.request(method,path,body)
        with self.assertRaises(ValueError):AnchorProbe('test-token',request=request).run()
    def test_setup_token_does_not_appear_in_public_report(self):
        n=Network();r=AnchorProbe('private-fixture-credential',request=n.request).run()
        self.assertNotIn('private-fixture-credential',str(r))
