"""Synthetic-only V6 acceptance: GitHub reserves before claim; no production authority."""
import base64
import secrets
import sys
import unittest
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization

ROOT=Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'providers/hf/r13-relay'))
from crypto_box import canonical,seal,hash_envelope
from relay_review_v6 import review_v6, GitHubLedger

NOW=1800000000

class Ledger:
    def __init__(self):
        self.challenges=set()
        self.tickets=set()
        self.used=set()
        self.calls=[]
        self.refuse_reserve=False
        self.refuse_claim=False
    def reserve(self,ticket,cid,digest,expiry):
        self.calls.append('reserve')
        if self.refuse_reserve or cid in self.challenges or ticket in self.tickets:
            return False
        self.challenges.add(cid);self.tickets.add(ticket)
        self.expected=(ticket,digest)
        return True
    def claim(self,ticket,digest):
        self.calls.append('claim')
        if self.refuse_claim or (ticket,digest)!=self.expected or ticket in self.used:
            return False
        self.used.add(ticket)
        return True

def fixture(*,synthetic=True):
    key=x25519.X25519PrivateKey.generate()
    sk=key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
    pub=key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
    cid=secrets.token_hex(16)
    capture={'schema':'arda.r13.capture.v2',
        'issued_challenge':{'challenge':{'challenge_id':cid,'issued_at':NOW-1,'expires_at':NOW+120}},
        'evidence':{},'receipt':{'test_only':'arda-r13.synthetic-transport-test.v1'} if synthetic else {}}
    box=seal(canonical(capture),pub)
    item={'schema':'arda.r13.relay_dispatch.v2','ticket':secrets.token_hex(24),
        'challenge_id':cid,'expires_at':NOW+120,'envelope_sha256':hash_envelope(box),'box':box}
    return item,base64.b64encode(sk).decode()

class V6Review(unittest.TestCase):
    def test_synthetic_reserve_claim_order_and_refusal(self):
        item,key=fixture()
        ledger=Ledger()
        outcome=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(ledger.calls,['reserve','claim'])
        self.assertEqual(outcome['reason'],'SYNTHETIC_TRANSPORT_DECRYPTED_R13_NOT_VERIFIED')
        self.assertEqual(outcome['status'],'REFUSE')
        self.assertEqual(outcome['interlock'],'KEEP_CLOSED')
        self.assertFalse(outcome['production_cutover_authorized'])
    def test_duplicate_challenge_is_rejected_before_claim(self):
        item,key=fixture()
        ledger=Ledger()
        review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        again=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(again['reason'],'V6_LEDGER_RESERVATION_REFUSED')
        self.assertEqual(ledger.calls,['reserve','claim','reserve'])
    def test_claim_refusal_is_terminal(self):
        item,key=fixture()
        ledger=Ledger();ledger.refuse_claim=True
        got=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(got['reason'],'V6_LEDGER_CLAIM_REFUSED')
        self.assertEqual(ledger.calls,['reserve','claim'])
    def test_unbound_challenge_never_reaches_ledger(self):
        item,key=fixture()
        ledger=Ledger();item['challenge_id']=secrets.token_hex(16)
        got=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(got['reason'],'V6_CHALLENGE_BINDING')
        self.assertEqual(ledger.calls,[])
    def test_non_synthetic_rejected_before_ledger(self):
        item,key=fixture(synthetic=False)
        ledger=Ledger()
        got=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(got['reason'],'V6_NON_SYNTHETIC_NOT_AUTHORIZED')
        self.assertEqual(ledger.calls,[])
    def test_stale_expiry_never_reaches_ledger(self):
        item,key=fixture()
        ledger=Ledger()
        got=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW+121)
        self.assertEqual(got['reason'],'V6_CHALLENGE_EXPIRED')
        self.assertEqual(ledger.calls,[])
    def test_envelope_digest_mismatch_never_reaches_ledger(self):
        item,key=fixture()
        ledger=Ledger();item['envelope_sha256']='0'*64
        got=review_v6(item,ledger=ledger,private_b64=key,clock=lambda:NOW)
        self.assertEqual(got['reason'],'V6_ENVELOPE_DIGEST')
        self.assertEqual(ledger.calls,[])
    def test_github_ledger_rejects_insecure_origin(self):
        for url in ('http://example.com','https://user:pass@example.com',
                    'https://example.com/bad','https://example.com?secret=1'):
            with self.subTest(url=url),self.assertRaises(ValueError):
                GitHubLedger(url,'x'*64)
    def test_ledger_responses_are_exact(self):
        class Response:
            status=201
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,n):return b'{"reserved":false}'
        class Opener:
            def open(self,request,timeout):return Response()
        ledger=GitHubLedger('https://example.com','x'*64)
        ledger.opener=Opener()
        self.assertFalse(ledger.reserve('a'*48,'b'*32,'c'*64,NOW+120))
    def test_hf_v6_dispatch_does_not_contact_cloudflare(self):
        from crypto_box import unseal
        from gateway import Relay
        item,key=fixture()
        private=base64.b64decode(key)
        public=x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        raw=unseal(item['box'],private)
        class ForbiddenLedger:
            def reserve(self,*args):raise AssertionError('HF must not reserve')
            def claim(self,*args):raise AssertionError('HF must not claim')
        dispatched=[]
        relay=Relay({},public,ForbiddenLedger(),dispatch=dispatched.append,clock=lambda:NOW)
        result=relay.submit_v6_synthetic(raw)
        self.assertTrue(result['accepted'])
        self.assertEqual(len(dispatched),1)
        self.assertEqual(dispatched[0]['event_type'],'arda_r13_capture_v6')
        self.assertEqual(dispatched[0]['client_payload']['schema'],'arda.r13.relay_dispatch.v2')
        self.assertEqual(dispatched[0]['client_payload']['challenge_id'],item['challenge_id'])
    def test_hf_v6_rejects_real_capture_before_dispatch(self):
        from crypto_box import unseal
        from gateway import Relay
        item,key=fixture(synthetic=False)
        private=base64.b64decode(key)
        public=x25519.X25519PrivateKey.from_private_bytes(private).public_key().public_bytes(
            serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        raw=unseal(item['box'],private)
        dispatched=[]
        relay=Relay({},public,None,dispatch=dispatched.append,clock=lambda:NOW)
        with self.assertRaises(ValueError):
            relay.submit_v6_synthetic(raw)
        self.assertEqual(dispatched,[])
    def test_github_permission_probe_no_dispatch_and_redacted(self):
        from gateway import Relay
        from unittest.mock import patch
        class Response:
            status=200
            def __enter__(self):return self
            def __exit__(self,*args):return False
            def read(self,n):return b'{"permissions":{"push":true},"secret":"DO_NOT_SHOW"}'
        class Opener:
            def open(self,request,timeout):
                self.request=request
                return Response()
        opener=Opener()
        relay=Relay({'ARDA_RELAY_GITHUB_REPO':'Byron2306/arda-pq-witnesses',
            'ARDA_RELAY_GITHUB_TOKEN':'SECRET_GITHUB_TOKEN'},b'',None)
        with patch('gateway.urllib.request.build_opener',return_value=opener):
            outcome=relay.probe_github_dispatch_permission()
        self.assertEqual(outcome,{'probe':'GITHUB_REPO_HTTP','http':200,'push':True})
        self.assertEqual(opener.request.get_method(),'GET')
        self.assertNotIn('SECRET',repr(outcome))
if __name__=='__main__':
    unittest.main()
