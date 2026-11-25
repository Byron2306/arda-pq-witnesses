import json
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
from crypto_box import seal,unseal,hash_envelope
from gateway import Relay

class MemoryDurableLedger:
    """Test double only. Cloudflare SQL must be integration-tested separately."""
    def __init__(self,clock):
        self.records={};self.challenges=set();self.clock=clock
        self.outage=False
    def reserve(self,ticket,cid,digest,expiry):
        if self.outage:raise RuntimeError('LEDGER_UNAVAILABLE')
        if cid in self.challenges or expiry<=int(self.clock()):return False
        self.challenges.add(cid);self.records[ticket]=[digest,expiry,False]
        return True
    def claim(self,ticket,digest):
        if self.outage:raise RuntimeError('LEDGER_UNAVAILABLE')
        entry=self.records.get(ticket)
        if not entry or entry[0]!=digest or entry[1]<=int(self.clock()) or entry[2]:return False
        entry[2]=True
        return True

class RelayTests(unittest.TestCase):
    def setUp(self):
        self.key=x25519.X25519PrivateKey.generate()
        self.private=self.key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.now=1795610000
        self.sent=[]
        self.ledger=MemoryDurableLedger(lambda:self.now)
        self.relay=Relay({},self.public,self.ledger,dispatch=self.sent.append,clock=lambda:self.now)
        ch={'challenge_id':'a'*32,'issued_at':self.now-5,'expires_at':self.now+100}
        self.capture=json.dumps({'schema':'arda.r13.capture.v2','issued_challenge':{'challenge':ch},'evidence':{},'receipt':{}}).encode()
    def test_seal_unseal(self):
        box=seal(self.capture,self.public)
        self.assertEqual(unseal(box,self.private),self.capture)
        self.assertEqual(len(hash_envelope(box)),64)
    def test_tamper_ciphertext_fails(self):
        box=seal(self.capture,self.public);box['ciphertext_b64']='AAAA'+box['ciphertext_b64'][4:]
        with self.assertRaises(Exception):unseal(box,self.private)
    def test_duplicate_challenge_refused(self):
        self.relay.submit(self.capture)
        with self.assertRaisesRegex(ValueError,'LEDGER_RESERVATION_REFUSED'):self.relay.submit(self.capture)
    def test_claim_one_time_across_relay_instances(self):
        self.relay.submit(self.capture);pkt=self.sent[0]['client_payload']
        other=Relay({},self.public,self.ledger,dispatch=self.sent.append,clock=lambda:self.now)
        self.assertTrue(other.claim(pkt['ticket'],pkt['envelope_sha256']))
        self.assertFalse(self.relay.claim(pkt['ticket'],pkt['envelope_sha256']))
    def test_wrong_digest_refused(self):
        self.relay.submit(self.capture);pkt=self.sent[0]['client_payload']
        self.assertFalse(self.relay.claim(pkt['ticket'],'f'*64))
        self.assertTrue(self.relay.claim(pkt['ticket'],pkt['envelope_sha256']))
    def test_expired_refused(self):
        self.now+=200
        with self.assertRaisesRegex(ValueError,'CHALLENGE_EXPIRED'):self.relay.submit(self.capture)
    def test_claim_expired_refused(self):
        self.relay.submit(self.capture);pkt=self.sent[0]['client_payload'];self.now+=200
        self.assertFalse(self.relay.claim(pkt['ticket'],pkt['envelope_sha256']))
    def test_no_phase4_claim(self):
        self.assertIs(self.relay.submit(self.capture)['phase4_authorized'],False)
    def test_ledger_outage_fails_closed_before_dispatch(self):
        self.ledger.outage=True
        with self.assertRaisesRegex(RuntimeError,'LEDGER_UNAVAILABLE'):self.relay.submit(self.capture)
        self.assertEqual(self.sent,[])
    def test_dispatch_failure_burns_reservation(self):
        def fail(_):raise RuntimeError('DISPATCH_FAILED')
        other=Relay({},self.public,self.ledger,dispatch=fail,clock=lambda:self.now)
        with self.assertRaisesRegex(RuntimeError,'DISPATCH_FAILED'):other.submit(self.capture)
        with self.assertRaisesRegex(ValueError,'LEDGER_RESERVATION_REFUSED'):self.relay.submit(self.capture)
        self.assertEqual(self.sent,[])
