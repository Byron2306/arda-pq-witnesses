import json
import tempfile
import unittest
from pathlib import Path
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
from crypto_box import seal,unseal,hash_envelope
from gateway import Relay

class RelayTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.key=x25519.X25519PrivateKey.generate()
        self.private=self.key.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        self.public=self.key.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        self.now=1795610000
        self.sent=[]
        self.relay=Relay({},self.public,Path(self.tmp.name)/'db.sqlite',dispatch=self.sent.append,clock=lambda:self.now)
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
        with self.assertRaisesRegex(ValueError,'CHALLENGE_ALREADY_SUBMITTED'):self.relay.submit(self.capture)
    def test_claim_one_time_and_reopen_db(self):
        self.relay.submit(self.capture);pkt=self.sent[0]['client_payload']
        other=Relay({},self.public,Path(self.tmp.name)/'db.sqlite',dispatch=self.sent.append,clock=lambda:self.now)
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
