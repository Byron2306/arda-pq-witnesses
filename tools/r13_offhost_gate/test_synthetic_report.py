import base64
import json
import sys
from pathlib import Path
import unittest
from unittest.mock import patch
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'tools/r13_offhost_gate'))
sys.path.insert(0,str(Path(__file__).resolve().parents[2]/'providers/hf/r13-relay'))
import relay_review
from crypto_box import canonical, seal, hash_envelope
from synthetic_lane import MARKER

class Response:
    status=200
    def __enter__(self):return self
    def __exit__(self,*args):pass
    def read(self,n):return b'{"claimed":true}'
class Opener:
    def open(self,*args,**kwargs):return Response()

class SyntheticReportTests(unittest.TestCase):
    def test_valid_encryption_and_claim_still_refuse_r13_authority(self):
        private=x25519.X25519PrivateKey.generate()
        raw_private=private.private_bytes(serialization.Encoding.Raw,serialization.PrivateFormat.Raw,serialization.NoEncryption())
        raw_public=private.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)
        capture=canonical({'schema':'arda.r13.capture.v2','issued_challenge':{'challenge':{}},
                           'evidence':{},'receipt':{'test_only':MARKER}})
        box=seal(capture,raw_public)
        payload={'schema':'arda.r13.relay_dispatch.v1','ticket':'a'*48,
                 'envelope_sha256':hash_envelope(box),'box':box}
        with patch.object(relay_review.urllib.request,'build_opener',return_value=Opener()):
            got=relay_review.review(payload,token='x'*64,
                recipient_private_b64=base64.b64encode(raw_private).decode(),
                endpoint='https://example.test',node_id='lenovo-valinor',
                verifier_id='cloudflare-r13-v2')
        self.assertEqual(got['status'],'REFUSE')
        self.assertEqual(got['reason'],'SYNTHETIC_TRANSPORT_DECRYPTED_R13_NOT_VERIFIED')
        self.assertFalse(got['r13_receipt_verified'])
        self.assertFalse(got['phase4_verdict_verified'])
        self.assertEqual(got['interlock'],'KEEP_CLOSED')
