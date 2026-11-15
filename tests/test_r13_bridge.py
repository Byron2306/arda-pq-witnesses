import copy
from pathlib import Path
import struct
import tempfile
import unittest
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa,ed25519,padding
from arda_quorum import r13_protocol as r
from arda_quorum import r13_bridge as bridge

class R13BridgeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ak=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        cls.signer=ed25519.Ed25519PrivateKey.generate()
        cls.profile={str(n):f'{n+1:02x}'*32 for n in r.PCRS}
        cls.policy=r.NodePolicy(cls.ak.public_key(),cls.profile)
        cls.boot='b08f1e0e-6397-440f-a0ad-73313b7bf87c';cls.now=1000
        cls.pins=dict(verifier_spki_sha256=r.public_pin(cls.signer.public_key()),ak_spki_sha256=cls.policy.ak_sha256,
            policy_sha256=cls.policy.sha256,node_id='lenovo-valinor',verifier_id='cloudflare-r13-v2')
        cls.public=cls.signer.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.ak_public=cls.ak.public_key().public_bytes(serialization.Encoding.PEM,serialization.PublicFormat.SubjectPublicKeyInfo)
        cls.gate=bridge.PinnedR13(cls.public,cls.ak_public,cls.profile,cls.pins)
        with tempfile.TemporaryDirectory() as directory:
            verifier=r.Verifier('cloudflare-r13-v2',cls.signer,{'lenovo-valinor':cls.policy},Path(directory)/'r13.db',clock=lambda:1000)
            issued=r.sign_challenge(verifier.issue(dict(node_id='lenovo-valinor',boot_id=cls.boot)),cls.signer);c=issued['challenge']
            qualification=r.qualifying_data(c)
            mask=sum(1<<n for n in r.PCRS).to_bytes(3,'little')
            pcr_hash=hashes.Hash(hashes.SHA256());pcr_hash.update(b''.join(bytes.fromhex(cls.profile[str(n)]) for n in r.PCRS))
            quote=bytes.fromhex('ff544347801800000020')+qualification+bytes(25)+bytes.fromhex('00000001000b03')+mask+bytes.fromhex('0020')+pcr_hash.finalize()
            signature=cls.ak.sign(quote,padding.PKCS1v15(),hashes.SHA256())
            evidence=dict(challenge_id=c['challenge_id'],boot_id=cls.boot,pcrs=cls.profile,quote_b64=r.encode(quote),
                signature_b64=r.encode(bytes.fromhex('0014000b')+struct.pack('>H',len(signature))+signature))
            receipt=verifier.verify(evidence)
            cls.capture=dict(schema='arda.r13.capture.v2',issued_challenge=issued,evidence=evidence,receipt=receipt)
    def verify(self,c=None,**kw):return self.gate.verify(c if c is not None else self.capture,expected_boot=kw.get('boot',self.boot),now=kw.get('now',1000))
    def test_real_quote_and_receipt_verify_independently(self):
        result=self.verify();self.assertTrue(result['r13_valid'],result)
        self.assertFalse(result['production_authorized']);self.assertEqual(result['expires_at'],1120)
    def test_expiry_and_future_refused(self):
        self.assertFalse(self.verify(now=1120)['r13_valid']);self.assertFalse(self.verify(now=999)['r13_valid'])
    def test_other_boot_refused(self):self.assertFalse(self.verify(boot='9e8897df-a2bb-4cdd-97c6-1e8ae42550fa')['r13_valid'])
    def test_pin_substitution_refused(self):
        for field in ('verifier_spki_sha256','ak_spki_sha256','policy_sha256'):
            pins=dict(self.pins);pins[field]='0'*64
            with self.assertRaises(ValueError):bridge.PinnedR13(self.public,self.ak_public,self.profile,pins)
    def test_receipt_signature_and_challenge_signature_tamper_refused(self):
        for field,sig in [('receipt','ed25519_signature_b64'),('issued_challenge','ed25519_signature_b64')]:
            c=copy.deepcopy(self.capture);c[field][sig]=r.encode(bytes(64))
            self.assertFalse(self.verify(c)['r13_valid'])
    def test_even_a_resigned_receipt_cannot_hide_invalid_raw_quote(self):
        c=copy.deepcopy(self.capture);c['evidence']['signature_b64']=r.encode(bytes.fromhex('0014000b0100')+bytes(256))
        p=c['receipt']['payload'];p['quote_signature_sha256']=r.sha(r.decode(c['evidence']['signature_b64'],1024,'fixture'))
        p['evidence_sha256']=r.digest(c['evidence'])
        c['receipt']['ed25519_signature_b64']=r.encode(self.signer.sign(b'ARDA/R13/EVIDENCE-RECEIPT/v2\0'+r.canonical(p)))
        self.assertFalse(self.verify(c)['r13_valid'])
    def test_baseline_is_not_learned_from_capture(self):
        c=copy.deepcopy(self.capture);c['evidence']['pcrs']['11']='ef'*32
        self.assertFalse(self.verify(c)['r13_valid'])
    def test_extra_pass_boolean_is_refused(self):
        c=copy.deepcopy(self.capture);c['r13_verified']=True
        self.assertFalse(self.verify(c)['r13_valid'])
    def test_configuration_and_result_are_snapshots(self):
        profile=dict(self.profile);pins=dict(self.pins);g=bridge.PinnedR13(self.public,self.ak_public,profile,pins)
        profile['11']='ff'*32;pins['node_id']='other'
        self.assertTrue(g.verify(self.capture,expected_boot=self.boot,now=1000)['r13_valid'])

class WorkerInteropTests(unittest.TestCase):
    def test_actual_javascript_handler_receipt_verifies_in_python_gate(self):
        import json,subprocess
        root=Path(__file__).resolve().parents[1]
        run=subprocess.run(['node',str(root/'cloudflare/export-r13-fixture.mjs')],capture_output=True,text=True,timeout=20)
        self.assertEqual(run.returncode,0,run.stderr)
        x=json.loads(run.stdout)
        gate=bridge.PinnedR13(x['verifier_pem'].encode(),x['ak_pem'].encode(),x['pcrs'],x['pins'])
        result=gate.verify(x['capture'],expected_boot=x['boot'],now=1000)
        self.assertTrue(result['r13_valid'],result)
