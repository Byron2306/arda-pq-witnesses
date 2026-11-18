import base64
import copy
import unittest
import test_quorum as pq
import test_r13_bridge as att
from arda_quorum import quorum as q
from arda_quorum.r13_bridge import verify_with_r13

class BoundQuorumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        pq.QuorumTests.setUpClass();att.R13BridgeTests.setUpClass()
        cls.expected=dict(pq.QuorumTests.expected,r13_evidence_sha256=q.sha(q.canonical(att.R13BridgeTests.capture)))
        cls.certificate=copy.deepcopy(pq.QuorumTests.certificate)
        cls.certificate['proposal'].update(cls.expected,issued_at=1000)
        for vote in cls.certificate['votes']:
            v=vote['payload'];v['issued_at']=1000;v['proposal_sha256']=q.sha(q.canonical(cls.certificate['proposal']))
            vote['signature_b64']=base64.b64encode(pq.QuorumTests.signers.sign(v['provider'],q.DOMAIN+q.canonical(v))).decode()
    @classmethod
    def tearDownClass(cls):pq.QuorumTests.tearDownClass()
    def verify(self,cert=None,capture=None,expected=None):
        return verify_with_r13(cert or self.certificate,pq.QuorumTests.policy,expected=expected or self.expected,
            capture=capture or att.R13BridgeTests.capture,r13_gate=att.R13BridgeTests.gate,now=1000,backends=pq.QuorumTests.backend)
    def test_all_three_pq_signatures_and_raw_tpm_proof_bind_together(self):
        r=self.verify();self.assertTrue(r['r13_valid'],r);self.assertTrue(r['quorum_valid'],r)
        self.assertFalse(r['production_authorized']);self.assertIn('REKOR_PROOF_VERIFICATION_REQUIRED',r['blockers'])
    def test_certificate_cannot_outlive_attestation(self):
        c=copy.deepcopy(self.certificate);c['proposal']['expires_at']=1121
        self.assertFalse(self.verify(cert=c)['quorum_valid'])
    def test_signatures_cannot_predate_receipt(self):
        c=copy.deepcopy(self.certificate);c['proposal']['issued_at']=999
        self.assertFalse(self.verify(cert=c)['quorum_valid'])
    def test_another_valid_capture_digest_is_not_interchangeable(self):
        e=dict(self.expected,r13_evidence_sha256='0'*64)
        self.assertFalse(self.verify(expected=e)['quorum_valid'])
    def test_fake_pass_cannot_replace_a_capture(self):
        self.assertFalse(self.verify(capture={'r13_verified':True})['quorum_valid'])
    def test_caller_mutation_during_evidence_verification_cannot_change_snapshot(self):
        original=copy.deepcopy(self.certificate)
        class MutatingGate:
            def verify(self,capture,**kw):
                result=att.R13BridgeTests.gate.verify(capture,**kw)
                original['proposal']['generation']=999
                return result
        result=verify_with_r13(original,pq.QuorumTests.policy,expected=self.expected,capture=att.R13BridgeTests.capture,
            r13_gate=MutatingGate(),now=1000,backends=pq.QuorumTests.backend)
        self.assertTrue(result['quorum_valid'],result)
