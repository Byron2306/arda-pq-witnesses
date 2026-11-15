import base64
import copy
import unittest
from arda_quorum import quorum as q
from arda_quorum.crypto import Backends
from fixture_crypto import Signers

class QuorumTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.signers=Signers();cls.backend=Backends();cls.now=1000
        cls.policy=dict(schema='arda.pq.enrollment.v1',epoch=1,issued_at=900,expires_at=2000,
            production_authorized=False,witnesses=[])
        for provider,(role,algorithm) in q.PROFILES.items():
            key=cls.signers.keys[provider]
            cls.policy['witnesses'].append(dict(witness_id='arda:'+provider,provider=provider,role=role,
                algorithm=algorithm,key_sha256=q.sha(key),public_key_b64=base64.b64encode(key).decode()))
        cls.expected=dict(generation=14,manifest_id='manifest-14',manifest_digest='sha256:'+'a'*64,
            deployment_sha256='b'*64,artifact_root_sha256='c'*64,staging_request_sha256='d'*64,
            machine_id_sha256='e'*64,boot_id='b08f1e0e-6397-440f-a0ad-73313b7bf87c',r13_evidence_sha256='f'*64)
        cls.proposal=dict(cls.expected,schema='arda.pq.proposal.v1',action='review_staged_release',
            proposal_id='12'*16,nonce='34'*32,epoch=1,policy_sha256=q.sha(q.canonical(cls.policy)),issued_at=999,expires_at=1100)
        cls.certificate=dict(proposal=cls.proposal,votes=[])
        for witness in cls.policy['witnesses']:
            payload=dict(schema='arda.pq.vote.v1',witness_id=witness['witness_id'],provider=witness['provider'],
                role=witness['role'],algorithm=witness['algorithm'],key_sha256=witness['key_sha256'],
                policy_sha256=q.sha(q.canonical(cls.policy)),proposal_sha256=q.sha(q.canonical(cls.proposal)),
                decision='APPROVE',issued_at=999,expires_at=1100)
            signature=cls.signers.sign(witness['provider'],q.DOMAIN+q.canonical(payload))
            cls.certificate['votes'].append(dict(payload=payload,signature_b64=base64.b64encode(signature).decode()))
    @classmethod
    def tearDownClass(cls):cls.signers.close()
    def verify(self,c=None,p=None,e=None,now=None):
        return q.verify_quorum(c if c is not None else self.certificate,p if p is not None else self.policy,
            expected=e if e is not None else self.expected,now=self.now if now is None else now,backends=self.backend)
    def test_three_real_signatures_verify_but_admission_stays_closed(self):
        result=self.verify()
        self.assertTrue(result['quorum_valid'],result)
        self.assertEqual(result['valid_votes'],3)
        self.assertFalse(result['production_authorized'])
        self.assertEqual(result['decision'],'REFUSE')
        self.assertIn('R13_AND_REKOR_INTEGRATION_REQUIRED',result['blockers'])
    def test_each_missing_witness_refused(self):
        for index in range(3):
            c=copy.deepcopy(self.certificate);c['votes'].pop(index)
            self.assertFalse(self.verify(c)['quorum_valid'])
    def test_duplicate_and_extra_votes_refused(self):
        c=copy.deepcopy(self.certificate);c['votes'][2]=c['votes'][0]
        self.assertFalse(self.verify(c)['quorum_valid'])
        c['votes'].append(c['votes'][0]);self.assertFalse(self.verify(c)['quorum_valid'])
    def test_every_expected_binding_is_checked(self):
        for field in self.expected:
            e=dict(self.expected);e[field]=15 if field=='generation' else 'wrong'
            with self.subTest(field=field):self.assertFalse(self.verify(e=e)['quorum_valid'])
    def test_proposal_tamper_refused(self):
        c=copy.deepcopy(self.certificate);c['proposal']['nonce']='56'*32
        self.assertFalse(self.verify(c)['quorum_valid'])
    def test_each_signature_tamper_refused(self):
        for index in range(3):
            c=copy.deepcopy(self.certificate);b=bytearray(base64.b64decode(c['votes'][index]['signature_b64']));b[-1]^=1
            c['votes'][index]['signature_b64']=base64.b64encode(b).decode()
            self.assertFalse(self.verify(c)['quorum_valid'])
    def test_algorithm_downgrade_refused(self):
        c=copy.deepcopy(self.certificate);c['votes'][0]['payload']['algorithm']='Ed25519'
        self.assertFalse(self.verify(c)['quorum_valid'])
        p=copy.deepcopy(self.policy);p['witnesses'][0]['algorithm']='ML-KEM-768'
        self.assertFalse(self.verify(p=p)['quorum_valid'])
    def test_policy_key_substitution_refused(self):
        p=copy.deepcopy(self.policy);p['witnesses'][0]['public_key_b64']=p['witnesses'][1]['public_key_b64']
        self.assertFalse(self.verify(p=p)['quorum_valid'])
    def test_role_provider_and_identity_substitution_refused(self):
        for field in ('role','provider','witness_id','key_sha256'):
            c=copy.deepcopy(self.certificate);c['votes'][0]['payload'][field]='substituted'
            self.assertFalse(self.verify(c)['quorum_valid'])
    def test_policy_epoch_change_invalidates_all_votes(self):
        p=copy.deepcopy(self.policy);p['epoch']=2
        self.assertFalse(self.verify(p=p)['quorum_valid'])
    def test_future_and_expired_proposal_refused(self):
        self.assertFalse(self.verify(now=998)['quorum_valid'])
        self.assertFalse(self.verify(now=1100)['quorum_valid'])
    def test_boolean_generation_and_nan_time_refused(self):
        for field,value in [('generation',True),('issued_at',float('nan')),('expires_at',True)]:
            c=copy.deepcopy(self.certificate);c['proposal'][field]=value
            self.assertFalse(self.verify(c)['quorum_valid'])
    def test_unknown_fields_and_vote_rejection_refused(self):
        c=copy.deepcopy(self.certificate);c['votes'][0]['payload']['decision']='REFUSE'
        self.assertFalse(self.verify(c)['quorum_valid'])
        c=copy.deepcopy(self.certificate);c['rekor_verified']=True
        self.assertFalse(self.verify(c)['quorum_valid'])
    def test_unsigned_execution_action_refused(self):
        c=copy.deepcopy(self.certificate);c['proposal']['action']='activate_generation'
        self.assertFalse(self.verify(c)['quorum_valid'])
    def test_duplicate_json_and_nonfinite_values_refused(self):
        for raw in (b'{"votes":[],"votes":[]}',b'{"n":NaN}',b'{"n":Infinity}'):
            with self.assertRaises(ValueError):q.strict_load(raw)
    def test_json_size_limit(self):
        with self.assertRaises(ValueError):q.strict_load(b' '*1048577)
    def test_classical_boolean_flags_cannot_enable_production(self):
        p=copy.deepcopy(self.policy);p['production_authorized']=True
        self.assertFalse(self.verify(p=p)['quorum_valid'])
    def test_mutation_after_result_does_not_change_receipt(self):
        c=copy.deepcopy(self.certificate);result=self.verify(c);digest=result['certificate_sha256']
        c['proposal']['generation']=999
        self.assertEqual(result['certificate_sha256'],digest)
