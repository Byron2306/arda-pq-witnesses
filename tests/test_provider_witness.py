import base64
import copy
from pathlib import Path
import shutil
import tempfile
import unittest
from arda_quorum import provider_witness as w
from arda_quorum import quorum as q
import test_quorum as pq
from provider_fixtures import ProviderFixtures as F,ROOT

class ProviderWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):F.start()
    @classmethod
    def tearDownClass(cls):F.stop()
    def witness(self,provider='github',**changes):
        kwargs=F.kwargs(provider);kwargs.update(changes);return w.ReviewWitness(**kwargs)
    def test_both_real_provider_signatures_verify_under_assigned_keys(self):
        for provider in ('github','hf'):
            witness=self.witness(provider);vote=witness.review(F.request)
            self.assertEqual(vote['payload']['provider'],provider)
            self.assertEqual(vote['payload']['algorithm'],q.PROFILES[provider][1])
            self.assertTrue(pq.QuorumTests.backend.verify(q.PROFILES[provider][1],pq.QuorumTests.signers.keys[provider],
                q.DOMAIN+q.canonical(vote['payload']),base64.b64decode(vote['signature_b64'])))
    def test_private_key_must_match_enrolled_public_key_and_algorithm(self):
        with self.assertRaises(ValueError):self.witness('github',private_key_der=F.private['hf'])
        with self.assertRaises(ValueError):self.witness('hf',private_key_der=b'not a key')
    def test_cloudflare_cannot_use_a_stateless_provider_entrypoint(self):
        kwargs=F.kwargs('github');kwargs['provider']='cloudflare'
        with self.assertRaises(ValueError):w.ReviewWitness(**kwargs)
    def test_policy_file_pin_required(self):
        with self.assertRaises(ValueError):self.witness(policy_file_sha256='0'*64)
    def test_stage_request_pin_required(self):
        with self.assertRaises(ValueError):self.witness(stage_request_sha256='0'*64)
    def test_source_manifest_pin_required(self):
        with self.assertRaises(ValueError):self.witness(source_manifest_sha256='0'*64)
    def test_wire_cannot_choose_provider_key_clock_or_algorithm(self):
        witness=self.witness('hf')
        for field,value in [('provider','github'),('private_key_der','secret'),('clock',1000),('algorithm','Ed25519')]:
            req=dict(F.request);req[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):witness.review(req)
    def test_every_staging_binding_is_enforced(self):
        witness=self.witness('hf')
        for field in q.BINDINGS-{'r13_evidence_sha256'}:
            req=copy.deepcopy(F.request);req['proposal'][field]=15 if field=='generation' else 'substituted'
            with self.subTest(field=field),self.assertRaises(ValueError):witness.review(req)
    def test_missing_or_fake_attestation_refused(self):
        witness=self.witness('hf')
        for capture in ({'r13_verified':True},{},None):
            req=dict(F.request,capture=capture)
            with self.assertRaises(ValueError):witness.review(req)
    def test_capture_digest_substitution_refused(self):
        req=copy.deepcopy(F.request);req['proposal']['r13_evidence_sha256']='0'*64
        with self.assertRaises(ValueError):self.witness('hf').review(req)
    def test_production_action_and_extra_authority_flags_refused(self):
        witness=self.witness('hf')
        for field,value in [('action','activate_generation'),('production_authorized',True)]:
            req=copy.deepcopy(F.request);req['proposal'][field]=value
            with self.assertRaises(ValueError):witness.review(req)
    def test_proposal_cannot_outlive_r13_receipt(self):
        req=copy.deepcopy(F.request);req['proposal']['expires_at']=1121
        with self.assertRaises(ValueError):self.witness('hf').review(req)
    def test_expiry_while_signing_refuses_to_release_vote(self):
        witness=self.witness('hf');times=iter([1000,1100]);witness.clock=lambda:next(times)
        with self.assertRaises(ValueError):witness.review(F.request)
    def test_clock_rollback_while_signing_refused(self):
        witness=self.witness('hf');times=iter([1000,999]);witness.clock=lambda:next(times)
        with self.assertRaises(ValueError):witness.review(F.request)
    def test_source_change_and_symlink_refused_by_github(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);shutil.copytree(ROOT/'reviewed-runtime',root/'reviewed-runtime')
            witness=self.witness(source_root=root)
            target=root/F.source['files'][0]['path'];original=target.read_bytes();target.write_bytes(original+b'\n# changed\n')
            with self.assertRaises(ValueError):witness.review(F.request)
            target.unlink();target.symlink_to(ROOT/F.source['files'][0]['path'])
            with self.assertRaises(ValueError):witness.review(F.request)
    def test_caller_mutation_after_construction_does_not_change_policy(self):
        raw=bytearray(F.policy_bytes)
        witness=self.witness('hf',policy_bytes=bytes(raw));raw[:]=b'x'*len(raw)
        self.assertEqual(witness.review(F.request)['payload']['provider'],'hf')
    def test_two_new_voters_join_a_real_three_algorithm_r13_bound_certificate(self):
        from arda_quorum.r13_bridge import verify_with_r13
        import test_r13_bridge as att
        votes=[self.witness('github').review(F.request),self.witness('hf').review(F.request)]
        v=dict(votes[0]['payload'])
        cf=next(w for w in pq.QuorumTests.policy['witnesses'] if w['provider']=='cloudflare')
        v.update({k:cf[k] for k in ('witness_id','provider','role','algorithm','key_sha256')})
        votes.append(dict(payload=v,signature_b64=base64.b64encode(pq.QuorumTests.signers.sign('cloudflare',q.DOMAIN+q.canonical(v))).decode()))
        expected=dict(F.proposal);expected={k:expected[k] for k in q.BINDINGS}
        result=verify_with_r13(dict(proposal=F.proposal,votes=votes),pq.QuorumTests.policy,
            expected=expected,capture=att.R13BridgeTests.capture,r13_gate=att.R13BridgeTests.gate,now=1000,backends=pq.QuorumTests.backend)
        self.assertTrue(result['quorum_valid'],result);self.assertTrue(result['r13_valid'],result)
        self.assertFalse(result['production_authorized']);self.assertIn('REKOR_PROOF_VERIFICATION_REQUIRED',result['blockers'])
