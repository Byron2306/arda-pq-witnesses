import copy
from pathlib import Path
import subprocess
import test_quorum as pq
import test_r13_bridge as att
from arda_quorum import quorum as q
from arda_quorum.proposal import validate_request
ROOT=Path(__file__).resolve().parents[1]

class ProviderFixtures:
    @classmethod
    def start(cls):
        pq.QuorumTests.setUpClass();att.R13BridgeTests.setUpClass()
        cls.policy_bytes=q.canonical(pq.QuorumTests.policy)
        stage=q.strict_load((ROOT/'inputs/generation14-staging-request.json').read_bytes());d=stage['deployment']
        for k,v in att.R13BridgeTests.pins.items():
            if k in ('verifier_spki_sha256','ak_spki_sha256','policy_sha256'):d['r13_'+k]=v
        cls.stage_bytes=q.canonical(stage);cls.stage_pin=q.sha(cls.stage_bytes)
        cls.source=q.strict_load((ROOT/'REVIEWED_SOURCE_FILES.json').read_bytes());cls.source['request_sha256']=cls.stage_pin
        cls.source_bytes=q.canonical(cls.source)
        expected=validate_request(cls.stage_bytes,cls.stage_pin)
        expected['r13_evidence_sha256']=q.sha(q.canonical(att.R13BridgeTests.capture))
        cls.proposal=dict(expected,schema='arda.pq.proposal.v1',action='review_staged_release',proposal_id='12'*16,
            nonce='34'*32,epoch=1,policy_sha256=q.sha(cls.policy_bytes),issued_at=1000,expires_at=1100)
        cls.request=dict(schema='arda.pq.witness_request.v1',proposal=cls.proposal,capture=att.R13BridgeTests.capture)
        cls.private={}
        for provider in ('github','hf'):
            cls.private[provider]=subprocess.check_output(['openssl','pkey','-in',str(pq.QuorumTests.signers.root/(provider+'.pem')),'-outform','DER'],timeout=10)
    @classmethod
    def stop(cls):pq.QuorumTests.tearDownClass()
    @classmethod
    def kwargs(cls,provider):
        return dict(provider=provider,policy_bytes=cls.policy_bytes,policy_file_sha256=q.sha(cls.policy_bytes),
            stage_bytes=cls.stage_bytes,stage_request_sha256=cls.stage_pin,verifier_pem=att.R13BridgeTests.public,
            ak_pem=att.R13BridgeTests.ak_public,approved_pcrs=att.R13BridgeTests.profile,
            private_key_der=cls.private[provider],source_root=ROOT,source_manifest_bytes=cls.source_bytes,
            source_manifest_sha256=q.sha(cls.source_bytes),clock=lambda:1000)
