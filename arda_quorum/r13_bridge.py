"""Independent pinned R13 challenge, raw TPM quote and receipt verification."""
from types import MappingProxyType
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from . import r13_protocol as r
from .quorum import canonical,sha,need,hex64,verify_quorum,strict_load

PIN_FIELDS={'verifier_spki_sha256','ak_spki_sha256','policy_sha256','node_id','verifier_id'}

class PinnedR13:
    def __init__(self,verifier_pem,ak_pem,approved_pcrs,pins):
        need(type(pins) is dict and pins.keys()==PIN_FIELDS,'r13_pin_fields')
        need(all(hex64(pins[k]) for k in ('verifier_spki_sha256','ak_spki_sha256','policy_sha256')),'r13_pin_format')
        need(all(r.matches(r.ID,pins[k]) for k in ('node_id','verifier_id')),'r13_identity_format')
        self.pins=MappingProxyType(dict(pins))
        self.key=serialization.load_pem_public_key(verifier_pem)
        need(isinstance(self.key,ed25519.Ed25519PublicKey),'r13_verifier_key_type')
        self.policy=r.NodePolicy(serialization.load_pem_public_key(ak_pem),dict(approved_pcrs))
        need(r.public_pin(self.key)==pins['verifier_spki_sha256'],'r13_verifier_key_pin')
        need(self.policy.ak_sha256==pins['ak_spki_sha256'],'r13_ak_pin')
        need(self.policy.sha256==pins['policy_sha256'],'r13_approved_policy_pin')

    def verify(self,capture,*,expected_boot,now):
        result=dict(r13_valid=False,production_authorized=False,interlock='KEEP_CLOSED')
        try:
            need(type(now) is int and now>0,'r13_trusted_clock')
            x=r.strict_json(r.canonical(capture))
            r.shape(x,{'schema','issued_challenge','evidence','receipt'},'R13_CAPTURE_FIELDS')
            need(x['schema']=='arda.r13.capture.v2','r13_capture_schema')
            challenge=r.verify_issued_challenge(x['issued_challenge'],self.key)
            need(challenge['verifier_id']==self.pins['verifier_id']
                 and challenge['node_id']==self.pins['node_id']
                 and challenge['boot_id']==expected_boot
                 and challenge['policy_sha256']==self.policy.sha256,'r13_challenge_context')
            need(challenge['issued_at']<=now<challenge['expires_at']
                 and challenge['expires_at']-challenge['issued_at']<=120,'r13_challenge_freshness')
            evidence=x['evidence'];r.shape(evidence,r.EVIDENCE_FIELDS,'R13_EVIDENCE_FIELDS')
            pcrs=r.normalized_pcrs(evidence['pcrs'])
            r.verify_quote(r.decode(evidence['quote_b64'],4096,'QUOTE_ENCODING'),
                r.decode(evidence['signature_b64'],1024,'SIGNATURE_ENCODING'),pcrs,r.qualifying_data(challenge),self.policy)
            payload=r.verify_receipt(x['receipt'],self.key,challenge,evidence,now=now)
            need(payload['ak_spki_sha256']==self.policy.ak_sha256,'r13_receipt_ak_pin')
            result.update(r13_valid=True,reason='PINNED_CHALLENGE_RAW_QUOTE_AND_RECEIPT_VALID',
                capture_sha256=sha(canonical(x)),evidence_sha256=payload['evidence_sha256'],
                issued_at=payload['issued_at'],expires_at=payload['expires_at'],
                verifier_spki_sha256=self.pins['verifier_spki_sha256'],policy_sha256=self.policy.sha256,
                node_id=payload['node_id'],boot_id=payload['boot_id'])
        except (ValueError,TypeError,KeyError,OverflowError,RecursionError) as exc:
            result['reason']='R13_CAPTURE_REFUSED:'+str(exc)
        return result


def verify_with_r13(certificate,policy,*,expected,capture,r13_gate,now,backends):
    # No caller-supplied PASS object is accepted. Both paths verify their own
    # signatures against trusted configuration on every call.
    result=dict(decision='REFUSE',quorum_valid=False,r13_valid=False,production_authorized=False,interlock='KEEP_CLOSED')
    try:
        certificate=strict_load(canonical(certificate));policy=strict_load(canonical(policy));expected=strict_load(canonical(expected))
        capture=strict_load(canonical(capture))
        evidence=r13_gate.verify(capture,expected_boot=expected['boot_id'],now=now)
        need(evidence['r13_valid'],'r13_gate_refused')
        need(expected['r13_evidence_sha256']==evidence['capture_sha256'],'r13_capture_expected_binding')
        p=certificate['proposal']
        need(evidence['issued_at']<=p['issued_at']<p['expires_at']<=evidence['expires_at'],'proposal_r13_validity_binding')
        result=verify_quorum(certificate,policy,expected=expected,now=now,backends=backends)
        result.update(r13_valid=True,r13_capture_sha256=evidence['capture_sha256'])
        if result['quorum_valid']:
            result.update(blockers=['REKOR_PROOF_VERIFICATION_REQUIRED','STATEFUL_SIGNER_REVIEW_REQUIRED','PRODUCTION_CONSUMER_NOT_INSTALLED'])
    except (ValueError,TypeError,KeyError,RecursionError) as exc:
        result.update(reason='R13_BOUND_QUORUM_REFUSED:'+str(exc),blockers=['R13_BOUND_QUORUM_INVALID'])
    return result
