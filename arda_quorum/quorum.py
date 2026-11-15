"""Exact all-three PQ quorum verification. No execution or production authority."""
import base64
import hashlib
import json
import re
import uuid
from .crypto import ML,SLH,HSS,validate_key

DOMAIN=b'ARDA/PQ-QUORUM/VOTE/v1\0'
PROFILES={'github':('build_witness',ML),'hf':('policy_witness',SLH),'cloudflare':('release_witness',HSS)}
BINDINGS=frozenset({'generation','manifest_id','manifest_digest','deployment_sha256','artifact_root_sha256',
    'staging_request_sha256','machine_id_sha256','boot_id','r13_evidence_sha256'})
PROPOSAL_FIELDS=BINDINGS|{'schema','action','proposal_id','nonce','epoch','policy_sha256','issued_at','expires_at'}
POLICY_FIELDS={'schema','epoch','issued_at','expires_at','production_authorized','witnesses'}
WITNESS_FIELDS={'witness_id','provider','role','algorithm','key_sha256','public_key_b64'}
VOTE_FIELDS={'schema','witness_id','provider','role','algorithm','key_sha256','policy_sha256','proposal_sha256','decision','issued_at','expires_at'}


def need(condition,reason):
    if not condition:raise ValueError(reason)


def canonical(value):return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=True,allow_nan=False).encode()
def sha(raw):return hashlib.sha256(raw).hexdigest()


def strict_load(raw):
    need(type(raw) is bytes and len(raw)<=1048576,'document_size')
    def unique(pairs):
        result={}
        for key,value in pairs:
            need(key not in result,'duplicate_json_key');result[key]=value
        return result
    def invalid(value):raise ValueError('nonfinite_json')
    return json.loads(raw.decode(),object_pairs_hook=unique,parse_constant=invalid)


def unbase64(value,cap):
    need(type(value) is str and len(value)<=4*((cap+2)//3),'base64_size')
    data=base64.b64decode(value,validate=True)
    need(len(data)<=cap and base64.b64encode(data).decode()==value,'base64_encoding')
    return data


def hex64(value):return type(value) is str and re.fullmatch('[0-9a-f]{64}',value) is not None

def window(payload,now,maximum):
    issued,expiry=payload['issued_at'],payload['expires_at']
    need(type(issued) is int and type(expiry) is int and 0<issued<=now<expiry,'expired_or_future')
    need(0<expiry-issued<=maximum,'validity_window')


def enrollment(policy,now):
    need(type(policy) is dict and policy.keys()==POLICY_FIELDS,'enrollment_fields')
    need(policy['schema']=='arda.pq.enrollment.v1' and policy['production_authorized'] is False,'enrollment_authority')
    need(type(policy['epoch']) is int and policy['epoch']>0,'enrollment_epoch')
    window(policy,now,366*86400)
    witnesses=policy['witnesses']
    need(type(witnesses) is list and len(witnesses)==3,'enrollment_count')
    result={};identities=set();keys=set()
    for w in witnesses:
        need(type(w) is dict and w.keys()==WITNESS_FIELDS,'enrollment_witness_fields')
        provider=w['provider'];need(type(provider) is str and provider in PROFILES and provider not in result,'enrollment_provider')
        need((w['role'],w['algorithm'])==PROFILES[provider],'enrollment_profile')
        identity=w['witness_id']
        need(type(identity) is str and re.fullmatch(r'[a-zA-Z0-9:_.-]{1,128}',identity) and identity not in identities,'enrollment_identity')
        key=unbase64(w['public_key_b64'],4096);validate_key(w['algorithm'],key)
        need(hex64(w['key_sha256']) and sha(key)==w['key_sha256'] and w['key_sha256'] not in keys,'enrollment_key_pin')
        identities.add(identity);keys.add(w['key_sha256']);result[provider]=(w,key)
    need(set(result)==set(PROFILES),'enrollment_role_coverage')
    return result


def proposal_check(p,policy,expected,now):
    need(type(p) is dict and p.keys()==PROPOSAL_FIELDS,'proposal_fields')
    need(p['schema']=='arda.pq.proposal.v1' and p['action']=='review_staged_release','proposal_action')
    need(type(expected) is dict and expected.keys()==BINDINGS,'expected_bindings_required')
    need(type(p['generation']) is int and 0<p['generation']<2**63,'proposal_generation')
    need(type(p['epoch']) is int and p['epoch']==policy['epoch'],'proposal_epoch')
    need(p['policy_sha256']==sha(canonical(policy)),'proposal_policy_binding')
    for key in BINDINGS:
        need(p[key]==expected[key] and type(p[key]) is type(expected[key]),'proposal_binding:'+key)
    for key in ('deployment_sha256','artifact_root_sha256','staging_request_sha256','machine_id_sha256','r13_evidence_sha256','policy_sha256','nonce'):
        need(hex64(p[key]),'proposal_digest:'+key)
    need(type(p['manifest_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}',p['manifest_digest']),'proposal_manifest_digest')
    need(type(p['manifest_id']) is str and re.fullmatch('[a-zA-Z0-9_.:-]{1,128}',p['manifest_id']),'proposal_manifest_identity')
    need(type(p['proposal_id']) is str and re.fullmatch('[0-9a-f]{32}',p['proposal_id']),'proposal_id')
    need(type(p['boot_id']) is str and str(uuid.UUID(p['boot_id']))==p['boot_id'],'proposal_boot')
    window(p,now,300)


def checked_quorum(certificate,policy,expected,now,backends):
    need(type(now) is int and now>0,'trusted_time_integer_required')
    # Snapshot all caller-owned containers; no mutable references escape.
    certificate=strict_load(canonical(certificate));policy=strict_load(canonical(policy));expected=strict_load(canonical(expected))
    admitted=enrollment(policy,now)
    need(type(certificate) is dict and certificate.keys()=={'proposal','votes'},'certificate_fields')
    p=certificate['proposal'];proposal_check(p,policy,expected,now)
    votes=certificate['votes'];need(type(votes) is list and len(votes)==3,'all_three_votes_required')
    proposal_digest=sha(canonical(p));policy_digest=sha(canonical(policy));seen=set();leaf=None
    for vote in votes:
        need(type(vote) is dict and vote.keys()=={'payload','signature_b64'},'vote_envelope')
        v=vote['payload'];need(type(v) is dict and v.keys()==VOTE_FIELDS,'vote_fields')
        provider=v['provider'];need(type(provider) is str and provider in admitted and provider not in seen,'duplicate_or_unknown_witness')
        w,key=admitted[provider]
        need(v['schema']=='arda.pq.vote.v1' and v['decision']=='APPROVE','vote_decision')
        need(all(v[k]==w[k] for k in ('witness_id','provider','role','algorithm','key_sha256')),'vote_enrollment_binding')
        need(v['policy_sha256']==policy_digest and v['proposal_sha256']==proposal_digest,'vote_proposal_binding')
        window(v,now,300)
        need(p['issued_at']<=v['issued_at']<v['expires_at']<=p['expires_at'],'vote_validity_binding')
        signature=unbase64(vote['signature_b64'],65536)
        need(backends.verify(w['algorithm'],key,DOMAIN+canonical(v),signature),'pq_signature_invalid:'+provider)
        if provider=='cloudflare':
            q=int.from_bytes(signature[4:8],'big')
            need(q<1024,'hss_leaf_range');leaf=(w['key_sha256'],q)
        seen.add(provider)
    need(seen==set(PROFILES),'quorum_role_coverage')
    return dict(certificate_sha256=sha(canonical(certificate)),proposal_sha256=proposal_digest,
        policy_sha256=policy_digest,nonce=p['nonce'],epoch=p['epoch'],hss_key_sha256=leaf[0],hss_leaf=leaf[1],
        expires_at=min(p['expires_at'],policy['expires_at'],*(v['payload']['expires_at'] for v in votes)))


def verify_quorum(certificate,policy,*,expected,now,backends):
    result=dict(decision='REFUSE',quorum_valid=False,valid_votes=0,production_authorized=False,interlock='KEEP_CLOSED')
    try:
        checked=checked_quorum(certificate,policy,expected,now,backends)
        result.update(checked,quorum_valid=True,valid_votes=3,reason='PQ_QUORUM_SIGNATURES_VALID',
            blockers=['R13_AND_REKOR_INTEGRATION_REQUIRED','STATEFUL_SIGNER_REVIEW_REQUIRED','PRODUCTION_CONSUMER_NOT_INSTALLED'])
    except (ValueError,KeyError,TypeError,OverflowError,RecursionError,OSError) as exc:
        result.update(reason='PQ_QUORUM_REFUSED:'+str(exc),blockers=['QUORUM_INVALID'])
    return result
