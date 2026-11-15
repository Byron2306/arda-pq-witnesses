"""Provider-local stateless key provisioning and public, closed enrollment records."""
import base64
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
from .crypto import ML, SLH, validate_key
from .provider_witness import OpenSSLSigner
from .quorum import canonical, strict_load, sha, need, hex64, unbase64, window, enrollment, PROFILES

REGISTRATION_DOMAIN=b'ARDA/PQ-QUORUM/ENROLLMENT/v1\0'
CEREMONY_FIELDS={'schema','nonce','image_digest','identities','issued_at','expires_at','production_authorized'}
REGISTRATION_FIELDS={'schema','ceremony_sha256','provider','provider_identity','witness_id','algorithm','role','key_sha256','public_key_b64','secret_name','issued_at','expires_at'}

def new_ceremony(*,nonce,image_digest,identities,now):
    c=dict(schema='arda.pq.enrollment_ceremony.v1',nonce=nonce,image_digest=image_digest,identities=identities,
           issued_at=now,expires_at=now+86400,production_authorized=False)
    check_ceremony(c,now);return strict_load(canonical(c))

def check_ceremony(c,now):
    need(type(c) is dict and c.keys()==CEREMONY_FIELDS,'ceremony_fields')
    need(c['schema']=='arda.pq.enrollment_ceremony.v1' and c['production_authorized'] is False,'ceremony_authority')
    need(hex64(c['nonce']) and type(c['image_digest']) is str and re.fullmatch('sha256:[0-9a-f]{64}',c['image_digest']),'ceremony_digest')
    need(type(now) is int,'ceremony_trusted_time');window(c,now,86400)
    ids=c['identities'];need(type(ids) is dict and ids.keys()==PROFILES.keys(),'ceremony_providers')
    need(all(type(v) is str and re.fullmatch('[A-Za-z0-9_.:/-]{1,128}',v) for v in ids.values()) and len(set(ids.values()))==3,'ceremony_identities')
    for p in ('github','hf'):need(re.fullmatch('[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+',ids[p]),'ceremony_repository_identity')

def secret_name(provider,key_sha256):
    need(provider in ('github','hf') and hex64(key_sha256),'stateless_secret_name')
    return 'ARDA_'+provider.upper()+'_SIGNER_PKCS8_B64_'+key_sha256.upper()

def registration_payload(c,provider,public,*,now):
    check_ceremony(c,now);need(provider in PROFILES,'registration_provider')
    role,algorithm=PROFILES[provider];validate_key(algorithm,public)
    key_sha=sha(public)
    return dict(schema='arda.pq.key_registration.v1',ceremony_sha256=sha(canonical(c)),provider=provider,
        provider_identity=c['identities'][provider],witness_id=provider+':'+c['identities'][provider].replace('/','.'),
        role=role,algorithm=algorithm,key_sha256=key_sha,public_key_b64=base64.b64encode(public).decode(),
        secret_name=secret_name(provider,key_sha) if provider!='cloudflare' else None,issued_at=now,expires_at=c['expires_at'])

def public_record(c,provider,private,*,now):
    need(provider in ('github','hf'),'stateless_provider_required');check_ceremony(c,now)
    signer=OpenSSLSigner(PROFILES[provider][1],private)
    payload=registration_payload(c,provider,signer.public,now=now)
    return dict(payload=payload,signature_b64=base64.b64encode(signer.sign(REGISTRATION_DOMAIN+canonical(payload))).decode())

def check_record(record,c,*,now,backends):
    check_ceremony(c,now)
    need(type(record) is dict and record.keys()=={'payload','signature_b64'},'registration_envelope')
    p=record['payload'];need(type(p) is dict and p.keys()==REGISTRATION_FIELDS,'registration_fields')
    provider=p['provider'];need(type(provider) is str and provider in PROFILES,'registration_provider')
    public=unbase64(p['public_key_b64'],4096)
    need(type(p['issued_at']) is int and c['issued_at']<=p['issued_at']<=now,'registration_time')
    expected=registration_payload(c,provider,public,now=p['issued_at'])
    need(p==expected,'registration_binding');window(p,now,86400)
    sig=unbase64(record['signature_b64'],65536)
    need(backends.verify(p['algorithm'],public,REGISTRATION_DOMAIN+canonical(p),sig),'registration_proof_invalid')
    return {k:p[k] for k in ('witness_id','provider','role','algorithm','key_sha256','public_key_b64')}

def assemble(c,records,record_pins,*,epoch,now,backends):
    c=strict_load(canonical(c));records=strict_load(canonical(records));record_pins=strict_load(canonical(record_pins))
    check_ceremony(c,now)
    need(type(records) is list and len(records)==3 and type(record_pins) is dict and record_pins.keys()==PROFILES.keys(),'all_three_reviewed_records_required')
    witnesses=[];seen=set()
    for r in records:
        need(type(r) is dict and type(r.get('payload')) is dict,'registration_envelope')
        p=r['payload'].get('provider');need(type(p) is str and p in PROFILES and p not in seen,'registration_provider_coverage')
        need(hex64(record_pins[p]) and sha(canonical(r))==record_pins[p],'operator_registration_pin')
        witnesses.append(check_record(r,c,now=now,backends=backends));seen.add(p)
    need(seen==set(PROFILES),'all_three_reviewed_records_required')
    policy=dict(schema='arda.pq.enrollment.v1',epoch=epoch,issued_at=now,expires_at=now+30*86400,production_authorized=False,
                witnesses=sorted(witnesses,key=lambda w:w['provider']))
    enrollment(policy,now)
    return dict(schema='arda.pq.enrollment_result.v1',policy=policy,policy_file_sha256=sha(canonical(policy)),
        registration_pins=record_pins,ceremony_sha256=sha(canonical(c)),production_authorized=False,interlock='KEEP_CLOSED',
        provider_provenance_verified=False,secret_store_readback_verified=False,
        blockers=['HOSTED_KEY_CUSTODY_ACCEPTANCE_REQUIRED','STATEFUL_SIGNER_REVIEW_REQUIRED','FRESH_R13_EVIDENCE_REQUIRED','LIVE_PROVIDER_VOTES_REQUIRED','REKOR_PROOF_REQUIRED','PRODUCTION_CONSUMER_NOT_INSTALLED'])

def generate_private(algorithm):
    need(algorithm in (ML,SLH),'stateless_algorithm_required')
    binary=shutil.which('openssl');need(binary is not None,'openssl_missing')
    with tempfile.TemporaryDirectory(prefix='arda-enrollment-key-') as directory:
        path=Path(directory)/'key.der'
        fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600);os.close(fd)
        run=subprocess.run([binary,'genpkey','-algorithm',algorithm,'-outform','DER','-out',str(path)],
            stdin=subprocess.DEVNULL,capture_output=True,timeout=60,env={'PATH':os.defpath,'OPENSSL_CONF':'/dev/null'})
        need(run.returncode==0,'provider_key_generation_refused')
        raw=path.read_bytes();need(0<len(raw)<=16384,'provider_private_key_size');return raw

def provision(c,provider,*,environ,now,key_factory=None,store=None):
    try:
        c=strict_load(canonical(c));check_ceremony(c,now)
        need(provider in ('github','hf'),'stateless_provider_required')
        need(environ.get('ARDA_ALLOW_PROVIDER_KEY_PROVISIONING')==sha(canonical(c)),'explicit_ceremony_enable_required')
        need(environ.get('ARDA_IMAGE_DIGEST')==c['image_digest'],'setup_image_binding')
        if provider=='github':
            need(environ.get('GITHUB_ACTIONS')=='true' and environ.get('GITHUB_REPOSITORY')==c['identities'][provider],'provider_setup_identity')
        else:need(environ.get('SPACE_ID')==c['identities'][provider],'provider_setup_identity')
        token=environ.get('ARDA_ENROLLMENT_STORE_TOKEN')
        need(type(token) is str and 0<len(token)<=4096 and all(33<=ord(ch)<=126 for ch in token),'provider_store_credential_required')
        if store is None:
            from .enrollment_store import ProviderSecretStore
            store=ProviderSecretStore(provider,c['identities'][provider],token)
        private=(key_factory or generate_private)(PROFILES[provider][1])
        record=public_record(c,provider,private,now=now)
        store.put(record['payload']['secret_name'],base64.b64encode(private).decode())
        # Python cannot promise memory zeroization; keys exist only in this process and private temp files.
        return record
    except Exception:
        raise ValueError('PROVIDER_ENROLLMENT_REFUSED') from None
