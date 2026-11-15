#!/usr/bin/env python3
"""Read public pin metadata only; never read tokens or deployment secret files."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from cryptography.hazmat.primitives import serialization
from arda_quorum.proposal import validate_request,REVIEWED_REQUEST_SHA256
from arda_quorum.quorum import strict_load
ROOT=Path(__file__).resolve().parents[1]

def read(path,cap):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC)
    with os.fdopen(fd,'rb') as stream:
        raw=stream.read(cap+1)
    if len(raw)>cap:raise ValueError('public_input_oversized')
    return raw

def public_pin(path):
    key=serialization.load_pem_public_key(read(path,8192))
    der=key.public_bytes(serialization.Encoding.DER,serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--out',type=Path,required=True);parser.add_argument('--state-dir',type=Path,default=Path.home()/'.local/state/arda-r13-cloudflare')
    args=parser.parse_args()
    raw=(ROOT/'inputs/generation14-staging-request.json').read_bytes();validate_request(raw,REVIEWED_REQUEST_SHA256)
    deployment=strict_load(raw)['deployment']
    expected=dict(verifier_spki_sha256=deployment['r13_verifier_spki_sha256'],policy_sha256=deployment['r13_policy_sha256'],
        ak_spki_sha256=deployment['r13_ak_spki_sha256'],node_id=deployment['r13_subject_node_id'])
    state=args.state_dir;observations=[]
    p=state/'pins.json'
    try:
        data=strict_load(read(p,8192))
        selected={k:data.get(k) for k in ('endpoint','node_id','verifier_id','verifier_spki_sha256','policy_sha256')}
        observations.append(dict(path=str(p),public_metadata=selected,
            proposal_fields_match=all(data.get(k)==expected[k] for k in ('node_id','verifier_spki_sha256','policy_sha256'))))
    except (OSError,ValueError) as exc:observations.append(dict(path=str(p),error=type(exc).__name__))
    for p in (state/'verifier-public.pem',Path('/etc/arda/verifier/verifier-key.pub.pem'),Path('/var/lib/arda/verifier/lenovo-r13-verifier-public.pem')):
        try:
            pin=public_pin(p);observations.append(dict(path=str(p),spki_sha256=pin,matches_proposal_verifier=pin==expected['verifier_spki_sha256']))
        except (OSError,ValueError) as exc:observations.append(dict(path=str(p),error=type(exc).__name__))
    report=dict(schema='arda.pq.r13_public_pin_inventory.v1',expected_from_reviewed_generation14=expected,
        observations=observations,active_deployed_service_identity_proven=False,fresh_quote_verified=False,
        production_authorized=False,interlock='KEEP_CLOSED')
    fd=os.open(args.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:json.dump(report,stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print('PUBLIC_PIN_REPORT='+str(args.out));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')

if __name__=='__main__':main()
