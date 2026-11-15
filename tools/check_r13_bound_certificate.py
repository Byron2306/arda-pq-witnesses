#!/usr/bin/env python3
"""Check real R13 evidence and all-three PQ review signatures; never admit production."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.quorum import strict_load,sha,canonical,need,hex64
from arda_quorum.crypto import Backends
from arda_quorum.proposal import validate_request,REVIEWED_REQUEST_SHA256
from arda_quorum.r13_bridge import PinnedR13,verify_with_r13

def bounded(path,cap=1048576):
    with path.open('rb') as stream:raw=stream.read(cap+1)
    need(len(raw)<=cap,'input_size');return raw

def main():
    p=argparse.ArgumentParser(description=__doc__)
    for flag in ('certificate','policy','request','capture','verifier-public-key','ak-public-key','approved-pcrs'):
        p.add_argument('--'+flag,type=Path,required=True)
    p.add_argument('--policy-sha256',required=True,help='Operator-approved enrollment file digest')
    a=p.parse_args()
    try:
        raw=bounded(a.request);expected=validate_request(raw,REVIEWED_REQUEST_SHA256);d=strict_load(raw)['deployment']
        pins=dict(verifier_spki_sha256=d['r13_verifier_spki_sha256'],ak_spki_sha256=d['r13_ak_spki_sha256'],
            policy_sha256=d['r13_policy_sha256'],node_id=d['r13_subject_node_id'],verifier_id='cloudflare-r13-v2')
        enrollment=bounded(a.policy);need(hex64(a.policy_sha256) and sha(enrollment)==a.policy_sha256,'operator_enrollment_pin')
        capture=strict_load(bounded(a.capture,65536));expected['r13_evidence_sha256']=sha(canonical(capture))
        gate=PinnedR13(bounded(a.verifier_public_key,8192),bounded(a.ak_public_key,8192),strict_load(bounded(a.approved_pcrs,4096)),pins)
        result=verify_with_r13(strict_load(bounded(a.certificate)),strict_load(enrollment),expected=expected,capture=capture,
            r13_gate=gate,now=int(time.time()),backends=Backends())
    except Exception as exc:
        result=dict(decision='REFUSE',quorum_valid=False,r13_valid=False,reason=str(exc),production_authorized=False,interlock='KEEP_CLOSED')
    print(json.dumps(result,indent=2,sort_keys=True));return 1

if __name__=='__main__':raise SystemExit(main())
