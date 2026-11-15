#!/usr/bin/env python3
"""Inspect PQ review signatures. Always refuses production admission."""
import argparse
import json
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.crypto import Backends
from arda_quorum.quorum import strict_load,sha,need,hex64,verify_quorum
from arda_quorum.proposal import validate_request,REVIEWED_REQUEST_SHA256
from arda_quorum.journal import ReviewJournal

def read(path):
    with path.open('rb') as stream:raw=stream.read(1048577)
    need(len(raw)<=1048576,'input_size')
    return raw

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--certificate',type=Path,required=True)
    parser.add_argument('--policy',type=Path,required=True)
    parser.add_argument('--policy-sha256',required=True,help='Operator-trusted enrollment pin, never extracted from the certificate')
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--r13-evidence-sha256',required=True,help='Binds evidence bytes only; does not claim the evidence was verified')
    parser.add_argument('--consume-review',type=Path,help='Optional private SQLite review-intent journal, never an execution grant')
    args=parser.parse_args()
    try:
        raw=read(args.policy);need(hex64(args.policy_sha256) and sha(raw)==args.policy_sha256,'operator_enrollment_pin')
        policy=strict_load(raw);certificate=strict_load(read(args.certificate))
        expected=validate_request(read(args.request),REVIEWED_REQUEST_SHA256)
        need(hex64(args.r13_evidence_sha256),'evidence_digest')
        expected['r13_evidence_sha256']=args.r13_evidence_sha256
        backends=Backends()
        if args.consume_review:
            result=ReviewJournal(args.consume_review,backends=backends).consume(certificate,policy,expected=expected)
        else:result=verify_quorum(certificate,policy,expected=expected,now=int(time.time()),backends=backends)
    except Exception as exc:
        result=dict(decision='REFUSE',quorum_valid=False,reason=str(exc),production_authorized=False,interlock='KEEP_CLOSED')
    print(json.dumps(result,indent=2,sort_keys=True))
    # No successful shell exit can accidentally be treated as release admission.
    return 1

if __name__=='__main__':raise SystemExit(main())
