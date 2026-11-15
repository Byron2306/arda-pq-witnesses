#!/usr/bin/env python3
"""Emit one bounded review vote using a provider-held stateless PQ key."""
import argparse
import json
import os
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.provider_runtime import load_runtime
from arda_quorum.quorum import strict_load,canonical,need

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provider',choices=('github','hf'),required=True)
    p.add_argument('--request',type=Path,required=True);p.add_argument('--out',type=Path,required=True);a=p.parse_args()
    try:
        with a.request.open('rb') as stream:raw=stream.read(65537)
        need(len(raw)<=65536,'request_size');request=strict_load(raw);need(canonical(request)==raw,'request_canonical_encoding')
        vote=load_runtime(a.provider).review(request)
        fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        with os.fdopen(fd,'wb') as stream:stream.write(canonical(vote)+b'\n');stream.flush();os.fsync(stream.fileno())
    except Exception:
        print('WITNESS_REVIEW_REFUSED',file=sys.stderr);return 1
    print('REVIEW_VOTE_WRITTEN\nPRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED');return 0
if __name__=='__main__':raise SystemExit(main())
