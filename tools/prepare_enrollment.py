#!/usr/bin/env python3
"""Prepare public setup pins; never generates provider keys."""
import argparse
from pathlib import Path
import secrets
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import new_ceremony
from arda_quorum.quorum import canonical,sha

def main():
    p=argparse.ArgumentParser();p.add_argument('--image-digest',required=True);p.add_argument('--cloudflare-identity',required=True)
    p.add_argument('--out',required=True);a=p.parse_args()
    c=new_ceremony(nonce=secrets.token_hex(32),image_digest=a.image_digest,now=int(time.time()),identities={
        'github':'Byron2306/arda-pq-witnesses','hf':'Byron230686/arda-pq-policy-witness','cloudflare':a.cloudflare_identity})
    raw=canonical(c)
    with Path(a.out).open('xb') as stream:stream.write(raw)
    print('CEREMONY_SHA256='+sha(raw));print('PRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')
if __name__=='__main__':main()
