#!/usr/bin/env python3
"""Create an unready unsigned review draft. No signing or network calls."""
import argparse
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.proposal import prepare_draft
from arda_quorum.quorum import strict_load

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--request',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    parser.add_argument('--policy',type=Path)
    args=parser.parse_args()
    draft=prepare_draft(args.request.read_bytes(),now=int(time.time()),
        policy=strict_load(args.policy.read_bytes()) if args.policy else None)
    fd=os.open(args.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
    with os.fdopen(fd,'w') as stream:
        json.dump(draft,stream,indent=2,sort_keys=True);stream.write('\n');stream.flush();os.fsync(stream.fileno())
    print('DRAFT='+str(args.out));print('STATE=UNREADY_DRAFT\nPRODUCTION_AUTHORIZED=FALSE\nINTERLOCK=KEEP_CLOSED')

if __name__=='__main__':main()
