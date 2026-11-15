#!/usr/bin/env python3
"""Explicit provider-local command. Never use as a Space startup command."""
import argparse
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from arda_quorum.enrollment import provision,check_ceremony
from arda_quorum.quorum import canonical,strict_load,sha,hex64,need

def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--provider',choices=['github','hf'],required=True)
    p.add_argument('--ceremony',required=True);p.add_argument('--ceremony-sha256',required=True);p.add_argument('--out')
    a=p.parse_args();fd=None
    try:
        path=Path(a.ceremony);need(path.stat().st_size<=16384,'ceremony_size');raw=path.read_bytes()
        need(hex64(a.ceremony_sha256) and sha(raw)==a.ceremony_sha256,'operator_ceremony_pin')
        c=strict_load(raw);need(raw==canonical(c),'canonical_ceremony_required')
        if a.out:fd=os.open(a.out,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        record=provision(c,a.provider,environ=os.environ,now=int(time.time()))
        check_ceremony(c,int(time.time()))
        if fd is not None:
            with os.fdopen(fd,'wb') as stream:fd=None;stream.write(canonical(record))
            print('PUBLIC_REGISTRATION_SHA256='+sha(canonical(record)))
        else:print(canonical(record).decode())
        return 0
    except Exception:
        if fd is not None:
            os.close(fd)
            try:Path(a.out).unlink()
            except OSError:pass
        print('PROVIDER_ENROLLMENT_REFUSED',file=sys.stderr);return 1
if __name__=='__main__':raise SystemExit(main())
